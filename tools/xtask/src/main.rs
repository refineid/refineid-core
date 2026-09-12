// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Repository policy tasks.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

use proc_macro2::{Span, TokenStream, TokenTree};
use rustc_lexer::TokenKind;
use syn::ext::IdentExt;
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    Attribute, Expr, ExprAsync, ExprClosure, ImplItemConst, Item, ItemConst, ItemMacro, ItemStatic,
    ItemUse, Lit, LitByte, LitByteStr, LitCStr, LitChar, LitFloat, LitInt, LitStr, Macro, Meta,
    TraitItemConst, UseTree, Variant,
};
use walkdir::{DirEntry, WalkDir};

const USAGE_EXIT_CODE: i32 = 2;
const POLICY_EXIT_CODE: i32 = 1;

fn main() {
    let mut args = std::env::args().skip(1);
    match (args.next().as_deref(), args.next()) {
        (Some("check-magic-numbers"), None) => {
            if let Err(error) = check_magic_numbers(&workspace_root()) {
                eprintln!("{error}");
                process::exit(POLICY_EXIT_CODE);
            }
        }
        _ => {
            eprintln!("usage: cargo run -p xtask -- check-magic-numbers");
            process::exit(USAGE_EXIT_CODE);
        }
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("xtask is stored at tools/xtask")
        .to_path_buf()
}

fn check_magic_numbers(root: &Path) -> Result<(), String> {
    validate_cargo_targets(root)?;

    let mut all_violations = Vec::new();
    for entry in WalkDir::new(root).into_iter().filter_entry(|entry| {
        is_source_tree_entry(root, entry) && !is_policy_exempt_path(root, entry.path())
    }) {
        let entry = entry.map_err(|error| format!("cannot walk source tree: {error}"))?;
        reject_source_tree_symlink(&entry)?;
        if !entry.file_type().is_file() {
            continue;
        }
        let bytes = fs::read(entry.path())
            .map_err(|error| format!("cannot read {}: {error}", entry.path().display()))?;
        if entry.path().extension() == Some(OsStr::new("rs")) {
            let source = String::from_utf8(bytes)
                .map_err(|error| format!("{} is not UTF-8: {error}", entry.path().display()))?;
            let syntax = syn::parse_file(&source)
                .map_err(|error| format!("cannot parse {}: {error}", entry.path().display()))?;
            inspect_rust_comments(entry.path(), &source, &mut all_violations);
            let mut visitor = MagicNumberVisitor::new(entry.path());
            visitor.visit_file(&syntax);
            all_violations.extend(visitor.violations);
        } else {
            inspect_non_rust_bytes(entry.path(), &bytes, &mut all_violations);
        }
    }

    if all_violations.is_empty() {
        println!("magic-number policy: clean");
        return Ok(());
    }

    all_violations.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.line.cmp(&right.line))
            .then(left.column.cmp(&right.column))
    });
    for violation in &all_violations {
        let location = format!(
            "{}:{}:{}",
            violation.path.display(),
            violation.line,
            violation.column
        );
        match &violation.kind {
            ViolationKind::AnonymousLiteral(literal) => {
                eprintln!("{location}: anonymous numeric spelling `{literal}`");
            }
            ViolationKind::SourceIndirection(form) => {
                eprintln!("{location}: source indirection `{form}` is prohibited");
            }
            ViolationKind::TextNumericSpelling(form) => {
                eprintln!("{location}: {form} in untyped text or a comment is prohibited");
            }
        }
    }
    Err(format!(
        "magic-number policy rejected {} issue(s); name the domain concept",
        all_violations.len()
    ))
}

fn validate_cargo_targets(root: &Path) -> Result<(), String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .arg("metadata")
        .arg("--format-version=1")
        .arg("--locked")
        .arg("--manifest-path")
        .arg(root.join("Cargo.toml"))
        .output()
        .map_err(|error| format!("cannot run cargo metadata: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("cannot parse cargo metadata: {error}"))?;
    validate_cargo_metadata(root, &metadata)
}

fn validate_cargo_metadata(root: &Path, metadata: &serde_json::Value) -> Result<(), String> {
    let packages = metadata
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .ok_or("cargo metadata omitted packages")?;

    for package in packages {
        let manifest = package
            .get("manifest_path")
            .and_then(serde_json::Value::as_str)
            .ok_or("cargo metadata package omitted manifest_path")?;
        let manifest = Path::new(manifest);
        let is_path_package = package.get("source").is_none_or(serde_json::Value::is_null);
        if is_path_package && !manifest.starts_with(root) {
            return Err(format!(
                "Cargo path dependency must remain inside the repository: {}",
                manifest.display()
            ));
        }
        let targets = package
            .get("targets")
            .and_then(serde_json::Value::as_array)
            .ok_or("cargo metadata package omitted targets")?;
        for target in targets {
            let source = target
                .get("src_path")
                .and_then(serde_json::Value::as_str)
                .ok_or("cargo metadata target omitted src_path")?;
            let source = Path::new(source);
            if is_path_package || source.starts_with(root) {
                validate_cargo_target_source(root, source)?;
                let doctest = target
                    .get("doctest")
                    .and_then(serde_json::Value::as_bool)
                    .ok_or("cargo metadata target omitted doctest")?;
                reject_executable_doctests(source, doctest)?;
            }
        }
    }
    Ok(())
}

fn reject_executable_doctests(source: &Path, enabled: bool) -> Result<(), String> {
    if enabled {
        return Err(format!(
            "Executable doctests are prohibited for policy-visible targets: {}",
            source.display()
        ));
    }
    Ok(())
}

fn validate_cargo_target_source(root: &Path, source: &Path) -> Result<(), String> {
    if !source.starts_with(root)
        || source.extension() != Some(OsStr::new("rs"))
        || is_ignored_root_path(root, source)
    {
        return Err(format!(
            "Cargo target source must be an in-repository .rs file: {}",
            source.display()
        ));
    }
    Ok(())
}

fn is_source_tree_entry(root: &Path, entry: &DirEntry) -> bool {
    !is_ignored_root_path(root, entry.path())
}

fn reject_source_tree_symlink(entry: &DirEntry) -> Result<(), String> {
    if entry.file_type().is_symlink() {
        return Err(format!(
            "source-tree symlinks are prohibited: {}",
            entry.path().display()
        ));
    }
    Ok(())
}

fn is_ignored_root_path(root: &Path, path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(root) else {
        return false;
    };
    // The lock file is generated, not authored; its dependency checksums
    // are hex strings that can contain radix-prefix lookalikes.
    if relative == Path::new("Cargo.lock") {
        return true;
    }
    matches!(
        relative.components().next(),
        Some(std::path::Component::Normal(name))
            if name == OsStr::new(".git") || name == OsStr::new("target")
    )
}

/// Subtrees admitted before they satisfy the numeric and source-indirection
/// policy. The RAPP engine arrived from the RefineID mono repository as the
/// working Android bridge, together with its pinned protocol corpus. The
/// Apple-native implementation is the only pairing proven live, so the bridge
/// is admitted as-is instead of being hardened speculatively; it may be
/// simplified against the live-proven behaviour rather than polished.
/// PC/SC and PKCS#11 subtrees interact with external C ABI specifications
/// (OASIS Cryptoki v2.40 and PC/SC Workgroup). Remove
/// an entry when its subtree is brought under policy or replaced.
const POLICY_EXEMPT_SUBTREES: &[&str] = &[
    "crates/pcsc",
    "crates/pkcs11",
    "crates/rapp",
    "docs/protocols",
];

fn is_policy_exempt_path(root: &Path, path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(root) else {
        return false;
    };
    POLICY_EXEMPT_SUBTREES
        .iter()
        .any(|subtree| relative.starts_with(subtree))
}

#[derive(Debug, PartialEq, Eq)]
struct Violation {
    path: PathBuf,
    line: usize,
    column: usize,
    kind: ViolationKind,
}

#[derive(Debug, PartialEq, Eq)]
enum ViolationKind {
    AnonymousLiteral(String),
    SourceIndirection(&'static str),
    TextNumericSpelling(&'static str),
}

fn inspect_non_rust_bytes(path: &Path, bytes: &[u8], violations: &mut Vec<Violation>) {
    inspect_numeric_bytes(path, bytes, 1, 0, violations);
}

fn inspect_rust_comments(path: &Path, source: &str, violations: &mut Vec<Violation>) {
    if let Some(shebang_length) = rustc_lexer::strip_shebang(source) {
        inspect_numeric_bytes(path, &source.as_bytes()[..shebang_length], 1, 0, violations);
    }
    let mut offset = 0;
    let mut line = 1;
    let mut column = 0;
    for token in rustc_lexer::tokenize(source) {
        let token_end = offset + token.len;
        let token_text = &source.as_bytes()[offset..token_end];
        if matches!(
            token.kind,
            TokenKind::LineComment | TokenKind::BlockComment { .. }
        ) {
            inspect_numeric_bytes(path, token_text, line, column, violations);
        }
        advance_location(token_text, &mut line, &mut column);
        offset = token_end;
    }
}

fn inspect_numeric_bytes(
    path: &Path,
    bytes: &[u8],
    mut line: usize,
    mut column: usize,
    violations: &mut Vec<Violation>,
) {
    let mut at = 0;
    while at < bytes.len() {
        if let Some((width, form)) = numeric_spelling_at(bytes, at) {
            violations.push(Violation {
                path: path.to_path_buf(),
                line,
                column,
                kind: ViolationKind::TextNumericSpelling(form),
            });
            advance_location(&bytes[at..at + width], &mut line, &mut column);
            at += width;
        } else {
            advance_location(&bytes[at..at + 1], &mut line, &mut column);
            at += 1;
        }
    }
}

fn advance_location(bytes: &[u8], line: &mut usize, column: &mut usize) {
    for byte in bytes {
        if *byte == b'\n' {
            *line += 1;
            *column = 0;
        } else {
            *column += 1;
        }
    }
}

fn numeric_spelling_at(bytes: &[u8], at: usize) -> Option<(usize, &'static str)> {
    const RADIX_PREFIX_WIDTH: usize = 3;
    const HEX_ESCAPE_WIDTH: usize = 4;
    const UNICODE_ESCAPE_PREFIX_WIDTH: usize = 4;
    const JSON_UNICODE_ESCAPE_WIDTH: usize = 6;
    const LONG_UNICODE_ESCAPE_WIDTH: usize = 10;
    const OCTAL_ESCAPE_PREFIX_WIDTH: usize = 2;
    const ESCAPE_PREFIX_WIDTH: usize = 2;

    let rest = bytes.get(at..)?;
    match rest {
        [b'0', b'x' | b'X', digit, ..] if digit.is_ascii_hexdigit() => {
            Some((RADIX_PREFIX_WIDTH, "radix numeric spelling"))
        }
        [b'0', b'b' | b'B', b'0' | b'1', ..] => {
            Some((RADIX_PREFIX_WIDTH, "radix numeric spelling"))
        }
        [b'0', b'o' | b'O', b'0'..=b'7', ..] => {
            Some((RADIX_PREFIX_WIDTH, "radix numeric spelling"))
        }
        [b'\\', b'x', high, low, ..] if high.is_ascii_hexdigit() && low.is_ascii_hexdigit() => {
            Some((HEX_ESCAPE_WIDTH, "numeric escape"))
        }
        [b'\\', b'u', b'{', digit, ..] if digit.is_ascii_hexdigit() => {
            Some((UNICODE_ESCAPE_PREFIX_WIDTH, "numeric escape"))
        }
        [b'\\', b'u', first, second, third, fourth, ..]
            if [first, second, third, fourth]
                .iter()
                .all(|digit| digit.is_ascii_hexdigit()) =>
        {
            Some((JSON_UNICODE_ESCAPE_WIDTH, "numeric escape"))
        }
        [b'\\', b'U', digits @ ..]
            if digits.len() >= LONG_UNICODE_ESCAPE_WIDTH - ESCAPE_PREFIX_WIDTH =>
        {
            let digits = &digits[..LONG_UNICODE_ESCAPE_WIDTH - ESCAPE_PREFIX_WIDTH];
            if digits.iter().all(|digit| digit.is_ascii_hexdigit()) {
                Some((LONG_UNICODE_ESCAPE_WIDTH, "numeric escape"))
            } else {
                None
            }
        }
        [b'\\', b'0'..=b'7', ..] => Some((OCTAL_ESCAPE_PREFIX_WIDTH, "numeric escape")),
        _ => None,
    }
}

struct MagicNumberVisitor<'path> {
    path: &'path Path,
    named_value_depth: usize,
    violations: Vec<Violation>,
}

impl<'path> MagicNumberVisitor<'path> {
    fn new(path: &'path Path) -> Self {
        Self {
            path,
            named_value_depth: 0,
            violations: Vec::new(),
        }
    }

    fn visit_named_value(&mut self, expression: &Expr) {
        self.named_value_depth += 1;
        self.visit_expr(expression);
        self.named_value_depth -= 1;
    }

    fn visit_constant_value(&mut self, name: &str, expression: &Expr) {
        if name == "_" {
            self.visit_expr(expression);
        } else {
            self.visit_named_value(expression);
        }
    }

    fn record(&mut self, span: Span, kind: ViolationKind) {
        let start = span.start();
        self.violations.push(Violation {
            path: self.path.to_path_buf(),
            line: start.line,
            column: start.column,
            kind,
        });
    }

    fn inspect_integer(&mut self, literal: &LitInt) {
        if self.named_value_depth > 0 || is_tier_zero_literal(literal) {
            return;
        }
        self.record(
            literal.span(),
            ViolationKind::AnonymousLiteral(literal.to_string()),
        );
    }

    fn inspect_float(&mut self, literal: &LitFloat) {
        if self.named_value_depth == 0 {
            self.record(
                literal.span(),
                ViolationKind::AnonymousLiteral(literal.to_string()),
            );
        }
    }

    fn inspect_encoded_literal(&mut self, span: Span, spelling: String) {
        if self.named_value_depth == 0 && contains_numeric_spelling(&spelling) {
            self.record(span, ViolationKind::AnonymousLiteral(spelling));
        }
    }

    fn inspect_literal(&mut self, literal: Lit) {
        match literal {
            Lit::Int(integer) => self.inspect_integer(&integer),
            Lit::Float(float) => self.inspect_float(&float),
            Lit::Byte(byte) => {
                self.inspect_encoded_literal(byte.span(), byte.token().to_string());
            }
            Lit::ByteStr(bytes) => {
                self.inspect_encoded_literal(bytes.span(), bytes.token().to_string());
            }
            Lit::CStr(text) => {
                self.inspect_encoded_literal(text.span(), text.token().to_string());
            }
            Lit::Char(character) => {
                self.inspect_encoded_literal(character.span(), character.token().to_string());
            }
            Lit::Str(text) => {
                self.inspect_encoded_literal(text.span(), text.token().to_string());
            }
            Lit::Bool(_) | Lit::Verbatim(_) => {}
            _ => {}
        }
    }

    fn inspect_tokens(&mut self, tokens: TokenStream) {
        const TOKEN_PAIR_WIDTH: usize = 2;

        let tokens: Vec<_> = tokens.into_iter().collect();
        for (index, pair) in tokens.windows(TOKEN_PAIR_WIDTH).enumerate() {
            if let [TokenTree::Ident(ident), TokenTree::Punct(punctuation)] = pair {
                let name = normalized_ident(ident);
                if punctuation.as_char() == '!' {
                    let is_qualified = index > 0
                        && matches!(
                            tokens.get(index - 1),
                            Some(TokenTree::Punct(previous)) if previous.as_char() == ':'
                        );
                    if name == "include" {
                        self.record(
                            ident.span(),
                            ViolationKind::SourceIndirection("macro-generated include!"),
                        );
                    } else if is_qualified || !is_trusted_macro_name(&name) {
                        self.record(
                            ident.span(),
                            ViolationKind::SourceIndirection("nested unapproved opaque macro"),
                        );
                    }
                } else if name == "path" && punctuation.as_char() == '=' {
                    self.record(
                        ident.span(),
                        ViolationKind::SourceIndirection("macro-generated path attribute"),
                    );
                }
            }
        }
        for token in tokens {
            match token {
                TokenTree::Group(group) => self.inspect_tokens(group.stream()),
                TokenTree::Literal(literal) => self.inspect_literal(Lit::new(literal)),
                TokenTree::Ident(_) | TokenTree::Punct(_) => {}
            }
        }
    }

    fn inspect_use_tree(&mut self, tree: &UseTree) {
        match tree {
            UseTree::Path(path) => {
                if ident_is(&path.ident, "include") {
                    self.record(
                        path.ident.span(),
                        ViolationKind::SourceIndirection("include! import"),
                    );
                }
                self.inspect_use_tree(&path.tree);
            }
            UseTree::Name(name) => {
                if ident_is(&name.ident, "include") {
                    self.record(
                        name.ident.span(),
                        ViolationKind::SourceIndirection("include! import"),
                    );
                } else if is_reserved_macro_binding(&normalized_ident(&name.ident)) {
                    self.record(
                        name.ident.span(),
                        ViolationKind::SourceIndirection("trusted macro name import"),
                    );
                }
            }
            UseTree::Rename(rename) => {
                if ident_is(&rename.ident, "include") {
                    self.record(
                        rename.ident.span(),
                        ViolationKind::SourceIndirection("include! import"),
                    );
                }
                if is_reserved_macro_binding(&normalized_ident(&rename.rename)) {
                    self.record(
                        rename.rename.span(),
                        ViolationKind::SourceIndirection("trusted macro name alias"),
                    );
                }
            }
            UseTree::Glob(glob) => self.record(
                glob.star_token.span(),
                ViolationKind::SourceIndirection("glob import"),
            ),
            UseTree::Group(group) => {
                for item in &group.items {
                    self.inspect_use_tree(item);
                }
            }
        }
    }

    fn inspect_derive_attribute(&mut self, attribute: &Attribute) {
        let Meta::List(list) = &attribute.meta else {
            self.record(
                attribute.span(),
                ViolationKind::SourceIndirection("malformed derive attribute"),
            );
            return;
        };
        let parser = Punctuated::<syn::Path, syn::token::Comma>::parse_terminated;
        let Ok(derives) = parser.parse2(list.tokens.clone()) else {
            self.record(
                attribute.span(),
                ViolationKind::SourceIndirection("unparsed derive attribute"),
            );
            return;
        };
        for derive in derives {
            if !is_trusted_derive(&derive) {
                self.record(
                    derive.span(),
                    ViolationKind::SourceIndirection("unapproved derive macro"),
                );
            }
        }
    }
}

impl<'ast> Visit<'ast> for MagicNumberVisitor<'_> {
    fn visit_item(&mut self, node: &'ast Item) {
        let outer_depth = self.named_value_depth;
        self.named_value_depth = 0;
        visit::visit_item(self, node);
        self.named_value_depth = outer_depth;
    }

    fn visit_item_macro(&mut self, node: &'ast ItemMacro) {
        if let Some(ident) = &node.ident
            && is_reserved_macro_binding(&normalized_ident(ident))
        {
            self.record(
                ident.span(),
                ViolationKind::SourceIndirection("trusted macro name definition"),
            );
        }
        visit::visit_item_macro(self, node);
    }

    fn visit_item_use(&mut self, node: &'ast ItemUse) {
        self.inspect_use_tree(&node.tree);
        visit::visit_item_use(self, node);
    }

    fn visit_expr_closure(&mut self, node: &'ast ExprClosure) {
        let outer_depth = self.named_value_depth;
        self.named_value_depth = 0;
        visit::visit_expr_closure(self, node);
        self.named_value_depth = outer_depth;
    }

    fn visit_expr_async(&mut self, node: &'ast ExprAsync) {
        let outer_depth = self.named_value_depth;
        self.named_value_depth = 0;
        visit::visit_expr_async(self, node);
        self.named_value_depth = outer_depth;
    }

    fn visit_attribute(&mut self, node: &'ast Attribute) {
        let outer_depth = self.named_value_depth;
        self.named_value_depth = 0;
        if path_is_ident(node.path(), "path") {
            self.record(
                node.path().span(),
                ViolationKind::SourceIndirection("path attribute"),
            );
        } else if path_is_ident(node.path(), "macro_use") {
            self.record(
                node.path().span(),
                ViolationKind::SourceIndirection("macro_use attribute"),
            );
        } else if path_is_ident(node.path(), "derive") {
            self.inspect_derive_attribute(node);
        } else if !is_trusted_inert_attribute(node.path()) {
            self.record(
                node.path().span(),
                ViolationKind::SourceIndirection("unapproved attribute macro"),
            );
        }
        visit::visit_attribute(self, node);
        self.named_value_depth = outer_depth;
    }

    fn visit_item_const(&mut self, node: &'ast ItemConst) {
        for attribute in &node.attrs {
            self.visit_attribute(attribute);
        }
        self.visit_visibility(&node.vis);
        self.visit_ident(&node.ident);
        self.visit_generics(&node.generics);
        self.visit_type(&node.ty);
        self.visit_constant_value(&node.ident.to_string(), &node.expr);
    }

    fn visit_item_static(&mut self, node: &'ast ItemStatic) {
        for attribute in &node.attrs {
            self.visit_attribute(attribute);
        }
        self.visit_visibility(&node.vis);
        self.visit_static_mutability(&node.mutability);
        self.visit_ident(&node.ident);
        self.visit_type(&node.ty);
        self.visit_constant_value(&node.ident.to_string(), &node.expr);
    }

    fn visit_impl_item_const(&mut self, node: &'ast ImplItemConst) {
        for attribute in &node.attrs {
            self.visit_attribute(attribute);
        }
        self.visit_visibility(&node.vis);
        self.visit_ident(&node.ident);
        self.visit_generics(&node.generics);
        self.visit_type(&node.ty);
        self.visit_constant_value(&node.ident.to_string(), &node.expr);
    }

    fn visit_trait_item_const(&mut self, node: &'ast TraitItemConst) {
        for attribute in &node.attrs {
            self.visit_attribute(attribute);
        }
        self.visit_ident(&node.ident);
        self.visit_generics(&node.generics);
        self.visit_type(&node.ty);
        if let Some((_, expression)) = &node.default {
            self.visit_constant_value(&node.ident.to_string(), expression);
        }
    }

    fn visit_variant(&mut self, node: &'ast Variant) {
        for attribute in &node.attrs {
            self.visit_attribute(attribute);
        }
        self.visit_ident(&node.ident);
        self.visit_fields(&node.fields);
        if let Some((_, expression)) = &node.discriminant {
            self.visit_named_value(expression);
        }
    }

    fn visit_lit_int(&mut self, node: &'ast LitInt) {
        self.inspect_integer(node);
    }

    fn visit_lit_float(&mut self, node: &'ast LitFloat) {
        self.inspect_float(node);
    }

    fn visit_lit_byte(&mut self, node: &'ast LitByte) {
        self.inspect_encoded_literal(node.span(), node.token().to_string());
    }

    fn visit_lit_byte_str(&mut self, node: &'ast LitByteStr) {
        self.inspect_encoded_literal(node.span(), node.token().to_string());
    }

    fn visit_lit_cstr(&mut self, node: &'ast LitCStr) {
        self.inspect_encoded_literal(node.span(), node.token().to_string());
    }

    fn visit_lit_char(&mut self, node: &'ast LitChar) {
        self.inspect_encoded_literal(node.span(), node.token().to_string());
    }

    fn visit_lit_str(&mut self, node: &'ast LitStr) {
        self.inspect_encoded_literal(node.span(), node.token().to_string());
    }

    fn visit_macro(&mut self, node: &'ast Macro) {
        let outer_depth = self.named_value_depth;
        self.named_value_depth = 0;
        let is_include = node
            .path
            .segments
            .last()
            .is_some_and(|segment| ident_is(&segment.ident, "include"));
        if is_include {
            self.record(
                node.path.span(),
                ViolationKind::SourceIndirection("include!"),
            );
        } else if !path_is_ident(&node.path, "macro_rules") && !is_trusted_macro(&node.path) {
            self.record(
                node.path.span(),
                ViolationKind::SourceIndirection("unapproved opaque macro"),
            );
        }
        visit::visit_macro(self, node);
        self.named_value_depth = outer_depth;
    }

    fn visit_token_stream(&mut self, tokens: &'ast TokenStream) {
        self.inspect_tokens(tokens.clone());
    }
}

fn is_trusted_macro(path: &syn::Path) -> bool {
    let mut segments = path.segments.iter();
    let Some(segment) = segments.next() else {
        return false;
    };
    if path.leading_colon.is_some() || segments.next().is_some() {
        return false;
    }
    is_trusted_macro_name(&normalized_ident(&segment.ident))
}

fn is_trusted_inert_attribute(path: &syn::Path) -> bool {
    ["cfg", "doc", "must_use", "test"]
        .iter()
        .any(|name| path_is_ident(path, name))
}

fn is_trusted_derive(path: &syn::Path) -> bool {
    let mut segments = path.segments.iter();
    let Some(segment) = segments.next() else {
        return false;
    };
    if path.leading_colon.is_some() || segments.next().is_some() {
        return false;
    }
    matches!(
        normalized_ident(&segment.ident).as_str(),
        "Clone" | "Copy" | "Debug" | "Eq" | "PartialEq" | "Zeroize" | "ZeroizeOnDrop"
    )
}

fn is_trusted_macro_name(name: &str) -> bool {
    matches!(
        name,
        "assert"
            | "assert_eq"
            | "concat"
            | "env"
            | "eprintln"
            | "format"
            | "matches"
            | "println"
            | "vec"
            | "write"
    )
}

fn is_reserved_macro_binding(name: &str) -> bool {
    is_trusted_macro_name(name)
}

fn normalized_ident(ident: &syn::Ident) -> String {
    ident.unraw().to_string()
}

fn ident_is(ident: &syn::Ident, expected: &str) -> bool {
    normalized_ident(ident) == expected
}

fn path_is_ident(path: &syn::Path, expected: &str) -> bool {
    let mut segments = path.segments.iter();
    let Some(segment) = segments.next() else {
        return false;
    };
    path.leading_colon.is_none() && segments.next().is_none() && ident_is(&segment.ident, expected)
}

fn contains_numeric_spelling(spelling: &str) -> bool {
    const MIN_RADIX_SPELLING_BYTES: usize = 3;
    const HEX_ESCAPE_PREFIX: &str = "\\x";
    const UNICODE_ESCAPE_PREFIX: &str = "\\u{";
    const NUL_ESCAPE: &str = "\\0";

    let has_radix_spelling = spelling
        .as_bytes()
        .windows(MIN_RADIX_SPELLING_BYTES)
        .any(|window| match window {
            [b'0', b'x' | b'X', digit] => digit.is_ascii_hexdigit(),
            [b'0', b'b' | b'B', b'0' | b'1'] => true,
            [b'0', b'o' | b'O', b'0'..=b'7'] => true,
            _ => false,
        });
    if has_radix_spelling {
        return true;
    }

    let is_raw =
        spelling.starts_with('r') || spelling.starts_with("br") || spelling.starts_with("cr");
    !is_raw
        && (spelling.contains(HEX_ESCAPE_PREFIX)
            || spelling.contains(UNICODE_ESCAPE_PREFIX)
            || spelling.contains(NUL_ESCAPE))
}

fn is_tier_zero_literal(literal: &LitInt) -> bool {
    let spelling = literal.to_string();
    let has_domain_base = spelling.starts_with("0x")
        || spelling.starts_with("0X")
        || spelling.starts_with("0b")
        || spelling.starts_with("0B")
        || spelling.starts_with("0o")
        || spelling.starts_with("0O");
    !has_domain_base && matches!(literal.base10_digits(), "0" | "1")
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    use std::path::Path;
    #[cfg(unix)]
    use std::process;

    use syn::visit::Visit;
    #[cfg(unix)]
    use walkdir::WalkDir;

    #[cfg(unix)]
    use super::reject_source_tree_symlink;
    use super::{
        MagicNumberVisitor, Violation, ViolationKind, inspect_non_rust_bytes,
        inspect_rust_comments, is_ignored_root_path, is_policy_exempt_path,
        reject_executable_doctests, validate_cargo_target_source,
    };

    fn literals(source: &str) -> Vec<String> {
        let syntax = syn::parse_file(source).expect("test source parses");
        let mut visitor = MagicNumberVisitor::new(Path::new("fixture.rs"));
        visitor.visit_file(&syntax);
        visitor
            .violations
            .into_iter()
            .filter_map(|violation| match violation.kind {
                ViolationKind::AnonymousLiteral(literal) => Some(literal),
                ViolationKind::SourceIndirection(_) | ViolationKind::TextNumericSpelling(_) => None,
            })
            .collect()
    }

    fn source_indirections(source: &str) -> Vec<&'static str> {
        let syntax = syn::parse_file(source).expect("test source parses");
        let mut visitor = MagicNumberVisitor::new(Path::new("fixture.rs"));
        visitor.visit_file(&syntax);
        visitor
            .violations
            .into_iter()
            .filter_map(|violation| match violation.kind {
                ViolationKind::AnonymousLiteral(_) => None,
                ViolationKind::SourceIndirection(form) => Some(form),
                ViolationKind::TextNumericSpelling(_) => None,
            })
            .collect()
    }

    fn text_issues(violations: Vec<Violation>) -> Vec<&'static str> {
        violations
            .into_iter()
            .filter_map(|violation| match violation.kind {
                ViolationKind::TextNumericSpelling(form) => Some(form),
                ViolationKind::AnonymousLiteral(_) | ViolationKind::SourceIndirection(_) => None,
            })
            .collect()
    }

    fn non_rust_issues(source: &str) -> Vec<&'static str> {
        let mut violations: Vec<Violation> = Vec::new();
        inspect_non_rust_bytes(Path::new("fixture.md"), source.as_bytes(), &mut violations);
        text_issues(violations)
    }

    fn rust_comment_issues(source: &str) -> Vec<&'static str> {
        let mut violations: Vec<Violation> = Vec::new();
        inspect_rust_comments(Path::new("fixture.rs"), source, &mut violations);
        text_issues(violations)
    }

    #[test]
    fn allows_literals_in_named_constant_definitions() {
        // Split the base prefix so the checker fixture itself does not leave
        // an anonymous hexadecimal spelling in the repository.
        let source = concat!(
            "const ISO_COMMAND_CLASS: u8 = 0",
            "x00; enum Tag { Application = 0",
            "x60 }"
        );
        assert!(literals(source).is_empty());
    }

    #[test]
    fn catches_nested_patterns_masks_arrays_and_macro_tokens() {
        for source in [
            concat!(
                "fn f(x: Option<u8>) { match x { Some(0",
                "x80) => (), _ => () } }"
            ),
            concat!("fn f(x: u8) { let _ = x & 0", "x80; }"),
            concat!("fn f() { let _ = [0", "x01, 0", "x02]; }"),
            concat!("fn f(x: u8) { let _ = matches!(x, 0", "x80); }"),
        ] {
            assert!(!literals(source).is_empty(), "missed source: {source}");
        }
    }

    #[test]
    fn delayed_executable_bodies_do_not_inherit_a_constant_name() {
        assert_eq!(literals("static CALLBACK: fn() -> u8 = || 128;"), ["128"]);
        assert_eq!(
            literals("const WRAPPER: () = { fn delayed() -> u8 { 128 } };"),
            ["128"]
        );
        assert_eq!(
            literals("const FUTURE: () = async { let _ = 128; };"),
            ["128"]
        );
    }

    #[test]
    fn opaque_macro_tokens_never_inherit_a_constant_name() {
        let delayed = concat!(
            "macro_rules! pass { ($e:expr) => { $e } } ",
            "static CALLBACK: fn() -> u8 = pass!(|| 128);"
        );
        assert_eq!(literals(delayed), ["128"]);
        assert_eq!(literals("const CODE: u8 = identity!(128);"), ["128"]);
    }

    #[test]
    fn enum_fields_and_attributes_are_not_named_values() {
        assert_eq!(literals("enum Example { Value([u8; 128]) }"), ["128"]);
        assert_eq!(
            literals("#[some_attr(code = 128)] const CODE: usize = 2;"),
            ["128"]
        );
    }

    #[test]
    fn decimal_laundering_is_rejected() {
        assert_eq!(literals("fn f() { let _ = 128; }"), ["128"]);
        assert_eq!(literals("fn f() { let _ = 128.0 as u8; }"), ["128.0"]);
    }

    #[test]
    fn anonymous_constants_are_not_named_definitions() {
        assert_eq!(literals("const _: u8 = 128;"), ["128"]);
        assert!(literals("const NAMED_VALUE: u8 = 128;").is_empty());
    }

    #[test]
    fn numeric_escapes_and_documented_hex_are_rejected() {
        let byte_literals = concat!(
            "fn f() { let _ = b'\\",
            "x80'; let _ = b\"\\",
            "x00\\",
            "xa4\"; }"
        );
        assert_eq!(
            literals(byte_literals),
            [concat!("b'\\", "x80'"), concat!("b\"\\", "x00\\", "xa4\"")]
        );

        let documented_hex = concat!("/// `0", "x80` is anonymous.\nfn f() {}");
        assert!(!literals(documented_hex).is_empty());
    }

    #[test]
    fn source_indirection_is_prohibited() {
        assert_eq!(
            source_indirections("include!(\"hidden.inc\");"),
            ["include!"]
        );
        assert_eq!(
            source_indirections("std::include!(\"hidden.inc\");"),
            ["include!"]
        );
        assert_eq!(
            source_indirections("#[path = \"hidden.inc\"] mod hidden;"),
            ["path attribute"]
        );
        assert_eq!(
            source_indirections("#[r#path = \"hidden.inc\"] mod hidden;"),
            ["path attribute"]
        );
        assert_eq!(
            source_indirections("#[cfg_attr(not(any()), path = \"hidden.inc\")] mod hidden;"),
            [
                "unapproved attribute macro",
                "macro-generated path attribute"
            ]
        );
        assert_eq!(
            source_indirections("macro_rules! hidden { () => { include!(\"hidden.inc\"); } }"),
            ["macro-generated include!"]
        );
        assert_eq!(
            source_indirections("use std::include as hidden; hidden!(\"/dev/null\");"),
            ["include! import", "unapproved opaque macro"]
        );
        assert_eq!(
            source_indirections(concat!(
                "macro_rules! module_with_attribute { ",
                "($attribute:ident) => { #[$attribute = \"/dev/null\"] mod hidden; }; } ",
                "module_with_attribute!(path);"
            )),
            ["unapproved opaque macro"]
        );
        assert_eq!(
            source_indirections(concat!(
                "macro_rules! dispatch { ",
                "($attribute:ident) => { #[$attribute = \"/dev/null\"] mod hidden; }; } ",
                "fn f() { assert!({ dispatch!(path); true }); }"
            )),
            ["nested unapproved opaque macro"]
        );
        assert_eq!(
            source_indirections("#[macro_use] extern crate hidden;"),
            ["macro_use attribute"]
        );
    }

    #[test]
    fn only_reviewed_transparent_macros_are_accepted() {
        assert!(source_indirections("fn f() { assert!(true); println!(\"ok\"); }").is_empty());
        assert_eq!(
            source_indirections("fn f() { opaque_macro!(); }"),
            ["unapproved opaque macro"]
        );
        assert_eq!(
            source_indirections("use hidden::format; fn f() { format!(\"ok\"); }"),
            ["trusted macro name import"]
        );
        assert_eq!(
            source_indirections("macro_rules! format { () => {} }"),
            ["trusted macro name definition"]
        );
        assert_eq!(
            source_indirections("macro_rules! r#format { () => {} } fn f() { format!(); }"),
            ["trusted macro name definition"]
        );
        assert_eq!(
            source_indirections("#[evil] fn generated() {}"),
            ["unapproved attribute macro"]
        );
        assert_eq!(
            source_indirections("#[derive(evil::Generate)] struct Generated;"),
            ["unapproved derive macro"]
        );
        assert!(
            source_indirections("#[derive(Debug, Zeroize, ZeroizeOnDrop)] struct Reviewed;")
                .is_empty()
        );
    }

    #[test]
    fn non_rust_text_has_a_strict_zero_radix_policy() {
        let source = concat!(
            "wire value 0",
            "x80\nbinary 0",
            "b10\nescape \\",
            "x7f\njson \\",
            "u0080\noctal \\",
            "200\nshort octal \\",
            "7"
        );
        assert_eq!(
            non_rust_issues(source),
            [
                "radix numeric spelling",
                "radix numeric spelling",
                "numeric escape",
                "numeric escape",
                "numeric escape",
                "numeric escape"
            ]
        );

        let bytes = [u8::MAX, b'\n', b'0', b'x', b'8', b'0'];
        let mut violations = Vec::new();
        inspect_non_rust_bytes(Path::new("fixture.bin"), &bytes, &mut violations);
        assert_eq!(text_issues(violations), ["radix numeric spelling"]);
    }

    #[test]
    fn ordinary_rust_comments_are_checked_lexically() {
        let source = concat!(
            "const NAMED: u8 = 0",
            "x80; // anonymous 0",
            "x81\nlet text = \"0",
            "x82\"; /* escape \\",
            "x7f */"
        );
        assert_eq!(
            rust_comment_issues(source),
            ["radix numeric spelling", "numeric escape"]
        );

        let shebang = concat!("#!/usr/bin/env rust-script 0", "x80\nfn main() {}");
        assert_eq!(rust_comment_issues(shebang), ["radix numeric spelling"]);
    }

    #[test]
    fn cargo_targets_must_be_in_repository_rust_files() {
        let root = Path::new("/workspace");
        assert!(validate_cargo_target_source(root, Path::new("/workspace/src/lib.rs")).is_ok());
        assert!(validate_cargo_target_source(root, Path::new("/workspace/src/lib.inc")).is_err());
        assert!(validate_cargo_target_source(root, Path::new("/elsewhere/lib.rs")).is_err());
        assert!(validate_cargo_target_source(root, Path::new("/workspace/target/lib.rs")).is_err());
        assert!(reject_executable_doctests(Path::new("/workspace/src/lib.rs"), false).is_ok());
        assert!(reject_executable_doctests(Path::new("/workspace/src/lib.rs"), true).is_err());
    }

    #[test]
    fn only_generated_build_and_git_paths_are_ignored() {
        let root = Path::new("/workspace");
        assert!(is_ignored_root_path(root, Path::new("/workspace/target")));
        assert!(is_ignored_root_path(
            root,
            Path::new("/workspace/.git/objects")
        ));
        assert!(is_ignored_root_path(
            root,
            Path::new("/workspace/Cargo.lock")
        ));
        assert!(!is_ignored_root_path(
            root,
            Path::new("/workspace/src/target/mod.rs")
        ));
        assert!(!is_ignored_root_path(
            root,
            Path::new("/workspace/crates/apdu/Cargo.lock")
        ));
    }

    #[test]
    fn policy_exemption_covers_only_the_admitted_subtrees() {
        let root = Path::new("/workspace");
        assert!(is_policy_exempt_path(
            root,
            Path::new("/workspace/crates/rapp/src/wire.rs")
        ));
        assert!(is_policy_exempt_path(
            root,
            Path::new("/workspace/crates/pcsc/src/lib.rs")
        ));
        assert!(is_policy_exempt_path(
            root,
            Path::new("/workspace/crates/pkcs11/src/lib.rs")
        ));
        assert!(is_policy_exempt_path(
            root,
            Path::new("/workspace/docs/protocols/vectors/rapp-v26.9.7.70.json")
        ));
        assert!(!is_policy_exempt_path(
            root,
            Path::new("/workspace/crates/rapp-other/src/lib.rs")
        ));
        assert!(!is_policy_exempt_path(
            root,
            Path::new("/workspace/crates/apdu/src/lib.rs")
        ));
    }

    #[test]
    #[cfg(unix)]
    fn source_tree_symlinks_are_rejected() {
        let root = std::env::temp_dir().join(format!("refineid-xtask-symlink-{}", process::id()));
        let link = root.join("linked.rs");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("temporary fixture directory is created");
        symlink("missing.rs", &link).expect("fixture symlink is created");

        let entry = WalkDir::new(&root)
            .into_iter()
            .filter_map(Result::ok)
            .find(|entry| entry.path() == link)
            .expect("fixture symlink is walked");
        let result = reject_source_tree_symlink(&entry);

        fs::remove_dir_all(&root).expect("temporary fixture directory is removed");
        assert!(result.is_err());
    }

    #[test]
    fn tier_zero_control_values_remain_available() {
        assert!(literals("fn f() { let _ = 0; let _ = 1; }").is_empty());
        assert_eq!(
            literals(concat!("fn f() { let _ = 0", "x0; }")),
            [concat!("0", "x0")]
        );
    }
}
