// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! What the revisions after a signed one change in a PDF.
//!
//! A signature covers the revision its `/ByteRange` ends; anyone may
//! append revisions after it. The verifier indexes the signed revision
//! on its own and compares it with the newest view of the document:
//! the trailers, the interactive form's field tree, each page's
//! `/Annots`, the `/DSS`, and every object by its number, each object
//! parsed once per view. An object that is the same value in both is
//! untouched. A later revision may, without changing what the signer
//! saw:
//!
//! - add signature fields and widgets that carry a signature (`/V`),
//!   attached to the form's field tree and, for a widget, to a page's
//!   `/Annots` after the annotations already there; the signature and
//!   document timestamp dictionaries they name; and new objects their
//!   appearance streams draw from;
//! - give an existing signature field without a value its `/V`, `/AP`
//!   and `/AS`;
//! - grow the `/DSS`: new streams in its `/Certs`, `/OCSPs` and
//!   `/CRLs`, and new `/VRI` entries;
//! - add cross-reference and object streams;
//! - change the document information dictionary and the catalog's
//!   `/Metadata` stream, which signing tools update and which change
//!   nothing rendered;
//! - rewrite the catalog only in `/DSS`, `/AcroForm`, `/Extensions` and
//!   `/Metadata`, the interactive form only in `/Fields` and
//!   `/SigFlags`, and the trailer anywhere but `/Root` and the first,
//!   permanent `/ID` element.
//!
//! Anything else, a new object that is none of these included, is a
//! change after signing, typed by what it touches.
//!
//! # Conformance
//!
//! - ISO 32000-1 sec.7.5.6: an incremental update appends changed and
//!   new objects with a cross-reference section of its own. Objects
//!   are compared by number: one whose generation rises replaces the
//!   freed one, and since the signed revision's references to it no
//!   longer resolve, it is a change.
//! - ISO 32000-1 sec.12.8.2.2 (`DocMDP`) and sec.12.8.2.4
//!   (`FieldMDP`): the changes a signature may be followed by are
//!   signing, filling in signature fields, and adding document-level
//!   validation material; `ETSI EN 319 142-1` V1.2.1 clauses 5.4.2 and
//!   5.4.3 add the `/DSS` and document timestamps.
//! - ISO 32000-1 sec.12.7.3.1: a field inherits `/FT` from its parent,
//!   and `/Kids` holds its children; sec.12.5.2: an annotation is a
//!   dictionary with `/Subtype` and `/Rect`, drawn in `/Annots` order.
//! - ISO 32000-1 sec.14.4: the first `/ID` element is permanent; the
//!   second changes with each update.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::pades::index::{MAX_XREF_ENTRIES, PdfIndex, PdfObjectReference, PdfValueParser};
use refineid_digest::Sha256;

/// Opens a dictionary (ISO 32000-1 sec.7.3.7).
const DICTIONARY_OPEN: &[u8] = b"<<";
/// Closes a dictionary.
const DICTIONARY_CLOSE: &[u8] = b">>";
/// Opens an array (ISO 32000-1 sec.7.3.6).
const ARRAY_OPEN: &[u8] = b"[";
/// Closes an array.
const ARRAY_CLOSE: &[u8] = b"]";
/// Opens a name (ISO 32000-1 sec.7.3.5).
const NAME_OPEN: &[u8] = b"/";
/// Opens a literal string (ISO 32000-1 sec.7.3.4.2).
const LITERAL_OPEN: &[u8] = b"(";
/// Opens a hexadecimal string (ISO 32000-1 sec.7.3.4.3).
const HEX_OPEN: &[u8] = b"<";
/// The keyword that opens a stream's payload (ISO 32000-1 sec.7.3.8).
const STREAM_KEYWORD: &[u8] = b"stream";

/// Trailer key of the catalog (ISO 32000-1 sec.7.5.5, Table 15).
const KEY_ROOT: &[u8] = b"Root";
/// Trailer key of the file identifier.
const KEY_ID: &[u8] = b"ID";
/// Trailer key of the document information dictionary (ISO 32000-1
/// sec.14.3.3).
const KEY_INFO: &[u8] = b"Info";
/// Key naming an object's type.
const KEY_TYPE: &[u8] = b"Type";
/// Key naming an annotation's or `XObject`'s subtype.
const KEY_SUBTYPE: &[u8] = b"Subtype";
/// Key of an annotation's rectangle (ISO 32000-1 sec.12.5.2).
const KEY_RECT: &[u8] = b"Rect";
/// Key of a field's type (ISO 32000-1 sec.12.7.3.1, Table 220).
const KEY_FIELD_TYPE: &[u8] = b"FT";
/// Key of a field's value.
const KEY_VALUE: &[u8] = b"V";
/// Key of a field's or a page's parent.
const KEY_PARENT: &[u8] = b"Parent";
/// Key of a field's children.
const KEY_KIDS: &[u8] = b"Kids";
/// Key of an annotation's appearance dictionary (ISO 32000-1
/// sec.12.5.5).
const KEY_APPEARANCE: &[u8] = b"AP";
/// Key of an annotation's appearance state.
const KEY_APPEARANCE_STATE: &[u8] = b"AS";
/// Key of a page's annotations (ISO 32000-1 sec.7.7.3.3, Table 30).
const KEY_ANNOTS: &[u8] = b"Annots";
/// Key of the catalog's interactive form (ISO 32000-1 sec.7.7.2).
const KEY_ACROFORM: &[u8] = b"AcroForm";
/// Key of the interactive form's root fields (ISO 32000-1
/// sec.12.7.2, Table 218).
const KEY_FIELDS: &[u8] = b"Fields";
/// Key of the interactive form's signature flags.
const KEY_SIG_FLAGS: &[u8] = b"SigFlags";
/// Key of the catalog's document security store (`ETSI EN 319 142-1`
/// clause 5.4.2).
const KEY_DSS: &[u8] = b"DSS";
/// Key of the store's certificates.
const KEY_CERTS: &[u8] = b"Certs";
/// Key of the store's OCSP responses.
const KEY_OCSPS: &[u8] = b"OCSPs";
/// Key of the store's CRLs.
const KEY_CRLS: &[u8] = b"CRLs";
/// Key of the store's validation-related information.
const KEY_VRI: &[u8] = b"VRI";
/// Keys of one `/VRI` entry's arrays (`ETSI EN 319 142-1` clause
/// 5.4.2.2).
const VRI_ARRAY_KEYS: [&[u8]; 3] = [b"Cert", b"OCSP", b"CRL"];
/// Key of one `/VRI` entry's timestamp stream.
const KEY_VRI_TIMESTAMP: &[u8] = b"TS";
/// Key of the catalog's developer extensions (ISO 32000-1 sec.7.12).
const KEY_EXTENSIONS: &[u8] = b"Extensions";
/// Key of the catalog's metadata stream (ISO 32000-1 sec.14.3.2).
const KEY_METADATA: &[u8] = b"Metadata";
/// Key of a signature dictionary's signed range (ISO 32000-1
/// sec.12.8.1, Table 252).
const KEY_BYTE_RANGE: &[u8] = b"ByteRange";
/// Key of a signature dictionary's value.
const KEY_CONTENTS: &[u8] = b"Contents";

/// `/Type` of a page (ISO 32000-1 sec.7.7.3.3).
const TYPE_PAGE: &[u8] = b"Page";
/// `/Type` of a page tree node (ISO 32000-1 sec.7.7.3.2).
const TYPE_PAGES: &[u8] = b"Pages";
/// `/Type` of an annotation (ISO 32000-1 sec.12.5.2).
const TYPE_ANNOT: &[u8] = b"Annot";
/// `/Type` of a cross-reference stream (ISO 32000-1 sec.7.5.8.2).
const TYPE_XREF: &[u8] = b"XRef";
/// `/Type` of an object stream (ISO 32000-1 sec.7.5.7).
const TYPE_OBJECT_STREAM: &[u8] = b"ObjStm";
/// `/Subtype` of a widget annotation (ISO 32000-1 sec.12.5.6.19).
const SUBTYPE_WIDGET: &[u8] = b"Widget";
/// `/FT` of a signature field (ISO 32000-1 sec.12.7.4.5).
const FIELD_TYPE_SIGNATURE: &[u8] = b"Sig";

/// Most `/Parent` links followed, and most `/Kids` levels walked, in a
/// field tree; a real one is a handful deep.
const MAX_FIELD_DEPTH: usize = 32;
/// Most objects followed from one appearance dictionary.
const MAX_REACHED_OBJECTS: usize = 4096;
/// Most live objects one view may hold to be compared.
const MAX_COMPARED_OBJECTS: usize = MAX_XREF_ENTRIES;
/// Most octets of object bodies read from one view to compare it.
const MAX_COMPARED_BYTES: usize = 1 << 30;

/// What a later revision changes in what the signer saw, in order of
/// precedence: when a revision changes several things, the first in
/// this order is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DocumentChange {
    /// The page tree: a page added, removed or moved.
    Pages,
    /// A form field other than a signature being added, or the
    /// interactive form beyond its signature fields.
    FormField,
    /// An annotation other than a signature widget, or the order of a
    /// page's annotations.
    Annotation,
    /// The catalog, beyond `/DSS`, `/AcroForm`, `/Extensions` and
    /// `/Metadata`.
    Catalog,
    /// The trailer's `/Root` or permanent `/ID`.
    Trailer,
    /// A page's content, its resources, the validation store beyond
    /// growing, or any other object of the document.
    Content,
}

/// How the bytes after a signed revision relate to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revision {
    /// No byte follows the signed revision.
    WholeDocument,
    /// Later revisions only add signatures, document timestamps and
    /// validation material: the document reads as it did when signed.
    LaterRevisionsHarmless,
    /// A later revision changes what the signer saw.
    ChangedAfterSigning(DocumentChange),
}

/// What the revisions after the one ending at `end` do to `file`,
/// whose newest view is `latest`. `None` when the first `end` bytes do
/// not index as a document of their own, or either view exceeds
/// [`MAX_COMPARED_OBJECTS`] or [`MAX_COMPARED_BYTES`].
pub(crate) fn later_revisions(file: &[u8], end: usize, latest: &PdfIndex<'_>) -> Option<Revision> {
    if end == file.len() {
        return Some(Revision::WholeDocument);
    }
    let signed = PdfIndex::parse(file.get(..end)?).ok()?;
    let before = Snapshot::new(&signed)?;
    let after = Snapshot::new(latest)?;
    Some(
        Comparison {
            before: &before,
            after: &after,
            after_roles: Roles::of(&after),
            before_roles: Roles::of(&before),
        }
        .first_change()
        .map_or(
            Revision::LaterRevisionsHarmless,
            Revision::ChangedAfterSigning,
        ),
    )
}

/// One PDF value, read for comparison: dictionaries by key, arrays in
/// order, names decoded, every other token as written.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    /// A dictionary.
    Dictionary(BTreeMap<Vec<u8>, Value>),
    /// An array.
    Array(Vec<Value>),
    /// A name, decoded.
    Name(Vec<u8>),
    /// An indirect reference.
    Reference(PdfObjectReference),
    /// A number, string, boolean or null, as written.
    Token(Vec<u8>),
}

impl Value {
    /// Read one value at the parser's position, `depth` levels deep.
    fn read(parser: &mut PdfValueParser<'_>, depth: usize) -> Option<Self> {
        PdfValueParser::check_depth(depth).ok()?;
        parser.skip_trivia();
        if parser.consume(DICTIONARY_OPEN) {
            let mut entries = BTreeMap::new();
            loop {
                parser.skip_trivia();
                if parser.consume(DICTIONARY_CLOSE) {
                    return Some(Self::Dictionary(entries));
                }
                let name = parser.name().ok()?;
                let value = Self::read(parser, depth.saturating_add(1))?;
                if entries.insert(name, value).is_some() {
                    return None;
                }
            }
        }
        if parser.consume(ARRAY_OPEN) {
            let mut items = Vec::new();
            loop {
                parser.skip_trivia();
                if parser.consume(ARRAY_CLOSE) {
                    return Some(Self::Array(items));
                }
                items.push(Self::read(parser, depth.saturating_add(1))?);
            }
        }
        if parser.starts_with(NAME_OPEN) {
            return parser.name().ok().map(Self::Name);
        }
        if parser.starts_with(LITERAL_OPEN) || parser.starts_with(HEX_OPEN) {
            let span = parser.value(depth).ok()?;
            return parser
                .bytes
                .get(span)
                .map(|token| Self::Token(token.to_vec()));
        }
        if let Some(reference) = parser.reference() {
            return Some(Self::Reference(reference));
        }
        let span = parser.atom().ok()?;
        parser
            .bytes
            .get(span)
            .map(|token| Self::Token(token.to_vec()))
    }

    /// The entries, when this is a dictionary.
    const fn dictionary(&self) -> Option<&BTreeMap<Vec<u8>, Self>> {
        match self {
            Self::Dictionary(entries) => Some(entries),
            Self::Array(_) | Self::Name(_) | Self::Reference(_) | Self::Token(_) => None,
        }
    }

    /// Every indirect reference inside this value.
    fn references(&self, out: &mut Vec<PdfObjectReference>) {
        match self {
            Self::Dictionary(entries) => {
                for value in entries.values() {
                    value.references(out);
                }
            }
            Self::Array(items) => {
                for item in items {
                    item.references(out);
                }
            }
            Self::Reference(reference) => out.push(*reference),
            Self::Name(_) | Self::Token(_) => {}
        }
    }
}

/// One object's body, read once.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Object {
    /// A value with nothing after it.
    Parsed(Value),
    /// A stream: its dictionary and the SHA-256 of the keyword and
    /// payload that follow it.
    Stream(Value, Vec<u8>),
    /// A body that is no value this reader reads, by its SHA-256.
    Unparsed(Vec<u8>),
}

impl Object {
    /// Read the body of one object.
    fn read(body: &[u8]) -> Self {
        let mut parser = PdfValueParser::new(body);
        let Some(value) = Value::read(&mut parser, 1) else {
            return Self::Unparsed(Sha256::of(body).as_bytes().to_vec());
        };
        parser.skip_trivia();
        let rest = body.get(parser.offset..).unwrap_or_default();
        if rest.is_empty() {
            Self::Parsed(value)
        } else if rest.starts_with(STREAM_KEYWORD) && value.dictionary().is_some() {
            Self::Stream(value, Sha256::of(rest).as_bytes().to_vec())
        } else {
            Self::Unparsed(Sha256::of(body).as_bytes().to_vec())
        }
    }

    /// The value, unless the body does not read.
    const fn value(&self) -> Option<&Value> {
        match self {
            Self::Parsed(value) | Self::Stream(value, _) => Some(value),
            Self::Unparsed(_) => None,
        }
    }

    /// The dictionary the object is or opens.
    fn dictionary(&self) -> Option<&BTreeMap<Vec<u8>, Value>> {
        self.value().and_then(Value::dictionary)
    }

    /// The value under `key` of the object's dictionary.
    fn entry(&self, key: &[u8]) -> Option<&Value> {
        self.dictionary().and_then(|entries| entries.get(key))
    }

    /// Whether the object's dictionary names `name` under `key`.
    fn names(&self, key: &[u8], name: &[u8]) -> bool {
        matches!(self.entry(key), Some(Value::Name(found)) if found == name)
    }

    /// Whether the object is a cross-reference or object stream.
    fn is_structure_stream(&self) -> bool {
        matches!(self, Self::Stream(..))
            && (self.names(KEY_TYPE, TYPE_XREF) || self.names(KEY_TYPE, TYPE_OBJECT_STREAM))
    }

    /// Whether the object is a stream other than a cross-reference or
    /// object stream.
    fn is_data_stream(&self) -> bool {
        matches!(self, Self::Stream(..)) && !self.is_structure_stream()
    }

    /// Whether the object is a signature or document timestamp
    /// dictionary (ISO 32000-1 sec.12.8.1).
    fn is_signature_value(&self) -> bool {
        self.entry(KEY_BYTE_RANGE).is_some() && self.entry(KEY_CONTENTS).is_some()
    }

    /// Whether the object is an annotation: `/Type /Annot`, or a
    /// dictionary with `/Subtype` and `/Rect`.
    fn is_annotation(&self) -> bool {
        self.names(KEY_TYPE, TYPE_ANNOT)
            || (self.entry(KEY_SUBTYPE).is_some() && self.entry(KEY_RECT).is_some())
    }
}

/// What a field's `/FT`, own or inherited, says it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FieldType {
    /// `/FT /Sig`.
    Signature,
    /// Any other field type.
    Other,
}

/// One view of the document, the signed revision or the newest, every
/// live object read once.
struct Snapshot {
    /// Each live object by number, with the generation that is live.
    objects: HashMap<u32, (u16, Object)>,
    /// The trailer's entries.
    trailer: BTreeMap<Vec<u8>, Value>,
    /// The catalog.
    root: PdfObjectReference,
}

impl Snapshot {
    /// The view `index` gives; `None` without a readable trailer and
    /// catalog reference, or past the comparison bounds.
    fn new(index: &PdfIndex<'_>) -> Option<Self> {
        let trailer = Value::read(&mut PdfValueParser::new(index.trailer()), 1)?
            .dictionary()?
            .clone();
        let Some(Value::Reference(root)) = trailer.get(KEY_ROOT) else {
            return None;
        };
        let root = *root;
        let live = index.live_references();
        if live.len() > MAX_COMPARED_OBJECTS {
            return None;
        }
        let mut objects = HashMap::new();
        let mut read = 0_usize;
        for reference in live {
            let Some(body) = index.object_body_reference(reference) else {
                continue;
            };
            read = read.saturating_add(body.len());
            if read > MAX_COMPARED_BYTES {
                return None;
            }
            objects.insert(
                reference.number,
                (reference.generation, Object::read(&body)),
            );
        }
        Some(Self {
            objects,
            trailer,
            root,
        })
    }

    /// The live object `reference` names, number and generation.
    fn object(&self, reference: PdfObjectReference) -> Option<&Object> {
        self.objects
            .get(&reference.number)
            .filter(|(generation, _)| *generation == reference.generation)
            .map(|(_, object)| object)
    }

    /// The catalog.
    fn catalog(&self) -> Option<&Object> {
        self.object(self.root)
    }

    /// `value`, or the value of the object it references.
    fn resolve<'v>(&'v self, value: &'v Value) -> Option<&'v Value> {
        match value {
            Value::Reference(reference) => self.object(*reference)?.value(),
            Value::Dictionary(_) | Value::Array(_) | Value::Name(_) | Value::Token(_) => {
                Some(value)
            }
        }
    }

    /// The dictionary `value` is, inline or indirect; an absent value
    /// is an empty one. `None` when it is neither.
    fn dictionary_of(&self, value: Option<&Value>) -> Option<BTreeMap<Vec<u8>, Value>> {
        match value {
            None => Some(BTreeMap::new()),
            Some(value) => self.resolve(value)?.dictionary().cloned(),
        }
    }

    /// The references a list value holds, inline or as an indirect
    /// array; an absent list is empty. `None` when it is neither, or an
    /// element is no reference.
    fn list(&self, value: Option<&Value>) -> Option<Vec<PdfObjectReference>> {
        let Some(value) = value else {
            return Some(Vec::new());
        };
        let Value::Array(items) = self.resolve(value)? else {
            return None;
        };
        items
            .iter()
            .map(|item| match item {
                Value::Reference(reference) => Some(*reference),
                Value::Dictionary(_) | Value::Array(_) | Value::Name(_) | Value::Token(_) => None,
            })
            .collect()
    }

    /// The interactive form's dictionary; empty without one.
    fn form(&self) -> Option<BTreeMap<Vec<u8>, Value>> {
        self.dictionary_of(self.catalog()?.entry(KEY_ACROFORM))
    }

    /// Every node of the form's field tree: the `/Fields` and their
    /// `/Kids`, walked once each, at most [`MAX_FIELD_DEPTH`] levels.
    /// `None` when a list does not read or the tree is deeper.
    fn field_tree(&self) -> Option<HashSet<PdfObjectReference>> {
        let form = self.form()?;
        let mut tree = HashSet::new();
        let mut pending: Vec<(PdfObjectReference, usize)> = self
            .list(form.get(KEY_FIELDS))?
            .into_iter()
            .map(|reference| (reference, 0))
            .collect();
        while let Some((reference, depth)) = pending.pop() {
            if depth > MAX_FIELD_DEPTH || tree.len() >= MAX_COMPARED_OBJECTS {
                return None;
            }
            if !tree.insert(reference) {
                continue;
            }
            if let Some(object) = self.object(reference) {
                for kid in self.list(object.entry(KEY_KIDS))? {
                    pending.push((kid, depth.saturating_add(1)));
                }
            }
        }
        Some(tree)
    }

    /// The field node that `reference` is or belongs to, with its type:
    /// the object itself or the nearest one up its `/Parent` chain that
    /// carries `/FT`, at most [`MAX_FIELD_DEPTH`] links, never twice.
    fn field_node(&self, reference: PdfObjectReference) -> Option<(PdfObjectReference, FieldType)> {
        let mut current = reference;
        let mut seen = HashSet::new();
        for _ in 0..MAX_FIELD_DEPTH {
            if !seen.insert(current) {
                return None;
            }
            let object = self.object(current)?;
            match object.entry(KEY_FIELD_TYPE) {
                Some(Value::Name(name)) if name == FIELD_TYPE_SIGNATURE => {
                    return Some((current, FieldType::Signature));
                }
                Some(_) => return Some((current, FieldType::Other)),
                None => {}
            }
            match object.entry(KEY_PARENT) {
                Some(Value::Reference(parent)) => current = *parent,
                _ => return None,
            }
        }
        None
    }

    /// The type of the field `reference` is or belongs to.
    fn field_type(&self, reference: PdfObjectReference) -> Option<FieldType> {
        self.field_node(reference).map(|(_, kind)| kind)
    }

    /// Whether `reference` is a signature field or widget whose field
    /// carries a value.
    fn is_signed(&self, reference: PdfObjectReference) -> bool {
        self.field_node(reference).is_some_and(|(node, kind)| {
            kind == FieldType::Signature
                && self
                    .object(node)
                    .is_some_and(|field| field.entry(KEY_VALUE).is_some())
        })
    }

    /// Whether `reference` is a signed signature field node: a field
    /// or a widget of type `/Sig` with a value, with no `/Subtype` or
    /// `/Subtype /Widget`.
    fn is_signed_field_node(&self, reference: PdfObjectReference) -> bool {
        self.is_signed(reference)
            && self.object(reference).is_some_and(|object| {
                object.entry(KEY_SUBTYPE).is_none() || object.names(KEY_SUBTYPE, SUBTYPE_WIDGET)
            })
    }

    /// Whether `reference` is a widget, `/Subtype /Widget` itself, of a
    /// signed signature field.
    fn is_signed_widget(&self, reference: PdfObjectReference) -> bool {
        self.is_signed(reference)
            && self
                .object(reference)
                .is_some_and(|object| object.names(KEY_SUBTYPE, SUBTYPE_WIDGET))
    }

    /// The pages of this view: every live `/Type /Page` object.
    fn pages(&self) -> Vec<(PdfObjectReference, &Object)> {
        self.objects
            .iter()
            .filter(|(_, (_, object))| object.names(KEY_TYPE, TYPE_PAGE))
            .map(|(number, (generation, object))| {
                (
                    PdfObjectReference {
                        number: *number,
                        generation: *generation,
                    },
                    object,
                )
            })
            .collect()
    }

    /// What a change to `object`, the object `reference` names in this
    /// view, touches, by what the object is.
    fn kind_of(&self, reference: PdfObjectReference, object: &Object) -> DocumentChange {
        if object.names(KEY_TYPE, TYPE_PAGE) || object.names(KEY_TYPE, TYPE_PAGES) {
            DocumentChange::Pages
        } else if self.field_type(reference).is_some() {
            DocumentChange::FormField
        } else if object.is_annotation() {
            DocumentChange::Annotation
        } else if reference.number == self.root.number {
            DocumentChange::Catalog
        } else {
            DocumentChange::Content
        }
    }
}

/// The objects of one view that play a role a later revision may add
/// or rewrite.
#[derive(Default)]
struct Roles {
    /// The `/DSS` dictionary, its category arrays and its `/VRI`
    /// dictionary, when indirect: these may grow.
    store_containers: HashSet<PdfObjectReference>,
    /// The `/VRI` entries and their arrays, when indirect: these may
    /// only be new.
    store_entries: HashSet<PdfObjectReference>,
    /// The streams the store's arrays and `/VRI` entries name.
    store_streams: HashSet<PdfObjectReference>,
    /// The interactive form and its `/Fields` array, when indirect, and
    /// each page's `/Annots` array, when indirect: judged as a whole.
    lists: HashSet<PdfObjectReference>,
    /// The signature dictionaries signed fields of the field tree name
    /// as their `/V`.
    signature_values: HashSet<PdfObjectReference>,
    /// The objects reached from the `/AP` of the signed signature
    /// fields and widgets of the field tree.
    appearances: HashSet<PdfObjectReference>,
    /// The trailer's `/Info` and the catalog's `/Metadata`.
    metadata: HashSet<PdfObjectReference>,
    /// The nodes of the form's field tree; empty when it does not read.
    field_tree: HashSet<PdfObjectReference>,
}

impl Roles {
    /// The roles in `view`.
    fn of(view: &Snapshot) -> Self {
        let mut roles = Self::default();
        let indirect = |value: Option<&Value>| match value {
            Some(Value::Reference(reference)) => Some(*reference),
            _ => None,
        };
        roles.metadata.extend(indirect(view.trailer.get(KEY_INFO)));
        let catalog = view.catalog();
        if let Some(catalog) = catalog {
            roles.metadata.extend(indirect(catalog.entry(KEY_METADATA)));
            roles.lists.extend(indirect(catalog.entry(KEY_ACROFORM)));
            roles.store(view, catalog.entry(KEY_DSS));
        }
        if let Some(form) = view.form() {
            roles.lists.extend(indirect(form.get(KEY_FIELDS)));
        }
        for (_, page) in view.pages() {
            roles.lists.extend(indirect(page.entry(KEY_ANNOTS)));
        }
        roles.field_tree = view.field_tree().unwrap_or_default();
        for node in roles.field_tree.clone() {
            if !view.is_signed_field_node(node) {
                continue;
            }
            let Some(object) = view.object(node) else {
                continue;
            };
            roles
                .signature_values
                .extend(indirect(object.entry(KEY_VALUE)));
            if let Some(appearance) = object.entry(KEY_APPEARANCE) {
                roles.appearances.extend(reached_from(view, appearance));
            }
        }
        roles
    }

    /// The store's containers, entries and streams.
    fn store(&mut self, view: &Snapshot, value: Option<&Value>) {
        let Some(value) = value else {
            return;
        };
        if let Value::Reference(reference) = value {
            self.store_containers.insert(*reference);
        }
        let Some(store) = view.resolve(value).and_then(Value::dictionary) else {
            return;
        };
        for key in [KEY_CERTS, KEY_OCSPS, KEY_CRLS] {
            if let Some(list) = store.get(key) {
                if let Value::Reference(reference) = list {
                    self.store_containers.insert(*reference);
                }
                self.streams(view, view.list(Some(list)).unwrap_or_default());
            }
        }
        let Some(entries) = store.get(KEY_VRI) else {
            return;
        };
        if let Value::Reference(reference) = entries {
            self.store_containers.insert(*reference);
        }
        let Some(entries) = view.resolve(entries).and_then(Value::dictionary) else {
            return;
        };
        for entry in entries.values() {
            if let Value::Reference(reference) = entry {
                self.store_entries.insert(*reference);
            }
            let Some(entry) = view.resolve(entry).and_then(Value::dictionary) else {
                continue;
            };
            for key in VRI_ARRAY_KEYS {
                if let Some(list) = entry.get(key) {
                    if let Value::Reference(reference) = list {
                        self.store_entries.insert(*reference);
                    }
                    self.streams(view, view.list(Some(list)).unwrap_or_default());
                }
            }
            if let Some(Value::Reference(stream)) = entry.get(KEY_VRI_TIMESTAMP) {
                self.streams(view, vec![*stream]);
            }
        }
    }

    /// The data streams among `references`.
    fn streams(&mut self, view: &Snapshot, references: Vec<PdfObjectReference>) {
        self.store_streams.extend(
            references
                .into_iter()
                .filter(|reference| view.object(*reference).is_some_and(Object::is_data_stream)),
        );
    }
}

/// The objects `value` references, and those they reference in turn,
/// each once, up to [`MAX_REACHED_OBJECTS`].
fn reached_from(view: &Snapshot, value: &Value) -> HashSet<PdfObjectReference> {
    let mut pending = Vec::new();
    value.references(&mut pending);
    let mut reached = HashSet::new();
    while let Some(reference) = pending.pop() {
        if reached.len() == MAX_REACHED_OBJECTS || !reached.insert(reference) {
            continue;
        }
        if let Some(value) = view.object(reference).and_then(Object::value) {
            value.references(&mut pending);
        }
    }
    reached
}

/// How one object number fares between the two views.
enum Fate<'o> {
    /// New in a later revision.
    Added(&'o Object),
    /// Rewritten in a later revision, its generation risen or not.
    Replaced {
        /// The signed revision's body.
        older: &'o Object,
        /// The newest body.
        newer: &'o Object,
    },
}

/// The signed revision against the newest view.
struct Comparison<'s> {
    /// The signed revision.
    before: &'s Snapshot,
    /// The newest view.
    after: &'s Snapshot,
    /// The roles in the newest view.
    after_roles: Roles,
    /// The roles in the signed revision.
    before_roles: Roles,
}

impl Comparison<'_> {
    /// The change of highest precedence the later revisions make, or
    /// `None` when they only add what may follow a signature.
    fn first_change(&self) -> Option<DocumentChange> {
        let mut changes = vec![
            self.trailer(),
            self.form(),
            self.annotations(),
            self.store(),
        ];
        for (number, (generation, newer)) in &self.after.objects {
            let reference = PdfObjectReference {
                number: *number,
                generation: *generation,
            };
            let fate = match self.before.objects.get(number) {
                None => Fate::Added(newer),
                Some((older_generation, older))
                    if older_generation == generation && older == newer =>
                {
                    continue;
                }
                Some((_, older)) => Fate::Replaced { older, newer },
            };
            changes.push(self.judge(reference, &fate));
        }
        for (number, (generation, older)) in &self.before.objects {
            if !self.after.objects.contains_key(number) {
                let reference = PdfObjectReference {
                    number: *number,
                    generation: *generation,
                };
                changes.push(Some(self.before.kind_of(reference, older)));
            }
        }
        changes.into_iter().flatten().min()
    }

    /// The trailer: `/Root` the same object, and the first `/ID`
    /// element, once present, kept.
    fn trailer(&self) -> Option<DocumentChange> {
        if self.before.root != self.after.root {
            return Some(DocumentChange::Trailer);
        }
        let permanent = |view: &Snapshot| match view.trailer.get(KEY_ID) {
            Some(Value::Array(items)) => items.first().cloned(),
            _ => None,
        };
        match (permanent(self.before), permanent(self.after)) {
            (Some(before), after) if after.as_ref() != Some(&before) => {
                Some(DocumentChange::Trailer)
            }
            _ => None,
        }
    }

    /// The interactive form: every entry but `/Fields` and `/SigFlags`
    /// unchanged; no node of the field tree removed; every node added a
    /// signed signature field or widget.
    fn form(&self) -> Option<DocumentChange> {
        let (Some(old), Some(new)) = (self.before.form(), self.after.form()) else {
            return Some(DocumentChange::FormField);
        };
        if changed_beyond(&old, &new, &[KEY_FIELDS, KEY_SIG_FLAGS]) {
            return Some(DocumentChange::FormField);
        }
        let (Some(old_tree), Some(new_tree)) = (self.before.field_tree(), self.after.field_tree())
        else {
            return Some(DocumentChange::FormField);
        };
        let removed = old_tree.iter().any(|node| !new_tree.contains(node));
        let foreign = new_tree
            .iter()
            .filter(|node| !old_tree.contains(node))
            .any(|node| !self.after.is_signed_field_node(*node));
        (removed || foreign).then_some(DocumentChange::FormField)
    }

    /// Each page's `/Annots`, resolved on both sides: the annotations
    /// already there kept in their order, and every one added a widget
    /// of a signed signature field of the field tree.
    fn annotations(&self) -> Option<DocumentChange> {
        let tree = &self.after_roles.field_tree;
        let mut changes = Vec::new();
        for (reference, newer) in self.after.pages() {
            let Some(older) = self
                .before
                .object(reference)
                .filter(|older| older.names(KEY_TYPE, TYPE_PAGE))
            else {
                continue;
            };
            let (Some(old), Some(new)) = (
                self.before.list(older.entry(KEY_ANNOTS)),
                self.after.list(newer.entry(KEY_ANNOTS)),
            ) else {
                changes.push(DocumentChange::Annotation);
                continue;
            };
            let kept: Vec<PdfObjectReference> = new
                .iter()
                .copied()
                .filter(|annotation| old.contains(annotation))
                .collect();
            if kept != old {
                changes.push(DocumentChange::Annotation);
            }
            for added in new.iter().filter(|annotation| !old.contains(annotation)) {
                let attached = self
                    .after
                    .field_node(*added)
                    .is_some_and(|(node, _)| tree.contains(&node) || tree.contains(added));
                if !(attached && self.after.is_signed_widget(*added)) {
                    changes.push(if self.after.field_type(*added).is_some() {
                        DocumentChange::FormField
                    } else {
                        DocumentChange::Annotation
                    });
                }
            }
        }
        changes.into_iter().min()
    }

    /// The `/DSS`: its category arrays only gaining entries, its `/VRI`
    /// entries kept, every other entry but `/Type` unchanged.
    fn store(&self) -> Option<DocumentChange> {
        let store = |view: &Snapshot| view.dictionary_of(view.catalog()?.entry(KEY_DSS));
        let (Some(old), Some(new)) = (store(self.before), store(self.after)) else {
            return Some(DocumentChange::Content);
        };
        if changed_beyond(
            &old,
            &new,
            &[KEY_TYPE, KEY_CERTS, KEY_OCSPS, KEY_CRLS, KEY_VRI],
        ) {
            return Some(DocumentChange::Content);
        }
        for key in [KEY_CERTS, KEY_OCSPS, KEY_CRLS] {
            let (Some(old_list), Some(new_list)) = (
                self.before.list(old.get(key)),
                self.after.list(new.get(key)),
            ) else {
                return Some(DocumentChange::Content);
            };
            if old_list.iter().any(|entry| !new_list.contains(entry)) {
                return Some(DocumentChange::Content);
            }
        }
        let (Some(old_vri), Some(new_vri)) = (
            self.before.dictionary_of(old.get(KEY_VRI)),
            self.after.dictionary_of(new.get(KEY_VRI)),
        ) else {
            return Some(DocumentChange::Content);
        };
        old_vri
            .iter()
            .any(|(key, entry)| new_vri.get(key) != Some(entry))
            .then_some(DocumentChange::Content)
    }

    /// What one object's fate touches; `None` when it may follow a
    /// signature.
    fn judge(&self, reference: PdfObjectReference, fate: &Fate<'_>) -> Option<DocumentChange> {
        let roles = &self.after_roles;
        match *fate {
            Fate::Added(newer) => {
                let kind = self.after.kind_of(reference, newer);
                let harmless = newer.is_structure_stream()
                    || roles.store_containers.contains(&reference)
                    || roles.store_entries.contains(&reference)
                    || roles.store_streams.contains(&reference)
                    || roles.lists.contains(&reference)
                    || (newer.is_signature_value() && roles.signature_values.contains(&reference))
                    || (self.after.is_signed_field_node(reference)
                        && roles.field_tree.contains(&reference))
                    || (kind == DocumentChange::Content
                        && (roles.appearances.contains(&reference)
                            || roles.metadata.contains(&reference)));
                (!harmless).then_some(kind)
            }
            Fate::Replaced { older, newer } => {
                let kind = self.after.kind_of(reference, newer);
                if self.before.object(reference).is_none() {
                    // The generation rose: the object the signed
                    // revision's references named is freed.
                    return Some(kind);
                }
                let unchanged_role = |set: fn(&Roles) -> &HashSet<PdfObjectReference>| {
                    set(roles).contains(&reference) && set(&self.before_roles).contains(&reference)
                };
                if (older.is_structure_stream() && newer.is_structure_stream())
                    || unchanged_role(|roles| &roles.store_containers)
                    || unchanged_role(|roles| &roles.lists)
                    || (kind == DocumentChange::Content
                        && roles.metadata.contains(&reference)
                        && self.before_roles.metadata.contains(&reference))
                {
                    return None;
                }
                if reference.number == self.after.root.number {
                    return Self::catalog(older, newer);
                }
                if older.names(KEY_TYPE, TYPE_PAGE) && newer.names(KEY_TYPE, TYPE_PAGE) {
                    return Self::page(older, newer);
                }
                if self.before.field_type(reference) == Some(FieldType::Signature) {
                    return self.signature_field(reference, older, newer);
                }
                Some(kind)
            }
        }
    }

    /// A rewritten catalog: every entry other than `/DSS`, `/AcroForm`,
    /// `/Extensions` and `/Metadata` unchanged; those are judged on
    /// their own.
    fn catalog(older: &Object, newer: &Object) -> Option<DocumentChange> {
        let (Some(old), Some(new)) = (older.dictionary(), newer.dictionary()) else {
            return Some(DocumentChange::Catalog);
        };
        changed_beyond(
            old,
            new,
            &[KEY_DSS, KEY_ACROFORM, KEY_EXTENSIONS, KEY_METADATA],
        )
        .then_some(DocumentChange::Catalog)
    }

    /// A rewritten page: every entry other than `/Annots` unchanged;
    /// `/Annots` is judged on its own.
    fn page(older: &Object, newer: &Object) -> Option<DocumentChange> {
        let (Some(old), Some(new)) = (older.dictionary(), newer.dictionary()) else {
            return Some(DocumentChange::Content);
        };
        if matches!(older, Object::Stream(..)) || matches!(newer, Object::Stream(..)) {
            return Some(DocumentChange::Content);
        }
        if old.get(KEY_PARENT) != new.get(KEY_PARENT) {
            return Some(DocumentChange::Pages);
        }
        changed_beyond(old, new, &[KEY_ANNOTS]).then_some(DocumentChange::Content)
    }

    /// A rewritten signature field or widget: its field carried no
    /// value before and carries one now, and only `/V`, `/AP` and `/AS`
    /// differ.
    fn signature_field(
        &self,
        reference: PdfObjectReference,
        older: &Object,
        newer: &Object,
    ) -> Option<DocumentChange> {
        let (Some(old), Some(new)) = (older.dictionary(), newer.dictionary()) else {
            return Some(DocumentChange::FormField);
        };
        let filled = !self.before.is_signed(reference) && self.after.is_signed(reference);
        (!filled || changed_beyond(old, new, &[KEY_VALUE, KEY_APPEARANCE, KEY_APPEARANCE_STATE]))
            .then_some(DocumentChange::FormField)
    }
}

/// Whether `old` and `new` differ in an entry other than `free`.
fn changed_beyond(
    old: &BTreeMap<Vec<u8>, Value>,
    new: &BTreeMap<Vec<u8>, Value>,
    free: &[&[u8]],
) -> bool {
    old.keys()
        .chain(new.keys())
        .filter(|key| !free.contains(&key.as_slice()))
        .any(|key| old.get(key) != new.get(key))
}
