// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! What the revisions after a signed one change in a PDF.
//!
//! A signature covers the revision its `/ByteRange` ends; anyone may
//! append revisions after it. The verifier indexes the signed
//! revision on its own and compares its objects with the newest view
//! of the document, object by object, through the cross-reference
//! index. An object that is the same value in both is untouched. Of the
//! rest, a later revision may add, without changing what the signer
//! saw:
//!
//! - signature and document timestamp dictionaries, the signature
//!   fields and widgets that hold them, and new objects their
//!   appearance streams draw from;
//! - the `/DSS` and the objects it reaches;
//! - cross-reference and object streams;
//! - the document information dictionary and the catalog's `/Metadata`
//!   stream, which signing tools update and which change nothing
//!   rendered;
//! - the catalog rewritten with a changed `/DSS`, `/AcroForm`,
//!   `/Perms`, `/Extensions` or `/Metadata`, an `/AcroForm` whose `/Fields` gains
//!   signature fields and whose `/SigFlags`, `/DA` or `/DR` change, and
//!   a page whose `/Annots` gains signature widgets.
//!
//! Anything else is a change after signing, typed by what it touches.
//!
//! # Conformance
//!
//! - ISO 32000-1 sec.7.5.6: an incremental update appends changed and
//!   new objects with a cross-reference section of its own.
//! - ISO 32000-1 sec.12.8.2.2 (`DocMDP`) and sec.12.8.2.4
//!   (`FieldMDP`): the changes a signature may be followed by are
//!   signing, filling in signature fields, and adding document-level
//!   validation material; `ETSI EN 319 142-1` V1.2.1 clauses 5.4.2 and
//!   5.4.3 add the `/DSS` and document timestamps.
//! - ISO 32000-1 sec.12.7.3.1: a field inherits `/FT` from its parent;
//!   sec.12.5.2: an annotation is a dictionary with `/Subtype` and
//!   `/Rect`.

use std::collections::{BTreeMap, HashSet};

use crate::pades::index::{PdfDictionary, PdfIndex, PdfObjectReference, PdfValueParser};

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

/// Trailer key of the catalog (ISO 32000-1 sec.7.5.5, Table 15).
const KEY_ROOT: &[u8] = b"Root";
/// Key naming an object's type.
const KEY_TYPE: &[u8] = b"Type";
/// Key naming an annotation's or `XObject`'s subtype.
const KEY_SUBTYPE: &[u8] = b"Subtype";
/// Key of an annotation's rectangle (ISO 32000-1 sec.12.5.2).
const KEY_RECT: &[u8] = b"Rect";
/// Key of a field's type (ISO 32000-1 sec.12.7.3.1, Table 220).
const KEY_FIELD_TYPE: &[u8] = b"FT";
/// Key of a field's or a page's parent.
const KEY_PARENT: &[u8] = b"Parent";
/// Key of an annotation's appearance dictionary (ISO 32000-1
/// sec.12.5.5).
const KEY_APPEARANCE: &[u8] = b"AP";
/// Key of a page's annotations (ISO 32000-1 sec.7.7.3.3, Table 30).
const KEY_ANNOTS: &[u8] = b"Annots";
/// Key of the catalog's interactive form (ISO 32000-1 sec.7.7.2).
const KEY_ACROFORM: &[u8] = b"AcroForm";
/// Key of the interactive form's root fields (ISO 32000-1
/// sec.12.7.2, Table 218).
const KEY_FIELDS: &[u8] = b"Fields";
/// Key of the interactive form's signature flags.
const KEY_SIG_FLAGS: &[u8] = b"SigFlags";
/// Key of the interactive form's default appearance string.
const KEY_DEFAULT_APPEARANCE: &[u8] = b"DA";
/// Key of the interactive form's default resources.
const KEY_DEFAULT_RESOURCES: &[u8] = b"DR";
/// Key of the catalog's document security store (`ETSI EN 319 142-1`
/// clause 5.4.2).
const KEY_DSS: &[u8] = b"DSS";
/// Key of the catalog's permissions (ISO 32000-1 sec.12.8.4).
const KEY_PERMS: &[u8] = b"Perms";
/// Key of the catalog's developer extensions (ISO 32000-1 sec.7.12).
const KEY_EXTENSIONS: &[u8] = b"Extensions";
/// Key of the catalog's metadata stream (ISO 32000-1 sec.14.3.2).
const KEY_METADATA: &[u8] = b"Metadata";
/// Trailer key of the document information dictionary (ISO 32000-1
/// sec.14.3.3).
const KEY_INFO: &[u8] = b"Info";
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
/// `/FT` of a signature field (ISO 32000-1 sec.12.7.4.5).
const FIELD_TYPE_SIGNATURE: &[u8] = b"Sig";

/// Most `/Parent` links followed to find a field's inherited type; a
/// real field tree is a handful deep.
const MAX_FIELD_DEPTH: usize = 32;
/// Most objects followed from the `/DSS` or from one appearance
/// dictionary.
const MAX_REACHED_OBJECTS: usize = 4096;

/// What a later revision changes in what the signer saw, in order of
/// precedence: when a revision changes several things, the first in
/// this order is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DocumentChange {
    /// The page tree: a page added, removed or moved.
    Pages,
    /// A form field other than a signature field, or the interactive
    /// form beyond its signature fields.
    FormField,
    /// An annotation other than a signature widget.
    Annotation,
    /// The catalog, beyond `/DSS`, `/AcroForm`, `/Perms`,
    /// `/Extensions` and `/Metadata`.
    Catalog,
    /// A page's content, its resources, or any other object of the
    /// document.
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
/// not index as a document of their own.
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

/// One object's body: its value, and the bytes after it (a stream's
/// keyword and payload), compared as written.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Object {
    /// The value, `None` when the body is no value this reader reads.
    value: Option<Value>,
    /// The bytes after the value, or the whole body when it does not
    /// read.
    rest: Vec<u8>,
}

impl Object {
    /// Read the body of one object.
    fn read(body: &[u8]) -> Self {
        let mut parser = PdfValueParser::new(body);
        match Value::read(&mut parser, 1) {
            Some(value) => {
                parser.skip_trivia();
                Self {
                    value: Some(value),
                    rest: body.get(parser.offset..).unwrap_or_default().to_vec(),
                }
            }
            None => Self {
                value: None,
                rest: body.to_vec(),
            },
        }
    }

    /// The dictionary the object is or opens.
    fn dictionary(&self) -> Option<&BTreeMap<Vec<u8>, Value>> {
        self.value.as_ref().and_then(Value::dictionary)
    }

    /// The value under `key` of the object's dictionary.
    fn entry(&self, key: &[u8]) -> Option<&Value> {
        self.dictionary().and_then(|entries| entries.get(key))
    }

    /// Whether the object's dictionary names `name` under `key`.
    fn names(&self, key: &[u8], name: &[u8]) -> bool {
        matches!(self.entry(key), Some(Value::Name(found)) if found == name)
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

/// One view of the document: the signed revision, or the newest.
struct Snapshot<'i, 'a> {
    /// The cross-reference index of this view.
    index: &'i PdfIndex<'a>,
    /// The catalog.
    root: PdfObjectReference,
    /// The objects the catalog's `/DSS` reaches, the store itself
    /// among them when it is indirect.
    store: HashSet<PdfObjectReference>,
    /// The objects the appearance dictionaries of signature widgets
    /// reach.
    appearances: HashSet<PdfObjectReference>,
    /// The arrays a page names indirectly as its `/Annots`.
    annotation_arrays: HashSet<PdfObjectReference>,
    /// The trailer's `/Info` dictionary and the catalog's `/Metadata`
    /// stream, when indirect.
    metadata: HashSet<PdfObjectReference>,
}

impl<'i, 'a> Snapshot<'i, 'a> {
    /// The view `index` gives; `None` without a catalog reference.
    fn new(index: &'i PdfIndex<'a>) -> Option<Self> {
        let trailer = PdfDictionary::parse(index.trailer()).ok()?;
        let root_value = trailer.entry(KEY_ROOT).ok()??;
        let mut parser = PdfValueParser::new(index.trailer().get(root_value.value.clone())?);
        parser.skip_trivia();
        let root = parser.reference()?;
        let mut metadata = HashSet::new();
        if let Some(info) = trailer.entry(KEY_INFO).ok()? {
            let mut parser = PdfValueParser::new(index.trailer().get(info.value.clone())?);
            parser.skip_trivia();
            metadata.extend(parser.reference());
        }
        let mut snapshot = Self {
            index,
            root,
            store: HashSet::new(),
            appearances: HashSet::new(),
            annotation_arrays: HashSet::new(),
            metadata,
        };
        let catalog = snapshot.object(root);
        if let Some(Value::Reference(stream)) = catalog
            .as_ref()
            .and_then(|catalog| catalog.entry(KEY_METADATA))
        {
            snapshot.metadata.insert(*stream);
        }
        if let Some(store) = catalog.as_ref().and_then(|catalog| catalog.entry(KEY_DSS)) {
            snapshot.store = snapshot.reached_from(store);
        }
        let mut appearances = HashSet::new();
        let mut annotation_arrays = HashSet::new();
        for reference in index.live_references() {
            let Some(object) = snapshot.object(reference) else {
                continue;
            };
            if object.names(KEY_TYPE, TYPE_PAGE)
                && let Some(Value::Reference(array)) = object.entry(KEY_ANNOTS)
            {
                annotation_arrays.insert(*array);
            }
            if snapshot.field_type(reference) == Some(FieldType::Signature)
                && let Some(appearance) = object.entry(KEY_APPEARANCE)
            {
                appearances.extend(snapshot.reached_from(appearance));
            }
        }
        snapshot.appearances = appearances;
        snapshot.annotation_arrays = annotation_arrays;
        Some(snapshot)
    }

    /// The object `reference` names in this view.
    fn object(&self, reference: PdfObjectReference) -> Option<Object> {
        self.index
            .object_body_reference(reference)
            .map(|body| Object::read(&body))
    }

    /// The objects `value` references, and those they reference in
    /// turn, up to [`MAX_REACHED_OBJECTS`].
    fn reached_from(&self, value: &Value) -> HashSet<PdfObjectReference> {
        let mut pending = Vec::new();
        value.references(&mut pending);
        let mut reached = HashSet::new();
        while let Some(reference) = pending.pop() {
            if reached.len() == MAX_REACHED_OBJECTS || !reached.insert(reference) {
                continue;
            }
            if let Some(value) = self.object(reference).and_then(|object| object.value) {
                value.references(&mut pending);
            }
        }
        reached
    }

    /// The type of the field `reference` names: its own `/FT`, or the
    /// nearest one up its `/Parent` chain. `None` for an object that is
    /// no field.
    fn field_type(&self, reference: PdfObjectReference) -> Option<FieldType> {
        let mut current = reference;
        for _ in 0..MAX_FIELD_DEPTH {
            let object = self.object(current)?;
            match object.entry(KEY_FIELD_TYPE) {
                Some(Value::Name(name)) if name == FIELD_TYPE_SIGNATURE => {
                    return Some(FieldType::Signature);
                }
                Some(_) => return Some(FieldType::Other),
                None => {}
            }
            match object.entry(KEY_PARENT) {
                Some(Value::Reference(parent)) => current = *parent,
                _ => return None,
            }
        }
        None
    }

    /// Whether `reference` is a signature field or a widget of one.
    fn is_signature_field(&self, reference: PdfObjectReference) -> bool {
        self.field_type(reference) == Some(FieldType::Signature)
    }

    /// The references a list value holds, inline or as an indirect
    /// array of this view; `None` when it is neither.
    fn list(&self, value: Option<&Value>) -> Option<Vec<PdfObjectReference>> {
        let items = match value {
            None => return Some(Vec::new()),
            Some(Value::Array(items)) => items.clone(),
            Some(Value::Reference(reference)) => match self.object(*reference)?.value? {
                Value::Array(items) => items,
                _ => return None,
            },
            Some(_) => return None,
        };
        items
            .into_iter()
            .map(|item| match item {
                Value::Reference(reference) => Some(reference),
                _ => None,
            })
            .collect()
    }

    /// The dictionary a value is, inline or as an indirect object of
    /// this view; empty when absent. `None` when it is neither.
    fn dictionary_of(&self, value: Option<&Value>) -> Option<BTreeMap<Vec<u8>, Value>> {
        match value {
            None => Some(BTreeMap::new()),
            Some(Value::Dictionary(entries)) => Some(entries.clone()),
            Some(Value::Reference(reference)) => match self.object(*reference)?.value? {
                Value::Dictionary(entries) => Some(entries),
                _ => None,
            },
            Some(_) => None,
        }
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
        } else if reference == self.root {
            DocumentChange::Catalog
        } else {
            DocumentChange::Content
        }
    }
}

/// The signed revision against the newest view.
struct Comparison<'s, 'i, 'a> {
    /// The signed revision.
    before: &'s Snapshot<'i, 'a>,
    /// The newest view.
    after: &'s Snapshot<'i, 'a>,
}

impl Comparison<'_, '_, '_> {
    /// The change of highest precedence the later revisions make, or
    /// `None` when they only add what may follow a signature.
    fn first_change(&self) -> Option<DocumentChange> {
        let mut changes = Vec::new();
        if self.before.root != self.after.root {
            changes.push(DocumentChange::Catalog);
        }
        for reference in self.after.index.live_references() {
            let newer = self.after.object(reference);
            let older = self.before.object(reference);
            if let Some(newer) = newer
                && older.as_ref() != Some(&newer)
                && let Some(change) = self.judge(reference, older.as_ref(), &newer)
            {
                changes.push(change);
            }
        }
        for reference in self.before.index.live_references() {
            if self.after.index.object_body_reference(reference).is_none()
                && let Some(older) = self.before.object(reference)
            {
                changes.push(self.before.kind_of(reference, &older));
            }
        }
        changes.into_iter().min()
    }

    /// What the change of the object `reference` from `older` (absent
    /// when new) to `newer` touches; `None` when it is a change that may
    /// follow a signature.
    fn judge(
        &self,
        reference: PdfObjectReference,
        older: Option<&Object>,
        newer: &Object,
    ) -> Option<DocumentChange> {
        let kind = self.after.kind_of(reference, newer);
        let new = older.is_none();
        if self.after.store.contains(&reference)
            && kind == DocumentChange::Content
            && (new || self.before.store.contains(&reference))
        {
            return None;
        }
        if self.after.metadata.contains(&reference)
            && kind == DocumentChange::Content
            && (new || self.before.metadata.contains(&reference))
        {
            return None;
        }
        let stream_type = |object: &Object| {
            object.names(KEY_TYPE, TYPE_XREF) || object.names(KEY_TYPE, TYPE_OBJECT_STREAM)
        };
        if stream_type(newer) && older.is_none_or(stream_type) {
            return None;
        }
        if newer.is_signature_value() {
            return (!new).then_some(DocumentChange::FormField);
        }
        if self.after.is_signature_field(reference) {
            return (!new && !self.before.is_signature_field(reference))
                .then_some(DocumentChange::FormField);
        }
        if new && kind == DocumentChange::Content && self.after.appearances.contains(&reference) {
            return None;
        }
        let older = older?;
        if reference == self.after.root {
            return self.catalog(older, newer);
        }
        if let Some(form) = self
            .after
            .object(self.after.root)
            .and_then(|catalog| catalog.entry(KEY_ACROFORM).cloned())
            && form == Value::Reference(reference)
        {
            return self.form(older.dictionary(), newer.dictionary());
        }
        if self.is_field_list(reference) {
            return self.list(
                self.before.list(older.value.as_ref()),
                self.after.list(newer.value.as_ref()),
                DocumentChange::FormField,
            );
        }
        if newer.names(KEY_TYPE, TYPE_PAGE) && older.names(KEY_TYPE, TYPE_PAGE) {
            return self.page(older, newer);
        }
        if self.after.annotation_arrays.contains(&reference) {
            return self.list(
                self.before.list(older.value.as_ref()),
                self.after.list(newer.value.as_ref()),
                DocumentChange::Annotation,
            );
        }
        Some(kind)
    }

    /// Whether `reference` is the array the newest `/AcroForm` names
    /// as its `/Fields`.
    fn is_field_list(&self, reference: PdfObjectReference) -> bool {
        let Some(catalog) = self.after.object(self.after.root) else {
            return false;
        };
        self.after
            .dictionary_of(catalog.entry(KEY_ACROFORM))
            .is_some_and(|form| form.get(KEY_FIELDS) == Some(&Value::Reference(reference)))
    }

    /// A rewritten catalog: every entry other than `/DSS`, `/Perms`,
    /// `/Extensions` and `/AcroForm` unchanged, and the interactive
    /// form changed only as [`Self::form`] allows.
    fn catalog(&self, older: &Object, newer: &Object) -> Option<DocumentChange> {
        let (Some(old), Some(new)) = (older.dictionary(), newer.dictionary()) else {
            return Some(DocumentChange::Catalog);
        };
        let free = [
            KEY_DSS,
            KEY_PERMS,
            KEY_EXTENSIONS,
            KEY_METADATA,
            KEY_ACROFORM,
        ];
        let others_changed = old
            .keys()
            .chain(new.keys())
            .filter(|key| !free.contains(&key.as_slice()))
            .any(|key| old.get(key) != new.get(key));
        if others_changed {
            return Some(DocumentChange::Catalog);
        }
        let (old_form, new_form) = (old.get(KEY_ACROFORM), new.get(KEY_ACROFORM));
        if old_form == new_form && matches!(new_form, None | Some(Value::Reference(_))) {
            return None;
        }
        let old_form = self.before.dictionary_of(old_form);
        let new_form = self.after.dictionary_of(new_form);
        self.form(old_form.as_ref(), new_form.as_ref())
    }

    /// A changed interactive form: `/SigFlags`, `/DA` and `/DR` free,
    /// every other entry but `/Fields` unchanged, and `/Fields` gaining
    /// only signature fields.
    fn form(
        &self,
        older: Option<&BTreeMap<Vec<u8>, Value>>,
        newer: Option<&BTreeMap<Vec<u8>, Value>>,
    ) -> Option<DocumentChange> {
        let (Some(old), Some(new)) = (older, newer) else {
            return Some(DocumentChange::FormField);
        };
        let free = [
            KEY_SIG_FLAGS,
            KEY_DEFAULT_APPEARANCE,
            KEY_DEFAULT_RESOURCES,
            KEY_FIELDS,
        ];
        let others_changed = old
            .keys()
            .chain(new.keys())
            .filter(|key| !free.contains(&key.as_slice()))
            .any(|key| old.get(key) != new.get(key));
        if others_changed {
            return Some(DocumentChange::FormField);
        }
        let (old_fields, new_fields) = (old.get(KEY_FIELDS), new.get(KEY_FIELDS));
        if old_fields == new_fields && matches!(new_fields, None | Some(Value::Reference(_))) {
            return None;
        }
        self.list(
            self.before.list(old_fields),
            self.after.list(new_fields),
            DocumentChange::FormField,
        )
    }

    /// A rewritten page: every entry other than `/Annots` unchanged,
    /// and `/Annots` gaining only signature widgets.
    fn page(&self, older: &Object, newer: &Object) -> Option<DocumentChange> {
        let (Some(old), Some(new)) = (older.dictionary(), newer.dictionary()) else {
            return Some(DocumentChange::Content);
        };
        if older.rest != newer.rest {
            return Some(DocumentChange::Content);
        }
        let changed = |key: &Vec<u8>| key.as_slice() != KEY_ANNOTS && old.get(key) != new.get(key);
        if let Some(key) = old.keys().chain(new.keys()).find(|key| changed(key)) {
            return Some(if key.as_slice() == KEY_PARENT {
                DocumentChange::Pages
            } else {
                DocumentChange::Content
            });
        }
        let (old_annots, new_annots) = (old.get(KEY_ANNOTS), new.get(KEY_ANNOTS));
        if old_annots == new_annots && matches!(new_annots, None | Some(Value::Reference(_))) {
            return None;
        }
        self.list(
            self.before.list(old_annots),
            self.after.list(new_annots),
            DocumentChange::Annotation,
        )
    }

    /// A changed list of fields or annotations: nothing removed, and
    /// every addition a signature field or widget. An addition that is
    /// another field is a [`DocumentChange::FormField`]; a removal, an
    /// unreadable list or any other addition is `kind`.
    fn list(
        &self,
        older: Option<Vec<PdfObjectReference>>,
        newer: Option<Vec<PdfObjectReference>>,
        kind: DocumentChange,
    ) -> Option<DocumentChange> {
        let (Some(older), Some(newer)) = (older, newer) else {
            return Some(kind);
        };
        if older.iter().any(|reference| !newer.contains(reference)) {
            return Some(kind);
        }
        newer
            .iter()
            .filter(|reference| !older.contains(reference))
            .filter(|reference| !self.after.is_signature_field(**reference))
            .map(|reference| {
                if self.after.field_type(*reference).is_some() {
                    DocumentChange::FormField
                } else {
                    kind
                }
            })
            .min()
    }
}
