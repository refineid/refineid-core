// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! The cross-reference index and value grammar shared by the `PAdES`
//! writer and the document reader.
//!
//! [`PdfIndex`] follows `startxref` and the `/Prev` chain through
//! classic tables, cross-reference streams and hybrid files, keeping
//! the newest entry for each object number with its generation.
//! [`PdfValueParser`] and [`PdfDictionary`] read the value grammar with
//! exact byte spans, so a caller can either interpret a value or carry
//! it forward unchanged. Keys are found through the grammar, never by
//! searching bytes: `/Preview` is not `/Prev`, and a key spelled inside
//! a string is not a key.
//!
//! Every count the file declares is bounded before anything is
//! allocated for it: [`MAX_XREF_ENTRIES`] entries per file,
//! [`PdfIndex::MAX_XREF_SECTIONS`] sections in the `/Prev` chain, and
//! [`MAX_PDF_VALUE_DEPTH`] levels of value nesting. A file past a bound
//! is refused with an error; nothing is read in part.
//!
//! # Conformance
//!
//! - ISO 32000-1 sec.7.2.2 Table 1: the white-space characters.
//! - ISO 32000-1 sec.7.3: objects, names, strings, dictionaries.
//! - ISO 32000-1 sec.7.5.4, sec.7.5.5, sec.7.5.6: the cross-reference
//!   table, the trailer and incremental updates.
//! - ISO 32000-1 sec.7.5.7, sec.7.5.8: object and cross-reference
//!   streams, read in `xref_stream`.

use std::collections::{HashMap, HashSet};

use super::PdfError;
use super::xref_stream;

/// Most cross-reference entries a file may declare, through `/Size`, a
/// classic subsection count or a stream's `/Index` pairs.
///
/// ISO 32000-1 Annex C, Table C.1, caps a file at 8 388 607 indirect
/// objects, numbered from one; with entry zero, which heads the free
/// list, that is two to the twenty-third entries. Every object number
/// this reader admits is below this, so the merged index never holds
/// more objects than this either.
pub(crate) const MAX_XREF_ENTRIES: usize = 1 << 23;

/// Maximum nesting accepted while reading PDF values.
///
/// The document security store can carry extension dictionaries and a
/// `/VRI` tree that the writer must preserve without interpreting, and
/// the reader parses every live dictionary. A fixed bound keeps both
/// from becoming an unbounded parser recursion on an attacker-supplied
/// PDF.
pub(crate) const MAX_PDF_VALUE_DEPTH: usize = 64;

/// The NUL white-space character (ISO 32000-1 sec.7.2.2, Table 1).
const NUL: u8 = 0x00;

/// The FORM FEED white-space character (ISO 32000-1 sec.7.2.2, Table 1).
const FORM_FEED: u8 = 0x0C;

/// Radix of a hexadecimal digit pair in a name escape or hex string.
const HEX_RADIX: u8 = 16;

/// Value of the first hexadecimal letter digit, `A`.
const HEX_LETTER_VALUE: u8 = 10;

/// Radix of a decimal integer.
const DECIMAL_RADIX: usize = 10;

/// Bytes of a `#xx` name escape (ISO 32000-1 sec.7.3.5).
const NAME_ESCAPE_LEN: usize = 3;

/// Introduces a `#xx` escape inside a name.
const NAME_ESCAPE: u8 = b'#';

/// Introduces a name (ISO 32000-1 sec.7.3.5).
const NAME_OPEN: &[u8] = b"/";

/// Opens a dictionary (ISO 32000-1 sec.7.3.7).
pub(crate) const DICTIONARY_OPEN: &[u8] = b"<<";

/// Closes a dictionary.
pub(crate) const DICTIONARY_CLOSE: &[u8] = b">>";

/// Opens an array (ISO 32000-1 sec.7.3.6).
pub(crate) const ARRAY_OPEN: &[u8] = b"[";

/// Closes an array.
pub(crate) const ARRAY_CLOSE: &[u8] = b"]";

/// Opens a literal string (ISO 32000-1 sec.7.3.4.2).
const LITERAL_OPEN: &[u8] = b"(";

/// Opens a hexadecimal string (ISO 32000-1 sec.7.3.4.3).
const HEX_OPEN: &[u8] = b"<";

/// The keyword closing an indirect reference (ISO 32000-1 sec.7.3.10).
const REFERENCE_KEYWORD: &[u8] = b"R";

/// The keyword that starts an indirect object.
const OBJ_KEYWORD: &[u8] = b"obj";

/// The keyword that ends an indirect object.
const ENDOBJ_KEYWORD: &[u8] = b"endobj";

/// The keyword naming the newest cross-reference section
/// (ISO 32000-1 sec.7.5.5).
const STARTXREF_KEYWORD: &[u8] = b"startxref";

/// The keyword opening a classic cross-reference table
/// (ISO 32000-1 sec.7.5.4).
const XREF_KEYWORD: &[u8] = b"xref";

/// The keyword opening the trailer dictionary (ISO 32000-1 sec.7.5.5).
const TRAILER_KEYWORD: &[u8] = b"trailer";

/// Cross-reference table keyword of an object in use
/// (ISO 32000-1 sec.7.5.4).
const XREF_IN_USE: &[u8] = b"n";

/// Cross-reference table keyword of a free entry.
const XREF_FREE: &[u8] = b"f";

/// Trailer key of the previous cross-reference section
/// (ISO 32000-1 sec.7.5.5, Table 15).
const KEY_PREV: &[u8] = b"Prev";

/// Trailer key of a hybrid file's cross-reference stream
/// (ISO 32000-1 sec.7.5.8.4, Table 19).
const KEY_XREF_STREAM: &[u8] = b"XRefStm";

/// Trailer key of the number of entries (ISO 32000-1 sec.7.5.5).
const KEY_SIZE: &[u8] = b"Size";

/// One indirect PDF object reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct PdfObjectReference {
    /// The object number.
    pub(crate) number: u32,
    /// The generation number.
    pub(crate) generation: u16,
}

impl PdfObjectReference {
    /// The reference as written: `N G R`.
    pub(crate) fn rendered(self) -> String {
        format!("{} {} R", self.number, self.generation)
    }
}

/// One top-level dictionary entry, retaining the exact value byte span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PdfDictionaryEntry {
    /// Decoded name bytes, without the leading slash.
    pub(crate) name: Vec<u8>,
    /// Exact value bytes in the dictionary source.
    pub(crate) value: core::ops::Range<usize>,
}

/// A parsed top-level dictionary.
pub(crate) struct PdfDictionary {
    /// The entries, in source order.
    pub(crate) entries: Vec<PdfDictionaryEntry>,
    /// Offset of the outer dictionary's closing `>>`.
    pub(crate) closing: usize,
}

impl PdfDictionary {
    /// Parse one complete dictionary, with only trivia around it.
    ///
    /// # Errors
    /// [`PdfError::MalformedValue`] when the bytes are not one
    /// dictionary, [`PdfError::NestingTooDeep`] past
    /// [`MAX_PDF_VALUE_DEPTH`].
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, PdfError> {
        let mut parser = PdfValueParser::new(bytes);
        parser.skip_trivia();
        let dictionary = parser.dictionary(1)?;
        parser.require_end()?;
        Ok(dictionary)
    }

    /// Parse the dictionary that opens `bytes`, ignoring what follows
    /// it, such as the `stream` keyword and payload of a stream object.
    ///
    /// # Errors
    /// As [`Self::parse`].
    pub(crate) fn parse_leading(bytes: &[u8]) -> Result<Self, PdfError> {
        let mut parser = PdfValueParser::new(bytes);
        parser.skip_trivia();
        parser.dictionary(1)
    }

    /// The sole entry whose decoded name equals `name`.
    ///
    /// Duplicate spellings such as `/DSS` and `/D#53S` are ambiguous and
    /// refused instead of silently choosing one.
    ///
    /// # Errors
    /// [`PdfError::MalformedValue`] when the name occurs more than once.
    pub(crate) fn entry(&self, name: &[u8]) -> Result<Option<&PdfDictionaryEntry>, PdfError> {
        let mut matching = self.entries.iter().filter(|entry| entry.name == name);
        let found = matching.next();
        if matching.next().is_some() {
            return Err(PdfError::MalformedValue);
        }
        Ok(found)
    }
}

/// Byte-oriented parser for the PDF value grammar.
pub(crate) struct PdfValueParser<'a> {
    /// The bytes being read.
    pub(crate) bytes: &'a [u8],
    /// The next unread offset.
    pub(crate) offset: usize,
}

impl<'a> PdfValueParser<'a> {
    /// A parser at the start of `bytes`.
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    /// A dictionary at the current position, `depth` levels deep.
    pub(crate) fn dictionary(&mut self, depth: usize) -> Result<PdfDictionary, PdfError> {
        Self::check_depth(depth)?;
        if !self.consume(DICTIONARY_OPEN) {
            return Err(PdfError::MalformedValue);
        }
        let mut entries = Vec::new();
        loop {
            self.skip_trivia();
            let closing = self.offset;
            if self.consume(DICTIONARY_CLOSE) {
                return Ok(PdfDictionary { entries, closing });
            }
            let name = self.name()?;
            self.skip_trivia();
            let value = self.value(depth)?;
            entries.push(PdfDictionaryEntry { name, value });
        }
    }

    /// The byte span of one value at the current position.
    pub(crate) fn value(&mut self, depth: usize) -> Result<core::ops::Range<usize>, PdfError> {
        self.skip_trivia();
        let start = self.offset;
        if self.starts_with(DICTIONARY_OPEN) {
            let _dictionary = self.dictionary(depth.saturating_add(1))?;
        } else if self.consume(ARRAY_OPEN) {
            self.array_remainder(depth.saturating_add(1))?;
        } else if self.consume(LITERAL_OPEN) {
            self.literal_string_remainder()?;
        } else if self.consume(HEX_OPEN) {
            self.hex_string_remainder()?;
        } else if self.starts_with(NAME_OPEN) {
            let _name = self.name()?;
        } else {
            let first = self.atom()?;
            self.consume_reference_tail(first);
        }
        Ok(start..self.offset)
    }

    /// The rest of an array after its `[`.
    pub(crate) fn array_remainder(&mut self, depth: usize) -> Result<(), PdfError> {
        Self::check_depth(depth)?;
        loop {
            self.skip_trivia();
            if self.consume(ARRAY_CLOSE) {
                return Ok(());
            }
            let _value = self.value(depth)?;
        }
    }

    /// The rest of a literal string after its `(`, balanced parentheses
    /// and escapes honoured (ISO 32000-1 sec.7.3.4.2).
    pub(crate) fn literal_string_remainder(&mut self) -> Result<(), PdfError> {
        let mut depth = 1_usize;
        while let Some(byte) = self.bytes.get(self.offset).copied() {
            self.offset = self.offset.saturating_add(1);
            match byte {
                b'\\' => {
                    let Some(escaped) = self.bytes.get(self.offset).copied() else {
                        return Err(PdfError::MalformedValue);
                    };
                    self.offset = self.offset.saturating_add(1);
                    if escaped == b'\r' && self.bytes.get(self.offset) == Some(&b'\n') {
                        self.offset = self.offset.saturating_add(1);
                    }
                }
                b'(' => {
                    depth = depth.saturating_add(1);
                    Self::check_depth(depth)?;
                }
                b')' => {
                    depth = depth.checked_sub(1).ok_or(PdfError::MalformedValue)?;
                    if depth == 0 {
                        return Ok(());
                    }
                }
                _ => {}
            }
        }
        Err(PdfError::MalformedValue)
    }

    /// The rest of a hexadecimal string after its `<`.
    pub(crate) fn hex_string_remainder(&mut self) -> Result<(), PdfError> {
        while let Some(byte) = self.bytes.get(self.offset).copied() {
            self.offset = self.offset.saturating_add(1);
            if byte == b'>' {
                return Ok(());
            }
        }
        Err(PdfError::MalformedValue)
    }

    /// A name decoded according to PDF's `#xx` byte escapes.
    pub(crate) fn name(&mut self) -> Result<Vec<u8>, PdfError> {
        if !self.consume(NAME_OPEN) {
            return Err(PdfError::MalformedValue);
        }
        let mut decoded = Vec::new();
        while let Some(byte) = self.bytes.get(self.offset).copied() {
            if Self::is_whitespace(byte) || Self::is_delimiter(byte) {
                break;
            }
            if byte == NAME_ESCAPE {
                let high = self
                    .bytes
                    .get(self.offset.saturating_add(1))
                    .and_then(|byte| Self::hex_digit(*byte));
                let low = self
                    .bytes
                    .get(self.offset.saturating_add(NAME_ESCAPE_LEN - 1))
                    .and_then(|byte| Self::hex_digit(*byte));
                let (Some(high), Some(low)) = (high, low) else {
                    return Err(PdfError::MalformedValue);
                };
                decoded.push(high.saturating_mul(HEX_RADIX).saturating_add(low));
                self.offset = self.offset.saturating_add(NAME_ESCAPE_LEN);
            } else {
                decoded.push(byte);
                self.offset = self.offset.saturating_add(1);
            }
        }
        Ok(decoded)
    }

    /// One non-delimiter token.
    pub(crate) fn atom(&mut self) -> Result<core::ops::Range<usize>, PdfError> {
        let start = self.offset;
        while self
            .bytes
            .get(self.offset)
            .is_some_and(|byte| !Self::is_whitespace(*byte) && !Self::is_delimiter(*byte))
        {
            self.offset = self.offset.saturating_add(1);
        }
        if start == self.offset {
            return Err(PdfError::MalformedValue);
        }
        Ok(start..self.offset)
    }

    /// Extend an atom value across `N G R` when that complete shape follows.
    pub(crate) fn consume_reference_tail(&mut self, first: core::ops::Range<usize>) {
        if self.bytes.get(first).and_then(parse_u32).is_none() {
            return;
        }
        let after_first = self.offset;
        let Some(_generation) = self.unsigned_u16() else {
            self.offset = after_first;
            return;
        };
        self.skip_trivia();
        if !self.consume_keyword(REFERENCE_KEYWORD) {
            self.offset = after_first;
        }
    }

    /// A complete indirect reference at the current position.
    pub(crate) fn reference(&mut self) -> Option<PdfObjectReference> {
        let start = self.offset;
        let number = self.unsigned_u32()?;
        let Some(generation) = self.unsigned_u16() else {
            self.offset = start;
            return None;
        };
        self.skip_trivia();
        if !self.consume_keyword(REFERENCE_KEYWORD) {
            self.offset = start;
            return None;
        }
        Some(PdfObjectReference { number, generation })
    }

    /// A non-negative integer that fits `u32`.
    pub(crate) fn unsigned_u32(&mut self) -> Option<u32> {
        self.unsigned_digits().and_then(parse_u32)
    }

    /// A non-negative integer that fits `u16`.
    pub(crate) fn unsigned_u16(&mut self) -> Option<u16> {
        self.unsigned_digits().and_then(parse_u16)
    }

    /// A run of decimal digits that forms a whole token.
    pub(crate) fn unsigned_digits(&mut self) -> Option<&'a [u8]> {
        self.skip_trivia();
        let start = self.offset;
        while self.bytes.get(self.offset).is_some_and(u8::is_ascii_digit) {
            self.offset = self.offset.saturating_add(1);
        }
        if start == self.offset
            || self
                .bytes
                .get(self.offset)
                .is_some_and(|byte| !Self::is_whitespace(*byte) && !Self::is_delimiter(*byte))
        {
            self.offset = start;
            return None;
        }
        self.bytes.get(start..self.offset)
    }

    /// Consume `keyword` when it stands as a whole token.
    pub(crate) fn consume_keyword(&mut self, keyword: &[u8]) -> bool {
        if !self.starts_with(keyword) {
            return false;
        }
        let after = self.offset.saturating_add(keyword.len());
        if self
            .bytes
            .get(after)
            .is_some_and(|byte| !Self::is_whitespace(*byte) && !Self::is_delimiter(*byte))
        {
            return false;
        }
        self.offset = after;
        true
    }

    /// Require that only trivia remains.
    pub(crate) fn require_end(&mut self) -> Result<(), PdfError> {
        self.skip_trivia();
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(PdfError::MalformedValue)
        }
    }

    /// Skip white space and comments.
    pub(crate) fn skip_trivia(&mut self) {
        loop {
            while self
                .bytes
                .get(self.offset)
                .is_some_and(|byte| Self::is_whitespace(*byte))
            {
                self.offset = self.offset.saturating_add(1);
            }
            if self.bytes.get(self.offset) != Some(&b'%') {
                return;
            }
            while self
                .bytes
                .get(self.offset)
                .is_some_and(|byte| *byte != b'\r' && *byte != b'\n')
            {
                self.offset = self.offset.saturating_add(1);
            }
        }
    }

    /// Consume `token` when the unread bytes start with it.
    pub(crate) fn consume(&mut self, token: &[u8]) -> bool {
        if !self.starts_with(token) {
            return false;
        }
        self.offset = self.offset.saturating_add(token.len());
        true
    }

    /// Whether the unread bytes start with `token`.
    pub(crate) fn starts_with(&self, token: &[u8]) -> bool {
        self.bytes
            .get(self.offset..)
            .is_some_and(|rest| rest.starts_with(token))
    }

    /// The six white-space characters of ISO 32000-1 sec.7.2.2,
    /// Table 1: NUL, HT, LF, FF, CR and SP.
    pub(crate) const fn is_whitespace(byte: u8) -> bool {
        matches!(byte, NUL | b'\t' | b'\n' | FORM_FEED | b'\r' | b' ')
    }

    /// The delimiter characters of ISO 32000-1 sec.7.2.2, Table 2.
    pub(crate) const fn is_delimiter(byte: u8) -> bool {
        matches!(
            byte,
            b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
        )
    }

    /// The value of one hexadecimal digit.
    pub(crate) const fn hex_digit(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + HEX_LETTER_VALUE),
            b'A'..=b'F' => Some(byte - b'A' + HEX_LETTER_VALUE),
            _ => None,
        }
    }

    /// Refuse nesting past [`MAX_PDF_VALUE_DEPTH`].
    pub(crate) const fn check_depth(depth: usize) -> Result<(), PdfError> {
        if depth <= MAX_PDF_VALUE_DEPTH {
            Ok(())
        } else {
            Err(PdfError::NestingTooDeep)
        }
    }
}

/// Parse a value as exactly one indirect reference.
///
/// `Ok(None)` when the value is not a reference.
///
/// # Errors
/// [`PdfError::MalformedValue`] when a reference is followed by more.
pub(crate) fn complete_object_reference(
    value: &[u8],
) -> Result<Option<PdfObjectReference>, PdfError> {
    let mut parser = PdfValueParser::new(value);
    parser.skip_trivia();
    let reference = parser.reference();
    if reference.is_some() {
        parser.require_end()?;
    }
    Ok(reference)
}

/// Parse an array containing only indirect references.
///
/// # Errors
/// [`PdfError::MalformedValue`] for any other shape.
pub(crate) fn complete_reference_array(value: &[u8]) -> Result<Vec<PdfObjectReference>, PdfError> {
    let mut parser = PdfValueParser::new(value);
    parser.skip_trivia();
    if !parser.consume(ARRAY_OPEN) {
        return Err(PdfError::MalformedValue);
    }
    let mut references = Vec::new();
    loop {
        parser.skip_trivia();
        if parser.consume(ARRAY_CLOSE) {
            parser.require_end()?;
            return Ok(references);
        }
        let Some(reference) = parser.reference() else {
            return Err(PdfError::MalformedValue);
        };
        references.push(reference);
    }
}

/// Resolve a direct or indirect array of indirect references, as a
/// `/DSS` category, `/Fields` or `/Kids` carries.
///
/// # Errors
/// [`PdfError::MalformedValue`] for another shape,
/// [`PdfError::MissingObject`] when an indirect array is not in the
/// file.
pub(crate) fn validation_references(
    index: &PdfIndex<'_>,
    value: &[u8],
) -> Result<Vec<PdfObjectReference>, PdfError> {
    let mut parser = PdfValueParser::new(value);
    parser.skip_trivia();
    if parser.starts_with(ARRAY_OPEN) {
        return complete_reference_array(value);
    }
    let reference = complete_object_reference(value)?.ok_or(PdfError::MalformedValue)?;
    let array = index
        .object_body_reference(reference)
        .ok_or(PdfError::MissingObject(reference.number))?;
    complete_reference_array(&array)
}

/// Where the tokenizer is while walking an object body.
pub(crate) enum Scan {
    /// Between tokens.
    Regular,
    /// Inside a comment.
    Comment,
    /// Inside a hexadecimal string.
    HexString,
    /// Inside a literal string, `depth` parentheses deep.
    LiteralString {
        /// Open parentheses.
        depth: u32,
        /// Whether the previous byte was a backslash.
        escaped: bool,
    },
}

/// The offset recorded by the file's last `startxref`.
///
/// # Errors
/// [`PdfError::MissingStartXref`] without a keyword followed by an
/// offset.
pub(crate) fn find_start_xref(pdf: &[u8]) -> Result<usize, PdfError> {
    let at = find_last(pdf, STARTXREF_KEYWORD).ok_or(PdfError::MissingStartXref)?;
    let mut parser = PdfValueParser::new(pdf);
    parser.offset = at.saturating_add(STARTXREF_KEYWORD.len());
    parser
        .unsigned_digits()
        .and_then(parse_usize)
        .ok_or(PdfError::MissingStartXref)
}

/// Where one live object's bytes sit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum XrefLocation {
    /// Free, or a stream entry type this reader does not know: the
    /// number is claimed so older sections' copies stay shadowed, and
    /// a reference to it resolves to nothing.
    Free,
    /// At a byte offset in the file, written as `N G obj`.
    Direct {
        /// The offset of the object header.
        offset: usize,
    },
    /// Inside an object stream (ISO 32000-1 sec.7.5.7).
    Compressed {
        /// The object stream's own number.
        container: u32,
        /// The object's position among the stream's contents.
        position: u32,
    },
}

/// One object entry resolved from the xref chain.
#[derive(Debug, Clone, Copy)]
pub(crate) struct XrefEntry {
    /// The object number.
    pub(crate) number: u32,
    /// The generation the entry names.
    pub(crate) generation: u16,
    /// Where the object is.
    pub(crate) location: XrefLocation,
}

/// The xref view of the current PDF revision, whichever shape its
/// sections take.
pub(crate) struct PdfIndex<'a> {
    /// The whole file.
    pdf: &'a [u8],
    /// The newest section's trailer dictionary.
    trailer: Vec<u8>,
    /// The offset the last `startxref` names.
    start_xref: usize,
    /// Whether the newest section is a cross-reference stream, which
    /// decides the shape of the section an update appends.
    newest_is_stream: bool,
    /// The newest entry for each object number.
    objects: HashMap<u32, XrefEntry>,
}

impl<'a> PdfIndex<'a> {
    /// Most cross-reference sections followed through `/Prev`; a
    /// longer chain is refused rather than read in part.
    pub(crate) const MAX_XREF_SECTIONS: usize = 64;

    /// Index `pdf` from its last `startxref` through every `/Prev`.
    ///
    /// # Errors
    /// [`PdfError::MissingStartXref`] without a usable `startxref`,
    /// [`PdfError::MissingTrailer`] when a section, a trailer or a
    /// `/Prev` link does not read or the chain loops,
    /// [`PdfError::TooManyRevisions`] past
    /// [`Self::MAX_XREF_SECTIONS`], and
    /// [`PdfError::UnsupportedCrossReferenceStream`] for a stream
    /// encoding `xref_stream` does not decode.
    pub(crate) fn parse(pdf: &'a [u8]) -> Result<Self, PdfError> {
        let start_xref = find_start_xref(pdf)?;
        let mut next = Some(start_xref);
        let mut visited = HashSet::new();
        let mut newest: Option<(Vec<u8>, bool)> = None;
        let mut objects: HashMap<u32, XrefEntry> = HashMap::new();

        while let Some(offset) = next {
            if visited.len() == Self::MAX_XREF_SECTIONS {
                return Err(PdfError::TooManyRevisions);
            }
            if !visited.insert(offset) {
                return Err(PdfError::MissingTrailer);
            }
            let section = parse_xref_section(pdf, offset)?;
            next = trailer_offset(&section.trailer, KEY_PREV)?;
            for entry in section.entries {
                // Newer sections win. A newer free entry is kept too:
                // it deletes the object and must suppress older copies.
                objects.entry(entry.number).or_insert(entry);
            }
            if newest.is_none() {
                newest = Some((section.trailer, section.is_stream));
            }
        }

        let (trailer, newest_is_stream) = newest.ok_or(PdfError::MissingTrailer)?;
        Ok(Self {
            pdf,
            trailer,
            start_xref,
            newest_is_stream,
            objects,
        })
    }

    /// An index over `objects` with an empty trailer, for tests that
    /// read fragments without a cross-reference chain.
    #[cfg(test)]
    pub(crate) const fn from_entries(pdf: &'a [u8], objects: HashMap<u32, XrefEntry>) -> Self {
        Self {
            pdf,
            trailer: Vec::new(),
            start_xref: 0,
            newest_is_stream: false,
            objects,
        }
    }

    /// The newest section's trailer dictionary.
    pub(crate) fn trailer(&self) -> &[u8] {
        &self.trailer
    }

    /// The offset the last `startxref` names.
    pub(crate) const fn start_xref(&self) -> usize {
        self.start_xref
    }

    /// Whether an update must close with a cross-reference stream.
    pub(crate) const fn newest_is_stream(&self) -> bool {
        self.newest_is_stream
    }

    /// The body of object `number` at generation zero.
    pub(crate) fn object_body(&self, number: u32) -> Option<Vec<u8>> {
        self.object_body_reference(PdfObjectReference {
            number,
            generation: 0,
        })
    }

    /// The body of the object `reference` names, between `obj` and
    /// `endobj`, or its slice of the object stream holding it.
    pub(crate) fn object_body_reference(&self, reference: PdfObjectReference) -> Option<Vec<u8>> {
        let entry = self.live_entry(reference)?;
        match entry.location {
            XrefLocation::Free => None,
            XrefLocation::Direct { offset } => {
                object_body_at(self.pdf, reference.number, reference.generation, offset)
            }
            XrefLocation::Compressed {
                container,
                position,
            } => {
                let offset = self.container_offset(container)?;
                xref_stream::compressed_body(self.pdf, offset, reference.number, position)
            }
        }
    }

    /// The dictionary of every live object that is one, or that opens
    /// a stream with one, in object-number order, each with the file
    /// offset of its `<<` when the object is not inside an object
    /// stream.
    ///
    /// Each object stream is decoded once however many objects it
    /// holds. A live object that is some other value, such as a number
    /// or an array, is left out.
    ///
    /// # Errors
    /// [`PdfError::MissingObject`] when a live entry does not lead to
    /// an object with its number and generation, or a dictionary there
    /// does not close: an unreadable object is never skipped, so a
    /// malformed signature dictionary cannot hide.
    pub(crate) fn object_dictionaries(&self) -> Result<Vec<ObjectDictionary>, PdfError> {
        let mut live: Vec<&XrefEntry> = self
            .objects
            .values()
            .filter(|entry| entry.location != XrefLocation::Free)
            .collect();
        live.sort_unstable_by_key(|entry| (entry.number, entry.generation));
        let mut containers: HashMap<u32, Option<xref_stream::ObjectStream>> = HashMap::new();
        let mut dictionaries = Vec::new();
        for entry in live {
            let reference = PdfObjectReference {
                number: entry.number,
                generation: entry.generation,
            };
            let unreadable = PdfError::MissingObject(reference.number);
            let dictionary = match entry.location {
                XrefLocation::Free => None,
                XrefLocation::Direct { offset } => {
                    object_dictionary_at(self.pdf, reference, offset)
                        .ok_or(unreadable)?
                        .map(|(start, bytes)| (Some(start), bytes))
                }
                XrefLocation::Compressed {
                    container,
                    position,
                } => {
                    let body = containers
                        .entry(container)
                        .or_insert_with(|| {
                            let offset = self.container_offset(container)?;
                            xref_stream::ObjectStream::at(self.pdf, offset)
                        })
                        .as_ref()
                        .and_then(|stream| stream.body(reference.number, position))
                        .ok_or(unreadable)?;
                    leading_dictionary(&body, 0)
                        .ok_or(unreadable)?
                        .map(|(_start, bytes)| (None, bytes))
                }
            };
            if let Some((file_offset, bytes)) = dictionary {
                dictionaries.push(ObjectDictionary { file_offset, bytes });
            }
        }
        Ok(dictionaries)
    }

    /// The decoded payload of the stream object `reference` names.
    ///
    /// A stream is always a direct object (ISO 32000-1 sec.7.3.8.1,
    /// sec.7.5.7), so an entry inside an object stream, a free entry
    /// or a missing one is `None`.
    ///
    /// # Errors
    /// [`PdfError`] when the object is not a stream or its filter is
    /// not one `xref_stream` decodes.
    pub(crate) fn stream_payload(
        &self,
        reference: PdfObjectReference,
    ) -> Result<Option<Vec<u8>>, PdfError> {
        let Some(entry) = self.live_entry(reference) else {
            return Ok(None);
        };
        let XrefLocation::Direct { offset } = entry.location else {
            return Ok(None);
        };
        xref_stream::stream_payload(self.pdf, offset, reference).map(Some)
    }

    /// The entry naming exactly `reference`, number and generation.
    fn live_entry(&self, reference: PdfObjectReference) -> Option<&XrefEntry> {
        self.objects
            .get(&reference.number)
            .filter(|entry| entry.generation == reference.generation)
    }

    /// The file offset of the object stream `container`, which is
    /// always a direct object.
    fn container_offset(&self, container: u32) -> Option<usize> {
        match self.objects.get(&container)?.location {
            XrefLocation::Direct { offset } => Some(offset),
            XrefLocation::Free | XrefLocation::Compressed { .. } => None,
        }
    }
}

/// One live object's dictionary, as [`PdfIndex::object_dictionaries`]
/// lists it.
pub(crate) struct ObjectDictionary {
    /// Offset of its `<<` in the file; `None` inside an object stream,
    /// where the bytes are not the file's.
    pub(crate) file_offset: Option<usize>,
    /// The dictionary, from `<<` to `>>`.
    pub(crate) bytes: Vec<u8>,
}

/// One cross-reference section and its trailer.
pub(crate) struct XrefSection {
    /// The trailer dictionary, or the stream dictionary that doubles
    /// as one.
    pub(crate) trailer: Vec<u8>,
    /// The section's entries, the authoritative copy first.
    pub(crate) entries: Vec<XrefEntry>,
    /// Whether the section is a cross-reference stream.
    pub(crate) is_stream: bool,
}

/// The byte offset a trailer stores under `name`, `None` when absent.
///
/// The trailer must parse, and a present value must be one
/// non-negative integer: a chain link that cannot be read is an error,
/// never the end of the chain.
fn trailer_offset(trailer: &[u8], name: &[u8]) -> Result<Option<usize>, PdfError> {
    let parsed = PdfDictionary::parse(trailer).map_err(|_ignored| PdfError::MissingTrailer)?;
    let Some(entry) = parsed
        .entry(name)
        .map_err(|_ignored| PdfError::MissingTrailer)?
    else {
        return Ok(None);
    };
    let value = trailer
        .get(entry.value.clone())
        .ok_or(PdfError::MissingTrailer)?;
    parse_usize(value).map(Some).ok_or(PdfError::MissingTrailer)
}

/// The cross-reference section at `offset`: a classic table, or a
/// stream when no `xref` keyword is there.
///
/// # Errors
/// [`PdfError::MissingTrailer`] for a section that does not read, a
/// flag other than `n` or `f`, or a declared count past
/// [`MAX_XREF_ENTRIES`].
pub(crate) fn parse_xref_section(pdf: &[u8], offset: usize) -> Result<XrefSection, PdfError> {
    let mut cursor = skip_pdf_whitespace(pdf, offset);
    let Some(rest) = pdf.get(cursor..) else {
        return Err(PdfError::MissingStartXref);
    };
    if !rest.starts_with(XREF_KEYWORD) {
        return xref_stream::parse_stream_section(pdf, cursor);
    }
    cursor = cursor.saturating_add(XREF_KEYWORD.len());

    let mut entries = Vec::new();
    loop {
        let token = read_pdf_token(pdf, &mut cursor).ok_or(PdfError::MissingTrailer)?;
        if token == TRAILER_KEYWORD {
            let (trailer, _after) = dictionary_at(pdf, cursor).ok_or(PdfError::MissingTrailer)?;
            if dictionary_usize(&trailer, KEY_SIZE).is_some_and(|size| size > MAX_XREF_ENTRIES) {
                return Err(PdfError::MissingTrailer);
            }
            return hybrid_merged(pdf, trailer, entries);
        }

        let start = parse_u32(token).ok_or(PdfError::MissingTrailer)?;
        let count = read_pdf_token(pdf, &mut cursor)
            .and_then(parse_u32)
            .ok_or(PdfError::MissingTrailer)?;
        let end = usize::try_from(start)
            .ok()
            .zip(usize::try_from(count).ok())
            .and_then(|(start, count)| start.checked_add(count))
            .ok_or(PdfError::MissingTrailer)?;
        // The subsections together declare no more entries than the
        // ceiling either.
        let total = usize::try_from(count)
            .ok()
            .and_then(|count| entries.len().checked_add(count))
            .ok_or(PdfError::MissingTrailer)?;
        if end > MAX_XREF_ENTRIES || total > MAX_XREF_ENTRIES {
            return Err(PdfError::MissingTrailer);
        }

        for index in 0..count {
            let object_offset = read_pdf_token(pdf, &mut cursor)
                .and_then(parse_usize)
                .ok_or(PdfError::MissingTrailer)?;
            let generation = read_pdf_token(pdf, &mut cursor)
                .and_then(parse_u16)
                .ok_or(PdfError::MissingTrailer)?;
            let flag = read_pdf_token(pdf, &mut cursor).ok_or(PdfError::MissingTrailer)?;
            let number = start.checked_add(index).ok_or(PdfError::MissingTrailer)?;
            let location = if flag == XREF_IN_USE {
                XrefLocation::Direct {
                    offset: object_offset,
                }
            } else if flag == XREF_FREE {
                XrefLocation::Free
            } else {
                return Err(PdfError::MissingTrailer);
            };
            entries.push(XrefEntry {
                number,
                generation,
                location,
            });
        }
    }
}

/// A classic table section, merged with the cross-reference stream a
/// hybrid trailer names.
///
/// A hybrid revision keeps the authoritative copy of its entries in
/// the stream its `/XRefStm` key points at; the table is the fallback
/// for readers that predate streams (ISO 32000-1 sec.7.5.8.4). The
/// stream's entries go first, so they win the newest-copy merge.
fn hybrid_merged(
    pdf: &[u8],
    trailer: Vec<u8>,
    entries: Vec<XrefEntry>,
) -> Result<XrefSection, PdfError> {
    let Some(hybrid) = trailer_offset(&trailer, KEY_XREF_STREAM)? else {
        return Ok(XrefSection {
            trailer,
            entries,
            is_stream: false,
        });
    };
    let stream = xref_stream::parse_stream_section(pdf, skip_pdf_whitespace(pdf, hybrid))?;
    let mut combined = stream.entries;
    combined.extend(entries);
    Ok(XrefSection {
        trailer,
        entries: combined,
        is_stream: false,
    })
}

/// The first offset at or after `cursor` that is not white space.
pub(crate) fn skip_pdf_whitespace(pdf: &[u8], mut cursor: usize) -> usize {
    while pdf
        .get(cursor)
        .is_some_and(|byte| PdfValueParser::is_whitespace(*byte))
    {
        cursor = cursor.saturating_add(1);
    }
    cursor
}

/// The next white-space delimited token at `cursor`, advancing it.
pub(crate) fn read_pdf_token<'a>(pdf: &'a [u8], cursor: &mut usize) -> Option<&'a [u8]> {
    *cursor = skip_pdf_whitespace(pdf, *cursor);
    let start = *cursor;
    while pdf
        .get(*cursor)
        .is_some_and(|byte| !PdfValueParser::is_whitespace(*byte))
    {
        *cursor = (*cursor).saturating_add(1);
    }
    (start < *cursor).then(|| &pdf[start..*cursor])
}

/// A whole token of decimal digits.
pub(crate) fn parse_usize(digits: &[u8]) -> Option<usize> {
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut out = 0_usize;
    for digit in digits {
        out = out
            .checked_mul(DECIMAL_RADIX)?
            .checked_add(usize::from(digit.saturating_sub(b'0')))?;
    }
    Some(out)
}

/// A whole token of decimal digits that fits `u32`.
pub(crate) fn parse_u32(digits: &[u8]) -> Option<u32> {
    parse_usize(digits).and_then(|value| u32::try_from(value).ok())
}

/// A whole token of decimal digits that fits `u16`.
pub(crate) fn parse_u16(digits: &[u8]) -> Option<u16> {
    parse_usize(digits).and_then(|value| u16::try_from(value).ok())
}

/// The dictionary opening at `cursor`, and the offset just past it.
///
/// Strings and comments are skipped so a `>>` inside them does not
/// close the dictionary.
pub(crate) fn dictionary_at(pdf: &[u8], cursor: usize) -> Option<(Vec<u8>, usize)> {
    let start = skip_pdf_whitespace(pdf, cursor);
    if !pdf.get(start..)?.starts_with(DICTIONARY_OPEN) {
        return None;
    }

    let mut cursor = start;
    let mut depth = 0_u32;
    let mut state = Scan::Regular;
    while let Some(&byte) = pdf.get(cursor) {
        match state {
            Scan::Regular => match byte {
                b'%' => {
                    state = Scan::Comment;
                    cursor = cursor.saturating_add(1);
                }
                b'(' => {
                    state = Scan::LiteralString {
                        depth: 1,
                        escaped: false,
                    };
                    cursor = cursor.saturating_add(1);
                }
                b'<' if pdf.get(cursor.saturating_add(1)) == Some(&b'<') => {
                    depth = depth.saturating_add(1);
                    cursor = cursor.saturating_add(DICTIONARY_OPEN.len());
                }
                b'<' => {
                    state = Scan::HexString;
                    cursor = cursor.saturating_add(1);
                }
                b'>' if pdf.get(cursor.saturating_add(1)) == Some(&b'>') => {
                    depth = depth.checked_sub(1)?;
                    cursor = cursor.saturating_add(DICTIONARY_CLOSE.len());
                    if depth == 0 {
                        return Some((pdf[start..cursor].to_vec(), cursor));
                    }
                }
                _ => cursor = cursor.saturating_add(1),
            },
            Scan::Comment => {
                cursor = cursor.saturating_add(1);
                if byte == b'\r' || byte == b'\n' {
                    state = Scan::Regular;
                }
            }
            Scan::HexString => {
                cursor = cursor.saturating_add(1);
                if byte == b'>' {
                    state = Scan::Regular;
                }
            }
            Scan::LiteralString {
                mut depth,
                mut escaped,
            } => {
                cursor = cursor.saturating_add(1);
                if escaped {
                    escaped = false;
                    state = Scan::LiteralString { depth, escaped };
                    continue;
                }
                match byte {
                    b'\\' => {
                        escaped = true;
                        state = Scan::LiteralString { depth, escaped };
                    }
                    b'(' => {
                        depth = depth.saturating_add(1);
                        state = Scan::LiteralString { depth, escaped };
                    }
                    b')' => {
                        depth = depth.checked_sub(1)?;
                        if depth == 0 {
                            state = Scan::Regular;
                        } else {
                            state = Scan::LiteralString { depth, escaped };
                        }
                    }
                    _ => state = Scan::LiteralString { depth, escaped },
                }
            }
        }
    }
    None
}

/// The value bytes stored under `key` (written with or without its
/// slash) in the dictionary opening `dictionary`, found through the
/// value grammar so a longer name or a string never matches.
pub(crate) fn dictionary_value<'d>(dictionary: &'d [u8], key: &[u8]) -> Option<&'d [u8]> {
    let name = key.strip_prefix(NAME_OPEN).unwrap_or(key);
    let parsed = PdfDictionary::parse_leading(dictionary).ok()?;
    let entry = parsed.entry(name).ok()??;
    dictionary.get(entry.value.clone())
}

/// The indirect reference stored under `key`, generation included.
pub(crate) fn dictionary_reference(dictionary: &[u8], key: &[u8]) -> Option<PdfObjectReference> {
    complete_object_reference(dictionary_value(dictionary, key)?)
        .ok()
        .flatten()
}

/// The integer stored directly under `key`, when it fits `u32`.
pub(crate) fn dictionary_integer(dictionary: &[u8], key: &[u8]) -> Option<u32> {
    dictionary_usize(dictionary, key).and_then(|value| u32::try_from(value).ok())
}

/// The non-negative integer stored directly under `key`; `None` when
/// absent, indirect or not an integer.
pub(crate) fn dictionary_usize(dictionary: &[u8], key: &[u8]) -> Option<usize> {
    let value = dictionary_value(dictionary, key)?;
    let mut parser = PdfValueParser::new(value);
    let digits = parser.unsigned_digits()?;
    parser.require_end().ok()?;
    parse_usize(digits)
}

/// The body of object `number` `generation` at `offset`: the bytes
/// between its `obj` and `endobj` keywords.
pub(crate) fn object_body_at(
    pdf: &[u8],
    number: u32,
    generation: u16,
    offset: usize,
) -> Option<Vec<u8>> {
    let cursor = object_header_end(pdf, PdfObjectReference { number, generation }, offset)?;
    let end = find_first(pdf.get(cursor..)?, ENDOBJ_KEYWORD)?;
    pdf.get(cursor..cursor.saturating_add(end))
        .map(<[u8]>::to_vec)
}

/// The offset just past `N G obj` at `offset`, when that header names
/// `reference`. The keyword may be followed directly by a delimiter,
/// as in `1 0 obj<<`.
pub(crate) fn object_header_end(
    pdf: &[u8],
    reference: PdfObjectReference,
    offset: usize,
) -> Option<usize> {
    let mut parser = PdfValueParser::new(pdf);
    parser.offset = offset;
    let number = parser.unsigned_u32()?;
    let generation = parser.unsigned_u16()?;
    parser.skip_trivia();
    (number == reference.number
        && generation == reference.generation
        && parser.consume_keyword(OBJ_KEYWORD))
    .then_some(parser.offset)
}

/// The dictionary opening the object `reference` at `offset`, without
/// reading any stream data after it.
///
/// `None` when the header is not `reference`'s or a dictionary there
/// does not close; `Some(None)` when the object is another value.
fn object_dictionary_at(
    pdf: &[u8],
    reference: PdfObjectReference,
    offset: usize,
) -> Option<Option<(usize, Vec<u8>)>> {
    let cursor = object_header_end(pdf, reference, offset)?;
    leading_dictionary(pdf, cursor)
}

/// The dictionary at `cursor`, with the offset of its `<<`, when the
/// value there opens with `<<`.
///
/// `None` when it opens one that does not close; `Some(None)` when the
/// value is not a dictionary.
fn leading_dictionary(bytes: &[u8], cursor: usize) -> Option<Option<(usize, Vec<u8>)>> {
    let start = skip_pdf_whitespace(bytes, cursor);
    if !bytes.get(start..)?.starts_with(DICTIONARY_OPEN) {
        return Some(None);
    }
    dictionary_at(bytes, start).map(|(dictionary, _end)| Some((start, dictionary)))
}

/// First occurrence of `needle`.
pub(crate) fn find_first(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Last occurrence of `needle`.
pub(crate) fn find_last(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .rposition(|window| window == needle)
}
