// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! The signatures, document timestamps and validation store of a PDF.
//!
//! [`PdfDocument::parse`] follows the cross-reference chain from the
//! last `startxref` through every `/Prev` section, classic tables,
//! cross-reference streams and hybrid files alike, with the same index
//! the `PAdES` writer in [`crate::pades`] extends documents with. Every
//! live object carrying both `/ByteRange` and `/Contents` is a
//! signature dictionary; its declared byte range is checked against
//! the file before the `CMS` in the hole is handed out. Nothing here
//! verifies a signature: the caller digests the spans with
//! [`PdfDocument::digest`] and judges the `CMS` itself.
//!
//! # Conformance
//!
//! - ISO 32000-1 sec.12.8.1: the signature dictionary, `/ByteRange`
//!   (two spans of the file around the `/Contents` hex string) and
//!   `/Contents` (a DER-encoded `CMS` object, zero padded to the
//!   reserved size).
//! - ISO 32000-1 sec.7.9.4: the `/M` date string.
//! - ISO 32000-1 sec.7.6.1: an encrypted document names `/Encrypt` in
//!   its trailer; it is refused, since its strings and streams would
//!   need the document key to read.
//! - `ETSI EN 319 142-1` V1.2.1 clause 5.4.2: the `/DSS` dictionary in
//!   the catalog, with `/Certs`, `/OCSPs` and `/CRLs` arrays of
//!   indirect references to streams holding DER. `/VRI` is not read:
//!   clause 6.3 requirement v puts everything a `VRI` entry names in
//!   those arrays too.
//! - `ETSI EN 319 142-1` V1.2.1 clause 5.4.3: the document timestamp
//!   dictionary, `/Type /DocTimeStamp` with `/SubFilter /ETSI.RFC3161`.
//! - `ETSI EN 319 142-2` V1.2.1 clause 4.2.3 and 5.3: the signature
//!   subfilters `adbe.pkcs7.detached` and `ETSI.CAdES.detached`.
//!
//! - ISO 32000-1 sec.12.8.2.2 and sec.12.8.2.4: what the revisions
//!   after a signed one change is judged by [`super::revision`].
//!
//! Only the newest revision's catalog is read for the `/DSS`: an
//! incremental update that extends the store rewrites it with the
//! earlier entries carried forward.

use crate::ber::{BerTlv, Sequence};
use crate::cades::DigestAlgorithm;
use crate::pades::PdfError;
use crate::pades::index::{
    ARRAY_CLOSE, ARRAY_OPEN, ObjectDictionary, PdfDictionary, PdfIndex, PdfValueParser,
    complete_object_reference, dictionary_at, parse_usize, validation_references,
};
use crate::validation::ValidationMaterial;
use crate::verification::revision::{Revision, later_revisions};
use refineid_cms::x509::DateTime;

/// The header every PDF file starts with (ISO 32000-1 sec.7.5.2).
const PDF_HEADER: &[u8] = b"%PDF-";

/// Signature dictionary key naming the signed spans
/// (ISO 32000-1 sec.12.8.1, Table 252).
const KEY_BYTE_RANGE: &[u8] = b"ByteRange";

/// Signature dictionary key holding the signature value.
const KEY_CONTENTS: &[u8] = b"Contents";

/// Dictionary key naming the dictionary's type.
const KEY_TYPE: &[u8] = b"Type";

/// Signature dictionary key naming the encoding of `/Contents`.
const KEY_SUBFILTER: &[u8] = b"SubFilter";

/// Signature dictionary key holding the claimed signing time.
const KEY_SIGNING_TIME: &[u8] = b"M";

/// Trailer key referencing the catalog (ISO 32000-1 sec.7.5.5).
const KEY_ROOT: &[u8] = b"Root";

/// Catalog key of the document security store
/// (`ETSI EN 319 142-1` V1.2.1 clause 5.4.2.2).
const KEY_DSS: &[u8] = b"DSS";

/// `/DSS` key listing certificate streams.
const KEY_CERTS: &[u8] = b"Certs";

/// `/DSS` key listing `OCSPResponse` streams.
const KEY_OCSPS: &[u8] = b"OCSPs";

/// `/DSS` key listing `CertificateList` streams.
const KEY_CRLS: &[u8] = b"CRLs";

/// `/Type` of a signature dictionary (ISO 32000-1 sec.12.8.1).
const TYPE_SIGNATURE: &[u8] = b"Sig";

/// `/Type` of a document timestamp dictionary
/// (`ETSI EN 319 142-1` V1.2.1 clause 5.4.3).
const TYPE_DOCUMENT_TIMESTAMP: &[u8] = b"DocTimeStamp";

/// `/SubFilter` of a `PAdES` signature
/// (`ETSI EN 319 142-2` V1.2.1 clause 5.3).
const SUBFILTER_ETSI_CADES_DETACHED: &[u8] = b"ETSI.CAdES.detached";

/// `/SubFilter` of a PKCS#7 detached signature
/// (`ETSI EN 319 142-2` V1.2.1 clause 4.2.3).
const SUBFILTER_ADBE_PKCS7_DETACHED: &[u8] = b"adbe.pkcs7.detached";

/// `/SubFilter` of a document timestamp
/// (`ETSI EN 319 142-1` V1.2.1 clause 5.4.3).
const SUBFILTER_ETSI_RFC3161: &[u8] = b"ETSI.RFC3161";

/// The marker closing every revision (ISO 32000-1 sec.7.5.5).
const END_OF_FILE_MARKER: &[u8] = b"%%EOF";

/// The end-of-line sequences of ISO 32000-1 sec.7.2.3.
const END_OF_LINE_CRLF: &[u8] = b"\r\n";

/// A lone LINE FEED end-of-line.
const END_OF_LINE_LF: &[u8] = b"\n";

/// A lone CARRIAGE RETURN end-of-line.
const END_OF_LINE_CR: &[u8] = b"\r";

/// Spans a `/ByteRange` names: one either side of the hole.
const BYTE_RANGE_SPANS: usize = 2;

/// Integers in a `/ByteRange`: a start and a length per span.
const BYTE_RANGE_ENTRIES: usize = 4;

/// Opening delimiter of a hex string (ISO 32000-1 sec.7.3.4.3).
const HEX_STRING_OPEN: u8 = b'<';

/// Closing delimiter of a hex string.
const HEX_STRING_CLOSE: u8 = b'>';

/// Opening delimiter of a literal string (ISO 32000-1 sec.7.3.4.2).
const LITERAL_STRING_OPEN: u8 = b'(';

/// Closing delimiter of a literal string.
const LITERAL_STRING_CLOSE: u8 = b')';

/// Escape character inside a literal string.
const LITERAL_STRING_ESCAPE: u8 = b'\\';

/// Bits carried by one hex digit.
const HEX_DIGIT_BITS: u32 = 4;

/// Hex digits per decoded byte.
const HEX_DIGITS_PER_BYTE: usize = 2;

/// The byte `/Contents` is padded with after the DER element
/// (ISO 32000-1 sec.12.8.1, Table 252, `Contents`).
const CONTENTS_PADDING: u8 = 0;

/// Why a PDF yielded no signature list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdfReadError {
    /// The file does not start with the `%PDF-` header.
    NotAPdf,
    /// The structure named does not parse, or contradicts the file.
    Malformed(&'static str),
    /// The document uses a feature this reader does not implement, or
    /// exceeds one of its bounds, named so the refusal says what it
    /// was.
    Unsupported(&'static str),
}

impl core::fmt::Display for PdfReadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotAPdf => f.write_str("not a PDF: no %PDF- header"),
            Self::Malformed(what) => write!(f, "malformed PDF: {what}"),
            Self::Unsupported(what) => write!(f, "unsupported PDF: {what}"),
        }
    }
}

impl core::error::Error for PdfReadError {}

impl PdfReadError {
    /// The reader's view of an index failure, `what` naming the
    /// structure that was being read.
    const fn from_index(error: PdfError, what: &'static str) -> Self {
        match error {
            PdfError::NotAPdf => Self::NotAPdf,
            PdfError::UnsupportedCrossReferenceStream => {
                Self::Unsupported("stream filter or predictor")
            }
            PdfError::UnsupportedEncryption => Self::Unsupported("encrypted document"),
            PdfError::NestingTooDeep => Self::Unsupported("value nesting depth"),
            PdfError::TooManyRevisions => Self::Unsupported("cross-reference chain length"),
            PdfError::MissingStartXref
            | PdfError::MissingTrailer
            | PdfError::MissingCatalogReference
            | PdfError::MissingObject(_)
            | PdfError::MissingPageTree
            | PdfError::UnreadableForm
            | PdfError::UnreadableValidationStore
            | PdfError::MalformedValue
            | PdfError::Corrupt
            | PdfError::SignatureTooLarge { .. } => Self::Malformed(what),
        }
    }
}

/// The encoding a signature dictionary declares for `/Contents`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubFilter {
    /// `ETSI.CAdES.detached`: a `PAdES` `CAdES` signature.
    EtsiCadesDetached,
    /// `adbe.pkcs7.detached`: a PKCS#7 detached signature.
    AdbePkcs7Detached,
    /// `ETSI.RFC3161`: an RFC 3161 timestamp token.
    EtsiRfc3161,
    /// Absent, or a subfilter `ETSI EN 319 142-2` does not name.
    Other,
}

impl SubFilter {
    /// The subfilter a decoded `/SubFilter` name declares.
    fn from_name(name: &[u8]) -> Self {
        if name == SUBFILTER_ETSI_CADES_DETACHED {
            Self::EtsiCadesDetached
        } else if name == SUBFILTER_ADBE_PKCS7_DETACHED {
            Self::AdbePkcs7Detached
        } else if name == SUBFILTER_ETSI_RFC3161 {
            Self::EtsiRfc3161
        } else {
            Self::Other
        }
    }
}

/// What a signature dictionary is, from its `/Type` and `/SubFilter`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureKind {
    /// `/Type /Sig`, or no `/Type`: a signature in the declared
    /// encoding.
    Signature(SubFilter),
    /// `/Type /DocTimeStamp` with `/SubFilter /ETSI.RFC3161`.
    DocumentTimestamp,
}

/// The two signed spans of one signature, checked against the file.
///
/// The first span starts at offset zero and ends where the hole opens;
/// the second starts where the hole closes. The hole is the
/// `/Contents` hex string of the dictionary that declares the range,
/// with its delimiters (ISO 32000-1 sec.12.8.1), and is never empty;
/// both spans lie within the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    /// Offset of the hole's opening `<`, which is the first span's
    /// length.
    hole_start: usize,
    /// Offset one past the hole's closing `>`, where the second span
    /// starts.
    hole_end: usize,
    /// Offset one past the second span.
    end: usize,
}

impl ByteRange {
    /// Check the four declared integers against a file of
    /// `file_length` bytes.
    fn from_declaration(
        values: [usize; BYTE_RANGE_ENTRIES],
        file_length: usize,
    ) -> Result<Self, PdfReadError> {
        const MALFORMED: PdfReadError = PdfReadError::Malformed("ByteRange");
        let [first_start, first_length, second_start, second_length] = values;
        let end = second_start.checked_add(second_length).ok_or(MALFORMED)?;
        if first_start != 0 || second_start <= first_length || end > file_length {
            return Err(MALFORMED);
        }
        Ok(Self {
            hole_start: first_length,
            hole_end: second_start,
            end,
        })
    }

    /// The two signed spans, in file order.
    #[must_use]
    pub const fn spans(&self) -> [core::ops::Range<usize>; BYTE_RANGE_SPANS] {
        [0..self.hole_start, self.hole_end..self.end]
    }

    /// The hole between the spans: the `/Contents` hex string.
    #[must_use]
    pub const fn hole(&self) -> core::ops::Range<usize> {
        self.hole_start..self.hole_end
    }

    /// Offset one past the second span: the length of the revision
    /// this signature covers.
    #[must_use]
    pub const fn end(&self) -> usize {
        self.end
    }
}

/// One signature or document timestamp dictionary of the document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdfSignature {
    /// What the dictionary declares itself to be.
    kind: SignatureKind,
    /// The DER element in the `/Contents` hole, padding removed.
    cms: Vec<u8>,
    /// The signed spans.
    byte_range: ByteRange,
    /// The `/M` entry, converted to UTC.
    signing_time_entry: Option<DateTime>,
    /// What the later revisions do to the revision the range ends;
    /// `None` when the range does not end a revision.
    revision: Option<Revision>,
}

impl PdfSignature {
    /// What the dictionary declares itself to be.
    #[must_use]
    pub const fn kind(&self) -> SignatureKind {
        self.kind
    }

    /// The DER element in the `/Contents` hole, its zero padding
    /// removed: a `CMS` `ContentInfo`, or an RFC 3161
    /// `TimeStampToken`, for the caller's `CMS` parser.
    #[must_use]
    pub fn cms(&self) -> &[u8] {
        &self.cms
    }

    /// The signed spans.
    #[must_use]
    pub const fn byte_range(&self) -> ByteRange {
        self.byte_range
    }

    /// What the revisions after the one this signature covers do to
    /// the document; `None` when the range does not end a revision.
    #[must_use]
    pub const fn revision(&self) -> Option<Revision> {
        self.revision
    }

    /// The `/M` entry, converted to UTC; `None` when absent, when it
    /// does not parse as an ISO 32000-1 sec.7.9.4 date, or when it
    /// carries no offset from UT. Nothing signs it: the claimed time
    /// the signer's software wrote.
    #[must_use]
    pub const fn signing_time_entry(&self) -> Option<DateTime> {
        self.signing_time_entry
    }

    /// Whether the signed spans end where a revision ends: just after
    /// an `%%EOF` marker and its end-of-line (ISO 32000-1 sec.7.5.5),
    /// with the bytes up to there indexing as a document of their own,
    /// so the whole signed revision is covered (sec.12.8.1, `ETSI EN
    /// 319 142-1` V1.2.1 clause 5.1). A range cut elsewhere signs part
    /// of a revision and is not judged.
    #[must_use]
    pub const fn ends_revision(&self) -> bool {
        self.revision.is_some()
    }
}

/// Whether `file` starts with the header every PDF starts with.
pub(crate) fn starts_as_pdf(file: &[u8]) -> bool {
    file.starts_with(PDF_HEADER)
}

/// The signatures and validation store of one parsed PDF.
#[derive(Debug, Clone)]
pub struct PdfDocument<'a> {
    /// The file the offsets refer to.
    file: &'a [u8],
    /// Every signature dictionary, in the order its range ends.
    signatures: Vec<PdfSignature>,
    /// The newest catalog's `/DSS` contents.
    validation_store: ValidationMaterial,
}

impl<'a> PdfDocument<'a> {
    /// Index `file` and read its signature dictionaries and `/DSS`.
    ///
    /// # Errors
    /// [`PdfReadError::NotAPdf`] without the header,
    /// [`PdfReadError::Unsupported`] for an encrypted document, a
    /// stream filter the index does not decode, or a file past one of
    /// the index bounds, and [`PdfReadError::Malformed`] when the
    /// cross-reference chain, a live dictionary, a signature dictionary
    /// or the `/DSS` does not parse, or a byte range contradicts the
    /// file or its own dictionary.
    pub fn parse(file: &'a [u8]) -> Result<Self, PdfReadError> {
        if !file.starts_with(PDF_HEADER) {
            return Err(PdfReadError::NotAPdf);
        }
        let index = PdfIndex::parse(file)
            .map_err(|error| PdfReadError::from_index(error, "cross-reference chain"))?;
        let trailer = PdfDictionary::parse(index.trailer())
            .map_err(|error| PdfReadError::from_index(error, "trailer"))?;

        let mut signatures = Vec::new();
        let dictionaries = index
            .object_dictionaries()
            .map_err(|error| PdfReadError::from_index(error, "object"))?;
        for dictionary in &dictionaries {
            if let Some(signature) = signature_from_dictionary(dictionary, file, &index)? {
                signatures.push(signature);
            }
        }
        signatures.sort_by_key(|signature: &PdfSignature| {
            (signature.byte_range.end(), signature.byte_range.hole_start)
        });
        let validation_store = validation_store(&index, index.trailer(), &trailer)?;
        Ok(Self {
            file,
            signatures,
            validation_store,
        })
    }

    /// Every signature and document timestamp dictionary, in the order
    /// their byte ranges end: the revision each covers, oldest first.
    #[must_use]
    pub fn signatures(&self) -> &[PdfSignature] {
        &self.signatures
    }

    /// The certificates, `OCSP` responses and `CRL`s of the newest
    /// catalog's `/DSS`, each the decoded stream content; empty when
    /// the document has no store.
    #[must_use]
    pub const fn validation_store(&self) -> &ValidationMaterial {
        &self.validation_store
    }

    /// Both spans of `range` in this document, concatenated in order:
    /// the octets a signature with that range is computed over.
    #[must_use]
    pub fn signed_octets(&self, range: &ByteRange) -> Vec<u8> {
        let mut signed = Vec::with_capacity(range.end.saturating_sub(range.hole().len()));
        for span in range.spans() {
            signed.extend_from_slice(self.file.get(span).unwrap_or_default());
        }
        signed
    }

    /// Digest of [`Self::signed_octets`] under `algorithm`.
    #[must_use]
    pub fn digest(&self, range: &ByteRange, algorithm: DigestAlgorithm) -> Vec<u8> {
        algorithm.digest(&self.signed_octets(range))
    }
}

/// The signature `object` declares, or `None` when its dictionary
/// carries no `/ByteRange` and `/Contents` pair.
fn signature_from_dictionary(
    object: &ObjectDictionary,
    file: &[u8],
    index: &PdfIndex<'_>,
) -> Result<Option<PdfSignature>, PdfReadError> {
    let dictionary = object.bytes.as_slice();
    let parsed = PdfDictionary::parse(dictionary)
        .map_err(|error| PdfReadError::from_index(error, "dictionary"))?;
    let entry = |key: &[u8]| {
        parsed
            .entry(key)
            .map_err(|error| PdfReadError::from_index(error, "signature dictionary"))
    };
    let (Some(contents), Some(byte_range)) = (entry(KEY_CONTENTS)?, entry(KEY_BYTE_RANGE)?) else {
        return Ok(None);
    };
    let value = |key: &[u8]| -> Result<Option<&[u8]>, PdfReadError> {
        Ok(entry(key)?.and_then(|entry| dictionary.get(entry.value.clone())))
    };
    let byte_range_value = dictionary
        .get(byte_range.value.clone())
        .ok_or(PdfReadError::Malformed("ByteRange"))?;
    let byte_range = ByteRange::from_declaration(byte_range_values(byte_range_value)?, file.len())?;

    // The hole must be this dictionary's own `/Contents` value, in
    // place in the file; a dictionary inside an object stream has no
    // bytes of its own in the file and cannot name a hole.
    let contents_span = contents.value.clone();
    let contents_in_file = object.file_offset.and_then(|offset| {
        Some(offset.checked_add(contents_span.start)?..offset.checked_add(contents_span.end)?)
    });
    if contents_in_file != Some(byte_range.hole()) {
        return Err(PdfReadError::Malformed(
            "Contents outside the ByteRange hole",
        ));
    }
    let hole = file
        .get(byte_range.hole())
        .ok_or(PdfReadError::Malformed("ByteRange"))?;
    let cms = contents_element(hole)?;

    let subfilter = value(KEY_SUBFILTER)?
        .map(name_value)
        .transpose()?
        .map_or(SubFilter::Other, |name| SubFilter::from_name(&name));
    let kind = match value(KEY_TYPE)?.map(name_value).transpose()? {
        None => SignatureKind::Signature(subfilter),
        Some(name) if name == TYPE_SIGNATURE => SignatureKind::Signature(subfilter),
        Some(name) if name == TYPE_DOCUMENT_TIMESTAMP => {
            if subfilter != SubFilter::EtsiRfc3161 {
                return Err(PdfReadError::Unsupported("document timestamp subfilter"));
            }
            SignatureKind::DocumentTimestamp
        }
        Some(_) => return Err(PdfReadError::Malformed("signature dictionary type")),
    };
    let signing_time_entry = value(KEY_SIGNING_TIME)?.and_then(pdf_date);

    Ok(Some(PdfSignature {
        kind,
        cms,
        byte_range,
        signing_time_entry,
        revision: ends_revision(file, byte_range.end())
            .then(|| later_revisions(file, byte_range.end(), index))
            .flatten(),
    }))
}

/// Whether the first `end` bytes of `file` end with the `%%EOF` marker,
/// followed by at most one end-of-line (ISO 32000-1 sec.7.5.5).
fn ends_revision(file: &[u8], end: usize) -> bool {
    let Some(signed) = file.get(..end) else {
        return false;
    };
    let marker_end = [END_OF_LINE_CRLF, END_OF_LINE_LF, END_OF_LINE_CR]
        .iter()
        .find_map(|eol| signed.strip_suffix(*eol))
        .unwrap_or(signed);
    marker_end.ends_with(END_OF_FILE_MARKER)
}

/// The DER element a `/Contents` hex string carries, after checking
/// that everything behind it is zero padding.
fn contents_element(hole: &[u8]) -> Result<Vec<u8>, PdfReadError> {
    const MALFORMED: PdfReadError = PdfReadError::Malformed("Contents");
    let mut carried = hex_string(hole).ok_or(MALFORMED)?;
    let size = BerTlv::<Sequence>::parse(&carried)
        .map_err(|_ignored| MALFORMED)?
        .size();
    let padding = carried.get(size..).ok_or(MALFORMED)?;
    if padding.iter().any(|byte| *byte != CONTENTS_PADDING) {
        return Err(PdfReadError::Malformed("Contents padding"));
    }
    carried.truncate(size);
    Ok(carried)
}

/// The four non-negative integers of a `/ByteRange` array.
fn byte_range_values(value: &[u8]) -> Result<[usize; BYTE_RANGE_ENTRIES], PdfReadError> {
    const MALFORMED: PdfReadError = PdfReadError::Malformed("ByteRange");
    let mut parser = PdfValueParser::new(value);
    parser.skip_trivia();
    if !parser.consume(ARRAY_OPEN) {
        return Err(MALFORMED);
    }
    let mut values = [0_usize; BYTE_RANGE_ENTRIES];
    for slot in &mut values {
        *slot = parser
            .unsigned_digits()
            .and_then(parse_usize)
            .ok_or(MALFORMED)?;
    }
    parser.skip_trivia();
    if !parser.consume(ARRAY_CLOSE) {
        return Err(MALFORMED);
    }
    parser.require_end().map_err(|_ignored| MALFORMED)?;
    Ok(values)
}

/// The decoded bytes of a name value such as `/Sig`.
fn name_value(value: &[u8]) -> Result<Vec<u8>, PdfReadError> {
    const MALFORMED: PdfReadError = PdfReadError::Malformed("signature dictionary name");
    let mut parser = PdfValueParser::new(value);
    parser.skip_trivia();
    let name = parser.name().map_err(|_ignored| MALFORMED)?;
    parser.require_end().map_err(|_ignored| MALFORMED)?;
    Ok(name)
}

/// The bytes a hex string `<...>` encodes, with trivia around it.
///
/// White space between digits is ignored and an odd final digit is
/// followed by zero (ISO 32000-1 sec.7.3.4.3). `None` when the value
/// is not exactly one hex string.
fn hex_string(value: &[u8]) -> Option<Vec<u8>> {
    let start = value
        .iter()
        .position(|byte| !PdfValueParser::is_whitespace(*byte))?;
    let end = value
        .iter()
        .rposition(|byte| !PdfValueParser::is_whitespace(*byte))?;
    if value.get(start) != Some(&HEX_STRING_OPEN) || value.get(end) != Some(&HEX_STRING_CLOSE) {
        return None;
    }
    let digits = value.get(start.saturating_add(1)..end)?;
    let mut decoded = Vec::with_capacity(digits.len() / HEX_DIGITS_PER_BYTE);
    let mut pending: Option<u8> = None;
    for byte in digits {
        if PdfValueParser::is_whitespace(*byte) {
            continue;
        }
        let digit = PdfValueParser::hex_digit(*byte)?;
        match pending.take() {
            Some(high) => decoded.push((high << HEX_DIGIT_BITS) | digit),
            None => pending = Some(digit),
        }
    }
    if let Some(high) = pending {
        decoded.push(high << HEX_DIGIT_BITS);
    }
    Some(decoded)
}

/// The bytes of a text string value, literal or hex, when it needs no
/// escape decoding.
fn plain_string(value: &[u8]) -> Option<Vec<u8>> {
    let start = value
        .iter()
        .position(|byte| !PdfValueParser::is_whitespace(*byte))?;
    if value.get(start) == Some(&HEX_STRING_OPEN) {
        return hex_string(value);
    }
    let end = value
        .iter()
        .rposition(|byte| !PdfValueParser::is_whitespace(*byte))?;
    if value.get(start) != Some(&LITERAL_STRING_OPEN)
        || value.get(end) != Some(&LITERAL_STRING_CLOSE)
    {
        return None;
    }
    let text = value.get(start.saturating_add(1)..end)?;
    if text.iter().any(|byte| {
        *byte == LITERAL_STRING_ESCAPE
            || *byte == LITERAL_STRING_OPEN
            || *byte == LITERAL_STRING_CLOSE
    }) {
        return None;
    }
    Some(text.to_vec())
}

/// An ISO 32000-1 sec.7.9.4 date value as a UTC instant.
fn pdf_date(value: &[u8]) -> Option<DateTime> {
    PdfDate::parse(&plain_string(value)?)?.utc()
}

/// The fields of a `D:YYYYMMDDHHmmSSOHH'mm'` date string.
struct PdfDate {
    /// Calendar year.
    year: u16,
    /// Month, `1..=12`.
    month: u8,
    /// Day of the month.
    day: u8,
    /// Hour of the local time.
    hour: u8,
    /// Minute of the local time.
    minute: u8,
    /// Second of the local time.
    second: u8,
    /// Local time minus UT, in seconds.
    offset_seconds: i64,
}

impl PdfDate {
    /// The prefix every date string carries.
    const PREFIX: &'static [u8] = b"D:";
    /// Digits in the year field.
    const YEAR_DIGITS: usize = 4;
    /// Digits in every other field.
    const FIELD_DIGITS: usize = 2;
    /// Default month and day when the string stops before them.
    const FIRST: u8 = 1;
    /// Offset marker: the time is UT.
    const UNIVERSAL: u8 = b'Z';
    /// Offset marker: local time is later than UT.
    const AHEAD: u8 = b'+';
    /// Offset marker: local time is earlier than UT.
    const BEHIND: u8 = b'-';
    /// Separator after the offset hours and minutes.
    const APOSTROPHE: u8 = b'\'';
    /// Seconds in a minute and minutes in an hour.
    const SIXTY: i64 = 60;

    /// The fields of `text`; `None` when it does not parse or carries
    /// no relationship to UT.
    fn parse(text: &[u8]) -> Option<Self> {
        let mut rest = text.strip_prefix(Self::PREFIX)?;
        let year = u16::try_from(Self::digits(&mut rest, Self::YEAR_DIGITS)?).ok()?;
        let mut fields = [Self::FIRST, Self::FIRST, 0, 0, 0];
        for field in &mut fields {
            if !rest.first().is_some_and(u8::is_ascii_digit) {
                break;
            }
            *field = u8::try_from(Self::digits(&mut rest, Self::FIELD_DIGITS)?).ok()?;
        }
        let [month, day, hour, minute, second] = fields;
        let (&marker, mut rest) = rest.split_first()?;
        let sign = match marker {
            Self::UNIVERSAL => 0,
            Self::AHEAD => 1,
            Self::BEHIND => -1,
            _ => return None,
        };
        let mut offset_minutes = 0_i64;
        if !rest.is_empty() {
            let hours = i64::from(Self::digits(&mut rest, Self::FIELD_DIGITS)?);
            rest = rest.strip_prefix(&[Self::APOSTROPHE]).unwrap_or(rest);
            let minutes = if rest.is_empty() {
                0
            } else {
                i64::from(Self::digits(&mut rest, Self::FIELD_DIGITS)?)
            };
            rest = rest.strip_prefix(&[Self::APOSTROPHE]).unwrap_or(rest);
            if !rest.is_empty() || minutes >= Self::SIXTY {
                return None;
            }
            offset_minutes = hours.checked_mul(Self::SIXTY)?.checked_add(minutes)?;
        }
        Some(Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            offset_seconds: offset_minutes.checked_mul(Self::SIXTY)?.checked_mul(sign)?,
        })
    }

    /// `count` ASCII digits from the front of `rest`, as a number.
    fn digits(rest: &mut &[u8], count: usize) -> Option<u32> {
        let field = rest.get(..count)?;
        if !field.iter().all(u8::is_ascii_digit) {
            return None;
        }
        *rest = rest.get(count..)?;
        core::str::from_utf8(field).ok()?.parse().ok()
    }

    /// The UTC instant the local fields and offset name.
    fn utc(&self) -> Option<DateTime> {
        let local = DateTime::new(
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
        )
        .ok()?;
        let local_seconds = i64::try_from(local.unix_duration().as_secs()).ok()?;
        let utc_seconds = u64::try_from(local_seconds.checked_sub(self.offset_seconds)?).ok()?;
        DateTime::from_unix_duration(core::time::Duration::from_secs(utc_seconds)).ok()
    }
}

/// The newest catalog's `/DSS` arrays, each entry's stream content.
fn validation_store(
    index: &PdfIndex<'_>,
    trailer_bytes: &[u8],
    trailer: &PdfDictionary,
) -> Result<ValidationMaterial, PdfReadError> {
    const MALFORMED: PdfReadError = PdfReadError::Malformed("DSS");
    let root = trailer
        .entry(KEY_ROOT)
        .map_err(|error| PdfReadError::from_index(error, "trailer"))?
        .and_then(|entry| trailer_bytes.get(entry.value.clone()))
        .ok_or(PdfReadError::Malformed("trailer /Root"))?;
    let catalog_reference = complete_object_reference(root)
        .ok()
        .flatten()
        .ok_or(PdfReadError::Malformed("trailer /Root"))?;
    let catalog = index
        .object_body_reference(catalog_reference)
        .and_then(|body| dictionary_at(&body, 0))
        .map(|(dictionary, _end)| dictionary)
        .ok_or(PdfReadError::Malformed("catalog"))?;
    let parsed = PdfDictionary::parse(&catalog)
        .map_err(|error| PdfReadError::from_index(error, "catalog"))?;
    let Some(store_value) = parsed
        .entry(KEY_DSS)
        .map_err(|error| PdfReadError::from_index(error, "catalog"))?
        .and_then(|entry| catalog.get(entry.value.clone()))
    else {
        return Ok(ValidationMaterial::default());
    };

    let store = match complete_object_reference(store_value).map_err(|_ignored| MALFORMED)? {
        Some(reference) => index
            .object_body_reference(reference)
            .and_then(|body| dictionary_at(&body, 0))
            .map(|(dictionary, _end)| dictionary)
            .ok_or(MALFORMED)?,
        None => store_value.to_vec(),
    };
    let parsed =
        PdfDictionary::parse(&store).map_err(|error| PdfReadError::from_index(error, "DSS"))?;
    let category = |key: &[u8]| -> Result<Vec<Vec<u8>>, PdfReadError> {
        let Some(value) = parsed
            .entry(key)
            .map_err(|error| PdfReadError::from_index(error, "DSS"))?
            .and_then(|entry| store.get(entry.value.clone()))
        else {
            return Ok(Vec::new());
        };
        let references = validation_references(index, value)
            .map_err(|error| PdfReadError::from_index(error, "DSS"))?;
        references
            .into_iter()
            .map(|reference| {
                index
                    .stream_payload(reference)
                    .map_err(|error| PdfReadError::from_index(error, "DSS stream"))?
                    .ok_or(PdfReadError::Malformed("DSS stream"))
            })
            .collect()
    };
    Ok(ValidationMaterial {
        certificates: category(KEY_CERTS)?,
        ocsp_responses: category(KEY_OCSPS)?,
        crls: category(KEY_CRLS)?,
    })
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::{
        END_OF_FILE_MARKER, END_OF_LINE_CR, END_OF_LINE_CRLF, END_OF_LINE_LF, PdfDate, PdfDocument,
        PdfReadError, SignatureKind, SubFilter, pdf_date,
    };
    use crate::ber::{BerTag, Sequence, tlv};
    use crate::cades::DigestAlgorithm;
    use crate::pades::index::{PdfIndex, PdfObjectReference, find_first, find_last};
    use crate::pades::{
        SignatureMetadata, append_validation_store, prepare, prepare_document_timestamp,
    };
    use crate::verification::exactly;
    use crate::verification::revision::{DocumentChange, Revision};
    use refineid_cms::x509::DateTime;

    /// Signature space reserved by the fixtures, in bytes.
    const FIXTURE_CAPACITY: usize = 256;

    /// Payload of the synthetic `CMS` blob.
    const SYNTHETIC_SIGNED_DATA: &[u8] = b"synthetic signed data";

    /// Payload of the synthetic timestamp token.
    const SYNTHETIC_TIMESTAMP_TOKEN: &[u8] = b"synthetic timestamp token";

    /// Synthetic `/DSS` certificate stream content.
    const SYNTHETIC_CERTIFICATE: &[u8] = b"synthetic certificate";

    /// Synthetic `/DSS` `OCSP` stream content.
    const SYNTHETIC_OCSP_RESPONSE: &[u8] = b"synthetic ocsp response";

    /// Synthetic `/DSS` `CRL` stream content.
    const SYNTHETIC_CRL: &[u8] = b"synthetic crl";

    /// The `/M` entry the fixtures write: a synthetic local time two
    /// hours ahead of UT.
    const SIGNING_TIME_ENTRY: &str = "D:20010203040506+02'00'";

    /// [`SIGNING_TIME_ENTRY`] in UTC.
    const SIGNING_TIME_UTC: (u16, u8, u8, u8, u8, u8) = (2001, 2, 3, 2, 5, 6);

    /// The page objects every fixture starts from, numbered from one.
    const PAGE_OBJECTS: &[&str] = &[
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
    ];

    /// Number of the first object in a fixture.
    const FIRST_OBJECT: usize = 1;

    /// Digits of a cross-reference table offset (ISO 32000-1 sec.7.5.4).
    const XREF_OFFSET_DIGITS: usize = 10;

    /// Digits of a cross-reference table generation.
    const XREF_GENERATION_DIGITS: usize = 5;

    /// Generation of the free-list head, object zero.
    const FREE_HEAD_GENERATION: u32 = 65_535;

    /// Offset written for the free-list head, and generation of most
    /// fixture objects.
    const ZERO: usize = 0;

    /// Hour, minute and second of a date string that stops at the day.
    const MIDNIGHT: u8 = 0;

    /// Cross-reference stream entry type of an object at a byte offset
    /// (ISO 32000-1 sec.7.5.8.3, Table 18).
    const XREF_TYPE_DIRECT: u8 = 1;

    /// Cross-reference stream entry type of an object inside an object
    /// stream.
    const XREF_TYPE_COMPRESSED: u8 = 2;

    /// Cross-reference table keyword of an object in use
    /// (ISO 32000-1 sec.7.5.4).
    const IN_USE: &str = "n";

    /// Cross-reference table keyword of a free entry.
    const FREE: &str = "f";

    /// A keyword ISO 32000-1 sec.7.5.4 does not define.
    const UNDEFINED_FLAG: &str = "x";

    /// Number of the object the fixtures add after the page objects.
    const EXTRA_OBJECT: usize = PAGE_OBJECTS.len() + FIRST_OBJECT;

    /// A white-space character (ISO 32000-1 sec.7.2.2, Table 1).
    const NUL: u8 = 0x00;

    /// LINE TABULATION, which ISO 32000-1 sec.7.2.2 does not list as
    /// white space.
    const VERTICAL_TAB: u8 = 0x0B;

    /// `/Size` of a fixture whose first update takes high object
    /// numbers.
    const HIGH_SIZE: usize = 40;

    /// `/Size` patched in so a later update takes lower numbers; the
    /// same digit count as the size the first update writes.
    const LOW_SIZE: usize = 10;

    /// `miniz_oxide` compression level for the flate fixture.
    const FLATE_LEVEL: u8 = 6;

    /// The generation the stream fixture gives the page object.
    const PAGE_GENERATION: u16 = 1;

    /// A hex digit that is not zero padding.
    const NONZERO_HEX_DIGIT: u8 = b'1';

    /// A DER `SEQUENCE` around `content`, standing in for a `CMS`
    /// `ContentInfo`.
    fn sequence(content: &[u8]) -> Vec<u8> {
        tlv(
            u8::try_from(Sequence::TAG).expect("SEQUENCE is a one-byte tag"),
            content,
        )
    }

    /// Bytes of `objects`, numbered from one, behind the PDF header.
    fn objects_prefix(objects: &[Vec<u8>]) -> (Vec<u8>, Vec<usize>) {
        let mut pdf = Vec::from("%PDF-1.7\n");
        let mut offsets = Vec::new();
        for (index, body) in objects.iter().enumerate() {
            offsets.push(pdf.len());
            pdf.extend_from_slice(format!("{} 0 obj\n", index + FIRST_OBJECT).as_bytes());
            pdf.extend_from_slice(body);
            pdf.extend_from_slice(b"\nendobj\n");
        }
        (pdf, offsets)
    }

    /// One classic cross-reference entry line (ISO 32000-1 sec.7.5.4).
    fn entry_line(offset: usize, flag: &str) -> String {
        format!(
            "{offset:0width$} {ZERO:0generation$} {flag} \n",
            width = XREF_OFFSET_DIGITS,
            generation = XREF_GENERATION_DIGITS
        )
    }

    /// The free-list head line.
    fn free_head_line() -> String {
        format!(
            "{ZERO:0offset$} {FREE_HEAD_GENERATION} f \n",
            offset = XREF_OFFSET_DIGITS
        )
    }

    /// A PDF of `objects` closed by a classic cross-reference table,
    /// with `trailer_extra` inside the trailer dictionary.
    fn classic_pdf(objects: &[Vec<u8>], trailer_extra: &str) -> Vec<u8> {
        let (mut pdf, offsets) = objects_prefix(objects);
        let xref_at = pdf.len();
        let size = objects.len() + FIRST_OBJECT;
        pdf.extend_from_slice(format!("xref\n0 {size}\n").as_bytes());
        pdf.extend_from_slice(free_head_line().as_bytes());
        for offset in &offsets {
            pdf.extend_from_slice(entry_line(*offset, IN_USE).as_bytes());
        }
        pdf.extend_from_slice(
            format!(
                "trailer\n<< /Size {size} /Root 1 0 R{trailer_extra} >>\nstartxref\n{xref_at}\n%%EOF\n"
            )
            .as_bytes(),
        );
        pdf
    }

    /// `pdf` with the one occurrence of `old` replaced by `new`.
    fn replaced(pdf: &[u8], old: &[u8], new: &[u8]) -> Vec<u8> {
        let at = find_first(pdf, old).expect("the fixture carries the text");
        let mut out = pdf[..at].to_vec();
        out.extend_from_slice(new);
        out.extend_from_slice(&pdf[at + old.len()..]);
        out
    }

    /// Offset of the header of object `number`.
    fn object_offset(pdf: &[u8], number: usize) -> usize {
        find_first(pdf, format!("\n{number} 0 obj").as_bytes()).expect("the object is written")
            + FIRST_OBJECT
    }

    /// `pdf` with the classic entry of object `number` flagged `flag`.
    fn reflagged(pdf: &[u8], number: usize, flag: &str) -> Vec<u8> {
        let offset = object_offset(pdf, number);
        replaced(
            pdf,
            entry_line(offset, IN_USE).as_bytes(),
            entry_line(offset, flag).as_bytes(),
        )
    }

    /// The offset the last `startxref` of `pdf` names.
    fn last_start_xref(pdf: &[u8]) -> usize {
        crate::pades::index::find_start_xref(pdf).expect("the base has a startxref")
    }

    /// `pdf` extended by an incremental update adding `objects`, its
    /// trailer carrying `trailer_extra` before `/Prev`.
    fn append_update(pdf: &[u8], objects: &[(usize, &str)], trailer_extra: &str) -> Vec<u8> {
        let previous = last_start_xref(pdf);
        let mut out = pdf.to_vec();
        let mut entries = String::new();
        for (number, body) in objects {
            entries.push_str(&format!("{number} 1\n{}", entry_line(out.len(), IN_USE)));
            out.extend_from_slice(format!("{number} 0 obj\n{body}\nendobj\n").as_bytes());
        }
        let xref_at = out.len();
        let size = EXTRA_OBJECT + objects.len();
        out.extend_from_slice(
            format!(
                "xref\n{entries}trailer\n<< /Size {size} /Root 1 0 R{trailer_extra} /Prev {previous} \
                 >>\nstartxref\n{xref_at}\n%%EOF\n"
            )
            .as_bytes(),
        );
        out
    }

    /// The outcome of reading `pdf`, reduced to the signature count.
    fn read(pdf: &[u8]) -> Result<usize, PdfReadError> {
        PdfDocument::parse(pdf).map(|document| document.signatures().len())
    }

    /// The page objects as owned bodies.
    fn page_objects() -> Vec<Vec<u8>> {
        PAGE_OBJECTS.iter().map(|body| Vec::from(*body)).collect()
    }

    /// One row of a cross-reference stream: the object number, its
    /// type, and the second and third fields (ISO 32000-1 Table 18).
    struct Row {
        number: usize,
        kind: u8,
        second: usize,
        third: u16,
    }

    /// A cross-reference stream object numbered `number` listing `rows`
    /// and itself at `at`, unfiltered, with `/W [1 4 2]`.
    fn xref_stream(number: usize, at: usize, rows: &[Row], size: usize, extra: &str) -> Vec<u8> {
        let [type_width, offset_width, generation_width] =
            [size_of::<u8>(), size_of::<u32>(), size_of::<u16>()];
        let mut index = String::new();
        let mut data = Vec::new();
        let own = Row {
            number,
            kind: XREF_TYPE_DIRECT,
            second: at,
            third: u16::MIN,
        };
        for row in rows.iter().chain(core::iter::once(&own)) {
            index.push_str(&format!("{} 1 ", row.number));
            data.push(row.kind);
            data.extend_from_slice(
                &u32::try_from(row.second)
                    .expect("small fixture")
                    .to_be_bytes(),
            );
            data.extend_from_slice(&row.third.to_be_bytes());
        }
        let mut object = format!(
            "{number} 0 obj\n<< /Type /XRef /Size {size} /Root 1 0 R{extra} /Index [{index}] \
             /W [{} {} {}] /Length {} >>\nstream\n",
            type_width,
            offset_width,
            generation_width,
            data.len()
        )
        .into_bytes();
        object.extend_from_slice(&data);
        object.extend_from_slice(b"\nendstream\nendobj\n");
        object
    }

    /// `pdf` closed by `stream`, written at its end, and a `startxref`
    /// naming it.
    fn closed_by(mut pdf: Vec<u8>, stream: &[u8]) -> Vec<u8> {
        let at = pdf.len();
        pdf.extend_from_slice(stream);
        pdf.extend_from_slice(format!("startxref\n{at}\n%%EOF\n").as_bytes());
        pdf
    }

    /// The direct rows of objects at `offsets`, numbered from one.
    fn direct_rows(offsets: &[usize]) -> Vec<Row> {
        offsets
            .iter()
            .enumerate()
            .map(|(index, offset)| Row {
                number: index + FIRST_OBJECT,
                kind: XREF_TYPE_DIRECT,
                second: *offset,
                third: u16::MIN,
            })
            .collect()
    }

    /// The page objects closed by an unfiltered cross-reference stream
    /// (ISO 32000-1 sec.7.5.8).
    fn stream_pdf() -> Vec<u8> {
        let objects = page_objects();
        let (pdf, offsets) = objects_prefix(&objects);
        let stream_number = objects.len() + FIRST_OBJECT;
        let at = pdf.len();
        let rows = direct_rows(&offsets);
        closed_by(
            pdf,
            &xref_stream(stream_number, at, &rows, stream_number + FIRST_OBJECT, ""),
        )
    }

    /// An unfiltered object stream (ISO 32000-1 sec.7.5.7) holding
    /// `bodies` as objects numbered from `first_number`.
    fn object_stream(first_number: usize, bodies: &[Vec<u8>]) -> Vec<u8> {
        let mut table = String::new();
        let mut content = Vec::new();
        for (index, body) in bodies.iter().enumerate() {
            table.push_str(&format!("{} {} ", first_number + index, content.len()));
            content.extend_from_slice(body);
            content.push(b' ');
        }
        let mut payload = table.clone().into_bytes();
        payload.extend_from_slice(&content);
        let mut object = format!(
            "<< /Type /ObjStm /N {} /First {} /Length {} >>\nstream\n",
            bodies.len(),
            table.len(),
            payload.len()
        )
        .into_bytes();
        object.extend_from_slice(&payload);
        object.extend_from_slice(b"\nendstream");
        object
    }

    /// A PDF of `direct` objects numbered from one, then `packed`
    /// objects inside one object stream, closed by a cross-reference
    /// stream.
    fn object_stream_pdf(direct: &[Vec<u8>], packed: &[Vec<u8>]) -> Vec<u8> {
        let first_packed = direct.len() + FIRST_OBJECT;
        let container = first_packed + packed.len();
        let (mut pdf, offsets) = objects_prefix(direct);
        let container_at = pdf.len();
        pdf.extend_from_slice(format!("{container} 0 obj\n").as_bytes());
        pdf.extend_from_slice(&object_stream(first_packed, packed));
        pdf.extend_from_slice(b"\nendobj\n");
        let mut rows = direct_rows(&offsets);
        for index in 0..packed.len() {
            rows.push(Row {
                number: first_packed + index,
                kind: XREF_TYPE_COMPRESSED,
                second: container,
                third: u16::try_from(index).expect("small fixture"),
            });
        }
        rows.push(Row {
            number: container,
            kind: XREF_TYPE_DIRECT,
            second: container_at,
            third: u16::MIN,
        });
        let stream_number = container + FIRST_OBJECT;
        let at = pdf.len();
        closed_by(
            pdf,
            &xref_stream(stream_number, at, &rows, stream_number + FIRST_OBJECT, ""),
        )
    }

    /// `pdf` signed once with the synthetic `CMS`, and the digest the
    /// writer computed over the placeholder's spans.
    fn signed(pdf: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let metadata = SignatureMetadata {
            signing_time: Some(SIGNING_TIME_ENTRY.to_owned()),
            ..SignatureMetadata::default()
        };
        let placeholder = prepare(pdf, &metadata, FIXTURE_CAPACITY).expect("the fixture prepares");
        let digest = placeholder.digest(DigestAlgorithm::Sha256);
        let document = placeholder
            .finish(&sequence(SYNTHETIC_SIGNED_DATA))
            .expect("the CMS fits");
        (document, digest)
    }

    /// The one signature of `pdf`.
    fn only_signature(pdf: &[u8]) -> super::PdfSignature {
        let document = PdfDocument::parse(pdf).expect("the signed PDF parses");
        let [signature] = exactly(document.signatures(), "exactly one signature");
        signature.clone()
    }

    #[test]
    fn one_signature_is_found_with_its_kind_subfilter_and_time() {
        let (pdf, _digest) = signed(&classic_pdf(&page_objects(), ""));
        let document = PdfDocument::parse(&pdf).expect("the signed PDF parses");
        let [signature] = exactly(document.signatures(), "exactly one signature");
        assert_eq!(
            signature.kind(),
            SignatureKind::Signature(SubFilter::EtsiCadesDetached)
        );
        assert_eq!(signature.cms(), sequence(SYNTHETIC_SIGNED_DATA));
        assert_eq!(signature.revision(), Some(Revision::WholeDocument));
        let (year, month, day, hour, minute, second) = SIGNING_TIME_UTC;
        assert_eq!(
            signature.signing_time_entry(),
            Some(DateTime::new(year, month, day, hour, minute, second).expect("valid date"))
        );
        assert!(document.validation_store().is_empty());
    }

    #[test]
    fn the_digest_over_the_spans_equals_the_writers_digest() {
        let (pdf, digest) = signed(&classic_pdf(&page_objects(), ""));
        let document = PdfDocument::parse(&pdf).expect("the signed PDF parses");
        let [signature] = exactly(document.signatures(), "exactly one signature");
        assert_eq!(
            document.digest(&signature.byte_range(), DigestAlgorithm::Sha256),
            digest
        );
    }

    #[test]
    fn a_document_timestamp_is_recognised() {
        let (pdf, _digest) = signed(&classic_pdf(&page_objects(), ""));
        let stamped = prepare_document_timestamp(&pdf, FIXTURE_CAPACITY)
            .expect("the timestamp prepares")
            .finish(&sequence(SYNTHETIC_TIMESTAMP_TOKEN))
            .expect("the token fits");
        let document = PdfDocument::parse(&stamped).expect("the stamped PDF parses");
        let [signature, timestamp] = exactly(
            document.signatures(),
            "a signature and a document timestamp",
        );
        assert_eq!(
            signature.kind(),
            SignatureKind::Signature(SubFilter::EtsiCadesDetached)
        );
        assert_eq!(signature.revision(), Some(Revision::LaterRevisionsHarmless));
        assert_eq!(timestamp.kind(), SignatureKind::DocumentTimestamp);
        assert_eq!(timestamp.cms(), sequence(SYNTHETIC_TIMESTAMP_TOKEN));
        assert_eq!(timestamp.revision(), Some(Revision::WholeDocument));
        assert_eq!(timestamp.signing_time_entry(), None);

        // A document timestamp under any other subfilter is refused.
        let respelled = replaced(&stamped, b"/ETSI.RFC3161", b"/ETSI.RFC3162");
        assert_eq!(
            read(&respelled),
            Err(PdfReadError::Unsupported("document timestamp subfilter"))
        );
    }

    #[test]
    fn serial_signatures_each_keep_their_own_range() {
        let (once, _first_digest) = signed(&classic_pdf(&page_objects(), ""));
        let (twice, second_digest) = signed(&once);
        let document = PdfDocument::parse(&twice).expect("the twice-signed PDF parses");
        let [first, second] = exactly(document.signatures(), "two signatures");
        assert_eq!(first.revision(), Some(Revision::LaterRevisionsHarmless));
        assert_eq!(first.byte_range().end(), once.len());
        assert_eq!(second.revision(), Some(Revision::WholeDocument));
        assert_eq!(
            document.digest(&second.byte_range(), DigestAlgorithm::Sha256),
            second_digest
        );
    }

    #[test]
    fn signatures_come_back_in_revision_order() {
        let base = classic_pdf(&page_objects(), "");
        let base = replaced(
            &base,
            format!("/Size {EXTRA_OBJECT} ").as_bytes(),
            format!("/Size {HIGH_SIZE} ").as_bytes(),
        );
        let (mut once, _digest) = signed(&base);
        let size_at =
            find_last(&once, b"/Size ").expect("the update has a trailer") + b"/Size ".len();
        let low = LOW_SIZE.to_string();
        once[size_at..size_at + low.len()].copy_from_slice(low.as_bytes());
        let (twice, _digest) = signed(&once);
        let document = PdfDocument::parse(&twice).expect("the twice-signed PDF parses");
        let [first, second] = exactly(document.signatures(), "two signatures");
        assert!(first.byte_range().end() < second.byte_range().end());
        assert_eq!(first.revision(), Some(Revision::LaterRevisionsHarmless));
        assert_eq!(second.revision(), Some(Revision::WholeDocument));
        assert!(
            find_first(&twice, format!("\n{HIGH_SIZE} 0 obj").as_bytes())
                < find_first(&twice, format!("\n{LOW_SIZE} 0 obj").as_bytes()),
            "the earlier revision holds the higher object number"
        );
    }

    #[test]
    fn the_validation_store_reads_back_byte_exact() {
        let (pdf, _digest) = signed(&classic_pdf(&page_objects(), ""));
        let stored = append_validation_store(
            &pdf,
            &[SYNTHETIC_CERTIFICATE.to_vec()],
            &[SYNTHETIC_OCSP_RESPONSE.to_vec()],
            &[SYNTHETIC_CRL.to_vec()],
        )
        .expect("the store appends");
        let document = PdfDocument::parse(&stored).expect("the PDF with a store parses");
        let store = document.validation_store();
        assert_eq!(store.certificates, [SYNTHETIC_CERTIFICATE]);
        assert_eq!(store.ocsp_responses, [SYNTHETIC_OCSP_RESPONSE]);
        assert_eq!(store.crls, [SYNTHETIC_CRL]);
        let [signature] = exactly(document.signatures(), "exactly one signature");
        assert_eq!(signature.revision(), Some(Revision::LaterRevisionsHarmless));
    }

    #[test]
    fn a_later_store_update_carries_earlier_entries_forward() {
        let (pdf, _digest) = signed(&classic_pdf(&page_objects(), ""));
        let first = append_validation_store(&pdf, &[SYNTHETIC_CERTIFICATE.to_vec()], &[], &[])
            .expect("the first store appends");
        let second = append_validation_store(&first, &[], &[], &[SYNTHETIC_CRL.to_vec()])
            .expect("the second store appends");
        let document = PdfDocument::parse(&second).expect("the PDF parses");
        let store = document.validation_store();
        assert_eq!(store.certificates, [SYNTHETIC_CERTIFICATE]);
        assert!(store.ocsp_responses.is_empty());
        assert_eq!(store.crls, [SYNTHETIC_CRL]);
    }

    #[test]
    fn a_direct_store_with_a_flate_stream_is_decoded() {
        let compressed =
            miniz_oxide::deflate::compress_to_vec_zlib(SYNTHETIC_CERTIFICATE, FLATE_LEVEL);
        let mut stream = Vec::from(
            format!(
                "<< /Length {} /Filter /FlateDecode >>\nstream\n",
                compressed.len()
            )
            .as_bytes(),
        );
        stream.extend_from_slice(&compressed);
        stream.extend_from_slice(b"\nendstream");
        let mut objects = page_objects();
        objects[ZERO] = Vec::from(
            format!(
                "<< /Type /Catalog /Pages 2 0 R /DSS << /Type /DSS /Certs [{EXTRA_OBJECT} 0 R] \
                 /VRI << >> >> >>"
            )
            .as_bytes(),
        );
        objects.push(stream);
        let pdf = classic_pdf(&objects, "");
        let document = PdfDocument::parse(&pdf).expect("the PDF parses");
        assert_eq!(
            document.validation_store().certificates,
            [SYNTHETIC_CERTIFICATE]
        );
        assert!(document.signatures().is_empty());
    }

    #[test]
    fn a_store_reference_to_a_freed_or_missing_object_is_malformed() {
        let mut stream = Vec::from(
            format!("<< /Length {} >>\nstream\n", SYNTHETIC_CERTIFICATE.len()).as_bytes(),
        );
        stream.extend_from_slice(SYNTHETIC_CERTIFICATE);
        stream.extend_from_slice(b"\nendstream");
        let mut objects = page_objects();
        objects[ZERO] = Vec::from(
            format!("<< /Type /Catalog /Pages 2 0 R /DSS << /Certs [{EXTRA_OBJECT} 0 R] >> >>")
                .as_bytes(),
        );
        objects.push(stream);
        let pdf = classic_pdf(&objects, "");
        assert_eq!(read(&pdf), Ok(ZERO), "the live store reads");
        assert_eq!(
            read(&reflagged(&pdf, EXTRA_OBJECT, FREE)),
            Err(PdfReadError::Malformed("DSS stream"))
        );
        objects.pop();
        assert_eq!(
            read(&classic_pdf(&objects, "")),
            Err(PdfReadError::Malformed("DSS stream"))
        );
    }

    #[test]
    fn a_cross_reference_stream_pdf_is_read() {
        let (pdf, digest) = signed(&stream_pdf());
        assert!(
            find_first(&pdf, b"/Type /XRef").is_some(),
            "the fixture is closed by a stream"
        );
        let stored = append_validation_store(&pdf, &[SYNTHETIC_CERTIFICATE.to_vec()], &[], &[])
            .expect("the store appends behind a stream");
        let document = PdfDocument::parse(&stored).expect("the stream PDF parses");
        let [signature] = exactly(document.signatures(), "exactly one signature");
        assert_eq!(
            signature.kind(),
            SignatureKind::Signature(SubFilter::EtsiCadesDetached)
        );
        assert_eq!(
            document.digest(&signature.byte_range(), DigestAlgorithm::Sha256),
            digest
        );
        assert_eq!(
            document.validation_store().certificates,
            [SYNTHETIC_CERTIFICATE]
        );
    }

    #[test]
    fn a_stream_entry_keeps_its_generation() {
        let objects = vec![
            Vec::from(PAGE_OBJECTS[ZERO]),
            Vec::from(format!(
                "<< /Type /Pages /Kids [{EXTRA_OBJECT} {PAGE_GENERATION} R] /Count 1 >>"
            )),
        ];
        let (mut pdf, offsets) = objects_prefix(&objects);
        let page_at = pdf.len();
        pdf.extend_from_slice(
            format!(
                "{EXTRA_OBJECT} {PAGE_GENERATION} obj\n{}\nendobj\n",
                PAGE_OBJECTS[PAGE_OBJECTS.len() - 1]
            )
            .as_bytes(),
        );
        let mut rows = direct_rows(&offsets);
        rows.push(Row {
            number: EXTRA_OBJECT,
            kind: XREF_TYPE_DIRECT,
            second: page_at,
            third: PAGE_GENERATION,
        });
        let stream_number = EXTRA_OBJECT + FIRST_OBJECT;
        let at = pdf.len();
        let pdf = closed_by(
            pdf,
            &xref_stream(stream_number, at, &rows, stream_number + FIRST_OBJECT, ""),
        );
        let index = PdfIndex::parse(&pdf).expect("the stream PDF indexes");
        let number = u32::try_from(EXTRA_OBJECT).expect("small fixture");
        assert!(
            index
                .object_body_reference(PdfObjectReference {
                    number,
                    generation: PAGE_GENERATION,
                })
                .is_some()
        );
        assert!(
            index.object_body(number).is_none(),
            "generation zero is not it"
        );
        assert_eq!(read(&pdf), Ok(ZERO));
    }

    #[test]
    fn objects_inside_an_object_stream_are_read() {
        let pdf = object_stream_pdf(&[], &page_objects());
        assert_eq!(read(&pdf), Ok(ZERO));
        let (signed_pdf, digest) = signed(&pdf);
        let signature = only_signature(&signed_pdf);
        let document = PdfDocument::parse(&signed_pdf).expect("parses");
        assert_eq!(
            document.digest(&signature.byte_range(), DigestAlgorithm::Sha256),
            digest
        );
    }

    #[test]
    fn a_signature_dictionary_inside_an_object_stream_names_no_hole() {
        // A range that lies inside the file, around a hole the
        // dictionary's own bytes cannot be.
        let hole_end = FIRST_OBJECT + FIRST_OBJECT;
        let packed = Vec::from(format!(
            "<< /Type /Sig /ByteRange [{ZERO} {FIRST_OBJECT} {hole_end} {FIRST_OBJECT}] \
             /Contents <{}> >>",
            crate::hexcodec::Hex::encode(&sequence(SYNTHETIC_SIGNED_DATA))
        ));
        assert_eq!(
            read(&object_stream_pdf(&page_objects(), &[packed])),
            Err(PdfReadError::Malformed(
                "Contents outside the ByteRange hole"
            ))
        );
    }

    #[test]
    fn a_hybrid_file_reads_its_stream_entries() {
        // Catalog and page direct, the page tree inside an object
        // stream that only the `/XRefStm` stream lists.
        let pages = Vec::from(PAGE_OBJECTS[FIRST_OBJECT]);
        let mut pdf = Vec::from("%PDF-1.7\n");
        let catalog_at = pdf.len();
        pdf.extend_from_slice(format!("1 0 obj\n{}\nendobj\n", PAGE_OBJECTS[ZERO]).as_bytes());
        let page_number = PAGE_OBJECTS.len();
        let page_at = pdf.len();
        pdf.extend_from_slice(
            format!(
                "{page_number} 0 obj\n{}\nendobj\n",
                PAGE_OBJECTS[page_number - 1]
            )
            .as_bytes(),
        );
        let container = EXTRA_OBJECT;
        let container_at = pdf.len();
        pdf.extend_from_slice(format!("{container} 0 obj\n").as_bytes());
        pdf.extend_from_slice(&object_stream(FIRST_OBJECT + FIRST_OBJECT, &[pages]));
        pdf.extend_from_slice(b"\nendobj\n");
        let stream_number = container + FIRST_OBJECT;
        let size = stream_number + FIRST_OBJECT;
        let stream_at = pdf.len();
        pdf.extend_from_slice(&xref_stream(
            stream_number,
            stream_at,
            &[
                Row {
                    number: FIRST_OBJECT + FIRST_OBJECT,
                    kind: XREF_TYPE_COMPRESSED,
                    second: container,
                    third: u16::MIN,
                },
                Row {
                    number: container,
                    kind: XREF_TYPE_DIRECT,
                    second: container_at,
                    third: u16::MIN,
                },
            ],
            size,
            "",
        ));
        let table_at = pdf.len();
        pdf.extend_from_slice(format!("xref\n0 {}\n", page_number + FIRST_OBJECT).as_bytes());
        pdf.extend_from_slice(free_head_line().as_bytes());
        pdf.extend_from_slice(entry_line(catalog_at, IN_USE).as_bytes());
        pdf.extend_from_slice(entry_line(ZERO, FREE).as_bytes());
        pdf.extend_from_slice(entry_line(page_at, IN_USE).as_bytes());
        pdf.extend_from_slice(
            format!(
                "trailer\n<< /Size {size} /Root 1 0 R /XRefStm {stream_at} >>\nstartxref\n\
                 {table_at}\n%%EOF\n"
            )
            .as_bytes(),
        );
        assert_eq!(read(&pdf), Ok(ZERO));
        let (signed_pdf, digest) = signed(&pdf);
        let document = PdfDocument::parse(&signed_pdf).expect("the signed hybrid parses");
        let [signature] = exactly(document.signatures(), "exactly one signature");
        assert_eq!(
            document.digest(&signature.byte_range(), DigestAlgorithm::Sha256),
            digest
        );
    }

    #[test]
    fn a_byte_range_not_starting_at_zero_is_rejected() {
        let (mut pdf, _digest) = signed(&classic_pdf(&page_objects(), ""));
        let key = b"/ByteRange [";
        let open = find_first(&pdf, key).expect("the range is written") + key.len();
        let close = open + find_first(&pdf[open..], b"]").expect("the range closes");
        let declared = String::from_utf8(pdf[open..close].to_vec()).expect("ASCII range");
        let mut values: Vec<usize> = declared
            .split_ascii_whitespace()
            .map(|value| value.parse().expect("integer"))
            .collect();
        values[ZERO] = FIRST_OBJECT;
        let rewritten = values
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        let padded = format!("{rewritten:>width$}", width = declared.len());
        pdf[open..close].copy_from_slice(padded.as_bytes());
        assert_eq!(read(&pdf), Err(PdfReadError::Malformed("ByteRange")));
    }

    #[test]
    fn a_byte_range_naming_another_dictionarys_hole_is_malformed() {
        let (pdf, _digest) = signed(&classic_pdf(&page_objects(), ""));
        let signature = only_signature(&pdf);
        let hole = signature.byte_range().hole();
        let end = signature.byte_range().end();
        let contents = String::from_utf8(pdf[hole.clone()].to_vec()).expect("hex is ASCII");
        let claimant = format!(
            "<< /Type /Sig /SubFilter /ETSI.CAdES.detached /ByteRange [{ZERO} {} {} {}] \
             /Contents {contents} >>",
            hole.start,
            hole.end,
            end - hole.end
        );
        let extended = append_update(&pdf, &[(HIGH_SIZE, &claimant)], "");
        assert_eq!(
            read(&extended),
            Err(PdfReadError::Malformed(
                "Contents outside the ByteRange hole"
            ))
        );
    }

    #[test]
    fn bytes_after_the_der_in_contents_must_be_zero_padding() {
        let (mut pdf, _digest) = signed(&classic_pdf(&page_objects(), ""));
        let hole = only_signature(&pdf).byte_range().hole();
        // The last hex digit before the closing `>` is padding.
        let last_digit = hole.end - FIRST_OBJECT - FIRST_OBJECT;
        pdf[last_digit] = NONZERO_HEX_DIGIT;
        assert_eq!(read(&pdf), Err(PdfReadError::Malformed("Contents padding")));
    }

    #[test]
    fn an_encrypted_trailer_is_refused() {
        assert_eq!(
            read(&classic_pdf(&page_objects(), " /Encrypt 9 0 R")),
            Err(PdfReadError::Unsupported("encrypted document"))
        );
        // An older revision's trailer counts as much as the newest.
        let older = classic_pdf(&page_objects(), " /Encrypt 9 0 R");
        let updated = append_update(&older, &[(EXTRA_OBJECT, "<< /Type /Annot >>")], "");
        assert_eq!(
            read(&updated),
            Err(PdfReadError::Unsupported("encrypted document"))
        );
    }

    #[test]
    fn a_file_without_the_header_is_not_a_pdf() {
        assert_eq!(read(SYNTHETIC_SIGNED_DATA), Err(PdfReadError::NotAPdf));
    }

    #[test]
    fn dates_without_a_relationship_to_ut_are_not_read() {
        assert!(PdfDate::parse(b"D:20010203040506").is_none());
        assert!(PdfDate::parse(b"20010203040506Z").is_none());
        let (year, month, day, _hour, _minute, _second) = SIGNING_TIME_UTC;
        assert_eq!(
            pdf_date(b"(D:20010203Z)"),
            Some(
                DateTime::new(year, month, day, MIDNIGHT, MIDNIGHT, MIDNIGHT).expect("valid date")
            )
        );
        assert_eq!(
            pdf_date(SIGNING_TIME_ENTRY.as_bytes()),
            None,
            "a bare value is not a string"
        );
    }

    #[test]
    fn an_object_keyword_followed_by_a_delimiter_is_read() {
        let (pdf, _digest) = signed(&classic_pdf(&page_objects(), ""));
        let tight = replaced(&pdf, b"1 0 obj\n<<", b"1 0 obj<<\n");
        let mut tight = tight;
        let keyword = find_last(&tight, b"startxref\n").expect("the update has a startxref");
        tight[keyword + b"startxref".len()] = b' ';
        assert_eq!(read(&tight), Ok(FIRST_OBJECT));
    }

    #[test]
    fn a_longer_name_or_a_string_does_not_shadow_prev() {
        let base = classic_pdf(&page_objects(), "");
        let longer = append_update(&base, &[], " /Preview 0");
        assert_eq!(read(&longer), Ok(ZERO), "the chain reaches the catalog");
        let quoted = append_update(&base, &[], " /Note (/Prev 1)");
        assert_eq!(read(&quoted), Ok(ZERO), "a string is not a key");
    }

    #[test]
    fn only_in_use_and_free_flags_are_accepted() {
        let mut objects = page_objects();
        objects.push(Vec::from("(synthetic string object)"));
        let pdf = classic_pdf(&objects, "");
        assert_eq!(read(&pdf), Ok(ZERO), "a string object is no dictionary");
        assert_eq!(read(&reflagged(&pdf, EXTRA_OBJECT, FREE)), Ok(ZERO));
        assert_eq!(
            read(&reflagged(&pdf, EXTRA_OBJECT, UNDEFINED_FLAG)),
            Err(PdfReadError::Malformed("cross-reference chain"))
        );
    }

    #[test]
    fn nul_is_white_space_and_vertical_tab_is_not() {
        let pdf = classic_pdf(&page_objects(), "");
        let line = entry_line(object_offset(&pdf, FIRST_OBJECT), IN_USE);
        let separated = |separator: u8| {
            let mut changed = line.clone().into_bytes();
            changed[XREF_OFFSET_DIGITS] = separator;
            replaced(&pdf, line.as_bytes(), &changed)
        };
        assert_eq!(read(&separated(NUL)), Ok(ZERO));
        assert_eq!(
            read(&separated(VERTICAL_TAB)),
            Err(PdfReadError::Malformed("cross-reference chain"))
        );
    }

    #[test]
    fn a_chain_longer_than_the_section_limit_is_refused() {
        let mut pdf = classic_pdf(&page_objects(), "");
        for _ in FIRST_OBJECT..PdfIndex::MAX_XREF_SECTIONS {
            pdf = append_update(&pdf, &[], "");
        }
        assert_eq!(read(&pdf), Ok(ZERO), "a chain at the bound is read");
        assert_eq!(
            read(&append_update(&pdf, &[], "")),
            Err(PdfReadError::Unsupported("cross-reference chain length"))
        );
    }

    #[test]
    fn a_prev_chain_that_loops_is_refused() {
        let base = classic_pdf(&page_objects(), "");
        let update = append_update(&base, &[], "");
        let own = last_start_xref(&update);
        let previous = last_start_xref(&base);
        let looped = replaced(
            &update,
            format!("/Prev {previous} ").as_bytes(),
            format!("/Prev {own:0width$} ", width = previous.to_string().len()).as_bytes(),
        );
        assert_eq!(
            read(&looped),
            Err(PdfReadError::Malformed("cross-reference chain"))
        );
    }

    #[test]
    fn a_malformed_live_signature_dictionary_is_an_error() {
        let mut objects = page_objects();
        objects.push(Vec::from(
            "<< /Type /Sig /ByteRange [0 1 2 3] /Contents (unterminated",
        ));
        assert_eq!(
            read(&classic_pdf(&objects, "")),
            Err(PdfReadError::Malformed("object"))
        );
    }

    /// A comment stands where white space may (ISO 32000-1 sec.7.2.3):
    /// before an object's value, a trailer's dictionary and the catalog.
    #[test]
    fn comments_count_as_white_space_where_a_value_starts() {
        let base = classic_pdf(&page_objects(), "");
        assert_eq!(read(&base), Ok(0));

        let mut commented_catalog = page_objects();
        commented_catalog[0] = format!("% a note\n{}", PAGE_OBJECTS[0]).into_bytes();
        assert_eq!(read(&classic_pdf(&commented_catalog, "")), Ok(0));

        let commented_trailer = replaced(&base, b"trailer\n<<", b"trailer\n% a note\n<<");
        assert_eq!(read(&commented_trailer), Ok(0));

        // A signature dictionary behind a comment is found: its range
        // here contradicts the file, so the document is refused rather
        // than read as unsigned.
        let behind_a_comment = append_update(
            &base,
            &[(
                EXTRA_OBJECT,
                "% a note\n<< /Type /Sig /ByteRange [0 1 2 3] /Contents <00> >>",
            )],
            "",
        );
        assert!(matches!(
            read(&behind_a_comment),
            Err(PdfReadError::Malformed(_))
        ));
        let without_the_comment = append_update(
            &base,
            &[(
                EXTRA_OBJECT,
                "<< /Type /Sig /ByteRange [0 1 2 3] /Contents <00> >>",
            )],
            "",
        );
        assert_eq!(read(&behind_a_comment), read(&without_the_comment));
    }

    #[test]
    fn an_object_body_that_is_no_value_is_an_error() {
        let garbled = append_update(
            &classic_pdf(&page_objects(), ""),
            &[(EXTRA_OBJECT, "]")],
            "",
        );
        assert!(matches!(read(&garbled), Err(PdfReadError::Malformed(_))));
    }

    /// A later revision that replaces the object number of an earlier
    /// signature dictionary does not make that signature vanish.
    #[test]
    fn a_signature_replaced_in_a_later_revision_is_still_found() {
        let (pdf, digest) = signed(&classic_pdf(&page_objects(), ""));
        let dictionary_at = find_first(&pdf, b"/ByteRange").expect("a signature dictionary");
        let header = find_last(&pdf[..dictionary_at], b" 0 obj").expect("its object header");
        let line_start = find_last(&pdf[..header], b"\n").map_or(0, |at| at + 1);
        let number: usize = core::str::from_utf8(&pdf[line_start..header])
            .expect("ASCII")
            .parse()
            .expect("an object number");
        let replaced = append_update(&pdf, &[(number, "<< /Type /Annot >>")], "");
        let document = PdfDocument::parse(&replaced).expect("the updated PDF parses");
        let [signature] = exactly(document.signatures(), "the replaced signature");
        assert_eq!(
            document.digest(&signature.byte_range(), DigestAlgorithm::Sha256),
            digest
        );
        assert_eq!(
            signature.revision(),
            Some(Revision::ChangedAfterSigning(DocumentChange::Annotation))
        );
    }

    #[test]
    fn a_range_must_end_where_a_revision_ends() {
        let (pdf, _digest) = signed(&classic_pdf(&page_objects(), ""));
        assert!(only_signature(&pdf).ends_revision());
        let marker = find_last(&pdf, END_OF_FILE_MARKER).expect("an end marker");
        for end in [marker, marker + END_OF_FILE_MARKER.len() - 1] {
            assert!(!super::ends_revision(&pdf, end), "cut at {end}");
        }
        for eol in [
            END_OF_LINE_LF,
            END_OF_LINE_CR,
            END_OF_LINE_CRLF,
            b"".as_slice(),
        ] {
            let mut revision = b"1 0 obj\nnull\nendobj\n".to_vec();
            revision.extend_from_slice(END_OF_FILE_MARKER);
            revision.extend_from_slice(eol);
            assert!(super::ends_revision(&revision, revision.len()));
        }
    }

    /// A catalog at generation one keeps its generation through the
    /// signature update and the validation-store update.
    #[test]
    fn a_catalog_at_a_nonzero_generation_is_signed_and_extended() {
        let base = classic_pdf(&page_objects(), "");
        let catalog_offset = object_offset(&base, FIRST_OBJECT);
        let mut generation_one = replaced(&base, b"\n1 0 obj", b"\n1 1 obj");
        generation_one = replaced(
            &generation_one,
            entry_line(catalog_offset, IN_USE).as_bytes(),
            format!(
                "{catalog_offset:0width$} {PAGE_GENERATION:0generation$} {IN_USE} \n",
                width = XREF_OFFSET_DIGITS,
                generation = XREF_GENERATION_DIGITS
            )
            .as_bytes(),
        );
        generation_one = replaced(&generation_one, b"/Root 1 0 R", b"/Root 1 1 R");
        assert_eq!(read(&generation_one), Ok(0));

        let (signed, _digest) = signed(&generation_one);
        assert!(find_first(&signed, b"/Root 1 1 R").is_some());
        assert_eq!(read(&signed), Ok(1));
        let stored = append_validation_store(&signed, &[SYNTHETIC_CERTIFICATE.to_vec()], &[], &[])
            .expect("the store appends");
        let document = PdfDocument::parse(&stored).expect("the extended PDF parses");
        assert_eq!(
            document.validation_store().certificates,
            [SYNTHETIC_CERTIFICATE]
        );
        assert_eq!(document.signatures().len(), 1);
    }

    /// A later revision that rewrites a page inside a new object stream
    /// is seen through the live view and judged a change.
    #[test]
    fn an_object_rewritten_through_a_new_object_stream_is_a_change() {
        let (pdf, _digest) = signed(&classic_pdf(&page_objects(), ""));
        let page_number = PAGE_OBJECTS.len();
        let index = PdfIndex::parse(&pdf).expect("the signed PDF indexes");
        let page = index
            .object_body(u32::try_from(page_number).expect("small fixture"))
            .expect("the page");
        let size =
            crate::pades::index::dictionary_usize(index.trailer(), b"/Size").expect("a /Size");
        let container = size;
        let stream_number = container + FIRST_OBJECT;
        let mut updated = pdf.clone();
        let container_at = updated.len();
        updated.extend_from_slice(format!("{container} 0 obj\n").as_bytes());
        updated.extend_from_slice(&object_stream(
            page_number,
            &[replaced(&page, b"200 200", b"200 300")],
        ));
        updated.extend_from_slice(b"\nendobj\n");
        let rows = [
            Row {
                number: page_number,
                kind: XREF_TYPE_COMPRESSED,
                second: container,
                third: u16::MIN,
            },
            Row {
                number: container,
                kind: XREF_TYPE_DIRECT,
                second: container_at,
                third: u16::MIN,
            },
        ];
        let at = updated.len();
        let updated = closed_by(
            updated,
            &xref_stream(
                stream_number,
                at,
                &rows,
                stream_number + FIRST_OBJECT,
                &format!(" /Prev {}", last_start_xref(&pdf)),
            ),
        );
        let [signature] = exactly(
            PdfDocument::parse(&updated)
                .expect("the updated PDF parses")
                .signatures(),
            "one signature",
        )
        .clone();
        assert_eq!(
            signature.revision(),
            Some(Revision::ChangedAfterSigning(DocumentChange::Content))
        );
    }
}
