// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! Reading an `ASiC-E` or `BDOC` container: the ZIP archive
//! [`crate::asic`] writes, and the ones other producers write.
//!
//! The archive is read the way an extractor reads it. The end of
//! central directory record names the central directory, the central
//! directory names every entry, and each local header must agree with
//! its record. Whatever could make two readers see different files is
//! refused: bytes after the end record, a central directory that does
//! not end at it, local entries that do not tile the archive exactly,
//! a name that is not a plain relative path or repeats another after
//! case folding, data whose CRC-32 is not the declared one, a data
//! descriptor that contradicts its record, an extra field that would
//! give an extractor another name, an entry an extractor would create
//! as a symbolic link or a special file, a directory attribute on a
//! file name, and ZIP64, multi-volume, encrypted or unknown-method
//! entries. Decompressed sizes are bounded, and inflation stops at the
//! declared size.
//!
//! The `mimetype` entry is required: the first entry, stored, without
//! an extra field, naming `ASiC-E` or `BDOC`. A container without it,
//! or naming another media type, is not one this reader verifies.
//!
//! The entries are then sorted by role: the data files, the `XAdES`
//! signature files, and each `CAdES` signature with the `ASiCManifest`
//! that names it.
//!
//! # Conformance
//!
//! - `ETSI EN 319 162-1` V1.1.1 clause 4.4 and annex A.1 to A.5: the
//!   `mimetype` entry, `META-INF/*signatures*.xml` for `XAdES`,
//!   `META-INF/*signature*.p7s` with `META-INF/*ASiCManifest*.xml` for
//!   `CAdES`, data files outside `META-INF/`. Clause 4.4.3 lets the
//!   `mimetype` entry be absent; this reader requires it.
//! - `ISO/IEC 21320-1` and PKWARE `APPNOTE.TXT` 6.3: stored (0) or
//!   deflated (8) entries, single volume, no encryption; sec.4.3.9
//!   the data descriptor, sec.4.3.12 the central directory record,
//!   sec.4.3.16 the end of central directory record, sec.4.4.7 the
//!   CRC-32, sec.4.4.15 the external attributes.

use std::collections::HashSet;

use crate::asic::{
    METHOD_STORED, MIMETYPE_ASICE, MIMETYPE_ENTRY, NAMESPACE_ASIC, SIGNATURE_CENTRAL_HEADER,
    SIGNATURE_END_OF_DIRECTORY, SIGNATURE_LOCAL_HEADER, crc32,
};
use crate::base64;
use crate::verification::xades::DigestMethod;
use crate::verification::xml::XmlDocument;
use crate::xades::NAMESPACE_DSIG;

/// Media type of a `BDOC 1.0` container; `BDOC 2.1` carries the
/// `ASiC-E` media type.
const MIMETYPE_BDOC: &str = "application/vnd.bdoc-1.0";

/// The folder holding signatures and manifests (EN 319 162-1 A.4).
const META_INF: &str = "META-INF/";

/// What an `XAdES` signature file's name contains (EN 319 162-1
/// clause 4.4.3.2).
const XADES_NAME_PART: &str = "signatures";

/// What a `CAdES` signature file's name contains (EN 319 162-1 clause
/// 4.4.3.1).
const CADES_NAME_PART: &str = "signature";

/// What an `ASiCManifest` file's name contains (EN 319 162-1 annex A.5).
const MANIFEST_NAME_PART: &str = "ASiCManifest";

/// Extension of an XML file.
const EXTENSION_XML: &str = ".xml";

/// Extension of a detached `CMS` signature.
const EXTENSION_P7S: &str = ".p7s";

/// Root element of an `ASiCManifest` (EN 319 162-1 annex A.5).
const ELEMENT_MANIFEST: &str = "ASiCManifest";

/// The element naming the signature a manifest is signed by.
const ELEMENT_SIG_REFERENCE: &str = "SigReference";

/// The element naming one data file and its digest (EN 319 162-1
/// annex A.5).
const ELEMENT_DATA_OBJECT_REFERENCE: &str = "DataObjectReference";

/// The `ds:DigestMethod` inside a `DataObjectReference`.
const ELEMENT_DIGEST_METHOD: &str = "DigestMethod";

/// The `ds:DigestValue` inside a `DataObjectReference`.
const ELEMENT_DIGEST_VALUE: &str = "DigestValue";

/// The attribute carrying a reference's target.
const ATTRIBUTE_URI: &str = "URI";

/// The attribute naming a digest algorithm.
const ATTRIBUTE_ALGORITHM: &str = "Algorithm";

/// Data descriptor signature, which may precede one (APPNOTE 4.3.9.3).
const SIGNATURE_DATA_DESCRIPTOR: u32 = 0x0807_4B50;

/// ZIP64 end of central directory locator signature (APPNOTE 4.3.15).
const SIGNATURE_ZIP64_LOCATOR: u32 = 0x0706_4B50;

/// Length of the ZIP64 end of central directory locator (APPNOTE 4.3.15).
const ZIP64_LOCATOR_LEN: usize = 20;

/// General-purpose bit 0: the entry is encrypted (APPNOTE 4.4.4).
const FLAG_ENCRYPTED: u16 = 0x0001;

/// General-purpose bit 3: CRC and sizes follow the data in a data
/// descriptor (APPNOTE 4.4.4).
const FLAG_DATA_DESCRIPTOR: u16 = 0x0008;

/// General-purpose bit 6: strong encryption (APPNOTE 4.4.4).
const FLAG_STRONG_ENCRYPTION: u16 = 0x0040;

/// Compression method 8: deflated (APPNOTE 4.4.5).
const METHOD_DEFLATED: u16 = 8;

/// Fixed part of the end of central directory record, signature
/// included (APPNOTE 4.3.16).
const END_OF_DIRECTORY_LEN: usize = 22;

/// Longest archive comment: its length field is 16 bits.
const MAX_ARCHIVE_COMMENT_LEN: usize = 0xFFFF;

/// A 16-bit field holding this value defers to a ZIP64 record
/// (APPNOTE 4.4.1.4).
const ZIP64_MARKER_U16: u16 = u16::MAX;

/// A 32-bit field holding this value defers to a ZIP64 record.
const ZIP64_MARKER_U32: u32 = u32::MAX;

/// The only disk number a single-volume archive carries.
const SINGLE_DISK: u16 = 0;

/// Extra field header id of the ZIP64 extended information (APPNOTE
/// 4.5.3).
const EXTRA_ZIP64: u16 = 0x0001;

/// Extra field header id of the Info-ZIP Unicode Comment (APPNOTE
/// 4.6.8).
const EXTRA_UNICODE_COMMENT: u16 = 0x6375;

/// Extra field header id of the Info-ZIP Unicode Path (APPNOTE 4.6.9),
/// which would give an extractor another name.
const EXTRA_UNICODE_PATH: u16 = 0x7075;

/// Shift to the host-dependent upper half of the external attributes,
/// where a Unix archiver stores the file mode (APPNOTE 4.4.15).
const UNIX_MODE_SHIFT: u32 = 16;

/// `S_IFMT`: the file-type bits of a Unix mode (POSIX `<sys/stat.h>`).
const UNIX_FILE_TYPE_MASK: u32 = 0o170_000;

/// `S_IFREG`: the regular-file type.
const UNIX_REGULAR_FILE: u32 = 0o100_000;

/// `S_IFDIR`: the directory type.
const UNIX_DIRECTORY: u32 = 0o040_000;

/// `S_IFLNK`: the symbolic-link type.
const UNIX_SYMBOLIC_LINK: u32 = 0o120_000;

/// The file-type bits of an archive that records no Unix mode.
const UNIX_NO_TYPE: u32 = 0;

/// MS-DOS directory attribute, in the low byte of the external
/// attributes (APPNOTE 4.4.15).
const DOS_DIRECTORY_ATTRIBUTE: u32 = 0x10;

/// Path separator inside an archive (APPNOTE 4.4.17.1).
const ENTRY_SEPARATOR: char = '/';

/// The separator an archive name must not use (APPNOTE 4.4.17.1).
const FORBIDDEN_SEPARATOR: char = '\\';

/// A path component naming the directory itself.
const CURRENT_DIRECTORY: &str = ".";

/// A path component naming the parent directory.
const PARENT_DIRECTORY: &str = "..";

/// Offset of the first local header: where the `mimetype` entry sits
/// (EN 319 162-1 annex A.1).
const FIRST_ENTRY_OFFSET: usize = 0;

/// Most entries a container may carry.
const MAX_ENTRIES: usize = 4096;

/// Most decompressed bytes in the whole container: 512 MiB.
const MAX_TOTAL_BYTES: usize = 512 << 20;

/// Octets of a little-endian `u16`.
const U16_LEN: usize = 2;

/// Octets of a little-endian `u32`.
const U32_LEN: usize = 4;

/// Radix of a percent escape's two digits (RFC 3986 sec.2.1).
const PERCENT_RADIX: u32 = 16;

/// Digits in one percent escape.
const PERCENT_DIGITS: usize = 2;

/// Introduces a percent escape.
const PERCENT: u8 = b'%';

/// Why a container yielded no entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsicReadError {
    /// The file does not start as a ZIP archive does.
    NotAZip,
    /// The archive structure is inconsistent.
    Malformed(&'static str),
    /// A ZIP feature outside the `ASiC` profile.
    Unsupported(&'static str),
    /// The archive has no `mimetype` entry, so it does not say it is an
    /// `ASiC-E` or `BDOC` container.
    MissingMimetype,
    /// The `mimetype` entry names a media type other than `ASiC-E` or
    /// `BDOC`.
    UnknownMimetype,
}

impl core::fmt::Display for AsicReadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotAZip => f.write_str("not a ZIP archive"),
            Self::Malformed(what) => write!(f, "malformed container: {what}"),
            Self::Unsupported(what) => write!(f, "unsupported container: {what}"),
            Self::MissingMimetype => f.write_str("unsupported container: no mimetype entry"),
            Self::UnknownMimetype => {
                f.write_str("unsupported container: the mimetype is neither ASiC-E nor BDOC")
            }
        }
    }
}

impl core::error::Error for AsicReadError {}

/// The container's media type, from its `mimetype` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mimetype {
    /// `application/vnd.etsi.asic-e+zip`: `ASiC-E`, and `BDOC 2.1`.
    AsicE,
    /// `application/vnd.bdoc-1.0`.
    Bdoc,
}

impl Mimetype {
    /// The media type `content` names, when it is a known one.
    fn from_content(content: &[u8]) -> Option<Self> {
        if content == MIMETYPE_ASICE.as_bytes() {
            Some(Self::AsicE)
        } else if content == MIMETYPE_BDOC.as_bytes() {
            Some(Self::Bdoc)
        } else {
            None
        }
    }
}

/// One file inside the container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The entry name: a plain relative path from the container root.
    name: String,
    /// The decompressed content, CRC-checked.
    content: Vec<u8>,
}

impl Entry {
    /// The entry name: a plain relative path from the container root.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The decompressed content, its CRC-32 checked.
    #[must_use]
    pub fn content(&self) -> &[u8] {
        &self.content
    }
}

/// A `CAdES` signature file with the manifest it signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CadesEntry {
    /// `META-INF/*signature*.p7s`.
    signature: Entry,
    /// The `META-INF/*ASiCManifest*.xml` whose `SigReference` names the
    /// signature.
    manifest: Option<Entry>,
}

impl CadesEntry {
    /// `META-INF/*signature*.p7s`.
    #[must_use]
    pub const fn signature(&self) -> &Entry {
        &self.signature
    }

    /// The `META-INF/*ASiCManifest*.xml` whose `SigReference` names the
    /// signature; `None` when no manifest names it.
    #[must_use]
    pub const fn manifest(&self) -> Option<&Entry> {
        self.manifest.as_ref()
    }
}

/// A read container, its entries sorted by role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsicContainer {
    /// From the `mimetype` entry.
    mimetype: Mimetype,
    /// Entries outside `META-INF/`, `mimetype` excluded.
    data_files: Vec<Entry>,
    /// `META-INF/*signatures*.xml`.
    xades_signature_files: Vec<Entry>,
    /// `META-INF/*signature*.p7s` with their manifests.
    cades_signatures: Vec<CadesEntry>,
}

impl AsicContainer {
    /// Read the container in `file`.
    ///
    /// # Errors
    /// [`AsicReadError::NotAZip`] when the file does not start with a
    /// local file header, [`AsicReadError::MissingMimetype`] and
    /// [`AsicReadError::UnknownMimetype`] for an archive that is not an
    /// `ASiC-E` or `BDOC` container, and otherwise the structural
    /// refusals the module documentation lists.
    pub fn parse(file: &[u8]) -> Result<Self, AsicReadError> {
        let entries = read_zip(file)?;
        Self::sort(entries)
    }

    /// Check the `mimetype` entry and sort the others by role.
    fn sort(entries: Vec<LocatedEntry>) -> Result<Self, AsicReadError> {
        let mut mimetype = None;
        let mut data_files = Vec::new();
        let mut xades_signature_files = Vec::new();
        let mut cades_files = Vec::new();
        let mut manifests = Vec::new();
        for located in entries {
            let entry = located.entry;
            if entry.name == MIMETYPE_ENTRY {
                if located.local_offset != FIRST_ENTRY_OFFSET {
                    return Err(AsicReadError::Malformed("mimetype is not the first entry"));
                }
                if !located.stored_plain {
                    return Err(AsicReadError::Malformed(
                        "mimetype is compressed or carries an extra field",
                    ));
                }
                mimetype = Some(
                    Mimetype::from_content(&entry.content).ok_or(AsicReadError::UnknownMimetype)?,
                );
                continue;
            }
            let Some(inside) = entry.name.strip_prefix(META_INF) else {
                data_files.push(entry);
                continue;
            };
            // Signature files sit directly in META-INF, not below it.
            if inside.contains(ENTRY_SEPARATOR) {
                continue;
            }
            if inside.contains(XADES_NAME_PART) && inside.ends_with(EXTENSION_XML) {
                xades_signature_files.push(entry);
            } else if inside.contains(CADES_NAME_PART) && inside.ends_with(EXTENSION_P7S) {
                cades_files.push(entry);
            } else if inside.contains(MANIFEST_NAME_PART) && inside.ends_with(EXTENSION_XML) {
                manifests.push(entry);
            }
        }
        let mimetype = mimetype.ok_or(AsicReadError::MissingMimetype)?;
        let cades_signatures = cades_files
            .into_iter()
            .map(|signature| {
                let manifest = manifests
                    .iter()
                    .find(|manifest| manifest_names(manifest, &signature.name))
                    .cloned();
                CadesEntry {
                    signature,
                    manifest,
                }
            })
            .collect();
        Ok(Self {
            mimetype,
            data_files,
            xades_signature_files,
            cades_signatures,
        })
    }

    /// The media type the `mimetype` entry names.
    #[must_use]
    pub const fn mimetype(&self) -> Mimetype {
        self.mimetype
    }

    /// Every entry outside `META-INF/` other than `mimetype`, in
    /// central directory order.
    #[must_use]
    pub fn data_files(&self) -> &[Entry] {
        &self.data_files
    }

    /// `META-INF/*signatures*.xml`, in central directory order.
    #[must_use]
    pub fn xades_signature_files(&self) -> &[Entry] {
        &self.xades_signature_files
    }

    /// `META-INF/*signature*.p7s` with the manifests naming them, in
    /// central directory order.
    #[must_use]
    pub fn cades_signatures(&self) -> &[CadesEntry] {
        &self.cades_signatures
    }

    /// The data file of this name.
    #[must_use]
    pub fn data_file(&self, name: &str) -> Option<&Entry> {
        self.data_files.iter().find(|entry| entry.name == name)
    }

    /// Whether the `ASiCManifest` paired with `entry` binds exactly
    /// this container's data files to its signature (EN 319 162-1
    /// annex A.5 and A.6): it parses, its one `SigReference` names
    /// `entry`'s signature, every `DataObjectReference` names a data
    /// file whose digest under a `SHA-256`, `SHA-384` or `SHA-512`
    /// `DigestMethod` equals its `DigestValue`, and every data file is
    /// referenced. A missing manifest, an unknown digest method, a
    /// missing file or an unreferenced data file gives false.
    ///
    /// The signature over the manifest bytes is judged by the caller.
    #[must_use]
    pub fn manifest_intact(&self, entry: &CadesEntry) -> bool {
        let Some(manifest) = &entry.manifest else {
            return false;
        };
        let Ok(document) = XmlDocument::parse(manifest.content.clone()) else {
            return false;
        };
        let root = document.root();
        if !root.is(NAMESPACE_ASIC, ELEMENT_MANIFEST) {
            return false;
        }
        let mut sig_references = root.children_named(NAMESPACE_ASIC, ELEMENT_SIG_REFERENCE);
        let names_signature = match (sig_references.next(), sig_references.next()) {
            (Some(reference), None) => reference
                .attribute(ATTRIBUTE_URI)
                .and_then(percent_decode)
                .is_some_and(|uri| uri == entry.signature.name),
            _ => false,
        };
        let mut referenced: HashSet<&str> = HashSet::new();
        for reference in root.children_named(NAMESPACE_ASIC, ELEMENT_DATA_OBJECT_REFERENCE) {
            let Some(file) = reference
                .attribute(ATTRIBUTE_URI)
                .and_then(percent_decode)
                .and_then(|name| self.data_file(&name))
            else {
                return false;
            };
            let Some(method) = reference
                .child(NAMESPACE_DSIG, ELEMENT_DIGEST_METHOD)
                .and_then(|method| method.attribute(ATTRIBUTE_ALGORITHM))
                .and_then(DigestMethod::from_uri)
            else {
                return false;
            };
            let Some(value) = reference
                .child(NAMESPACE_DSIG, ELEMENT_DIGEST_VALUE)
                .and_then(|value| base64::decode_wrapped(&value.text()).ok())
            else {
                return false;
            };
            if method.digest(&file.content) != value {
                return false;
            }
            referenced.insert(&file.name);
        }
        names_signature
            && self
                .data_files
                .iter()
                .all(|file| referenced.contains(file.name.as_str()))
    }
}

/// Whether `manifest` is an `ASiCManifest` whose `SigReference` names
/// the entry `signature_name`. A manifest that does not parse names
/// nothing.
fn manifest_names(manifest: &Entry, signature_name: &str) -> bool {
    let Ok(document) = XmlDocument::parse(manifest.content.clone()) else {
        return false;
    };
    let root = document.root();
    if !root.is(NAMESPACE_ASIC, ELEMENT_MANIFEST) {
        return false;
    }
    root.children_named(NAMESPACE_ASIC, ELEMENT_SIG_REFERENCE)
        .filter_map(|reference| reference.attribute(ATTRIBUTE_URI))
        .filter_map(percent_decode)
        .any(|uri| uri == signature_name)
}

/// Decode `%XX` escapes in a reference URI (RFC 3986 sec.2.1) into the
/// UTF-8 entry name they spell. `None` for a malformed escape or a
/// result that is not UTF-8.
pub(crate) fn percent_decode(uri: &str) -> Option<String> {
    let mut out = Vec::with_capacity(uri.len());
    let mut bytes = uri.bytes();
    while let Some(byte) = bytes.next() {
        if byte == PERCENT {
            let digits: Vec<u8> = bytes.by_ref().take(PERCENT_DIGITS).collect();
            let text = core::str::from_utf8(&digits).ok()?;
            if text.len() != PERCENT_DIGITS || !text.chars().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            out.push(u8::from_str_radix(text, PERCENT_RADIX).ok()?);
        } else {
            out.push(byte);
        }
    }
    String::from_utf8(out).ok()
}

/// One file entry with the facts about its placement that the
/// `mimetype` rules consult.
struct LocatedEntry {
    /// The entry.
    entry: Entry,
    /// Offset of its local header.
    local_offset: usize,
    /// Whether it is stored uncompressed with no extra field in either
    /// header.
    stored_plain: bool,
}

/// Where the central directory sits, from the end record.
struct EndOfDirectory {
    /// Offset of the end record: where the central directory must end.
    offset: usize,
    /// Number of central directory records.
    count: usize,
    /// Offset of the first central directory record.
    central_offset: usize,
}

/// One central directory record.
struct CentralRecord {
    /// General-purpose flags.
    flags: u16,
    /// Compression method.
    method: u16,
    /// CRC-32 of the uncompressed data.
    crc: u32,
    /// Stored length.
    compressed_len: usize,
    /// Decompressed length.
    uncompressed_len: usize,
    /// Entry name as stored.
    name: Vec<u8>,
    /// Whether the record carries an extra field.
    has_extra: bool,
    /// Whether the external attributes declare a directory.
    directory_attribute: bool,
    /// Offset of the local file header.
    local_offset: usize,
}

/// The archive extent one local entry occupies.
struct LocalExtent {
    /// The local header's offset.
    start: usize,
    /// One past the data, or the data descriptor.
    end: usize,
}

/// Read every entry the central directory lists.
/// Whether `file` starts with a ZIP local file header, as every `ASiC`
/// container does (`ETSI EN 319 162-1` clause A.1).
pub(crate) fn starts_as_zip(file: &[u8]) -> bool {
    Cursor::new(file).u32() == Some(SIGNATURE_LOCAL_HEADER)
}

fn read_zip(bytes: &[u8]) -> Result<Vec<LocatedEntry>, AsicReadError> {
    if Cursor::new(bytes).u32() != Some(SIGNATURE_LOCAL_HEADER) {
        return Err(AsicReadError::NotAZip);
    }
    let end = find_end_of_directory(bytes)?;
    let records = read_central_directory(bytes, &end)?;
    let mut entries = Vec::with_capacity(records.len());
    let mut extents = Vec::with_capacity(records.len());
    let mut folded_names: HashSet<String> = HashSet::with_capacity(records.len());
    let mut total = 0_usize;
    for record in &records {
        total = total
            .checked_add(record.uncompressed_len)
            .filter(|declared| *declared <= MAX_TOTAL_BYTES)
            .ok_or(AsicReadError::Unsupported(
                "container exceeds the decompressed-size bound",
            ))?;
        let (entry, extent) = read_local_entry(bytes, record)?;
        extents.push(extent);
        let Some(entry) = entry else {
            continue;
        };
        if !folded_names.insert(entry.entry.name.to_lowercase()) {
            return Err(AsicReadError::Malformed("duplicate entry name"));
        }
        entries.push(entry);
    }
    require_exact_tiling(extents, end.central_offset)?;
    Ok(entries)
}

/// Locate the end of central directory record, which must end exactly
/// at the end of the file, and check the geometry it declares.
///
/// An archive comment may itself contain the signature bytes, so a
/// candidate whose comment does not reach the end of the file is
/// skipped rather than refused.
fn find_end_of_directory(bytes: &[u8]) -> Result<EndOfDirectory, AsicReadError> {
    /// No candidate record ends the file.
    const MISSING: AsicReadError =
        AsicReadError::Malformed("no end of central directory record ends the file");
    /// A candidate record is cut short.
    const TRUNCATED: AsicReadError =
        AsicReadError::Malformed("truncated end of central directory record");
    let latest = bytes
        .len()
        .checked_sub(END_OF_DIRECTORY_LEN)
        .ok_or(MISSING)?;
    let earliest = latest.saturating_sub(MAX_ARCHIVE_COMMENT_LEN);
    for offset in (earliest..=latest).rev() {
        let mut cursor = Cursor::at(bytes, offset);
        if cursor.u32() != Some(SIGNATURE_END_OF_DIRECTORY) {
            continue;
        }
        let disk = cursor.u16().ok_or(TRUNCATED)?;
        let directory_disk = cursor.u16().ok_or(TRUNCATED)?;
        let count_on_disk = cursor.u16().ok_or(TRUNCATED)?;
        let count = cursor.u16().ok_or(TRUNCATED)?;
        let central_size = cursor.u32().ok_or(TRUNCATED)?;
        let central_offset = cursor.u32().ok_or(TRUNCATED)?;
        let comment_len = cursor.u16().ok_or(TRUNCATED)?;
        if cursor.position().checked_add(usize::from(comment_len)) != Some(bytes.len()) {
            continue;
        }
        if count_on_disk == ZIP64_MARKER_U16
            || count == ZIP64_MARKER_U16
            || central_size == ZIP64_MARKER_U32
            || central_offset == ZIP64_MARKER_U32
            || offset
                .checked_sub(ZIP64_LOCATOR_LEN)
                .is_some_and(|at| Cursor::at(bytes, at).u32() == Some(SIGNATURE_ZIP64_LOCATOR))
        {
            return Err(AsicReadError::Unsupported("ZIP64"));
        }
        if disk != SINGLE_DISK || directory_disk != SINGLE_DISK {
            return Err(AsicReadError::Unsupported("multi-volume archive"));
        }
        if count_on_disk != count {
            return Err(AsicReadError::Malformed("entry counts disagree"));
        }
        let central_offset = usize::try_from(central_offset).map_err(|_ignored| TRUNCATED)?;
        let central_size = usize::try_from(central_size).map_err(|_ignored| TRUNCATED)?;
        if central_offset.checked_add(central_size) != Some(offset) {
            return Err(AsicReadError::Malformed(
                "central directory does not end at the end record",
            ));
        }
        return Ok(EndOfDirectory {
            offset,
            count: usize::from(count),
            central_offset,
        });
    }
    Err(MISSING)
}

/// Read exactly the declared number of central directory records,
/// which must fill the central directory to the byte.
fn read_central_directory(
    bytes: &[u8],
    end: &EndOfDirectory,
) -> Result<Vec<CentralRecord>, AsicReadError> {
    if end.count > MAX_ENTRIES {
        return Err(AsicReadError::Unsupported("too many entries"));
    }
    let mut cursor = Cursor::at(bytes, end.central_offset);
    let mut records = Vec::with_capacity(end.count);
    for _ in 0..end.count {
        if cursor.u32() != Some(SIGNATURE_CENTRAL_HEADER) {
            return Err(AsicReadError::Malformed(
                "central directory record without its signature",
            ));
        }
        records.push(CentralRecord::read(&mut cursor)?);
    }
    if cursor.position() != end.offset {
        return Err(AsicReadError::Malformed(
            "central directory does not end at the end record",
        ));
    }
    Ok(records)
}

impl CentralRecord {
    /// Read one record past its signature (APPNOTE 4.3.12).
    fn read(cursor: &mut Cursor<'_>) -> Result<Self, AsicReadError> {
        /// The record is cut short.
        const TRUNCATED: AsicReadError =
            AsicReadError::Malformed("truncated central directory record");
        let _version_made_by = cursor.u16().ok_or(TRUNCATED)?;
        let _version_needed = cursor.u16().ok_or(TRUNCATED)?;
        let flags = cursor.u16().ok_or(TRUNCATED)?;
        let method = cursor.u16().ok_or(TRUNCATED)?;
        let _modification_time = cursor.u16().ok_or(TRUNCATED)?;
        let _modification_date = cursor.u16().ok_or(TRUNCATED)?;
        let crc = cursor.u32().ok_or(TRUNCATED)?;
        let compressed = cursor.u32().ok_or(TRUNCATED)?;
        let uncompressed = cursor.u32().ok_or(TRUNCATED)?;
        let name_len = cursor.u16().ok_or(TRUNCATED)?;
        let extra_len = cursor.u16().ok_or(TRUNCATED)?;
        let comment_len = cursor.u16().ok_or(TRUNCATED)?;
        let disk = cursor.u16().ok_or(TRUNCATED)?;
        let _internal_attributes = cursor.u16().ok_or(TRUNCATED)?;
        let external_attributes = cursor.u32().ok_or(TRUNCATED)?;
        let local_offset = cursor.u32().ok_or(TRUNCATED)?;
        let name = cursor
            .take(usize::from(name_len))
            .ok_or(TRUNCATED)?
            .to_vec();
        let extra = cursor.take(usize::from(extra_len)).ok_or(TRUNCATED)?;
        cursor.take(usize::from(comment_len)).ok_or(TRUNCATED)?;
        if compressed == ZIP64_MARKER_U32
            || uncompressed == ZIP64_MARKER_U32
            || local_offset == ZIP64_MARKER_U32
        {
            return Err(AsicReadError::Unsupported("ZIP64"));
        }
        if disk != SINGLE_DISK {
            return Err(AsicReadError::Unsupported("multi-volume archive"));
        }
        let directory_attribute = file_type_is_directory(external_attributes)?;
        require_plain_extra_field(extra)?;
        Ok(Self {
            flags,
            method,
            crc,
            compressed_len: usize::try_from(compressed).map_err(|_ignored| TRUNCATED)?,
            uncompressed_len: usize::try_from(uncompressed).map_err(|_ignored| TRUNCATED)?,
            name,
            has_extra: !extra.is_empty(),
            directory_attribute,
            local_offset: usize::try_from(local_offset).map_err(|_ignored| TRUNCATED)?,
        })
    }
}

/// Whether the external attributes declare a directory, refusing an
/// entry an extractor would create as a symbolic link or a special
/// file (APPNOTE 4.4.15; the Unix mode in the upper half, the MS-DOS
/// attributes in the low byte).
fn file_type_is_directory(external: u32) -> Result<bool, AsicReadError> {
    let unix_type = (external >> UNIX_MODE_SHIFT) & UNIX_FILE_TYPE_MASK;
    let unix_directory = match unix_type {
        UNIX_NO_TYPE | UNIX_REGULAR_FILE => false,
        UNIX_DIRECTORY => true,
        UNIX_SYMBOLIC_LINK => return Err(AsicReadError::Unsupported("symbolic link entry")),
        _ => return Err(AsicReadError::Unsupported("special file entry")),
    };
    Ok(unix_directory || external & DOS_DIRECTORY_ATTRIBUTE != 0)
}

/// Walk an extra field as the (id, size, data) records APPNOTE 4.5.1
/// defines, refusing a malformed one and any that would give an
/// extractor another name or size.
fn require_plain_extra_field(extra: &[u8]) -> Result<(), AsicReadError> {
    /// The extra field is not a sequence of records.
    const MALFORMED: AsicReadError = AsicReadError::Malformed("malformed extra field");
    let mut cursor = Cursor::new(extra);
    while cursor.position() < extra.len() {
        let id = cursor.u16().ok_or(MALFORMED)?;
        let size = cursor.u16().ok_or(MALFORMED)?;
        cursor.take(usize::from(size)).ok_or(MALFORMED)?;
        match id {
            EXTRA_ZIP64 => return Err(AsicReadError::Unsupported("ZIP64")),
            EXTRA_UNICODE_PATH => {
                return Err(AsicReadError::Unsupported("Unicode Path extra field"));
            }
            EXTRA_UNICODE_COMMENT => {
                return Err(AsicReadError::Unsupported("Unicode Comment extra field"));
            }
            _ => {}
        }
    }
    Ok(())
}

/// The entry name as a plain relative path: UTF-8, not absolute, no
/// backslash or control character, every component non-empty and
/// neither `.` nor `..`. `Ok(None)` for a directory entry, which an
/// archiver may list and which carries no file.
fn plain_entry_name(name: &[u8]) -> Result<Option<String>, AsicReadError> {
    let name = String::from_utf8(name.to_vec())
        .map_err(|_ignored| AsicReadError::Malformed("entry name is not UTF-8"))?;
    if name.is_empty() {
        return Err(AsicReadError::Malformed("empty entry name"));
    }
    if name.starts_with(ENTRY_SEPARATOR) {
        return Err(AsicReadError::Malformed("absolute entry name"));
    }
    if name.contains(FORBIDDEN_SEPARATOR) {
        return Err(AsicReadError::Malformed("backslash in an entry name"));
    }
    if name.chars().any(char::is_control) {
        return Err(AsicReadError::Malformed(
            "control character in an entry name",
        ));
    }
    let (path, directory) = match name.strip_suffix(ENTRY_SEPARATOR) {
        Some(path) => (path, true),
        None => (name.as_str(), false),
    };
    for component in path.split(ENTRY_SEPARATOR) {
        if component.is_empty() || component == CURRENT_DIRECTORY || component == PARENT_DIRECTORY {
            return Err(AsicReadError::Malformed("entry name is not a plain path"));
        }
    }
    Ok((!directory).then_some(name))
}

/// The local header fields a reader compares with the central record
/// (APPNOTE 4.3.7).
struct LocalHeader {
    /// General-purpose flags.
    flags: u16,
    /// Compression method.
    method: u16,
    /// CRC-32, zero when a data descriptor carries it.
    crc: u32,
    /// Stored length, zero when a data descriptor carries it.
    compressed_len: usize,
    /// Decompressed length, zero when a data descriptor carries it.
    uncompressed_len: usize,
    /// Name length.
    name_len: usize,
    /// Extra field length.
    extra_len: usize,
}

impl LocalHeader {
    /// Read one header past its signature.
    fn read(cursor: &mut Cursor<'_>) -> Option<Self> {
        let _version_needed = cursor.u16()?;
        let flags = cursor.u16()?;
        let method = cursor.u16()?;
        let _modification_time = cursor.u16()?;
        let _modification_date = cursor.u16()?;
        let crc = cursor.u32()?;
        let compressed = cursor.u32()?;
        let uncompressed = cursor.u32()?;
        let name_len = cursor.u16()?;
        let extra_len = cursor.u16()?;
        Some(Self {
            flags,
            method,
            crc,
            compressed_len: usize::try_from(compressed).ok()?,
            uncompressed_len: usize::try_from(uncompressed).ok()?,
            name_len: usize::from(name_len),
            extra_len: usize::from(extra_len),
        })
    }
}

/// Read the local entry a central record points at, requiring the two
/// to agree on everything that decides what the entry is. `None` for a
/// directory entry.
fn read_local_entry(
    bytes: &[u8],
    record: &CentralRecord,
) -> Result<(Option<LocatedEntry>, LocalExtent), AsicReadError> {
    let mut cursor = Cursor::at(bytes, record.local_offset);
    if cursor.u32() != Some(SIGNATURE_LOCAL_HEADER) {
        return Err(AsicReadError::Malformed(
            "central directory names an offset that is not a local header",
        ));
    }
    let header =
        LocalHeader::read(&mut cursor).ok_or(AsicReadError::Malformed("truncated local header"))?;
    let name_bytes = cursor
        .take(header.name_len)
        .ok_or(AsicReadError::Malformed("truncated entry name"))?;
    let extra = cursor
        .take(header.extra_len)
        .ok_or(AsicReadError::Malformed("truncated extra field"))?;
    if header.flags & (FLAG_ENCRYPTED | FLAG_STRONG_ENCRYPTION) != 0 {
        return Err(AsicReadError::Unsupported("encrypted entry"));
    }
    let descriptor = header.flags & FLAG_DATA_DESCRIPTOR != 0;
    // With a data descriptor the local header may carry zeros where the
    // CRC and sizes go; the central record and the descriptor carry
    // them (APPNOTE 4.4.4 bit 3).
    let sizes_agree = if descriptor {
        (header.crc == 0 || header.crc == record.crc)
            && (header.compressed_len == 0 || header.compressed_len == record.compressed_len)
            && (header.uncompressed_len == 0 || header.uncompressed_len == record.uncompressed_len)
    } else {
        header.crc == record.crc
            && header.compressed_len == record.compressed_len
            && header.uncompressed_len == record.uncompressed_len
    };
    if header.flags != record.flags
        || header.method != record.method
        || !sizes_agree
        || name_bytes != record.name.as_slice()
    {
        return Err(AsicReadError::Malformed(
            "central directory and local header disagree",
        ));
    }
    require_plain_extra_field(extra)?;
    let stored = cursor
        .take(record.compressed_len)
        .ok_or(AsicReadError::Malformed("truncated entry data"))?;
    if descriptor {
        read_data_descriptor(&mut cursor, record)?;
    }
    let extent = LocalExtent {
        start: record.local_offset,
        end: cursor.position(),
    };
    let Some(name) = plain_entry_name(&record.name)? else {
        if record.uncompressed_len != 0 {
            return Err(AsicReadError::Malformed("directory entry with content"));
        }
        return Ok((None, extent));
    };
    if record.directory_attribute {
        return Err(AsicReadError::Malformed(
            "directory attribute on a file entry",
        ));
    }
    let content = match header.method {
        METHOD_STORED => stored.to_vec(),
        METHOD_DEFLATED => {
            miniz_oxide::inflate::decompress_to_vec_with_limit(stored, record.uncompressed_len)
                .map_err(|_ignored| {
                    AsicReadError::Malformed("deflated data does not inflate to its size")
                })?
        }
        _ => return Err(AsicReadError::Unsupported("compression method")),
    };
    if content.len() != record.uncompressed_len {
        return Err(AsicReadError::Malformed(
            "entry size does not match its header",
        ));
    }
    if crc32(&content) != record.crc {
        return Err(AsicReadError::Malformed(
            "entry data does not match its CRC-32",
        ));
    }
    let stored_plain = header.method == METHOD_STORED && extra.is_empty() && !record.has_extra;
    Ok((
        Some(LocatedEntry {
            entry: Entry { name, content },
            local_offset: record.local_offset,
            stored_plain,
        }),
        extent,
    ))
}

/// Read the data descriptor after an entry's data (APPNOTE 4.3.9): an
/// optional signature, the CRC-32 and both sizes, which must equal the
/// central record's.
fn read_data_descriptor(
    cursor: &mut Cursor<'_>,
    record: &CentralRecord,
) -> Result<(), AsicReadError> {
    /// The descriptor is cut short or disagrees with the record.
    const DISAGREES: AsicReadError =
        AsicReadError::Malformed("data descriptor disagrees with the central directory");
    let mut probe = Cursor::at(cursor.bytes, cursor.position());
    if probe.u32() == Some(SIGNATURE_DATA_DESCRIPTOR) {
        cursor.u32().ok_or(DISAGREES)?;
    }
    let crc = cursor.u32().ok_or(DISAGREES)?;
    let compressed = cursor.u32().ok_or(DISAGREES)?;
    let uncompressed = cursor.u32().ok_or(DISAGREES)?;
    if crc != record.crc
        || usize::try_from(compressed).ok() != Some(record.compressed_len)
        || usize::try_from(uncompressed).ok() != Some(record.uncompressed_len)
    {
        return Err(DISAGREES);
    }
    Ok(())
}

/// The listed local entries must cover the bytes before the central
/// directory exactly, so nothing hides between or beside them.
fn require_exact_tiling(
    mut extents: Vec<LocalExtent>,
    central_offset: usize,
) -> Result<(), AsicReadError> {
    /// Bytes outside every listed entry.
    const GAP: AsicReadError =
        AsicReadError::Malformed("local entries do not tile the archive exactly");
    extents.sort_unstable_by_key(|extent| extent.start);
    let mut expected = 0_usize;
    for extent in &extents {
        if extent.start != expected {
            return Err(GAP);
        }
        expected = extent.end;
    }
    if expected != central_offset {
        return Err(GAP);
    }
    Ok(())
}

/// Byte cursor that fails closed instead of slicing out of range.
struct Cursor<'a> {
    /// The whole input.
    bytes: &'a [u8],
    /// The next unread offset.
    position: usize,
}

impl<'a> Cursor<'a> {
    /// A cursor at the start of `bytes`.
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    /// A cursor at `position`; reads past the end fail.
    const fn at(bytes: &'a [u8], position: usize) -> Self {
        Self { bytes, position }
    }

    /// The next unread offset.
    const fn position(&self) -> usize {
        self.position
    }

    /// The next `len` bytes.
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.position.checked_add(len)?;
        let slice = self.bytes.get(self.position..end)?;
        self.position = end;
        Some(slice)
    }

    /// A little-endian `u16`.
    fn u16(&mut self) -> Option<u16> {
        let pair: [u8; U16_LEN] = self.take(U16_LEN)?.try_into().ok()?;
        Some(u16::from_le_bytes(pair))
    }

    /// A little-endian `u32`.
    fn u32(&mut self) -> Option<u32> {
        let quad: [u8; U32_LEN] = self.take(U32_LEN)?.try_into().ok()?;
        Some(u32::from_le_bytes(quad))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AsicContainer, AsicReadError, DOS_DIRECTORY_ATTRIBUTE, EXTRA_UNICODE_PATH, EXTRA_ZIP64,
        FLAG_DATA_DESCRIPTOR, FLAG_ENCRYPTED, METHOD_DEFLATED, MIMETYPE_BDOC, Mimetype,
        SIGNATURE_DATA_DESCRIPTOR, UNIX_DIRECTORY, UNIX_MODE_SHIFT, UNIX_REGULAR_FILE,
        UNIX_SYMBOLIC_LINK, percent_decode,
    };
    use crate::asic::{DataObject, MIMETYPE_ASICE, MIMETYPE_ENTRY, crc32, plan};
    use crate::cades::DigestAlgorithm;
    use crate::verification::exactly;

    /// Test-only archive assembler: every record is a plain function,
    /// so a test can duplicate, hide, misplace or contradict one.
    mod raw {
        use super::super::{
            METHOD_DEFLATED, METHOD_STORED, SIGNATURE_CENTRAL_HEADER, SIGNATURE_END_OF_DIRECTORY,
            SIGNATURE_LOCAL_HEADER, SIGNATURE_ZIP64_LOCATOR, ZIP64_LOCATOR_LEN, crc32,
        };

        /// Version needed to extract: 2.0 (APPNOTE 4.4.3.2).
        const VERSION: u16 = 20;
        /// No general-purpose flags: not encrypted, no data descriptor.
        const NO_FLAGS: u16 = 0;
        /// Single-volume disk number (ISO/IEC 21320-1).
        const DISK: u16 = 0;
        /// External attributes of a plain file as a DOS archiver writes
        /// them.
        const PLAIN_FILE: u32 = 0;
        /// `deflate` level for the hand-built archives: the default.
        const DEFLATE_LEVEL: u8 = 6;

        /// What a header declares about its data; a test may declare
        /// something other than the truth.
        #[derive(Clone)]
        pub struct Declared {
            pub name: Vec<u8>,
            pub flags: u16,
            pub method: u16,
            pub compressed: u32,
            pub uncompressed: u32,
            pub crc: u32,
            pub extra: Vec<u8>,
            pub external: u32,
        }

        impl Declared {
            /// A stored entry declaring `data` truthfully.
            pub fn truthful(name: &[u8], data: &[u8]) -> Self {
                let size = u32::try_from(data.len()).expect("fixture fits");
                Self {
                    name: name.to_vec(),
                    flags: NO_FLAGS,
                    method: METHOD_STORED,
                    compressed: size,
                    uncompressed: size,
                    crc: crc32(data),
                    extra: Vec::new(),
                    external: PLAIN_FILE,
                }
            }
        }

        /// `content` deflated, and the header declaring it truthfully.
        pub fn deflated(name: &[u8], content: &[u8]) -> (Declared, Vec<u8>) {
            let stored = miniz_oxide::deflate::compress_to_vec(content, DEFLATE_LEVEL);
            let mut declared = Declared::truthful(name, content);
            declared.method = METHOD_DEFLATED;
            declared.compressed = u32::try_from(stored.len()).expect("fixture fits");
            (declared, stored)
        }

        /// One extra-field record (APPNOTE 4.5.1).
        pub fn extra_field(id: u16, data: &[u8]) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(&id.to_le_bytes());
            let size = u16::try_from(data.len()).expect("fixture fits");
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(data);
            out
        }

        /// A local file header declaring `declared`.
        pub fn local_header(declared: &Declared) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(&SIGNATURE_LOCAL_HEADER.to_le_bytes());
            out.extend_from_slice(&VERSION.to_le_bytes());
            out.extend_from_slice(&declared.flags.to_le_bytes());
            out.extend_from_slice(&declared.method.to_le_bytes());
            out.extend_from_slice(&u16::MIN.to_le_bytes());
            out.extend_from_slice(&u16::MIN.to_le_bytes());
            out.extend_from_slice(&declared.crc.to_le_bytes());
            out.extend_from_slice(&declared.compressed.to_le_bytes());
            out.extend_from_slice(&declared.uncompressed.to_le_bytes());
            let name_len = u16::try_from(declared.name.len()).expect("fixture name fits");
            out.extend_from_slice(&name_len.to_le_bytes());
            let extra_len = u16::try_from(declared.extra.len()).expect("fixture extra fits");
            out.extend_from_slice(&extra_len.to_le_bytes());
            out.extend_from_slice(&declared.name);
            out.extend_from_slice(&declared.extra);
            out
        }

        /// A central directory record declaring `declared` at
        /// `local_offset`.
        pub fn central_record(declared: &Declared, local_offset: u32) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(&SIGNATURE_CENTRAL_HEADER.to_le_bytes());
            out.extend_from_slice(&VERSION.to_le_bytes());
            out.extend_from_slice(&VERSION.to_le_bytes());
            out.extend_from_slice(&declared.flags.to_le_bytes());
            out.extend_from_slice(&declared.method.to_le_bytes());
            out.extend_from_slice(&u16::MIN.to_le_bytes());
            out.extend_from_slice(&u16::MIN.to_le_bytes());
            out.extend_from_slice(&declared.crc.to_le_bytes());
            out.extend_from_slice(&declared.compressed.to_le_bytes());
            out.extend_from_slice(&declared.uncompressed.to_le_bytes());
            let name_len = u16::try_from(declared.name.len()).expect("fixture name fits");
            out.extend_from_slice(&name_len.to_le_bytes());
            let extra_len = u16::try_from(declared.extra.len()).expect("fixture extra fits");
            out.extend_from_slice(&extra_len.to_le_bytes());
            // Comment length.
            out.extend_from_slice(&u16::MIN.to_le_bytes());
            out.extend_from_slice(&DISK.to_le_bytes());
            // Internal attributes.
            out.extend_from_slice(&u16::MIN.to_le_bytes());
            out.extend_from_slice(&declared.external.to_le_bytes());
            out.extend_from_slice(&local_offset.to_le_bytes());
            out.extend_from_slice(&declared.name);
            out.extend_from_slice(&declared.extra);
            out
        }

        /// What the end record declares; a test may declare otherwise.
        pub struct Ending {
            pub disk: u16,
            pub comment: Vec<u8>,
            pub zip64_locator: bool,
        }

        impl Default for Ending {
            fn default() -> Self {
                Self {
                    disk: DISK,
                    comment: Vec::new(),
                    zip64_locator: false,
                }
            }
        }

        /// An archive under construction.
        pub struct Archive {
            body: Vec<u8>,
            directory: Vec<Vec<u8>>,
        }

        impl Archive {
            /// An empty archive.
            pub const fn new() -> Self {
                Self {
                    body: Vec::new(),
                    directory: Vec::new(),
                }
            }

            /// An archive whose first entry is a stored `mimetype`
            /// holding `media_type`.
            pub fn with_mimetype(name: &[u8], media_type: &[u8]) -> Self {
                let mut archive = Self::new();
                archive.add(name, media_type);
                archive
            }

            /// A well-formed stored entry: local header and central
            /// record agree.
            pub fn add(&mut self, name: &[u8], data: &[u8]) {
                let declared = Declared::truthful(name, data);
                self.add_declaring(data, &declared, &declared);
            }

            /// An entry whose local header and central record declare
            /// what the test says, truthful or not.
            pub fn add_declaring(&mut self, data: &[u8], local: &Declared, central: &Declared) {
                let offset = self.add_unlisted_declaring(data, local);
                self.add_record(central, offset);
            }

            /// A local entry the central directory does not list.
            pub fn add_unlisted(&mut self, name: &[u8], data: &[u8]) -> u32 {
                let declared = Declared::truthful(name, data);
                self.add_unlisted_declaring(data, &declared)
            }

            /// A local entry declaring what the test says, unlisted;
            /// returns its offset.
            pub fn add_unlisted_declaring(&mut self, data: &[u8], local: &Declared) -> u32 {
                let offset = u32::try_from(self.body.len()).expect("fixture fits");
                self.body.extend_from_slice(&local_header(local));
                self.body.extend_from_slice(data);
                offset
            }

            /// Bytes written straight after the last entry's data, such
            /// as a data descriptor.
            pub fn append(&mut self, bytes: &[u8]) {
                self.body.extend_from_slice(bytes);
            }

            /// A central record for whatever sits at `offset`.
            pub fn add_record(&mut self, central: &Declared, offset: u32) {
                self.directory.push(central_record(central, offset));
            }

            /// Central directory and a truthful end record.
            pub fn finish(self) -> Vec<u8> {
                self.finish_declaring(Ending::default())
            }

            /// Central directory and an end record as `ending` says.
            pub fn finish_declaring(mut self, ending: Ending) -> Vec<u8> {
                let directory_at = u32::try_from(self.body.len()).expect("fixture fits");
                let count = u16::try_from(self.directory.len()).expect("fixture fits");
                let directory: Vec<u8> = self.directory.concat();
                let directory_size = u32::try_from(directory.len()).expect("fixture fits");
                self.body.extend_from_slice(&directory);
                if ending.zip64_locator {
                    self.body
                        .extend_from_slice(&SIGNATURE_ZIP64_LOCATOR.to_le_bytes());
                    let padding = ZIP64_LOCATOR_LEN - SIGNATURE_ZIP64_LOCATOR.to_le_bytes().len();
                    self.body.extend(core::iter::repeat_n(u8::MIN, padding));
                }
                self.body
                    .extend_from_slice(&SIGNATURE_END_OF_DIRECTORY.to_le_bytes());
                self.body.extend_from_slice(&ending.disk.to_le_bytes());
                self.body.extend_from_slice(&ending.disk.to_le_bytes());
                self.body.extend_from_slice(&count.to_le_bytes());
                self.body.extend_from_slice(&count.to_le_bytes());
                self.body.extend_from_slice(&directory_size.to_le_bytes());
                self.body.extend_from_slice(&directory_at.to_le_bytes());
                let comment_len = u16::try_from(ending.comment.len()).expect("fixture fits");
                self.body.extend_from_slice(&comment_len.to_le_bytes());
                self.body.extend_from_slice(&ending.comment);
                self.body
            }
        }
    }

    const TEXT: &[u8] = b"a declaration of a means of cryptology, repeated, repeated, repeated";
    const FIRST_NAME: &[u8] = b"contract.pdf";
    const SECOND_NAME: &[u8] = b"annex.txt";
    const SECOND_DATA: &[u8] = b"an annex";
    const XADES_NAME: &[u8] = b"META-INF/signatures0.xml";
    const XADES_CONTENT: &[u8] = b"<x/>";
    const CADES_NAME: &str = "META-INF/signature.p7s";
    const MANIFEST_NAME: &str = "META-INF/ASiCManifest.xml";
    const CMS: &[u8] = b"cms";

    /// A container archive with the `ASiC-E` media type first.
    fn container() -> raw::Archive {
        raw::Archive::with_mimetype(MIMETYPE_ENTRY.as_bytes(), MIMETYPE_ASICE.as_bytes())
    }

    fn parse(bytes: &[u8]) -> Result<AsicContainer, AsicReadError> {
        AsicContainer::parse(bytes)
    }

    /// One data entry behind the mimetype, both declaring `declared`
    /// over `data`.
    fn single(data: &[u8], declared: &raw::Declared) -> Vec<u8> {
        let mut archive = container();
        archive.add_declaring(data, declared, declared);
        archive.finish()
    }

    fn malformed(bytes: &[u8]) -> &'static str {
        match parse(bytes) {
            Err(AsicReadError::Malformed(what)) => what,
            _ => "not a malformed refusal",
        }
    }

    fn unsupported(bytes: &[u8]) -> &'static str {
        match parse(bytes) {
            Err(AsicReadError::Unsupported(what)) => what,
            _ => "not an unsupported refusal",
        }
    }

    #[test]
    fn stored_deflated_and_descriptor_entries_read_back() {
        let mut archive = container();
        archive.add(FIRST_NAME, TEXT);
        let (declared, stored) = raw::deflated(SECOND_NAME, TEXT);
        archive.add_declaring(&stored, &declared, &declared);

        // A streamed entry: zeros in the local header, a data
        // descriptor after the data.
        let (mut streamed, stored) = raw::deflated(b"streamed.txt", TEXT);
        streamed.flags = FLAG_DATA_DESCRIPTOR;
        let mut local = streamed.clone();
        local.crc = u32::MIN;
        local.compressed = u32::MIN;
        local.uncompressed = u32::MIN;
        let offset = archive.add_unlisted_declaring(&stored, &local);
        let mut descriptor = SIGNATURE_DATA_DESCRIPTOR.to_le_bytes().to_vec();
        descriptor.extend_from_slice(&streamed.crc.to_le_bytes());
        descriptor.extend_from_slice(&streamed.compressed.to_le_bytes());
        descriptor.extend_from_slice(&streamed.uncompressed.to_le_bytes());
        archive.append(&descriptor);
        archive.add_record(&streamed, offset);

        archive.add(b"META-INF/", b"");
        let (declared, stored) = raw::deflated(XADES_NAME, XADES_CONTENT);
        archive.add_declaring(&stored, &declared, &declared);

        let container = parse(&archive.finish()).expect("reads");
        assert_eq!(container.mimetype(), Mimetype::AsicE);
        let names: Vec<_> = container
            .data_files()
            .iter()
            .map(|entry| entry.name())
            .collect();
        assert_eq!(names, ["contract.pdf", "annex.txt", "streamed.txt"]);
        assert!(
            container
                .data_files()
                .iter()
                .all(|entry| entry.content() == TEXT)
        );
        let [xades] = exactly(
            container.xades_signature_files(),
            "one XAdES signature file",
        );
        assert_eq!(xades.content(), XADES_CONTENT);
        assert!(container.cades_signatures().is_empty());
    }

    #[test]
    fn a_data_descriptor_that_disagrees_is_refused() {
        let mut declared = raw::Declared::truthful(FIRST_NAME, TEXT);
        declared.flags = FLAG_DATA_DESCRIPTOR;
        let mut archive = container();
        let offset = archive.add_unlisted_declaring(TEXT, &declared);
        let mut descriptor = SIGNATURE_DATA_DESCRIPTOR.to_le_bytes().to_vec();
        descriptor.extend_from_slice(&declared.crc.wrapping_add(1).to_le_bytes());
        descriptor.extend_from_slice(&declared.compressed.to_le_bytes());
        descriptor.extend_from_slice(&declared.uncompressed.to_le_bytes());
        archive.append(&descriptor);
        archive.add_record(&declared, offset);
        assert_eq!(
            malformed(&archive.finish()),
            "data descriptor disagrees with the central directory"
        );
    }

    #[test]
    fn the_mimetype_entry_is_required_first_stored_and_known() {
        let mut archive = raw::Archive::new();
        archive.add(FIRST_NAME, TEXT);
        assert_eq!(
            parse(&archive.finish()).err(),
            Some(AsicReadError::MissingMimetype)
        );

        let unknown = raw::Archive::with_mimetype(MIMETYPE_ENTRY.as_bytes(), b"text/plain");
        assert_eq!(
            parse(&unknown.finish()).err(),
            Some(AsicReadError::UnknownMimetype)
        );

        let bdoc = raw::Archive::with_mimetype(MIMETYPE_ENTRY.as_bytes(), MIMETYPE_BDOC.as_bytes());
        assert_eq!(
            parse(&bdoc.finish()).map(|container| container.mimetype()),
            Ok(Mimetype::Bdoc)
        );

        let mut late = raw::Archive::new();
        late.add(FIRST_NAME, TEXT);
        late.add(MIMETYPE_ENTRY.as_bytes(), MIMETYPE_ASICE.as_bytes());
        assert_eq!(malformed(&late.finish()), "mimetype is not the first entry");

        let mut compressed = raw::Archive::new();
        let (declared, stored) =
            raw::deflated(MIMETYPE_ENTRY.as_bytes(), MIMETYPE_ASICE.as_bytes());
        compressed.add_declaring(&stored, &declared, &declared);
        assert_eq!(
            malformed(&compressed.finish()),
            "mimetype is compressed or carries an extra field"
        );

        let mut extra = raw::Archive::new();
        let mut declared =
            raw::Declared::truthful(MIMETYPE_ENTRY.as_bytes(), MIMETYPE_ASICE.as_bytes());
        declared.extra = raw::extra_field(u16::MAX, b"");
        extra.add_declaring(MIMETYPE_ASICE.as_bytes(), &declared, &declared);
        assert_eq!(
            malformed(&extra.finish()),
            "mimetype is compressed or carries an extra field"
        );
    }

    #[test]
    fn a_crc_mismatch_is_refused() {
        let mut archive = container();
        archive.add(FIRST_NAME, TEXT);
        let mut bytes = archive.finish();
        let at = bytes
            .windows(TEXT.len())
            .position(|window| window == TEXT)
            .expect("stored content");
        bytes[at] ^= 1;
        assert_eq!(malformed(&bytes), "entry data does not match its CRC-32");
    }

    #[test]
    fn deflated_data_is_inflated_only_to_the_declared_size() {
        let (mut declared, stored) = raw::deflated(FIRST_NAME, TEXT);
        declared.uncompressed = declared.uncompressed.saturating_sub(1);
        assert_eq!(
            malformed(&single(&stored, &declared)),
            "deflated data does not inflate to its size"
        );
    }

    #[test]
    fn a_non_zip_is_refused() {
        assert_eq!(
            parse(b"%PDF-1.7 not a container").err(),
            Some(AsicReadError::NotAZip)
        );
        assert_eq!(parse(b"").err(), Some(AsicReadError::NotAZip));
    }

    #[test]
    fn trailing_bytes_after_the_end_record_are_refused() {
        let mut archive = container();
        archive.add(FIRST_NAME, TEXT);
        let mut bytes = archive.finish();
        bytes.extend_from_slice(b"trailing");
        assert_eq!(
            malformed(&bytes),
            "no end of central directory record ends the file"
        );
    }

    #[test]
    fn a_comment_reaching_the_end_is_tolerated() {
        let mut archive = container();
        archive.add(FIRST_NAME, TEXT);
        let bytes = archive.finish_declaring(raw::Ending {
            comment: b"mimetype=application/vnd.etsi.asic-e+zip".to_vec(),
            ..raw::Ending::default()
        });
        assert!(parse(&bytes).is_ok());
    }

    #[test]
    fn hidden_local_entries_are_refused() {
        let mut between = container();
        between.add(FIRST_NAME, TEXT);
        between.add_unlisted(b"hidden.txt", SECOND_DATA);
        between.add(SECOND_NAME, SECOND_DATA);
        assert_eq!(
            malformed(&between.finish()),
            "local entries do not tile the archive exactly"
        );

        let mut before_directory = container();
        before_directory.add(FIRST_NAME, TEXT);
        before_directory.add_unlisted(b"hidden.txt", SECOND_DATA);
        assert_eq!(
            malformed(&before_directory.finish()),
            "local entries do not tile the archive exactly"
        );
    }

    #[test]
    fn unsafe_names_are_refused() {
        for name in [
            "../escape.txt",
            "/absolute.txt",
            "a\\b.txt",
            "a//b.txt",
            "a/./b.txt",
            "a\tb.txt",
        ] {
            let mut archive = container();
            archive.add(name.as_bytes(), TEXT);
            assert!(
                matches!(parse(&archive.finish()), Err(AsicReadError::Malformed(_))),
                "{name}"
            );
        }
    }

    #[test]
    fn duplicate_and_case_folded_duplicate_names_are_refused() {
        for second in [FIRST_NAME, b"CONTRACT.PDF".as_slice()] {
            let mut archive = container();
            archive.add(FIRST_NAME, TEXT);
            archive.add(second, TEXT);
            assert_eq!(malformed(&archive.finish()), "duplicate entry name");
        }
    }

    #[test]
    fn zip64_is_refused() {
        let mut locator = container();
        locator.add(FIRST_NAME, TEXT);
        assert_eq!(
            unsupported(&locator.finish_declaring(raw::Ending {
                zip64_locator: true,
                ..raw::Ending::default()
            })),
            "ZIP64"
        );

        let mut marker = raw::Declared::truthful(FIRST_NAME, TEXT);
        marker.uncompressed = u32::MAX;
        assert_eq!(unsupported(&single(TEXT, &marker)), "ZIP64");

        let mut extra = raw::Declared::truthful(FIRST_NAME, TEXT);
        extra.extra = raw::extra_field(EXTRA_ZIP64, b"");
        assert_eq!(unsupported(&single(TEXT, &extra)), "ZIP64");
    }

    #[test]
    fn a_unicode_path_extra_field_is_refused() {
        let mut declared = raw::Declared::truthful(FIRST_NAME, TEXT);
        declared.extra = raw::extra_field(EXTRA_UNICODE_PATH, b"other.pdf");
        assert_eq!(
            unsupported(&single(TEXT, &declared)),
            "Unicode Path extra field"
        );
    }

    #[test]
    fn a_multi_volume_archive_is_refused() {
        let mut archive = container();
        archive.add(FIRST_NAME, TEXT);
        assert_eq!(
            unsupported(&archive.finish_declaring(raw::Ending {
                disk: 1,
                ..raw::Ending::default()
            })),
            "multi-volume archive"
        );
    }

    #[test]
    fn central_and_local_headers_must_agree() {
        let truthful = raw::Declared::truthful(FIRST_NAME, TEXT);
        let mut contradictions = Vec::new();
        let mut name = truthful.clone();
        name.name = b"contract.txt".to_vec();
        contradictions.push(name);
        let mut size = truthful.clone();
        size.compressed = size.compressed.saturating_sub(1);
        size.uncompressed = size.compressed;
        contradictions.push(size);
        let mut crc = truthful.clone();
        crc.crc = crc.crc.wrapping_add(1);
        contradictions.push(crc);
        let mut method = truthful.clone();
        method.method = METHOD_DEFLATED;
        contradictions.push(method);
        for central in contradictions {
            let mut archive = container();
            archive.add_declaring(TEXT, &truthful, &central);
            assert_eq!(
                malformed(&archive.finish()),
                "central directory and local header disagree"
            );
        }
    }

    #[test]
    fn an_encrypted_entry_is_refused() {
        let mut declared = raw::Declared::truthful(FIRST_NAME, TEXT);
        declared.flags = FLAG_ENCRYPTED;
        assert_eq!(unsupported(&single(TEXT, &declared)), "encrypted entry");
    }

    #[test]
    fn symbolic_links_special_files_and_misdeclared_directories_are_refused() {
        let mode = |file_type: u32| file_type << UNIX_MODE_SHIFT;
        let mut link = raw::Declared::truthful(FIRST_NAME, TEXT);
        link.external = mode(UNIX_SYMBOLIC_LINK);
        assert_eq!(unsupported(&single(TEXT, &link)), "symbolic link entry");

        // `S_IFSOCK`, a socket, shares its bits with both of these.
        let mut socket = raw::Declared::truthful(FIRST_NAME, TEXT);
        socket.external = mode(UNIX_DIRECTORY | UNIX_REGULAR_FILE);
        assert_eq!(unsupported(&single(TEXT, &socket)), "special file entry");

        for external in [mode(UNIX_DIRECTORY), DOS_DIRECTORY_ATTRIBUTE] {
            let mut directory = raw::Declared::truthful(FIRST_NAME, TEXT);
            directory.external = external;
            assert_eq!(
                malformed(&single(TEXT, &directory)),
                "directory attribute on a file entry"
            );
        }

        let mut regular = raw::Declared::truthful(FIRST_NAME, TEXT);
        regular.external = mode(UNIX_REGULAR_FILE);
        assert!(parse(&single(TEXT, &regular)).is_ok());

        let mut folder = raw::Declared::truthful(b"folder/", b"");
        folder.external = mode(UNIX_DIRECTORY);
        assert!(
            parse(&single(b"", &folder)).is_ok(),
            "a real directory entry"
        );
        assert_eq!(
            malformed(&single(TEXT, &raw::Declared::truthful(b"folder/", TEXT))),
            "directory entry with content"
        );
    }

    fn signed_objects() -> Vec<DataObject> {
        vec![
            DataObject {
                name: "dossier.pdf".to_owned(),
                mime_type: "application/pdf".to_owned(),
                content: TEXT.to_vec(),
            },
            DataObject {
                name: "annex one.txt".to_owned(),
                mime_type: "text/plain".to_owned(),
                content: SECOND_DATA.to_vec(),
            },
        ]
    }

    /// The `CAdES` flavour the writer produces: the signature is paired
    /// with the manifest whose `SigReference` names it, and the archive
    /// manifest, which names a timestamp, is not mistaken for it.
    #[test]
    fn the_writers_cades_container_pairs_signature_and_manifest() {
        let plan = plan(signed_objects(), DigestAlgorithm::Sha256);
        let manifest = plan.manifest().to_vec();
        let archive_manifest = plan.archive_manifest(CMS, DigestAlgorithm::Sha256);
        let archive = plan
            .finish_archived(CMS, &archive_manifest, b"token")
            .expect("fits");
        let container = parse(&archive).expect("reads");
        assert_eq!(container.mimetype(), Mimetype::AsicE);
        assert_eq!(container.data_files().len(), signed_objects().len());
        let [cades] = exactly(container.cades_signatures(), "one CAdES signature");
        assert_eq!(cades.signature().name(), CADES_NAME);
        assert_eq!(cades.signature().content(), CMS);
        let paired = cades.manifest().expect("manifest paired");
        assert_eq!(paired.name(), MANIFEST_NAME);
        assert_eq!(paired.content(), manifest);
        assert!(container.manifest_intact(cades));
    }

    /// A `CAdES` container with `objects` as data files and `manifest`
    /// in place of the writer's.
    fn cades_container(objects: &[DataObject], manifest: Option<Vec<u8>>) -> AsicContainer {
        let plan = plan(signed_objects(), DigestAlgorithm::Sha256);
        let manifest = manifest.unwrap_or_else(|| plan.manifest().to_vec());
        let mut archive = container();
        for object in objects {
            archive.add(object.name.as_bytes(), &object.content);
        }
        archive.add(MANIFEST_NAME.as_bytes(), &manifest);
        archive.add(CADES_NAME.as_bytes(), CMS);
        parse(&archive.finish()).expect("reads")
    }

    fn manifest_intact(container: &AsicContainer) -> bool {
        let [cades] = exactly(container.cades_signatures(), "one CAdES signature");
        container.manifest_intact(cades)
    }

    #[test]
    fn a_modified_or_unreferenced_data_file_breaks_the_manifest() {
        assert!(manifest_intact(&cades_container(&signed_objects(), None)));
        let mut modified = signed_objects();
        modified[0].content = b"a different declaration".to_vec();
        assert!(!manifest_intact(&cades_container(&modified, None)));
        let mut extended = signed_objects();
        extended.push(DataObject {
            name: "smuggled.txt".to_owned(),
            mime_type: "text/plain".to_owned(),
            content: b"not listed".to_vec(),
        });
        assert!(!manifest_intact(&cades_container(&extended, None)));
    }

    #[test]
    fn a_wrong_digest_method_or_signature_breaks_the_manifest() {
        let manifest = String::from_utf8(
            plan(signed_objects(), DigestAlgorithm::Sha256)
                .manifest()
                .to_vec(),
        )
        .expect("utf-8");
        let right = crate::base64::encode(&DigestAlgorithm::Sha256.digest(TEXT));
        let wrong = crate::base64::encode(&DigestAlgorithm::Sha256.digest(b"other"));
        let wrong_digest = manifest.replace(&right, &wrong);
        assert!(wrong_digest.as_str() != manifest);
        assert!(!manifest_intact(&cades_container(
            &signed_objects(),
            Some(wrong_digest.into_bytes())
        )));

        let sha1 = manifest.replace(
            crate::xades::DIGEST_METHOD_SHA256,
            "http://www.w3.org/2000/09/xmldsig#sha1",
        );
        assert!(sha1.as_str() != manifest);
        assert!(!manifest_intact(&cades_container(
            &signed_objects(),
            Some(sha1.into_bytes())
        )));

        let other_signature = manifest.replace(
            &format!("URI=\"{CADES_NAME}\""),
            "URI=\"META-INF/signature2.p7s\"",
        );
        assert!(other_signature.as_str() != manifest);
        let container = cades_container(&signed_objects(), Some(other_signature.into_bytes()));
        let [cades] = exactly(container.cades_signatures(), "one CAdES signature");
        assert!(
            cades.manifest().is_none(),
            "a manifest naming another signature is not paired"
        );
        assert!(!container.manifest_intact(cades));
    }

    /// LATIN SMALL LETTER A WITH DIAERESIS, which UTF-8 spells as the
    /// two octets `%C3%A4` escape.
    const A_DIAERESIS: char = '\u{e4}';

    #[test]
    fn percent_escapes_decode_to_utf8_names() {
        assert_eq!(
            percent_decode("a%20b%C3%A4.txt"),
            Some(format!("a b{A_DIAERESIS}.txt"))
        );
        assert_eq!(percent_decode("plain.txt").as_deref(), Some("plain.txt"));
        assert_eq!(percent_decode("bad%2"), None);
        assert_eq!(percent_decode("bad%zz"), None);
        assert_eq!(percent_decode("bad%FF"), None, "not UTF-8");
    }

    #[test]
    fn the_crc_is_the_writers() {
        // The reader and writer share one CRC-32: a container the
        // writer produced reads back.
        let archive = plan(signed_objects(), DigestAlgorithm::Sha256)
            .finish(CMS)
            .expect("fits");
        assert!(parse(&archive).is_ok());
        assert!(crc32(TEXT) != crc32(SECOND_DATA));
    }
}
