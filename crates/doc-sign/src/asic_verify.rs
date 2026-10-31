// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! Offline verification of `ASiC-E` containers carrying detached `CAdES`.
//!
//! The flow mirrors the writer ([`crate::asic`]): the ZIP yields the
//! manifest plus the files; every manifest digest is recomputed; each
//! detached `CAdES` is parsed and verified against its embedded signer
//! certificate with the manifest supplied as the external content.
//! Nothing here touches the network, the clock beyond file reads, or a
//! card: a container either checks against its own bytes or it does not.
//!
//! `XAdES` containers and PDFs are reported as unsupported rather than
//! mis-verified. A wrong verdict is worse than no verdict.
use std::path::{Path, PathBuf};

use refineid_cms::oid::{Oid, known};
use refineid_cms::x509::{Certificate, OwnedCert};

use crate::base64;
use crate::ber::{BerTag, BerTlv, BerTlvIter, Boolean, OctetString, Oid as BerOid, Sequence};
use crate::cades::DigestAlgorithm;
use crate::cms::{SignedData, SignerIdentifier};
use crate::oids;
use crate::x509_ext::NameExt;

/// Outcome of verifying one container.
#[derive(Debug)]
pub struct DocumentVerifyReport {
    /// Container display name (file name, not the full path).
    pub container: String,
    /// One entry per manifest-covered file, plus any data file the
    /// manifest does not cover.
    pub files: Vec<VerifiedFile>,
    /// One entry per `CAdES` signature in the container.
    pub signatures: Vec<VerifiedSignature>,
    /// Overall verdict: every digest matched, every signature
    /// verified, and no data file sits outside the manifest.
    pub ok: bool,
}

/// One manifest-covered (or uncovered) file and its digest verdict.
#[derive(Debug)]
pub struct VerifiedFile {
    /// Entry name inside the container.
    pub name: String,
    /// Digest algorithm the manifest names, as a short label.
    pub algorithm: String,
    /// `true` when the recomputed digest matches the manifest.
    pub digest_ok: bool,
    /// Why not, when it does not. Empty on success.
    pub detail: String,
}

/// One `CAdES` signature and its cryptographic verdict.
#[derive(Debug)]
pub struct VerifiedSignature {
    /// Subject common name of the signer certificate, when the
    /// certificate carries one.
    pub signer_cn: Option<String>,
    /// `true` when the signature verifies against the embedded
    /// signer certificate over the manifest bytes.
    pub valid: bool,
    /// Why not, when it does not. Empty on success.
    pub detail: String,
}

impl DocumentVerifyReport {
    /// Multi-line verdict for the GUI result box (`\r\n` separated).
    /// Names files and signers; carries no key material.
    #[must_use]
    pub fn render(&self) -> String {
        let mut lines = vec![
            format!("Container: {}", self.container),
            format!("Files ({}):", self.files.len()),
        ];
        for file in &self.files {
            if file.digest_ok {
                lines.push(format!("  {} — {} ok", file.name, file.algorithm));
            } else {
                lines.push(format!("  {} — FAILED ({})", file.name, file.detail));
            }
        }
        lines.push(format!("Signatures ({}):", self.signatures.len()));
        for signature in &self.signatures {
            let who = signature.signer_cn.as_deref().unwrap_or("unknown signer");
            if signature.valid {
                lines.push(format!("  {who} — valid"));
            } else {
                lines.push(format!("  {who} — INVALID ({})", signature.detail));
            }
        }
        lines.push(if self.ok {
            "Result: VALID".to_owned()
        } else {
            "Result: INVALID".to_owned()
        });
        let mut out = lines.join("\r\n");
        out.push_str("\r\n");
        out
    }
}

/// Why a container could not be verified at all.
///
/// A negative verdict -- digest mismatch, bad signature -- is not an
/// error; it lands on the report with `ok = false`. These are the
/// cases where there is no verdict to report.
#[derive(Debug)]
pub enum DocumentVerifyError {
    /// The container file could not be read.
    Read {
        /// Filesystem path the read was attempted against.
        path: PathBuf,
        /// Underlying `std::io::Error`.
        source: std::io::Error,
    },
    /// Not a ZIP container at all.
    NotAContainer,
    /// A signed format this verifier does not implement.
    Unsupported(String),
    /// The ZIP structure is malformed or uses features outside the
    /// `ASiC` profile (encryption, data descriptors, unknown methods).
    Zip(String),
    /// The manifest is missing, malformed, or names a digest this
    /// verifier does not implement.
    Manifest(String),
    /// A signature entry does not parse as CMS, names an unexpected
    /// content type, or does not embed its signer certificate.
    Cms(String),
    /// The container carries no `CAdES` signature entries.
    NoSignatures,
}

impl core::fmt::Display for DocumentVerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Read { path, .. } => write!(f, "cannot read {}", path.display()),
            Self::NotAContainer => f.write_str("not an ASiC-E container"),
            Self::Unsupported(detail) => write!(f, "unsupported: {detail}"),
            Self::Zip(detail) => write!(f, "container ZIP error: {detail}"),
            Self::Manifest(detail) => write!(f, "manifest error: {detail}"),
            Self::Cms(detail) => write!(f, "signature error: {detail}"),
            Self::NoSignatures => f.write_str("container carries no CAdES signatures"),
        }
    }
}

impl core::error::Error for DocumentVerifyError {}

/// Verify the `ASiC-E` container at `path`.
///
/// # Errors
/// [`DocumentVerifyError`] when the file cannot be read, is not a
/// container, is an unimplemented flavour, or is structurally
/// broken. Cryptographic failures are verdicts, not errors.
pub fn verify_document(path: &Path) -> Result<DocumentVerifyReport, DocumentVerifyError> {
    let bytes = std::fs::read(path).map_err(|source| DocumentVerifyError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let container = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("container")
        .to_owned();
    verify_bytes(&bytes, container)
}

/// Verify container `bytes` under the display name `container`.
fn verify_bytes(
    bytes: &[u8],
    container: String,
) -> Result<DocumentVerifyReport, DocumentVerifyError> {
    if bytes.starts_with(b"%PDF") {
        return Err(DocumentVerifyError::Unsupported(
            "PDF verification is not implemented; verify signed PDFs in their reader application"
                .to_owned(),
        ));
    }
    let entries = read_zip(bytes)?;
    let manifest = entries
        .iter()
        .find(|entry| entry.name == MANIFEST_ENTRY)
        .map(|entry| entry.data.clone());
    let Some(manifest) = manifest else {
        if entries.iter().any(|entry| entry.name == MANIFEST_ENTRY_ODF) {
            return Err(DocumentVerifyError::Unsupported(
                "XAdES verification is not implemented; this container needs its native application"
                    .to_owned(),
            ));
        }
        return Err(DocumentVerifyError::Manifest(
            "no ASiCManifest.xml in META-INF".to_owned(),
        ));
    };
    let refs = parse_manifest(&manifest)?;
    let mut files = check_digests(&entries, &refs);
    flag_uncovered_files(&entries, &refs, &mut files);
    let signatures = verify_signatures(&entries, &manifest)?;
    let ok = files.iter().all(|file| file.digest_ok)
        && signatures.iter().all(|signature| signature.valid);
    Ok(DocumentVerifyReport {
        container,
        files,
        signatures,
        ok,
    })
}

/// Where the manifest lives, in the `CAdES` flavour.
const MANIFEST_ENTRY: &str = "META-INF/ASiCManifest.xml";

/// Where the manifest lives, in the `XAdES` flavour (unsupported).
const MANIFEST_ENTRY_ODF: &str = "META-INF/manifest.xml";

/// One ZIP entry: name plus decompressed bytes.
struct ZipEntry {
    name: String,
    data: Vec<u8>,
}

/// Local file header signature (`PK\x03\x04`).
const ZIP_LOCAL_SIG: u32 = 0x0403_4B50;

/// Central directory file header signature: entries end here.
const ZIP_CENTRAL_SIG: u32 = 0x0201_4B50;

/// End of central directory signature: entries end here too.
const ZIP_EOD_SIG: u32 = 0x0605_4B50;

/// General-purpose bit 0: encryption, outside the `ASiC` profile.
const ZIP_FLAG_ENCRYPTED: u16 = 0x0001;

/// General-purpose bit 3: data descriptor; sizes are unknown up
/// front, so a streaming writer's shape. Outside the profile.
const ZIP_FLAG_DESCRIPTOR: u16 = 0x0008;

/// Compression method 0: stored.
const ZIP_METHOD_STORED: u16 = 0;

/// Compression method 8: deflated.
const ZIP_METHOD_DEFLATED: u16 = 8;

/// Most entries any container may carry.
const MAX_ENTRIES: usize = 4096;

/// Most decompressed bytes in total: decompression-bomb ceiling.
const MAX_TOTAL_BYTES: usize = 512 << 20;

/// Most decompressed bytes in one entry.
const MAX_ENTRY_BYTES: usize = 512 << 20;

/// Fixed part of the end of central directory record, signature
/// included (APPNOTE 4.3.16).
const END_OF_DIRECTORY_LEN: usize = 22;

/// Longest archive comment: its length field is 16 bits (APPNOTE 4.3.16).
const MAX_ARCHIVE_COMMENT_LEN: usize = 65_535;

/// ZIP64 end of central directory locator signature (APPNOTE 4.3.15).
const ZIP64_LOCATOR_SIG: u32 = 0x0706_4B50;

/// Size of the ZIP64 end of central directory locator (APPNOTE 4.3.15).
const ZIP64_LOCATOR_LEN: usize = 20;

/// A 16-bit field holding this value defers to a ZIP64 record (APPNOTE 4.4.1.4).
const ZIP64_MARKER_U16: u16 = u16::MAX;

/// A 32-bit field holding this value defers to a ZIP64 record (APPNOTE 4.4.1.4).
const ZIP64_MARKER_U32: u32 = u32::MAX;

/// The only disk number a single-volume archive carries (ISO/IEC 21320-1).
const SINGLE_DISK: u16 = 0;

/// Extra field header id of the ZIP64 extended information (APPNOTE 4.5.3).
const EXTRA_ZIP64: u16 = 0x0001;

/// Extra field header id of the Info-ZIP Unicode Comment (APPNOTE 4.6.8).
const EXTRA_UNICODE_COMMENT: u16 = 0x6375;

/// Extra field header id of the Info-ZIP Unicode Path (APPNOTE 4.6.9).
const EXTRA_UNICODE_PATH: u16 = 0x7075;

/// The host-dependent upper half of the external attributes, where a
/// Unix archiver stores the file mode (APPNOTE 4.4.15, Info-ZIP).
const UNIX_MODE_SHIFT: u32 = 16;

/// `S_IFMT`: the file-type bits of a Unix mode (POSIX `<sys/stat.h>`).
const UNIX_FILE_TYPE_MASK: u16 = 0o170_000;

/// `S_IFLNK`: the symbolic-link file type (POSIX `<sys/stat.h>`).
const UNIX_SYMBOLIC_LINK: u16 = 0o120_000;

/// `S_IFDIR`: the directory file type (POSIX `<sys/stat.h>`).
const UNIX_DIRECTORY: u16 = 0o040_000;

/// MS-DOS directory attribute, in the low byte of the external
/// attributes (APPNOTE 4.4.15).
const DOS_DIRECTORY_ATTRIBUTE: u32 = 0x10;

/// Path separator inside an archive (APPNOTE 4.4.17.1).
const ENTRY_SEPARATOR: char = '/';

/// The separator an archive name must not use (APPNOTE 4.4.17.1).
const FORBIDDEN_SEPARATOR: char = '\\';

/// Where the central directory sits, from the end of central directory record.
struct EndOfDirectory {
    /// Offset of the record itself: where the central directory must end.
    offset: usize,
    /// Number of central directory records.
    count: usize,
    /// Offset of the first central directory record.
    central_offset: usize,
}

/// One central directory record: what an extractor believes about an entry.
struct CentralRecord {
    flags: u16,
    method: u16,
    crc: u32,
    compressed_len: usize,
    uncompressed_len: usize,
    name: Vec<u8>,
    local_offset: usize,
}

/// The archive extent one local entry occupies: header through data.
struct LocalExtent {
    start: usize,
    end: usize,
}

fn zip_error(detail: &str) -> DocumentVerifyError {
    DocumentVerifyError::Zip(detail.to_owned())
}

/// Read the container the way an extractor does.
///
/// The end of central directory record names the central directory,
/// the central directory names every entry, and each entry's local
/// header must agree with its record. The verifier then sees exactly
/// what an extractor shows, and refuses whatever could make two readers
/// disagree: bytes after the end of central directory record, a central
/// directory that does not end at that record, a local header that
/// contradicts its record, local entries that do not tile the archive
/// exactly (a hidden entry between listed ones, or stray bytes), a
/// name that is not a plain relative file path or repeats another
/// after case folding, data whose CRC-32 is not the declared one, an
/// extra field that would give an extractor another name or size, an
/// entry declared a directory or symbolic link, and ZIP64, multi-volume,
/// encrypted, data-descriptor or unknown-method entries.
fn read_zip(bytes: &[u8]) -> Result<Vec<ZipEntry>, DocumentVerifyError> {
    if Cursor::new(bytes).u32() != Some(ZIP_LOCAL_SIG) {
        return Err(DocumentVerifyError::NotAContainer);
    }
    let end = find_end_of_directory(bytes)?;
    let records = read_central_directory(bytes, &end)?;
    let mut entries = Vec::with_capacity(records.len());
    let mut extents = Vec::with_capacity(records.len());
    let mut folded_names = std::collections::BTreeSet::new();
    let mut total = 0_usize;
    for record in &records {
        total = total
            .checked_add(record.uncompressed_len)
            .filter(|declared| *declared <= MAX_TOTAL_BYTES)
            .ok_or_else(|| zip_error("container exceeds the decompressed-size ceiling"))?;
        let (entry, extent) = read_local_entry(bytes, record)?;
        if !folded_names.insert(entry.name.to_lowercase()) {
            return Err(zip_error("duplicate entry name"));
        }
        entries.push(entry);
        extents.push(extent);
    }
    require_exact_tiling(extents, end.central_offset)?;
    Ok(entries)
}

/// Locate the end of central directory record, which must end exactly
/// at the end of the file, and check the archive geometry it declares.
///
/// An archive comment may itself contain the signature bytes, so a
/// candidate whose comment does not reach the end of the file is
/// skipped rather than refused.
fn find_end_of_directory(bytes: &[u8]) -> Result<EndOfDirectory, DocumentVerifyError> {
    const MISSING: &str = "no end of central directory record ends at the end of the file";
    let Some(latest) = bytes.len().checked_sub(END_OF_DIRECTORY_LEN) else {
        return Err(zip_error(MISSING));
    };
    let earliest = latest.saturating_sub(MAX_ARCHIVE_COMMENT_LEN);
    for offset in (earliest..=latest).rev() {
        let mut cursor = Cursor::at(bytes, offset);
        if cursor.u32() != Some(ZIP_EOD_SIG) {
            continue;
        }
        let truncated = || zip_error("truncated end of central directory record");
        let disk = cursor.u16().ok_or_else(truncated)?;
        let directory_disk = cursor.u16().ok_or_else(truncated)?;
        let count_on_disk = cursor.u16().ok_or_else(truncated)?;
        let count = cursor.u16().ok_or_else(truncated)?;
        let central_size = cursor.u32().ok_or_else(truncated)?;
        let central_offset = cursor.u32().ok_or_else(truncated)?;
        let comment_len = cursor.u16().ok_or_else(truncated)?;
        if cursor.position().checked_add(usize::from(comment_len)) != Some(bytes.len()) {
            continue;
        }
        if count_on_disk == ZIP64_MARKER_U16
            || count == ZIP64_MARKER_U16
            || central_size == ZIP64_MARKER_U32
            || central_offset == ZIP64_MARKER_U32
            || offset
                .checked_sub(ZIP64_LOCATOR_LEN)
                .is_some_and(|at| Cursor::at(bytes, at).u32() == Some(ZIP64_LOCATOR_SIG))
        {
            return Err(DocumentVerifyError::Unsupported(
                "ZIP64 containers are not supported".to_owned(),
            ));
        }
        if disk != SINGLE_DISK || directory_disk != SINGLE_DISK {
            return Err(zip_error("multi-volume archives are not supported"));
        }
        if count_on_disk != count {
            return Err(zip_error("entry counts disagree"));
        }
        let central_offset = usize::try_from(central_offset).map_err(|_| truncated())?;
        let central_size = usize::try_from(central_size).map_err(|_| truncated())?;
        if central_offset.checked_add(central_size) != Some(offset) {
            return Err(zip_error(
                "central directory does not end at the end of central directory record",
            ));
        }
        return Ok(EndOfDirectory {
            offset,
            count: usize::from(count),
            central_offset,
        });
    }
    Err(zip_error(MISSING))
}

/// Read exactly the declared number of central directory records, which
/// must fill the central directory to the byte.
fn read_central_directory(
    bytes: &[u8],
    end: &EndOfDirectory,
) -> Result<Vec<CentralRecord>, DocumentVerifyError> {
    if end.count > MAX_ENTRIES {
        return Err(zip_error("too many entries"));
    }
    let mut cursor = Cursor::at(bytes, end.central_offset);
    let mut records = Vec::with_capacity(end.count);
    for _ in 0..end.count {
        if cursor.u32() != Some(ZIP_CENTRAL_SIG) {
            return Err(zip_error(
                "central directory record does not start with its signature",
            ));
        }
        records.push(CentralRecord::read(&mut cursor)?);
    }
    if cursor.position() != end.offset {
        return Err(zip_error(
            "central directory does not end at the end of central directory record",
        ));
    }
    Ok(records)
}

impl CentralRecord {
    /// Read one record past the already-consumed signature.
    fn read(cursor: &mut Cursor<'_>) -> Result<Self, DocumentVerifyError> {
        let truncated = || zip_error("truncated central directory record");
        let _version_made_by = cursor.u16().ok_or_else(truncated)?;
        let _version_needed = cursor.u16().ok_or_else(truncated)?;
        let flags = cursor.u16().ok_or_else(truncated)?;
        let method = cursor.u16().ok_or_else(truncated)?;
        let _mod_time = cursor.u16().ok_or_else(truncated)?;
        let _mod_date = cursor.u16().ok_or_else(truncated)?;
        let crc = cursor.u32().ok_or_else(truncated)?;
        let compressed = cursor.u32().ok_or_else(truncated)?;
        let uncompressed = cursor.u32().ok_or_else(truncated)?;
        let name_len = cursor.u16().ok_or_else(truncated)?;
        let extra_len = cursor.u16().ok_or_else(truncated)?;
        let comment_len = cursor.u16().ok_or_else(truncated)?;
        let disk = cursor.u16().ok_or_else(truncated)?;
        let _internal_attributes = cursor.u16().ok_or_else(truncated)?;
        let external_attributes = cursor.u32().ok_or_else(truncated)?;
        let local_offset = cursor.u32().ok_or_else(truncated)?;
        let name = cursor
            .take(usize::from(name_len))
            .ok_or_else(truncated)?
            .to_vec();
        let extra = cursor.take(usize::from(extra_len)).ok_or_else(truncated)?;
        cursor
            .take(usize::from(comment_len))
            .ok_or_else(truncated)?;
        if compressed == ZIP64_MARKER_U32
            || uncompressed == ZIP64_MARKER_U32
            || local_offset == ZIP64_MARKER_U32
        {
            return Err(DocumentVerifyError::Unsupported(
                "ZIP64 containers are not supported".to_owned(),
            ));
        }
        if disk != SINGLE_DISK {
            return Err(zip_error("multi-volume archives are not supported"));
        }
        require_plain_file_attributes(external_attributes)?;
        require_plain_extra_field(extra)?;
        Ok(Self {
            flags,
            method,
            crc,
            compressed_len: usize::try_from(compressed).map_err(|_| truncated())?,
            uncompressed_len: usize::try_from(uncompressed).map_err(|_| truncated())?,
            name,
            local_offset: usize::try_from(local_offset).map_err(|_| truncated())?,
        })
    }
}

/// An entry an extractor would create as a directory or a symbolic
/// link is not a data file and has no place in the container.
fn require_plain_file_attributes(external: u32) -> Result<(), DocumentVerifyError> {
    let unix_mode = u16::try_from(external >> UNIX_MODE_SHIFT)
        .map_err(|_| zip_error("malformed external attributes"))?;
    match unix_mode & UNIX_FILE_TYPE_MASK {
        UNIX_SYMBOLIC_LINK => return Err(zip_error("symbolic link entry")),
        UNIX_DIRECTORY => return Err(zip_error("directory entry")),
        _ => {}
    }
    if external & DOS_DIRECTORY_ATTRIBUTE != 0 {
        return Err(zip_error("directory entry"));
    }
    Ok(())
}

/// Walk an extra field as the (id, size, data) records APPNOTE 4.5.1
/// defines, refusing a malformed one and any record that would give
/// an extractor a name or size other than the header's.
fn require_plain_extra_field(extra: &[u8]) -> Result<(), DocumentVerifyError> {
    let mut cursor = Cursor::new(extra);
    while cursor.position() < extra.len() {
        let malformed = || zip_error("malformed extra field");
        let id = cursor.u16().ok_or_else(malformed)?;
        let size = cursor.u16().ok_or_else(malformed)?;
        cursor.take(usize::from(size)).ok_or_else(malformed)?;
        match id {
            EXTRA_ZIP64 => {
                return Err(DocumentVerifyError::Unsupported(
                    "ZIP64 containers are not supported".to_owned(),
                ));
            }
            EXTRA_UNICODE_PATH => return Err(zip_error("Unicode Path extra field")),
            EXTRA_UNICODE_COMMENT => return Err(zip_error("Unicode Comment extra field")),
            _ => {}
        }
    }
    Ok(())
}

/// An entry name must be a plain relative file path: UTF-8, no
/// absolute or backslash form, no control characters, every component
/// non-empty and neither `.` nor `..`, and not a directory.
fn require_plain_entry_name(name: &[u8]) -> Result<String, DocumentVerifyError> {
    let name =
        String::from_utf8(name.to_vec()).map_err(|_| zip_error("entry name is not UTF-8"))?;
    if name.is_empty() {
        return Err(zip_error("empty entry name"));
    }
    if name.starts_with(ENTRY_SEPARATOR) {
        return Err(zip_error("absolute entry name"));
    }
    if name.contains(FORBIDDEN_SEPARATOR) {
        return Err(zip_error("backslash in entry name"));
    }
    if name.chars().any(char::is_control) {
        return Err(zip_error("control character in entry name"));
    }
    if name.ends_with(ENTRY_SEPARATOR) {
        return Err(zip_error("directory entry"));
    }
    for component in name.split(ENTRY_SEPARATOR) {
        if component.is_empty() {
            return Err(zip_error("empty path component in entry name"));
        }
        if component == "." || component == ".." {
            return Err(zip_error("relative path component in entry name"));
        }
    }
    Ok(name)
}

/// Read the local entry a central record points at, requiring the two
/// to agree on everything that decides what the entry is.
fn read_local_entry(
    bytes: &[u8],
    record: &CentralRecord,
) -> Result<(ZipEntry, LocalExtent), DocumentVerifyError> {
    let mut cursor = Cursor::at(bytes, record.local_offset);
    if cursor.u32() != Some(ZIP_LOCAL_SIG) {
        return Err(zip_error(
            "central directory names an offset that is not a local file header",
        ));
    }
    let header =
        LocalHeader::read(&mut cursor).ok_or_else(|| zip_error("truncated local header"))?;
    let name_bytes = cursor
        .take(header.name_len)
        .ok_or_else(|| zip_error("truncated entry name"))?;
    let extra = cursor
        .take(header.extra_len)
        .ok_or_else(|| zip_error("truncated extra field"))?;
    let stored = cursor
        .take(header.compressed_len)
        .ok_or_else(|| zip_error("truncated entry data"))?;
    if header.flags != record.flags
        || header.method != record.method
        || header.crc != record.crc
        || header.compressed_len != record.compressed_len
        || header.uncompressed_len != record.uncompressed_len
        || name_bytes != record.name.as_slice()
    {
        return Err(zip_error(
            "central directory and local file header disagree",
        ));
    }
    if header.flags & ZIP_FLAG_ENCRYPTED != 0 {
        return Err(zip_error("encrypted entries are not supported"));
    }
    if header.flags & ZIP_FLAG_DESCRIPTOR != 0 {
        return Err(zip_error("data descriptors are not supported"));
    }
    require_plain_extra_field(extra)?;
    let name = require_plain_entry_name(&record.name)?;
    let data = match header.method {
        ZIP_METHOD_STORED => stored.to_vec(),
        ZIP_METHOD_DEFLATED => {
            miniz_oxide::inflate::decompress_to_vec_with_limit(stored, MAX_ENTRY_BYTES)
                .map_err(|error| zip_error(&format!("deflate error: {error:?}")))?
        }
        method => {
            return Err(zip_error(&format!(
                "unsupported compression method {method}"
            )));
        }
    };
    if data.len() != header.uncompressed_len {
        return Err(zip_error("entry size does not match its header"));
    }
    if crate::asic::crc32(&data) != header.crc {
        return Err(zip_error("entry data does not match its CRC-32"));
    }
    Ok((
        ZipEntry { name, data },
        LocalExtent {
            start: record.local_offset,
            end: cursor.position(),
        },
    ))
}

/// The listed local entries must cover the bytes before the central
/// directory exactly, so nothing hides between or beside them.
fn require_exact_tiling(
    mut extents: Vec<LocalExtent>,
    central_offset: usize,
) -> Result<(), DocumentVerifyError> {
    const GAP: &str = "local entries do not tile the archive exactly";
    extents.sort_unstable_by_key(|extent| extent.start);
    let mut expected = 0_usize;
    for extent in &extents {
        if extent.start != expected {
            return Err(zip_error(GAP));
        }
        expected = extent.end;
    }
    if expected != central_offset {
        return Err(zip_error(GAP));
    }
    Ok(())
}

/// Byte cursor that fails closed instead of slicing.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// A cursor positioned at `pos`; reads past the end fail closed.
    const fn at(bytes: &'a [u8], pos: usize) -> Self {
        Self { bytes, pos }
    }

    const fn position(&self) -> usize {
        self.pos
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        let slice = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u16(&mut self) -> Option<u16> {
        let bytes = self.take(2)?;
        let pair: [u8; 2] = bytes.try_into().ok()?;
        Some(u16::from_le_bytes(pair))
    }

    fn u32(&mut self) -> Option<u32> {
        let bytes = self.take(4)?;
        let quad: [u8; 4] = bytes.try_into().ok()?;
        Some(u32::from_le_bytes(quad))
    }
}

/// Local file header fields a verifier needs.
struct LocalHeader {
    flags: u16,
    method: u16,
    crc: u32,
    compressed_len: usize,
    uncompressed_len: usize,
    name_len: usize,
    extra_len: usize,
}

impl LocalHeader {
    /// Read one header past the already-consumed signature. Times are
    /// skipped; the CRC must match the central record and the data.
    fn read(cursor: &mut Cursor<'_>) -> Option<Self> {
        let _version = cursor.u16()?;
        let flags = cursor.u16()?;
        let method = cursor.u16()?;
        let _mod_time = cursor.u16()?;
        let _mod_date = cursor.u16()?;
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

/// One manifest-covered file: where it lives and what it must hash to.
struct ManifestRef {
    /// Entry name after XML-unescape plus percent-decoding.
    uri: String,
    /// Entry name exactly as written, for writers that encode neither.
    raw_uri: String,
    /// Digest algorithm the manifest names.
    algorithm: DigestAlgorithm,
    /// Short label for the report.
    label: String,
    /// Expected digest bytes.
    expected: Vec<u8>,
}

/// Parse the `ASiCManifest.xml` references with a liberal tag scan.
///
/// The scan understands tags, prefixes, and both quote styles, and
/// nothing else: comments and processing instructions between
/// elements are skipped as not-tags, which is all a verifier needs
/// from them.
fn parse_manifest(xml: &[u8]) -> Result<Vec<ManifestRef>, DocumentVerifyError> {
    let text = std::str::from_utf8(xml)
        .map_err(|_| DocumentVerifyError::Manifest("manifest is not UTF-8".to_owned()))?;
    let mut refs = Vec::new();
    let mut pos = 0_usize;
    while let Some((tag, after)) = next_tag(text, pos) {
        pos = after;
        if tag.closing || local_name(tag.name) != "DataObjectReference" {
            continue;
        }
        let raw_uri = attr_value(tag.attrs, "URI")
            .ok_or_else(|| DocumentVerifyError::Manifest("reference without URI".to_owned()))?;
        let mut algorithm = None;
        let mut value = None;
        while let Some((inner, inner_after)) = next_tag(text, pos) {
            pos = inner_after;
            let local = local_name(inner.name);
            if inner.closing && local == "DataObjectReference" {
                break;
            }
            if !inner.closing && local == "DigestMethod" {
                algorithm = attr_value(inner.attrs, "Algorithm");
            }
            if !inner.closing && local == "DigestValue" {
                let content = text
                    .get(pos..)
                    .and_then(|rest| rest.find('<').and_then(|end| rest.get(..end)))
                    .ok_or_else(|| {
                        DocumentVerifyError::Manifest("unterminated DigestValue".to_owned())
                    })?;
                value = Some(content.trim().to_owned());
            }
        }
        let algorithm_uri = algorithm.ok_or_else(|| {
            DocumentVerifyError::Manifest("reference without DigestMethod".to_owned())
        })?;
        let (algorithm, label) = digest_by_uri(&algorithm_uri)?;
        let encoded = value.ok_or_else(|| {
            DocumentVerifyError::Manifest("reference without DigestValue".to_owned())
        })?;
        let expected = base64::decode(&encoded)
            .map_err(|why| DocumentVerifyError::Manifest(format!("bad DigestValue: {why}")))?;
        refs.push(ManifestRef {
            uri: decode_uri(&raw_uri),
            raw_uri,
            algorithm,
            label,
            expected,
        });
    }
    if refs.is_empty() {
        return Err(DocumentVerifyError::Manifest(
            "no DataObjectReference entries".to_owned(),
        ));
    }
    Ok(refs)
}

/// One `<...>` tag: name, attribute text, and whether it closes.
struct Tag<'a> {
    name: &'a str,
    attrs: &'a str,
    closing: bool,
}

/// Next tag at or after `from`: returns the tag plus the offset
/// just past its closing `>`. Comments, processing instructions,
/// and declarations are skipped as not-tags.
fn next_tag(text: &str, from: usize) -> Option<(Tag<'_>, usize)> {
    let mut pos = from;
    loop {
        let rest = text.get(pos..)?;
        let open = rest.find('<')?;
        pos += open;
        let after_open = text.get(pos + 1..)?;
        // Skip comments, PIs, and declarations: none of them is an
        // element a verifier reads.
        if let Some(stripped) = after_open.strip_prefix("!--") {
            let end = stripped.find("-->")?;
            pos += 4 + end + 3;
            continue;
        }
        if after_open.starts_with('?') {
            let end = after_open.find("?>")?;
            pos += 1 + end + 2;
            continue;
        }
        if after_open.starts_with('!') {
            let end = after_open.find('>')?;
            pos += 1 + end + 1;
            continue;
        }
        let end = after_open.find('>')?;
        let body = text.get(pos + 1..pos + 1 + end)?;
        let after = pos + 1 + end + 1;
        let (closing, body) = body
            .strip_prefix('/')
            .map_or((false, body), |rest| (true, rest));
        let body = body.strip_suffix('/').unwrap_or(body);
        let split = body.find(char::is_whitespace).unwrap_or(body.len());
        let (name, attrs) = body.split_at(split);
        if name.is_empty() {
            return None;
        }
        return Some((
            Tag {
                name,
                attrs,
                closing,
            },
            after,
        ));
    }
}

/// Tag name without its namespace prefix.
fn local_name(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

/// Value of attribute `wanted` (either quote style), or `None`.
/// Only `name="value"` with no space around the `=` is accepted;
/// the writer never emits anything else, and foreign writers that
/// do are rare enough to fail closed on.
fn attr_value(attrs: &str, wanted: &str) -> Option<String> {
    for form in [format!("{wanted}=\""), format!("{wanted}='")] {
        if let Some(start) = attrs.find(&form) {
            let quote = form.as_bytes().last().copied().unwrap_or(b'"');
            let rest = attrs.get(start + form.len()..)?;
            let end = rest.find(char::from(quote))?;
            return rest.get(..end).map(str::to_owned);
        }
    }
    None
}

/// Map a digest-method URI onto the crate's algorithms.
fn digest_by_uri(uri: &str) -> Result<(DigestAlgorithm, String), DocumentVerifyError> {
    // Canonical xmldsig URIs, plus the xmlenc-namespace SHA-384 some
    // writers emit (same hash, wrong namespace).
    if uri == "http://www.w3.org/2001/04/xmlenc#sha256" {
        Ok((DigestAlgorithm::Sha256, "SHA-256".to_owned()))
    } else if uri == "http://www.w3.org/2001/04/xmldsig-more#sha384"
        || uri == "http://www.w3.org/2001/04/xmlenc#sha384"
    {
        Ok((DigestAlgorithm::Sha384, "SHA-384".to_owned()))
    } else {
        Err(DocumentVerifyError::Manifest(format!(
            "unsupported digest {uri}"
        )))
    }
}

/// XML-unescape plus percent-decode a manifest URI, liberally:
/// malformed escapes stay literal and fail closed at lookup.
fn decode_uri(raw: &str) -> String {
    let unescaped = raw
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&");
    let bytes = unescaped.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0_usize;
    while let Some(byte) = bytes.get(index) {
        if *byte == b'%' {
            let hex = bytes.get(index + 1..index + 3);
            if let Some(hex) = hex
                && let Ok(text) = std::str::from_utf8(hex)
                && let Ok(value) = u8::from_str_radix(text, 16)
            {
                out.push(value);
                index += 3;
                continue;
            }
        }
        out.push(*byte);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Recompute every manifest digest against the container entries.
fn check_digests(entries: &[ZipEntry], refs: &[ManifestRef]) -> Vec<VerifiedFile> {
    refs.iter()
        .map(|reference| {
            entries
                .iter()
                .find(|entry| entry.name == reference.uri)
                .or_else(|| entries.iter().find(|entry| entry.name == reference.raw_uri))
                .map_or_else(
                    || VerifiedFile {
                        name: reference.uri.clone(),
                        algorithm: reference.label.clone(),
                        digest_ok: false,
                        detail: "missing from container".to_owned(),
                    },
                    |entry| {
                        let actual = reference.algorithm.digest(&entry.data);
                        if actual == reference.expected {
                            VerifiedFile {
                                name: reference.uri.clone(),
                                algorithm: reference.label.clone(),
                                digest_ok: true,
                                detail: String::new(),
                            }
                        } else {
                            VerifiedFile {
                                name: reference.uri.clone(),
                                algorithm: reference.label.clone(),
                                digest_ok: false,
                                detail: "digest mismatch".to_owned(),
                            }
                        }
                    },
                )
        })
        .collect()
}

/// Data files the manifest does not cover fail closed: an
/// unreferenced file rides along unattested, which defeats the
/// point of the container. `mimetype` and `META-INF/*` are
/// container furniture, not data.
fn flag_uncovered_files(entries: &[ZipEntry], refs: &[ManifestRef], files: &mut Vec<VerifiedFile>) {
    for entry in entries {
        if entry.name == "mimetype" || entry.name.starts_with("META-INF/") {
            continue;
        }
        let covered = refs
            .iter()
            .any(|reference| reference.uri == entry.name || reference.raw_uri == entry.name);
        if !covered {
            files.push(VerifiedFile {
                name: entry.name.clone(),
                algorithm: "—".to_owned(),
                digest_ok: false,
                detail: "not covered by manifest".to_owned(),
            });
        }
    }
}

/// Verify every `CAdES` signature entry against the manifest bytes.
#[allow(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "ZIP entry names are byte-exact, not filesystem paths: a case-insensitive match would accept entries the manifest does not name"
)]
fn verify_signatures(
    entries: &[ZipEntry],
    manifest: &[u8],
) -> Result<Vec<VerifiedSignature>, DocumentVerifyError> {
    let signatures: Vec<&ZipEntry> = entries
        .iter()
        .filter(|entry| {
            entry.name.starts_with("META-INF/")
                && (entry.name.ends_with(".p7s") || entry.name.ends_with(".p7m"))
        })
        .collect();
    if signatures.is_empty() {
        return Err(DocumentVerifyError::NoSignatures);
    }
    signatures
        .iter()
        .map(|entry| verify_signature(&entry.data, manifest))
        .collect()
}

/// Verify one detached `CAdES` over the manifest bytes.
///
/// The manifest is the external content of the detached signature
/// (ETSI EN 319 162-1 V1.1.1 clause 4.4.4.2 item 3a).
fn verify_signature<'a>(
    p7: &'a [u8],
    manifest: &'a [u8],
) -> Result<VerifiedSignature, DocumentVerifyError> {
    let signed = SignedData::parse(p7)
        .map_err(|error| DocumentVerifyError::Cms(format!("signature does not parse: {error}")))?;
    if signed.econtent_type_oid != known::DATA {
        return Err(DocumentVerifyError::Cms(
            "signature eContentType is not id-data".to_owned(),
        ));
    }
    let mut matched: Option<(OwnedCert, Option<String>)> = None;
    for candidate in &signed.certificates_der {
        let owned = OwnedCert::from_der(candidate).map_err(|error| {
            DocumentVerifyError::Cms(format!("embedded certificate does not parse: {error:?}"))
        })?;
        let binds = {
            let view = owned.view();
            certificate_matches_sid(&view, signed.signer.signer_identifier)
        };
        if binds {
            let cn = owned
                .view()
                .subject
                .common_name()
                .map(|cn| cn.as_str().to_owned());
            matched = Some((owned, cn));
            break;
        }
    }
    let Some((owned, cn)) = matched else {
        return Err(DocumentVerifyError::Cms(
            "signer certificate is not embedded".to_owned(),
        ));
    };
    let view = owned.view();
    match signed.verify_detached(view.spki, manifest) {
        Ok(()) => Ok(VerifiedSignature {
            signer_cn: cn,
            valid: true,
            detail: String::new(),
        }),
        Err(error) => Ok(VerifiedSignature {
            signer_cn: cn,
            valid: false,
            detail: error.to_string(),
        }),
    }
}

/// Whether `certificate` is the one `sid` names: issuer plus
/// serial, or subject key identifier.
fn certificate_matches_sid(certificate: &Certificate<'_>, sid: SignerIdentifier<'_>) -> bool {
    match sid {
        SignerIdentifier::IssuerAndSerialNumber {
            issuer_der,
            serial_number,
        } => certificate.issuer.as_der() == issuer_der && certificate.serial_der == serial_number,
        SignerIdentifier::SubjectKeyIdentifier(wanted) => {
            certificate.extensions.and_then(subject_key_id).as_deref() == Some(wanted)
        }
    }
}

/// Subject key identifier extension value, when present and
/// well-formed: `extnValue` is an `OCTET STRING` wrapping the key
/// identifier `OCTET STRING`.
fn subject_key_id(extensions: &[u8]) -> Option<Vec<u8>> {
    for extension in BerTlvIter::new(extensions) {
        let extension = extension.ok()?.expect::<Sequence>().ok()?;
        let mut fields = extension.iter_children();
        let oid = fields.next()?.ok()?.expect::<BerOid>().ok()?;
        let oid = Oid::new(oid.value()).ok()?;
        if oid != oids::SUBJECT_KEY_IDENTIFIER {
            continue;
        }
        let next = fields.next()?.ok()?;
        let value = if next.tag() == <Boolean as BerTag>::TAG {
            fields.next()?.ok()?.expect::<OctetString>().ok()?
        } else {
            next.expect::<OctetString>().ok()?
        };
        let inner = BerTlv::<OctetString>::parse(value.value()).ok()?;
        if inner.size() != value.value().len() {
            continue;
        }
        return Some(inner.value().to_vec());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asic::{DataObject, plan, xades_container};
    use std::process::Command;

    fn objects() -> Vec<DataObject> {
        vec![
            DataObject {
                name: "hello.txt".to_owned(),
                mime_type: "text/plain".to_owned(),
                content: b"hello RefineID".to_vec(),
            },
            DataObject {
                name: "data.bin".to_owned(),
                mime_type: "application/octet-stream".to_owned(),
                content: vec![0, 1, 2, 3, 4, 5, 6, 7],
            },
        ]
    }

    #[test]
    fn writer_output_parses_back() {
        let container = plan(objects(), DigestAlgorithm::Sha256)
            .finish(b"dummy-signature")
            .expect("finish");
        let entries = read_zip(&container).expect("parse");
        let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "mimetype",
                "hello.txt",
                "data.bin",
                MANIFEST_ENTRY,
                "META-INF/signature.p7s",
            ]
        );
        let hello = entries
            .iter()
            .find(|entry| entry.name == "hello.txt")
            .expect("hello");
        assert_eq!(hello.data, b"hello RefineID");
    }

    #[test]
    fn writer_manifest_parses_to_covering_refs() {
        let manifest = plan(objects(), DigestAlgorithm::Sha256).manifest().to_vec();
        let refs = parse_manifest(&manifest).expect("parse");
        assert_eq!(refs.len(), 2);
        let first = refs.first().expect("first ref");
        assert_eq!(first.uri, "hello.txt");
        assert_eq!(first.label, "SHA-256");
        assert_eq!(
            first.expected,
            DigestAlgorithm::Sha256.digest(b"hello RefineID")
        );
        assert_eq!(refs.get(1).expect("second ref").uri, "data.bin");
    }

    #[test]
    fn writer_round_trip_digests_check() {
        let container = plan(objects(), DigestAlgorithm::Sha384)
            .finish(b"dummy-signature")
            .expect("finish");
        let entries = read_zip(&container).expect("parse");
        let manifest = entries
            .iter()
            .find(|entry| entry.name == MANIFEST_ENTRY)
            .expect("manifest");
        let refs = parse_manifest(&manifest.data).expect("refs");
        let files = check_digests(&entries, &refs);
        assert_eq!(files.len(), 2);
        assert!(files.iter().all(|file| file.digest_ok));
        assert_eq!(files.first().expect("first file").algorithm, "SHA-384");
    }

    #[test]
    fn tampered_file_fails_its_digest() {
        let container = plan(objects(), DigestAlgorithm::Sha256)
            .finish(b"dummy-signature")
            .expect("finish");
        let mut entries = read_zip(&container).expect("parse");
        let manifest = entries
            .iter()
            .find(|entry| entry.name == MANIFEST_ENTRY)
            .expect("manifest")
            .data
            .clone();
        let refs = parse_manifest(&manifest).expect("refs");
        let hello = entries
            .iter_mut()
            .find(|entry| entry.name == "hello.txt")
            .expect("hello");
        if let Some(first) = hello.data.first_mut() {
            *first ^= 0xFF;
        }
        let files = check_digests(&entries, &refs);
        let hello = files
            .iter()
            .find(|file| file.name == "hello.txt")
            .expect("hello verdict");
        assert!(!hello.digest_ok);
        assert_eq!(hello.detail, "digest mismatch");
    }

    #[test]
    fn uncovered_file_fails_closed() {
        let container = plan(objects(), DigestAlgorithm::Sha256)
            .finish(b"dummy-signature")
            .expect("finish");
        let mut entries = read_zip(&container).expect("parse");
        entries.push(ZipEntry {
            name: "smuggled.txt".to_owned(),
            data: b"rides along".to_vec(),
        });
        let manifest = entries
            .iter()
            .find(|entry| entry.name == MANIFEST_ENTRY)
            .expect("manifest")
            .data
            .clone();
        let refs = parse_manifest(&manifest).expect("refs");
        let mut files = check_digests(&entries, &refs);
        flag_uncovered_files(&entries, &refs, &mut files);
        let smuggled = files
            .iter()
            .find(|file| file.name == "smuggled.txt")
            .expect("smuggled verdict");
        assert!(!smuggled.digest_ok);
        assert_eq!(smuggled.detail, "not covered by manifest");
    }

    #[test]
    fn non_containers_are_named() {
        assert!(matches!(
            verify_bytes(
                b"not a container at all, far too short?",
                "x.asice".to_owned()
            ),
            Err(DocumentVerifyError::NotAContainer)
        ));
        assert!(matches!(
            verify_bytes(b"%PDF-1.7 fake", "x.pdf".to_owned()),
            Err(DocumentVerifyError::Unsupported(_))
        ));
        let xades = xades_container(&objects(), b"<xml/>").expect("xades");
        assert!(matches!(
            verify_bytes(&xades, "x.bdoc".to_owned()),
            Err(DocumentVerifyError::Unsupported(_))
        ));
    }

    #[test]
    fn empty_manifest_is_an_error() {
        let container = plan(Vec::new(), DigestAlgorithm::Sha256)
            .finish(b"dummy-signature")
            .expect("finish");
        assert!(matches!(
            verify_bytes(&container, "empty.asice".to_owned()),
            Err(DocumentVerifyError::Manifest(_))
        ));
    }

    /// Test-only archive assembler: every record is a plain function,
    /// so a test can duplicate, hide, misplace or contradict one.
    mod raw {
        use super::super::{
            ZIP_CENTRAL_SIG, ZIP_EOD_SIG, ZIP_LOCAL_SIG, ZIP_METHOD_STORED, ZIP64_LOCATOR_LEN,
            ZIP64_LOCATOR_SIG,
        };
        use crate::asic::crc32;

        /// Version needed to extract: 2.0 (APPNOTE 4.4.3.2).
        const VERSION: u16 = 20;
        /// No general-purpose flags: not encrypted, no data descriptor.
        const NO_FLAGS: u16 = 0;
        /// Single-volume disk number (ISO/IEC 21320-1).
        const DISK: u16 = 0;
        /// External attributes of a plain file as a DOS archiver writes them.
        const PLAIN_FILE: u32 = 0;

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
            pub fn truthful(name: &[u8], data: &[u8]) -> Self {
                let size = u32::try_from(data.len()).expect("fixture fits");
                Self {
                    name: name.to_vec(),
                    flags: NO_FLAGS,
                    method: ZIP_METHOD_STORED,
                    compressed: size,
                    uncompressed: size,
                    crc: crc32(data),
                    extra: Vec::new(),
                    external: PLAIN_FILE,
                }
            }
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

        pub fn local_header(declared: &Declared) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(&ZIP_LOCAL_SIG.to_le_bytes());
            out.extend_from_slice(&VERSION.to_le_bytes());
            out.extend_from_slice(&declared.flags.to_le_bytes());
            out.extend_from_slice(&declared.method.to_le_bytes());
            out.extend_from_slice(&0_u16.to_le_bytes());
            out.extend_from_slice(&0_u16.to_le_bytes());
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

        pub fn central_record(declared: &Declared, local_offset: u32) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(&ZIP_CENTRAL_SIG.to_le_bytes());
            out.extend_from_slice(&VERSION.to_le_bytes());
            out.extend_from_slice(&VERSION.to_le_bytes());
            out.extend_from_slice(&declared.flags.to_le_bytes());
            out.extend_from_slice(&declared.method.to_le_bytes());
            out.extend_from_slice(&0_u16.to_le_bytes());
            out.extend_from_slice(&0_u16.to_le_bytes());
            out.extend_from_slice(&declared.crc.to_le_bytes());
            out.extend_from_slice(&declared.compressed.to_le_bytes());
            out.extend_from_slice(&declared.uncompressed.to_le_bytes());
            let name_len = u16::try_from(declared.name.len()).expect("fixture name fits");
            out.extend_from_slice(&name_len.to_le_bytes());
            let extra_len = u16::try_from(declared.extra.len()).expect("fixture extra fits");
            out.extend_from_slice(&extra_len.to_le_bytes());
            // Comment length.
            out.extend_from_slice(&0_u16.to_le_bytes());
            out.extend_from_slice(&DISK.to_le_bytes());
            // Internal attributes.
            out.extend_from_slice(&0_u16.to_le_bytes());
            out.extend_from_slice(&declared.external.to_le_bytes());
            out.extend_from_slice(&local_offset.to_le_bytes());
            out.extend_from_slice(&declared.name);
            out.extend_from_slice(&declared.extra);
            out
        }

        /// What the end record declares; a test may declare otherwise.
        pub struct Ending {
            pub disk: u16,
            pub count: Option<u16>,
            pub comment: Vec<u8>,
            pub zip64_locator: bool,
        }

        impl Default for Ending {
            fn default() -> Self {
                Self {
                    disk: DISK,
                    count: None,
                    comment: Vec::new(),
                    zip64_locator: false,
                }
            }
        }

        /// An archive under construction.
        #[derive(Default)]
        pub struct Archive {
            body: Vec<u8>,
            directory: Vec<Vec<u8>>,
        }

        impl Archive {
            pub fn new() -> Self {
                Self::default()
            }

            /// A well-formed entry: local header and central record agree.
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

            /// A central record for whatever sits at `offset`.
            pub fn add_record(&mut self, central: &Declared, offset: u32) {
                self.directory.push(central_record(central, offset));
            }

            /// A central directory record given as raw bytes.
            pub fn add_record_bytes(&mut self, record: Vec<u8>) {
                self.directory.push(record);
            }

            /// List the entries in the opposite order to their bytes.
            pub fn reverse_directory(&mut self) {
                self.directory.reverse();
            }

            /// Central directory and a truthful end record.
            pub fn finish(self) -> Vec<u8> {
                self.finish_declaring(Ending::default())
            }

            /// Central directory and an end record as `ending` says.
            pub fn finish_declaring(mut self, ending: Ending) -> Vec<u8> {
                let directory_at = u32::try_from(self.body.len()).expect("fixture fits");
                let true_count = u16::try_from(self.directory.len()).expect("fixture fits");
                let directory: Vec<u8> = self.directory.concat();
                let directory_size = u32::try_from(directory.len()).expect("fixture fits");
                self.body.extend_from_slice(&directory);
                if ending.zip64_locator {
                    self.body
                        .extend_from_slice(&ZIP64_LOCATOR_SIG.to_le_bytes());
                    let padding = ZIP64_LOCATOR_LEN - ZIP64_LOCATOR_SIG.to_le_bytes().len();
                    self.body.extend(std::iter::repeat_n(0_u8, padding));
                }
                let count = ending.count.unwrap_or(true_count);
                self.body.extend_from_slice(&ZIP_EOD_SIG.to_le_bytes());
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

    const FIRST_NAME: &[u8] = b"contract.pdf";
    const FIRST_DATA: &[u8] = b"the agreed text";
    const SECOND_NAME: &[u8] = b"annex.txt";
    const SECOND_DATA: &[u8] = b"an annex";
    const OTHER_DATA: &[u8] = b"a different text";

    fn two_entry_archive() -> raw::Archive {
        let mut archive = raw::Archive::new();
        archive.add(FIRST_NAME, FIRST_DATA);
        archive.add(SECOND_NAME, SECOND_DATA);
        archive
    }

    /// The ZIP-structure detail a refusal names.
    fn refusal(bytes: &[u8]) -> String {
        match read_zip(bytes) {
            Err(DocumentVerifyError::Zip(detail)) => detail,
            Err(other) => panic!("expected a ZIP refusal, got {other}"),
            Ok(_) => panic!("expected a refusal, got entries"),
        }
    }

    fn unsupported(bytes: &[u8]) -> String {
        match read_zip(bytes) {
            Err(DocumentVerifyError::Unsupported(detail)) => detail,
            Err(other) => panic!("expected an unsupported refusal, got {other}"),
            Ok(_) => panic!("expected a refusal, got entries"),
        }
    }

    /// One entry whose local header and central record both declare
    /// `declared` over `data`.
    fn single(data: &[u8], declared: &raw::Declared) -> Vec<u8> {
        let mut archive = raw::Archive::new();
        archive.add_declaring(data, declared, declared);
        archive.finish()
    }

    #[test]
    fn raw_archive_reads_in_directory_order() {
        let entries = read_zip(&two_entry_archive().finish()).expect("parse");
        let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
        assert_eq!(names, ["contract.pdf", "annex.txt"]);
        assert_eq!(entries.first().expect("first").data, FIRST_DATA);
    }

    #[test]
    fn a_comment_containing_the_signature_is_tolerated() {
        let mut comment = b"comment that mentions ".to_vec();
        comment.extend_from_slice(&ZIP_EOD_SIG.to_le_bytes());
        comment.extend_from_slice(b" and goes on");
        let bytes = two_entry_archive().finish_declaring(raw::Ending {
            comment,
            ..raw::Ending::default()
        });
        assert_eq!(read_zip(&bytes).expect("parse").len(), 2);
    }

    #[test]
    fn entries_out_of_physical_order_still_tile() {
        let mut archive = two_entry_archive();
        archive.reverse_directory();
        let entries = read_zip(&archive.finish()).expect("parse");
        let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
        assert_eq!(names, ["annex.txt", "contract.pdf"]);
    }

    #[test]
    fn duplicate_entry_name_is_refused() {
        let mut archive = two_entry_archive();
        archive.add(FIRST_NAME, OTHER_DATA);
        assert_eq!(refusal(&archive.finish()), "duplicate entry name");
    }

    #[test]
    fn case_insensitive_duplicate_name_is_refused() {
        let mut archive = two_entry_archive();
        archive.add(b"Contract.PDF", OTHER_DATA);
        assert_eq!(refusal(&archive.finish()), "duplicate entry name");
    }

    #[test]
    fn local_and_central_size_disagreement_is_refused() {
        let local = raw::Declared::truthful(FIRST_NAME, FIRST_DATA);
        let mut central = local.clone();
        central.uncompressed += 1;
        let mut archive = raw::Archive::new();
        archive.add_declaring(FIRST_DATA, &local, &central);
        assert_eq!(
            refusal(&archive.finish()),
            "central directory and local file header disagree"
        );
    }

    #[test]
    fn local_and_central_name_disagreement_is_refused() {
        let local = raw::Declared::truthful(FIRST_NAME, FIRST_DATA);
        let central = raw::Declared::truthful(SECOND_NAME, FIRST_DATA);
        let mut archive = raw::Archive::new();
        archive.add_declaring(FIRST_DATA, &local, &central);
        assert_eq!(
            refusal(&archive.finish()),
            "central directory and local file header disagree"
        );
    }

    #[test]
    fn crc_disagreement_is_refused() {
        let local = raw::Declared::truthful(FIRST_NAME, FIRST_DATA);
        let mut central = local.clone();
        central.crc ^= 1;
        let mut archive = raw::Archive::new();
        archive.add_declaring(FIRST_DATA, &local, &central);
        assert_eq!(
            refusal(&archive.finish()),
            "central directory and local file header disagree"
        );
    }

    #[test]
    fn flags_disagreement_is_refused() {
        let local = raw::Declared::truthful(FIRST_NAME, FIRST_DATA);
        let mut central = local.clone();
        central.flags |= ZIP_FLAG_ENCRYPTED;
        let mut archive = raw::Archive::new();
        archive.add_declaring(FIRST_DATA, &local, &central);
        assert_eq!(
            refusal(&archive.finish()),
            "central directory and local file header disagree"
        );
    }

    #[test]
    fn method_disagreement_is_refused() {
        let local = raw::Declared::truthful(FIRST_NAME, FIRST_DATA);
        let mut central = local.clone();
        central.method = ZIP_METHOD_DEFLATED;
        let mut archive = raw::Archive::new();
        archive.add_declaring(FIRST_DATA, &local, &central);
        assert_eq!(
            refusal(&archive.finish()),
            "central directory and local file header disagree"
        );
    }

    #[test]
    fn wrong_crc_is_refused() {
        let mut declared = raw::Declared::truthful(FIRST_NAME, FIRST_DATA);
        declared.crc ^= 1;
        assert_eq!(
            refusal(&single(FIRST_DATA, &declared)),
            "entry data does not match its CRC-32"
        );
    }

    #[test]
    fn encrypted_entry_is_refused() {
        let mut declared = raw::Declared::truthful(FIRST_NAME, FIRST_DATA);
        declared.flags |= ZIP_FLAG_ENCRYPTED;
        assert_eq!(
            refusal(&single(FIRST_DATA, &declared)),
            "encrypted entries are not supported"
        );
    }

    #[test]
    fn data_descriptor_entry_is_refused() {
        let mut declared = raw::Declared::truthful(FIRST_NAME, FIRST_DATA);
        declared.flags |= ZIP_FLAG_DESCRIPTOR;
        assert_eq!(
            refusal(&single(FIRST_DATA, &declared)),
            "data descriptors are not supported"
        );
    }

    #[test]
    fn trailing_bytes_after_eocd_are_refused() {
        let mut bytes = two_entry_archive().finish();
        bytes.extend_from_slice(b"appended after the end record");
        assert_eq!(
            refusal(&bytes),
            "no end of central directory record ends at the end of the file"
        );
    }

    #[test]
    fn missing_central_directory_is_refused() {
        let complete = two_entry_archive().finish();
        let directory_at = complete
            .windows(ZIP_CENTRAL_SIG.to_le_bytes().len())
            .position(|window| window == ZIP_CENTRAL_SIG.to_le_bytes())
            .expect("central directory present");
        let locals_only = complete.get(..directory_at).expect("prefix");
        assert_eq!(
            refusal(locals_only),
            "no end of central directory record ends at the end of the file"
        );
    }

    #[test]
    fn hidden_local_entry_between_entries_is_refused() {
        let mut archive = raw::Archive::new();
        archive.add(FIRST_NAME, FIRST_DATA);
        archive.add_unlisted(FIRST_NAME, OTHER_DATA);
        archive.add(SECOND_NAME, SECOND_DATA);
        assert_eq!(
            refusal(&archive.finish()),
            "local entries do not tile the archive exactly"
        );
    }

    #[test]
    fn hidden_local_entry_before_the_directory_is_refused() {
        let mut archive = two_entry_archive();
        archive.add_unlisted(FIRST_NAME, OTHER_DATA);
        assert_eq!(
            refusal(&archive.finish()),
            "local entries do not tile the archive exactly"
        );
    }

    #[test]
    fn overlapping_extents_are_refused() {
        // The outer entry's data is itself a complete inner entry, and
        // the directory lists both.
        let inner = raw::Declared::truthful(SECOND_NAME, SECOND_DATA);
        let mut outer_data = raw::local_header(&inner);
        outer_data.extend_from_slice(SECOND_DATA);
        let outer = raw::Declared::truthful(FIRST_NAME, &outer_data);
        let mut archive = raw::Archive::new();
        let outer_at = archive.add_unlisted_declaring(&outer_data, &outer);
        archive.add_record(&outer, outer_at);
        let inner_at = u32::try_from(raw::local_header(&outer).len()).expect("fixture fits");
        archive.add_record(&inner, inner_at);
        assert_eq!(
            refusal(&archive.finish()),
            "local entries do not tile the archive exactly"
        );
    }

    #[test]
    fn local_offset_not_at_a_local_header_is_refused() {
        let mut archive = two_entry_archive();
        let declared = raw::Declared::truthful(b"phantom.txt", OTHER_DATA);
        archive.add_record(&declared, 1);
        assert_eq!(
            refusal(&archive.finish()),
            "central directory names an offset that is not a local file header"
        );
    }

    #[test]
    fn zip64_markers_are_refused() {
        let bytes = two_entry_archive().finish_declaring(raw::Ending {
            count: Some(ZIP64_MARKER_U16),
            ..raw::Ending::default()
        });
        assert_eq!(unsupported(&bytes), "ZIP64 containers are not supported");
    }

    #[test]
    fn zip64_locator_is_refused() {
        let bytes = two_entry_archive().finish_declaring(raw::Ending {
            zip64_locator: true,
            ..raw::Ending::default()
        });
        assert_eq!(unsupported(&bytes), "ZIP64 containers are not supported");
    }

    #[test]
    fn zip64_extra_field_is_refused() {
        let mut declared = raw::Declared::truthful(FIRST_NAME, FIRST_DATA);
        declared.extra = raw::extra_field(EXTRA_ZIP64, b"");
        assert_eq!(
            unsupported(&single(FIRST_DATA, &declared)),
            "ZIP64 containers are not supported"
        );
    }

    #[test]
    fn unicode_path_extra_field_is_refused() {
        let mut declared = raw::Declared::truthful(FIRST_NAME, FIRST_DATA);
        declared.extra = raw::extra_field(EXTRA_UNICODE_PATH, b"another-name.pdf");
        assert_eq!(
            refusal(&single(FIRST_DATA, &declared)),
            "Unicode Path extra field"
        );
    }

    #[test]
    fn malformed_extra_field_is_refused() {
        let mut declared = raw::Declared::truthful(FIRST_NAME, FIRST_DATA);
        declared.extra = raw::extra_field(EXTRA_UNICODE_COMMENT, b"cut");
        declared.extra.pop();
        assert_eq!(
            refusal(&single(FIRST_DATA, &declared)),
            "malformed extra field"
        );
    }

    #[test]
    fn multi_disk_archive_is_refused() {
        let bytes = two_entry_archive().finish_declaring(raw::Ending {
            disk: 1,
            ..raw::Ending::default()
        });
        assert_eq!(refusal(&bytes), "multi-volume archives are not supported");
    }

    #[test]
    fn truncated_central_record_is_refused() {
        let mut archive = two_entry_archive();
        let mut declared = raw::Declared::truthful(b"long.txt", OTHER_DATA);
        declared.name = vec![b'n'; MAX_ARCHIVE_COMMENT_LEN];
        let mut record = raw::central_record(&declared, 0);
        record.truncate(record.len() - declared.name.len());
        archive.add_record_bytes(record);
        assert_eq!(
            refusal(&archive.finish()),
            "truncated central directory record"
        );
    }

    #[test]
    fn entry_count_mismatch_is_refused() {
        let over = two_entry_archive().finish_declaring(raw::Ending {
            count: Some(1 + 1 + 1),
            ..raw::Ending::default()
        });
        assert_eq!(
            refusal(&over),
            "central directory record does not start with its signature"
        );
        let under = two_entry_archive().finish_declaring(raw::Ending {
            count: Some(1),
            ..raw::Ending::default()
        });
        assert_eq!(
            refusal(&under),
            "central directory does not end at the end of central directory record"
        );
    }

    #[test]
    fn symlink_entry_is_refused() {
        let mut declared = raw::Declared::truthful(FIRST_NAME, FIRST_DATA);
        declared.external = u32::from(UNIX_SYMBOLIC_LINK) << UNIX_MODE_SHIFT;
        assert_eq!(
            refusal(&single(FIRST_DATA, &declared)),
            "symbolic link entry"
        );
    }

    #[test]
    fn directory_entry_is_refused() {
        let mut by_mode = raw::Declared::truthful(FIRST_NAME, FIRST_DATA);
        by_mode.external = u32::from(UNIX_DIRECTORY) << UNIX_MODE_SHIFT;
        assert_eq!(refusal(&single(FIRST_DATA, &by_mode)), "directory entry");
        let mut by_dos = raw::Declared::truthful(FIRST_NAME, FIRST_DATA);
        by_dos.external = DOS_DIRECTORY_ATTRIBUTE;
        assert_eq!(refusal(&single(FIRST_DATA, &by_dos)), "directory entry");
        let by_name = raw::Declared::truthful(b"folder/", b"");
        assert_eq!(refusal(&single(b"", &by_name)), "directory entry");
    }

    #[test]
    fn traversal_name_is_refused() {
        for (name, rule) in [
            (
                b"../contract.pdf".as_slice(),
                "relative path component in entry name",
            ),
            (
                b"docs/./contract.pdf",
                "relative path component in entry name",
            ),
            (b"/contract.pdf", "absolute entry name"),
            (b"docs\\contract.pdf", "backslash in entry name"),
            (b"docs//contract.pdf", "empty path component in entry name"),
            (b"contract\n.pdf", "control character in entry name"),
        ] {
            let declared = raw::Declared::truthful(name, FIRST_DATA);
            assert_eq!(refusal(&single(FIRST_DATA, &declared)), rule);
        }
    }

    #[test]
    fn empty_entry_name_is_refused() {
        let declared = raw::Declared::truthful(b"", FIRST_DATA);
        assert_eq!(refusal(&single(FIRST_DATA, &declared)), "empty entry name");
    }

    #[test]
    fn non_utf8_entry_name_is_refused() {
        let mut name = FIRST_NAME.to_vec();
        name.push(u8::MAX);
        let declared = raw::Declared::truthful(&name, FIRST_DATA);
        assert_eq!(
            refusal(&single(FIRST_DATA, &declared)),
            "entry name is not UTF-8"
        );
    }

    #[test]
    fn decompressed_ceiling_is_checked_before_inflating() {
        // A stored entry of a few bytes declaring a size past the
        // ceiling: the declared total is refused before the entry is
        // read, where the size mismatch would otherwise be named.
        let mut declared = raw::Declared::truthful(FIRST_NAME, FIRST_DATA);
        declared.uncompressed = ZIP64_MARKER_U32 - 1;
        assert_eq!(
            refusal(&single(FIRST_DATA, &declared)),
            "container exceeds the decompressed-size ceiling"
        );
    }

    /// Shell out, the way the `cades` interop tests do: the goal is a
    /// real RSA signature over a real manifest, which needs a real key.
    fn run(program: &str, args: &[&str]) -> Vec<u8> {
        let output = Command::new(program)
            .args(args)
            .output()
            .expect("openssl runs");
        // No argv in the message: it holds temp key/cert paths,
        // and path-shaped diagnostics do not belong in output.
        assert!(
            output.status.success(),
            "{program} failed: {}",
            output.status
        );
        output.stdout
    }

    /// Throwaway RSA key plus self-signed certificate minted by
    /// the `openssl` binary. Returns the key path, the cert DER,
    /// and the scratch dir the caller removes.
    fn openssl_key_and_cert() -> (PathBuf, Vec<u8>, PathBuf) {
        let dir = std::env::temp_dir().join(format!("refineid-asic-verify-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let key = dir.join("key.pem");
        let cert = dir.join("cert.der");
        run(
            "openssl",
            &["genrsa", "-out", key.to_str().expect("key path"), "2048"],
        );
        run(
            "openssl",
            &[
                "req",
                "-new",
                "-x509",
                "-key",
                key.to_str().expect("key path"),
                "-outform",
                "DER",
                "-out",
                cert.to_str().expect("cert path"),
                "-days",
                "2",
                "-subj",
                "/CN=RefineID ASiC interop",
            ],
        );
        let cert_der = std::fs::read(&cert).expect("cert der");
        (key, cert_der, dir)
    }

    /// End to end: `openssl` signs a manifest the writer built, the
    /// container verifies, and a flipped digest bit flips the verdict.
    /// Ignored by default: needs the `openssl` binary, like the
    /// `cades` interop tests it mirrors.
    #[test]
    #[ignore = "requires the openssl binary"]
    fn openssl_signed_container_verifies() {
        use crate::cades::{
            Encapsulation, SignatureAlgorithm, SignerParameters, SigningTime, signed_attributes,
            signed_data,
        };
        use crate::test_support::parse_certificate_for_test;
        use crate::validation::ValidationMaterial;

        let (key, cert_der, dir) = openssl_key_and_cert();
        let certificate = parse_certificate_for_test(&cert_der);
        let manifest = plan(objects(), DigestAlgorithm::Sha256).manifest().to_vec();
        let parameters = SignerParameters {
            certificate: &certificate,
            signature_algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            digest_algorithm: DigestAlgorithm::Sha256,
            signing_time: Some(SigningTime {
                year: 2026,
                month: 1,
                day: 2,
                hour: 3,
                minute: 4,
                second: 5,
            }),
        };
        let content_digest = DigestAlgorithm::Sha256.digest(&manifest);
        let attributes = signed_attributes(&parameters, &content_digest);
        let tbs_path = dir.join("tbs.der");
        std::fs::write(&tbs_path, attributes.as_bytes()).expect("tbs");
        let sig_path = dir.join("sig.bin");
        run(
            "openssl",
            &[
                "dgst",
                "-sha256",
                "-sign",
                key.to_str().expect("key path"),
                "-out",
                sig_path.to_str().expect("sig path"),
                tbs_path.to_str().expect("tbs path"),
            ],
        );
        let signature = std::fs::read(&sig_path).expect("sig");
        let p7 = signed_data(
            &parameters,
            &attributes,
            &signature,
            Encapsulation::Detached,
            &manifest,
            &ValidationMaterial::default(),
            &[],
        );
        let container = plan(objects(), DigestAlgorithm::Sha256)
            .finish(&p7)
            .expect("finish");
        let report =
            verify_bytes(&container, "interop.asice".to_owned()).expect("container verifies");
        assert!(report.ok, "report:\n{}", report.render());
        assert_eq!(report.files.len(), 2);
        assert_eq!(report.signatures.len(), 1);
        assert_eq!(
            report
                .signatures
                .first()
                .expect("one signature")
                .signer_cn
                .as_deref(),
            Some("RefineID ASiC interop")
        );
        assert!(report.render().contains("Result: VALID"));

        // Flip one manifest digest bit: same structure, failed verdict.
        let mut tampered = manifest.clone();
        tamper_first_digest(&mut tampered);
        let mut tampered_container = plan(objects(), DigestAlgorithm::Sha256)
            .finish(&p7)
            .expect("finish");
        let at = tampered_container
            .windows(manifest.len())
            .position(|window| window == manifest.as_slice())
            .expect("manifest inside");
        tampered_container.splice(at..at + manifest.len(), tampered.iter().copied());
        let report = verify_bytes(&tampered_container, "tampered.asice".to_owned())
            .expect("tamper still parses");
        assert!(!report.ok);
        assert!(report.files.iter().any(|file| !file.digest_ok));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Flip the first digest character to a different valid base64
    /// character, so the manifest stays well-formed but names a
    /// digest no file has.
    fn tamper_first_digest(manifest: &mut [u8]) {
        let marker = b"DigestValue>";
        let start = manifest
            .windows(marker.len())
            .position(|window| window == marker)
            .expect("DigestValue present")
            + marker.len();
        let byte = manifest.get_mut(start).expect("digest char");
        *byte = if *byte == b'A' { b'B' } else { b'A' };
    }
}
