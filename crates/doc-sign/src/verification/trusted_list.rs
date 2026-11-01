// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! Reading the EU trusted lists (`ETSI TS 119 612`): the List of
//! Trusted Lists the European Commission publishes and the national
//! lists it points at, into the trust anchors a relying party takes
//! from them.
//!
//! [`TrustedList::read`] is the border for one list: its enveloped
//! `XAdES` signature must verify under a certificate the caller names
//! as entitled to sign it, and every field this crate consults is read
//! once into typed facts. [`TrustedLists::read`] applies it twice: to
//! the list of the lists under the Commission certificates the core
//! pins ([`crate::trust::LOTL_SIGNER_DER`]), then to each national list
//! under the certificates the list of the lists carries in its pointer.
//! Pointers are followed one level: a national list's own pointers are
//! read but never fetched. [`TrustAnchors::from_trusted_lists`] turns
//! the qualified certificate-issuing and time-stamping services of the
//! national lists into anchors granted for the periods their status
//! history grants.
//!
//! Fetching and caching are the shell's: [`TrustedLists::fetch`] reads
//! over the crate's HTTP transport ([`fetch_over_http`]), and returns
//! beside the lists one [`CachedList`] per list for the shell to store;
//! [`TrustedLists::from_cache`] reads the stored records back, verifying
//! every signature again. Nothing here writes a file.
//!
//! # Conformance
//!
//! - `ETSI TS 119 612` V2.3.1 clause 5.3.3: the list types
//!   `EUlistofthelists` and `EUgeneric`; clause 5.3.13: a pointer
//!   carries the location of another list, the digital identities of
//!   its signer and its type, territory and media type; clause 5.3.14
//!   and 5.3.15: issue time and next update, a list past its next
//!   update being expired; clause 5.5.1.1: the service types `CA/QC`
//!   and `TSA/QTST`; clause 5.5.3: a service's digital identity is its
//!   public key, represented by one or more certificates whose subject
//!   name and key are the trust anchor; clauses 5.5.4, 5.5.5, 5.5.10
//!   and 5.6: the current status with its starting time and the
//!   previous statuses with theirs; annex D.5.6: the status
//!   identifiers; annex J: the statuses a qualified certificate service
//!   held before Regulation (EU) No 910/2014 applied that became
//!   `granted` on 1 July 2016, and the time-stamping statuses that
//!   became `withdrawn`.
//! - `ETSI TS 119 612` V2.3.1 clause 5.7.1, annex A.1 and annex B.1: a
//!   list is signed `XAdES-B-B` with an enveloped signature whose
//!   reference to the list carries the enveloped-signature transform
//!   and a canonicalisation; the signer is authenticated by comparing
//!   its certificate with the ones published for the list, the
//!   Commission's in the Official Journal and a national operator's in
//!   the list of the lists.
//! - W3C XML Signature 1.1 sec.6.6.4: the enveloped-signature
//!   transform removes the `ds:Signature` holding the reference.

use super::trust::{AnchorRole, GrantedPeriod, TrustAnchor, TrustAnchors};
use super::xades::{
    ATTRIBUTE_ALGORITHM, ATTRIBUTE_TYPE, ATTRIBUTE_URI, DigestValue,
    ELEMENT_CANONICALIZATION_METHOD, ELEMENT_KEY_INFO, ELEMENT_OBJECT,
    ELEMENT_QUALIFYING_PROPERTIES, ELEMENT_REFERENCE, ELEMENT_SIGNATURE, ELEMENT_SIGNATURE_METHOD,
    ELEMENT_SIGNATURE_VALUE, ELEMENT_SIGNED_INFO, ELEMENT_SIGNED_PROPERTIES,
    ELEMENT_SIGNED_SIGNATURE_PROPERTIES, ELEMENT_SIGNING_CERTIFICATE,
    ELEMENT_SIGNING_CERTIFICATE_V2, ELEMENT_TRANSFORM, ELEMENT_TRANSFORMS,
    ELEMENT_X509_CERTIFICATE, ELEMENT_X509_DATA, FRAGMENT_MARK, XadesReadError,
    canonicalization_method, default_canonicalization, read_cert_digest, signature_method,
    xml_date_time,
};
use super::xml::{ATTRIBUTE_ID, ElementRef, XmlDocument, XmlError};
use crate::base64;
use crate::http;
use crate::trust::LOTL_SIGNER_DER;
use crate::uri::Uri;
use crate::xades::{NAMESPACE_DSIG, NAMESPACE_XADES, TYPE_SIGNED_PROPERTIES};
use refineid_cms::x509::{DateTime, OwnedCert};

/// Where the European Commission publishes the List of Trusted Lists
/// (its `DistributionPoints` entry, and the location notified in the
/// Official Journal).
pub const LOTL_LOCATION: &str = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";

/// Most bytes one list may have: the largest national list is a few
/// megabytes.
pub const MAX_LIST_BYTES: usize = 16 * 1024 * 1024;

/// Most pointers one list may carry: the list of the lists carries
/// one or two per member state.
pub const MAX_POINTERS: usize = 64;

/// Most signer certificates one pointer may carry (TS 119 612 annex
/// A.2 asks operators to publish a few with shifted validity).
pub const MAX_POINTER_SIGNERS: usize = 16;

/// Most services one list may carry: the largest national list has
/// about a thousand.
pub const MAX_SERVICES: usize = 8192;

/// Most history entries one service may carry.
pub const MAX_HISTORY: usize = 64;

/// Most certificates one service digital identity may carry: they all
/// represent one public key (TS 119 612 clause 5.5.3). National lists
/// in use list up to 13 renewals of one key in one identity.
pub const MAX_IDENTITY_CERTIFICATES: usize = 32;

/// The trusted-list namespace (TS 119 612 annex B.0).
const NAMESPACE_TSL: &str = "http://uri.etsi.org/02231/v2#";

/// The namespace of the additional types, among them a pointer's
/// `MimeType` (TS 119 612 annex B.0).
const NAMESPACE_TSL_ADDITIONAL: &str = "http://uri.etsi.org/02231/v2/additionaltypes#";

/// The list type of the EU list of the lists (annex D.5.1).
const TSL_TYPE_EU_LIST_OF_THE_LISTS: &str =
    "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists";

/// The list type of an EU member state's list (annex D.5.1).
const TSL_TYPE_EU_GENERIC: &str = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric";

/// The qualified certificate-issuing service type (clause 5.5.1.1 (a)).
const SERVICE_TYPE_CA_QC: &str = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";

/// The qualified time-stamping service type (clause 5.5.1.1 (d)).
const SERVICE_TYPE_TSA_QTST: &str = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST";

/// The prefix every status identifier shares (annex D.5.6).
const STATUS_PREFIX: &str = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/";

/// The instant the Directive 1999/93/EC regime ended: Regulation (EU)
/// No 910/2014 applies from 1 July 2016 (its article 52(2)), and TS
/// 119 612 annex J moved every service holding a status of the
/// Directive to `granted` or `withdrawn` then.
const DIRECTIVE_REGIME_END: &str = "2016-07-01T00:00:00Z";

/// The media type of a machine-processable list (clause 6.2).
const MIME_TYPE_TSL_XML: &str = "application/vnd.etsi.tsl+xml";

/// The enveloped-signature transform (XML Signature 1.1 sec.6.6.4).
const TRANSFORM_ENVELOPED_SIGNATURE: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/// The language tag of English, the operator and service name
/// preferred when a name comes in several languages (clause 5.1.4).
const LANGUAGE_ENGLISH: &str = "en";

/// The `xml:lang` attribute.
const XML_LANG: &str = "lang";

/// `TrustServiceStatusList`, the document element.
const ELEMENT_TRUST_SERVICE_STATUS_LIST: &str = "TrustServiceStatusList";
/// `SchemeInformation`.
const ELEMENT_SCHEME_INFORMATION: &str = "SchemeInformation";
/// `TSLType`.
const ELEMENT_TSL_TYPE: &str = "TSLType";
/// `SchemeOperatorName`.
const ELEMENT_SCHEME_OPERATOR_NAME: &str = "SchemeOperatorName";
/// `Name`, a multilingual name entry.
const ELEMENT_NAME: &str = "Name";
/// `SchemeTerritory`.
const ELEMENT_SCHEME_TERRITORY: &str = "SchemeTerritory";
/// `PointersToOtherTSL`.
const ELEMENT_POINTERS_TO_OTHER_TSL: &str = "PointersToOtherTSL";
/// `OtherTSLPointer`.
const ELEMENT_OTHER_TSL_POINTER: &str = "OtherTSLPointer";
/// `ServiceDigitalIdentities`.
const ELEMENT_SERVICE_DIGITAL_IDENTITIES: &str = "ServiceDigitalIdentities";
/// `ServiceDigitalIdentity`.
const ELEMENT_SERVICE_DIGITAL_IDENTITY: &str = "ServiceDigitalIdentity";
/// `DigitalId`.
const ELEMENT_DIGITAL_ID: &str = "DigitalId";
/// `X509Certificate` in the trusted-list namespace.
const ELEMENT_TSL_X509_CERTIFICATE: &str = "X509Certificate";
/// `TSLLocation`.
const ELEMENT_TSL_LOCATION: &str = "TSLLocation";
/// `AdditionalInformation`.
const ELEMENT_ADDITIONAL_INFORMATION: &str = "AdditionalInformation";
/// `OtherInformation`.
const ELEMENT_OTHER_INFORMATION: &str = "OtherInformation";
/// `MimeType`, in the additional-types namespace.
const ELEMENT_MIME_TYPE: &str = "MimeType";
/// `ListIssueDateTime`.
const ELEMENT_LIST_ISSUE_DATE_TIME: &str = "ListIssueDateTime";
/// `NextUpdate`.
const ELEMENT_NEXT_UPDATE: &str = "NextUpdate";
/// `dateTime`, the child of `NextUpdate`.
const ELEMENT_DATE_TIME: &str = "dateTime";
/// `TrustServiceProviderList`.
const ELEMENT_TRUST_SERVICE_PROVIDER_LIST: &str = "TrustServiceProviderList";
/// `TrustServiceProvider`.
const ELEMENT_TRUST_SERVICE_PROVIDER: &str = "TrustServiceProvider";
/// `TSPInformation`.
const ELEMENT_TSP_INFORMATION: &str = "TSPInformation";
/// `TSPName`.
const ELEMENT_TSP_NAME: &str = "TSPName";
/// `TSPServices`.
const ELEMENT_TSP_SERVICES: &str = "TSPServices";
/// `TSPService`.
const ELEMENT_TSP_SERVICE: &str = "TSPService";
/// `ServiceInformation`.
const ELEMENT_SERVICE_INFORMATION: &str = "ServiceInformation";
/// `ServiceTypeIdentifier`.
const ELEMENT_SERVICE_TYPE_IDENTIFIER: &str = "ServiceTypeIdentifier";
/// `ServiceName`.
const ELEMENT_SERVICE_NAME: &str = "ServiceName";
/// `ServiceStatus`.
const ELEMENT_SERVICE_STATUS: &str = "ServiceStatus";
/// `StatusStartingTime`.
const ELEMENT_STATUS_STARTING_TIME: &str = "StatusStartingTime";
/// `ServiceHistory`.
const ELEMENT_SERVICE_HISTORY: &str = "ServiceHistory";
/// `ServiceHistoryInstance`.
const ELEMENT_SERVICE_HISTORY_INSTANCE: &str = "ServiceHistoryInstance";

/// Why a list was not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedListError {
    /// The list exceeds [`MAX_LIST_BYTES`].
    TooLarge,
    /// The bytes are not XML this crate reads.
    Xml(XmlError),
    /// The document element is not a `TrustServiceStatusList`.
    NotTrustedList,
    /// A field every list has is absent or does not read.
    Malformed(&'static str),
    /// The `TSLType` is neither the EU list of the lists nor an EU
    /// member state list.
    UnknownListType,
    /// A service status identifier is none of annex D.5.6.
    UnknownServiceStatus,
    /// A count exceeds its bound.
    Bound(ListBound),
    /// The list carries no `ds:Signature`, or more than one.
    NoSignature,
    /// The signature uses an algorithm, canonicalisation or reference
    /// this crate does not compute, so it cannot be verified.
    Unverifiable(&'static str),
    /// The signer certificate is none of the certificates entitled to
    /// sign this list.
    SignerNotEntitled,
    /// A reference digest or the signature value does not verify.
    SignatureInvalid,
    /// The list of the lists was asked for but not fetched.
    NotFetched,
    /// The list read as the list of the lists is not one.
    NotListOfTheLists,
}

impl From<XadesReadError> for TrustedListError {
    fn from(error: XadesReadError) -> Self {
        match error {
            XadesReadError::Xml(error) => Self::Xml(error),
            XadesReadError::NoSignature => Self::NoSignature,
            XadesReadError::Malformed(what) => Self::Malformed(what),
        }
    }
}

impl core::fmt::Display for TrustedListError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLarge => f.write_str("the trusted list exceeds the size bound"),
            Self::Xml(error) => write!(f, "trusted list: {error}"),
            Self::NotTrustedList => f.write_str("the document is not a trusted list"),
            Self::Malformed(what) => write!(f, "malformed trusted list: {what}"),
            Self::UnknownListType => f.write_str("the trusted list is of a type not read"),
            Self::UnknownServiceStatus => f.write_str("a service status is not one of the known"),
            Self::Bound(bound) => write!(f, "the trusted list exceeds its {bound} bound"),
            Self::NoSignature => f.write_str("the trusted list carries no single signature"),
            Self::Unverifiable(what) => {
                write!(f, "the trusted list signature cannot be verified: {what}")
            }
            Self::SignerNotEntitled => {
                f.write_str("the trusted list is signed by a certificate not entitled to sign it")
            }
            Self::SignatureInvalid => f.write_str("the trusted list signature does not verify"),
            Self::NotFetched => f.write_str("the list of the lists was not fetched"),
            Self::NotListOfTheLists => f.write_str("the list is not the list of the lists"),
        }
    }
}

impl core::error::Error for TrustedListError {}

/// A count a list exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListBound {
    /// [`MAX_POINTERS`].
    Pointers,
    /// [`MAX_POINTER_SIGNERS`].
    PointerSigners,
    /// [`MAX_SERVICES`].
    Services,
    /// [`MAX_HISTORY`].
    History,
    /// [`MAX_IDENTITY_CERTIFICATES`].
    IdentityCertificates,
}

impl core::fmt::Display for ListBound {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Pointers => "pointer",
            Self::PointerSigners => "pointer signer",
            Self::Services => "service",
            Self::History => "history",
            Self::IdentityCertificates => "identity certificate",
        })
    }
}

/// The type of a list (TS 119 612 clause 5.3.3, annex D.5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListType {
    /// The Commission's compiled list of pointers to the member
    /// states' lists.
    EuListOfTheLists,
    /// A member state's list of supervised trust services.
    EuGeneric,
}

impl ListType {
    /// The type `uri` names.
    fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            TSL_TYPE_EU_LIST_OF_THE_LISTS => Some(Self::EuListOfTheLists),
            TSL_TYPE_EU_GENERIC => Some(Self::EuGeneric),
            _ => None,
        }
    }
}

/// The form a pointer says the list it points at takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListFormat {
    /// The machine-processable XML list.
    Xml,
    /// Another form, such as the human-readable PDF, or none stated.
    Other,
}

/// What a listed service provides (TS 119 612 clause 5.5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceType {
    /// Qualified certificates (`CA/QC`).
    QualifiedCertificates,
    /// Qualified time-stamps (`TSA/QTST`).
    QualifiedTimeStamps,
    /// A type this crate takes no anchor from, by its identifier.
    Other(String),
}

impl ServiceType {
    /// The type `uri` names.
    fn from_uri(uri: &str) -> Self {
        match uri {
            SERVICE_TYPE_CA_QC => Self::QualifiedCertificates,
            SERVICE_TYPE_TSA_QTST => Self::QualifiedTimeStamps,
            other => Self::Other(other.to_owned()),
        }
    }

    /// The role an anchor taken from a service of this type plays.
    const fn anchor_role(&self) -> Option<AnchorRole> {
        match self {
            Self::QualifiedCertificates => Some(AnchorRole::CertificateIssuing),
            Self::QualifiedTimeStamps => Some(AnchorRole::TimeStamping),
            Self::Other(_) => None,
        }
    }
}

/// The status of a listed service (TS 119 612 annex D.5.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStatus {
    /// The qualified status is granted.
    Granted,
    /// The qualified status was not granted, or was withdrawn.
    Withdrawn,
    /// Under supervision (before Regulation (EU) No 910/2014 applied).
    UnderSupervision,
    /// Supervision of a service in cessation.
    SupervisionInCessation,
    /// Supervision ceased.
    SupervisionCeased,
    /// Supervision revoked.
    SupervisionRevoked,
    /// Accredited.
    Accredited,
    /// Accreditation ceased.
    AccreditationCeased,
    /// Accreditation revoked.
    AccreditationRevoked,
    /// Set by national law.
    SetByNationalLaw,
    /// Deprecated by national law.
    DeprecatedByNationalLaw,
    /// Recognised at national level.
    RecognisedAtNationalLevel,
    /// Deprecated at national level.
    DeprecatedAtNationalLevel,
}

impl ServiceStatus {
    /// The status `uri` names.
    fn from_uri(uri: &str) -> Option<Self> {
        /// The identifiers under [`STATUS_PREFIX`], annex D.5.6.
        const NAMES: [(&str, ServiceStatus); 13] = [
            ("granted", ServiceStatus::Granted),
            ("withdrawn", ServiceStatus::Withdrawn),
            ("undersupervision", ServiceStatus::UnderSupervision),
            (
                "supervisionincessation",
                ServiceStatus::SupervisionInCessation,
            ),
            ("supervisionceased", ServiceStatus::SupervisionCeased),
            ("supervisionrevoked", ServiceStatus::SupervisionRevoked),
            ("accredited", ServiceStatus::Accredited),
            ("accreditationceased", ServiceStatus::AccreditationCeased),
            ("accreditationrevoked", ServiceStatus::AccreditationRevoked),
            ("setbynationallaw", ServiceStatus::SetByNationalLaw),
            (
                "deprecatedbynationallaw",
                ServiceStatus::DeprecatedByNationalLaw,
            ),
            (
                "recognisedatnationallevel",
                ServiceStatus::RecognisedAtNationalLevel,
            ),
            (
                "deprecatedatnationallevel",
                ServiceStatus::DeprecatedAtNationalLevel,
            ),
        ];
        let name = uri.strip_prefix(STATUS_PREFIX)?;
        NAMES
            .iter()
            .find(|(known, _)| *known == name)
            .map(|(_, status)| *status)
    }

    /// Whether this is a status a qualified certificate service held
    /// under Directive 1999/93/EC that annex J (a) turned into
    /// `granted` when the Regulation applied.
    const fn is_directive_grant(self) -> bool {
        matches!(
            self,
            Self::UnderSupervision | Self::SupervisionInCessation | Self::Accredited
        )
    }
}

/// [`DIRECTIVE_REGIME_END`] as an instant.
///
/// # Panics
/// Never: the constant is a well-formed `xsd:dateTime`.
fn directive_regime_end() -> DateTime {
    xml_date_time(DIRECTIVE_REGIME_END).expect("the end of the Directive regime is a dateTime")
}

/// How far one status entry grants trust in a service's outputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Grant {
    /// It grants nothing.
    Nothing,
    /// It grants until a later status says otherwise, and at the
    /// latest until this instant.
    Until(DateTime),
    /// It grants until a later status says otherwise.
    OpenEnded,
}

/// One status a service held, from when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusEntry {
    /// The status.
    status: ServiceStatus,
    /// When it became effective.
    since: DateTime,
    /// The service type the entry was recorded under.
    service_type: ServiceType,
}

impl StatusEntry {
    /// What this entry grants a service of `service_type`. `granted`
    /// grants a qualified certificate or time-stamping service (clause
    /// 5.5.4). On a qualified certificate service the statuses of
    /// Directive 1999/93/EC that started before
    /// [`DIRECTIVE_REGIME_END`] grant until then at the latest (annex J
    /// (a)), and nothing when they start later; on a qualified
    /// time-stamping service annex J (c) made them `withdrawn`. An
    /// entry recorded under another service type grants nothing.
    fn grant(&self, service_type: &ServiceType) -> Grant {
        if self.service_type != *service_type {
            return Grant::Nothing;
        }
        match (service_type, self.status) {
            (
                ServiceType::QualifiedCertificates | ServiceType::QualifiedTimeStamps,
                ServiceStatus::Granted,
            ) => Grant::OpenEnded,
            (ServiceType::QualifiedCertificates, status) if status.is_directive_grant() => {
                let end = directive_regime_end();
                if self.since < end {
                    Grant::Until(end)
                } else {
                    Grant::Nothing
                }
            }
            _ => Grant::Nothing,
        }
    }

    /// The status.
    #[must_use]
    pub const fn status(&self) -> ServiceStatus {
        self.status
    }

    /// When it became effective.
    #[must_use]
    pub const fn since(&self) -> DateTime {
        self.since
    }
}

/// One trust service a list names (TS 119 612 clause 5.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustService {
    /// The provider's name.
    provider: String,
    /// The service's name.
    name: String,
    /// What it provides.
    service_type: ServiceType,
    /// The certificates representing its public key, the trust anchor
    /// it yields; empty for a type this crate takes no anchor from, or
    /// when none of them reads.
    certificates: Vec<OwnedCert>,
    /// How many certificates of its digital identity did not parse and
    /// were left out.
    unreadable_certificates: usize,
    /// The current status, from when.
    current: StatusEntry,
    /// The previous statuses, as listed.
    history: Vec<StatusEntry>,
}

impl TrustService {
    /// The provider's name.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// The service's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// What it provides.
    #[must_use]
    pub const fn service_type(&self) -> &ServiceType {
        &self.service_type
    }

    /// The certificates representing its public key.
    #[must_use]
    pub fn certificates(&self) -> &[OwnedCert] {
        &self.certificates
    }

    /// How many certificates of its digital identity did not parse as
    /// certificates this crate reads and were left out: nothing is
    /// anchored on them.
    #[must_use]
    pub const fn unreadable_certificates(&self) -> usize {
        self.unreadable_certificates
    }

    /// The current status, from when.
    #[must_use]
    pub const fn current(&self) -> &StatusEntry {
        &self.current
    }

    /// The previous statuses, as listed.
    #[must_use]
    pub fn history(&self) -> &[StatusEntry] {
        &self.history
    }

    /// The periods during which the service's status granted trust in
    /// its outputs, walking every status in time order: a period opens
    /// at a status that grants and closes at
    /// the next that does not, an entry of another service type than
    /// the current one included, or at the end a Directive status
    /// grants until; it stays open-ended while the current status
    /// grants. Of statuses starting at one instant the most recent
    /// fact counts last: the history, listed newest first, from its
    /// last entry to its first, then the current status. A period that
    /// closes at the instant it opened grants nothing and is left out.
    #[must_use]
    pub fn granted_periods(&self) -> Vec<GrantedPeriod> {
        let mut entries: Vec<&StatusEntry> = self
            .history
            .iter()
            .rev()
            .chain(core::iter::once(&self.current))
            .collect();
        entries.sort_by_key(|entry| entry.since);
        let mut periods = Vec::new();
        let mut close = |from: DateTime, to: Option<DateTime>| {
            if to != Some(from) {
                periods.extend(GrantedPeriod::new(from, to).ok());
            }
        };
        let mut open: Option<(DateTime, Option<DateTime>)> = None;
        for entry in entries {
            if let Some((from, Some(until))) = open
                && until < entry.since
            {
                close(from, Some(until));
                open = None;
            }
            open = match (open, entry.grant(&self.service_type)) {
                (None, Grant::Nothing) => None,
                (Some((from, _until)), Grant::Nothing) => {
                    close(from, Some(entry.since));
                    None
                }
                (None, Grant::Until(until)) => Some((entry.since, Some(until))),
                (None, Grant::OpenEnded) => Some((entry.since, None)),
                (Some((from, _until)), Grant::Until(until)) => Some((from, Some(until))),
                (Some((from, _until)), Grant::OpenEnded) => Some((from, None)),
            };
        }
        if let Some((from, until)) = open {
            close(from, until);
        }
        periods
    }

    /// The anchors this service yields: one per certificate, for the
    /// role its type names, granted for [`Self::granted_periods`]; none
    /// for a type no anchor is taken from, and none for a service never
    /// granted.
    fn anchors(&self) -> Vec<TrustAnchor> {
        let Some(role) = self.service_type.anchor_role() else {
            return Vec::new();
        };
        let periods = self.granted_periods();
        self.certificates
            .iter()
            .filter_map(|certificate| {
                TrustAnchor::new(certificate.clone(), role, periods.clone()).ok()
            })
            .collect()
    }
}

/// A pointer to another list (TS 119 612 clause 5.3.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListPointer {
    /// Where the list is published; `None` when the location is not a
    /// URL this crate fetches.
    location: Option<Uri>,
    /// The territory of the list pointed at.
    territory: String,
    /// The declared type of the list pointed at; `None` for a type
    /// this crate does not read.
    list_type: Option<ListType>,
    /// The declared form of the list pointed at.
    format: ListFormat,
    /// The certificates entitled to sign the list pointed at.
    signers: Vec<OwnedCert>,
    /// How many of the pointer's certificates did not parse and were
    /// left out.
    unreadable_signers: usize,
}

impl ListPointer {
    /// Where the list is published.
    #[must_use]
    pub const fn location(&self) -> Option<&Uri> {
        self.location.as_ref()
    }

    /// The territory of the list pointed at.
    #[must_use]
    pub fn territory(&self) -> &str {
        &self.territory
    }

    /// The declared type of the list pointed at.
    #[must_use]
    pub const fn list_type(&self) -> Option<ListType> {
        self.list_type
    }

    /// The declared form of the list pointed at.
    #[must_use]
    pub const fn format(&self) -> ListFormat {
        self.format
    }

    /// The certificates entitled to sign the list pointed at.
    #[must_use]
    pub fn signers(&self) -> &[OwnedCert] {
        &self.signers
    }

    /// How many of the pointer's certificates did not parse as
    /// certificates this crate reads and were left out: a list signed
    /// under one of them does not read.
    #[must_use]
    pub const fn unreadable_signers(&self) -> usize {
        self.unreadable_signers
    }

    /// Whether this pointer names a machine-processable national list:
    /// the ones [`TrustedLists::read`] follows.
    #[must_use]
    pub fn names_national_list(&self) -> bool {
        self.list_type == Some(ListType::EuGeneric) && self.format == ListFormat::Xml
    }
}

/// One trusted list, read and verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedList {
    /// Its type.
    list_type: ListType,
    /// The territory of its scheme.
    territory: String,
    /// The scheme operator's name.
    operator: String,
    /// When it was issued.
    issued_at: DateTime,
    /// By when the next update is due; `None` for a closed list.
    next_update: Option<DateTime>,
    /// Its pointers to other lists.
    pointers: Vec<ListPointer>,
    /// The services it lists, in document order.
    services: Vec<TrustService>,
    /// The certificate that signed it.
    signer: OwnedCert,
}

impl TrustedList {
    /// Read and verify one list: its signature must verify under one
    /// of `signers`, the certificates entitled to sign it.
    ///
    /// # Errors
    /// [`TrustedListError`] when the bytes are not a well-formed list
    /// inside the bounds, or the signature does not verify under
    /// `signers`.
    pub fn read(bytes: Vec<u8>, signers: &[OwnedCert]) -> Result<Self, TrustedListError> {
        if bytes.len() > MAX_LIST_BYTES {
            return Err(TrustedListError::TooLarge);
        }
        let document = XmlDocument::parse(bytes).map_err(TrustedListError::Xml)?;
        let root = document.root();
        if !root.is(NAMESPACE_TSL, ELEMENT_TRUST_SERVICE_STATUS_LIST) {
            return Err(TrustedListError::NotTrustedList);
        }
        let mut signatures = root.children_named(NAMESPACE_DSIG, ELEMENT_SIGNATURE);
        let signature = match (signatures.next(), signatures.next()) {
            (Some(signature), None) => signature,
            _ => return Err(TrustedListError::NoSignature),
        };
        let signer = verify_enveloped_signature(&document, root, signature, signers)?;

        let scheme = root
            .child(NAMESPACE_TSL, ELEMENT_SCHEME_INFORMATION)
            .ok_or(TrustedListError::Malformed("no SchemeInformation"))?;
        let list_type = ListType::from_uri(&required_text(scheme, ELEMENT_TSL_TYPE)?)
            .ok_or(TrustedListError::UnknownListType)?;
        let territory = required_text(scheme, ELEMENT_SCHEME_TERRITORY)?;
        let operator = scheme
            .child(NAMESPACE_TSL, ELEMENT_SCHEME_OPERATOR_NAME)
            .and_then(preferred_name)
            .ok_or(TrustedListError::Malformed("no SchemeOperatorName"))?;
        let issued_at = xml_date_time(&required_text(scheme, ELEMENT_LIST_ISSUE_DATE_TIME)?)
            .ok_or(TrustedListError::Malformed(
                "ListIssueDateTime is not a dateTime",
            ))?;
        let next_update = scheme
            .child(NAMESPACE_TSL, ELEMENT_NEXT_UPDATE)
            .ok_or(TrustedListError::Malformed("no NextUpdate"))?
            .child(NAMESPACE_TSL, ELEMENT_DATE_TIME)
            .map(|time| {
                xml_date_time(&time.text())
                    .ok_or(TrustedListError::Malformed("NextUpdate is not a dateTime"))
            })
            .transpose()?;

        let mut pointers = Vec::new();
        for pointer in scheme
            .child(NAMESPACE_TSL, ELEMENT_POINTERS_TO_OTHER_TSL)
            .into_iter()
            .flat_map(|pointers| pointers.children_named(NAMESPACE_TSL, ELEMENT_OTHER_TSL_POINTER))
        {
            if pointers.len() >= MAX_POINTERS {
                return Err(TrustedListError::Bound(ListBound::Pointers));
            }
            pointers.push(read_pointer(pointer)?);
        }

        let mut services = Vec::new();
        for provider in root
            .child(NAMESPACE_TSL, ELEMENT_TRUST_SERVICE_PROVIDER_LIST)
            .into_iter()
            .flat_map(|list| list.children_named(NAMESPACE_TSL, ELEMENT_TRUST_SERVICE_PROVIDER))
        {
            let provider_name = provider
                .child(NAMESPACE_TSL, ELEMENT_TSP_INFORMATION)
                .and_then(|information| information.child(NAMESPACE_TSL, ELEMENT_TSP_NAME))
                .and_then(preferred_name)
                .ok_or(TrustedListError::Malformed("no TSPName"))?;
            for service in provider
                .child(NAMESPACE_TSL, ELEMENT_TSP_SERVICES)
                .into_iter()
                .flat_map(|list| list.children_named(NAMESPACE_TSL, ELEMENT_TSP_SERVICE))
            {
                if services.len() >= MAX_SERVICES {
                    return Err(TrustedListError::Bound(ListBound::Services));
                }
                services.push(read_service(service, &provider_name)?);
            }
        }

        Ok(Self {
            list_type,
            territory,
            operator,
            issued_at,
            next_update,
            pointers,
            services,
            signer,
        })
    }

    /// Its type.
    #[must_use]
    pub const fn list_type(&self) -> ListType {
        self.list_type
    }

    /// The territory of its scheme.
    #[must_use]
    pub fn territory(&self) -> &str {
        &self.territory
    }

    /// The scheme operator's name.
    #[must_use]
    pub fn operator(&self) -> &str {
        &self.operator
    }

    /// When it was issued.
    #[must_use]
    pub const fn issued_at(&self) -> DateTime {
        self.issued_at
    }

    /// By when the next update is due; `None` for a closed list.
    #[must_use]
    pub const fn next_update(&self) -> Option<DateTime> {
        self.next_update
    }

    /// Whether the list is past its next update at `now` (TS 119 612
    /// clause 5.3.15: such a list is expired).
    #[must_use]
    pub fn is_stale(&self, now: DateTime) -> bool {
        self.next_update.is_some_and(|due| due < now)
    }

    /// Its pointers to other lists.
    #[must_use]
    pub fn pointers(&self) -> &[ListPointer] {
        &self.pointers
    }

    /// The services it lists.
    #[must_use]
    pub fn services(&self) -> &[TrustService] {
        &self.services
    }

    /// The certificate that signed it.
    #[must_use]
    pub const fn signer(&self) -> &OwnedCert {
        &self.signer
    }
}

/// Why a national list the list of the lists points at yielded no
/// anchors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListFailure {
    /// The pointer's location is not a URL this crate fetches.
    NoLocation,
    /// The shell supplied no bytes for the location.
    NotFetched,
    /// The bytes did not read as a list signed by a pointer signer.
    Unreadable(TrustedListError),
    /// The list read is not a member state list.
    NotNational,
}

impl core::fmt::Display for ListFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoLocation => f.write_str("the pointer names no fetchable location"),
            Self::NotFetched => f.write_str("the list was not fetched"),
            Self::Unreadable(error) => write!(f, "{error}"),
            Self::NotNational => f.write_str("the list is not a member state list"),
        }
    }
}

/// One national list the list of the lists points at, read or not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NationalList {
    /// The pointer's territory.
    territory: String,
    /// The pointer's location.
    location: Option<Uri>,
    /// The list, or why there is none.
    outcome: Result<TrustedList, ListFailure>,
}

impl NationalList {
    /// The pointer's territory.
    #[must_use]
    pub fn territory(&self) -> &str {
        &self.territory
    }

    /// The pointer's location.
    #[must_use]
    pub const fn location(&self) -> Option<&Uri> {
        self.location.as_ref()
    }

    /// The list, or why there is none.
    pub const fn outcome(&self) -> Result<&TrustedList, ListFailure> {
        match &self.outcome {
            Ok(list) => Ok(list),
            Err(failure) => Err(*failure),
        }
    }
}

/// One fetched list as the shell stores it: the bytes, when they were
/// fetched and when the list says it will be superseded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedList {
    /// Where the bytes were fetched from.
    location: Uri,
    /// When they were fetched.
    fetched_at: DateTime,
    /// The list's next update; `None` for a closed list.
    next_update: Option<DateTime>,
    /// The bytes, as fetched, for [`TrustedLists::from_cache`] to read
    /// and verify again.
    bytes: Vec<u8>,
}

impl CachedList {
    /// A record the shell reconstructs from its store.
    #[must_use]
    pub const fn new(
        location: Uri,
        fetched_at: DateTime,
        next_update: Option<DateTime>,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            location,
            fetched_at,
            next_update,
            bytes,
        }
    }

    /// Where the bytes were fetched from.
    #[must_use]
    pub const fn location(&self) -> &Uri {
        &self.location
    }

    /// When they were fetched.
    #[must_use]
    pub const fn fetched_at(&self) -> DateTime {
        self.fetched_at
    }

    /// The list's next update; `None` for a closed list.
    #[must_use]
    pub const fn next_update(&self) -> Option<DateTime> {
        self.next_update
    }

    /// The bytes, as fetched.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// The list of the lists and the national lists it points at, each
/// verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedLists {
    /// The list of the lists.
    list_of_the_lists: TrustedList,
    /// One entry per pointer to a machine-processable national list,
    /// in the order the list of the lists carries them.
    national: Vec<NationalList>,
    /// When the lists were fetched.
    fetched_at: DateTime,
}

impl TrustedLists {
    /// Read the list of the lists from `lotl` under `lotl_signers`,
    /// then each national list it points at from the bytes `national`
    /// returns for the pointer's location, under the pointer's
    /// signers. Pointers to a human-readable form, to the list of the
    /// lists itself or to a list type this crate does not read are not
    /// followed; a national list's own pointers are never followed.
    /// Beside the lists, one [`CachedList`] per list that read, for
    /// the shell to store.
    ///
    /// # Errors
    /// [`TrustedListError`] when the list of the lists does not read,
    /// or is not of the list-of-the-lists type. A national list that
    /// does not read is an entry with its [`ListFailure`], not an
    /// error.
    pub fn read(
        lotl: Vec<u8>,
        lotl_signers: &[OwnedCert],
        mut national: impl FnMut(&Uri) -> Option<Vec<u8>>,
        fetched_at: DateTime,
    ) -> Result<(Self, Vec<CachedList>), TrustedListError> {
        let lotl_location = lotl_location();
        let mut cache = Vec::new();
        let list_of_the_lists = TrustedList::read(lotl.clone(), lotl_signers)?;
        if list_of_the_lists.list_type != ListType::EuListOfTheLists {
            return Err(TrustedListError::NotListOfTheLists);
        }
        cache.push(CachedList::new(
            lotl_location,
            fetched_at,
            list_of_the_lists.next_update,
            lotl,
        ));
        let mut lists = Vec::new();
        for pointer in list_of_the_lists
            .pointers
            .iter()
            .filter(|pointer| pointer.names_national_list())
        {
            let outcome = match pointer.location.as_ref() {
                None => Err(ListFailure::NoLocation),
                Some(location) => match national(location) {
                    None => Err(ListFailure::NotFetched),
                    Some(bytes) => match TrustedList::read(bytes.clone(), &pointer.signers) {
                        Err(error) => Err(ListFailure::Unreadable(error)),
                        Ok(list) if list.list_type != ListType::EuGeneric => {
                            Err(ListFailure::NotNational)
                        }
                        Ok(list) => {
                            cache.push(CachedList::new(
                                location.clone(),
                                fetched_at,
                                list.next_update,
                                bytes,
                            ));
                            Ok(list)
                        }
                    },
                },
            };
            lists.push(NationalList {
                territory: pointer.territory.clone(),
                location: pointer.location.clone(),
                outcome,
            });
        }
        Ok((
            Self {
                list_of_the_lists,
                national: lists,
                fetched_at,
            },
            cache,
        ))
    }

    /// Fetch the list of the lists from [`LOTL_LOCATION`] and the
    /// national lists it points at over the crate's HTTP transport
    /// ([`fetch_over_http`]), and read them under the Commission
    /// certificates the core pins ([`lotl_signers`]).
    ///
    /// # Errors
    /// [`TrustedListError::NotFetched`] when the list of the lists does
    /// not arrive; otherwise as [`Self::read`].
    pub fn fetch(now: DateTime) -> Result<(Self, Vec<CachedList>), TrustedListError> {
        let lotl = fetch_over_http(&lotl_location()).ok_or(TrustedListError::NotFetched)?;
        Self::read(lotl, &lotl_signers(), fetch_over_http, now)
    }

    /// Read the lists back from the records a shell stored: the record
    /// at [`LOTL_LOCATION`] is the list of the lists, read under
    /// `lotl_signers` ([`lotl_signers`] for the Commission's), the
    /// others serve its pointers by location. Every signature is
    /// verified again; the lists count as fetched at the oldest
    /// record's time.
    ///
    /// # Errors
    /// [`TrustedListError::NotFetched`] without a record for the list
    /// of the lists; otherwise as [`Self::read`].
    pub fn from_cache(
        records: &[CachedList],
        lotl_signers: &[OwnedCert],
    ) -> Result<Self, TrustedListError> {
        let lotl_location = lotl_location();
        let lotl = records
            .iter()
            .find(|record| record.location == lotl_location)
            .ok_or(TrustedListError::NotFetched)?;
        let fetched_at = records
            .iter()
            .map(|record| record.fetched_at)
            .min()
            .unwrap_or(lotl.fetched_at);
        let (lists, _records) = Self::read(
            lotl.bytes.clone(),
            lotl_signers,
            |location| {
                records
                    .iter()
                    .find(|record| record.location == *location)
                    .map(|record| record.bytes.clone())
            },
            fetched_at,
        )?;
        Ok(lists)
    }

    /// The list of the lists.
    #[must_use]
    pub const fn list_of_the_lists(&self) -> &TrustedList {
        &self.list_of_the_lists
    }

    /// The national lists, read or not.
    #[must_use]
    pub fn national(&self) -> &[NationalList] {
        &self.national
    }

    /// When the lists were fetched.
    #[must_use]
    pub const fn fetched_at(&self) -> DateTime {
        self.fetched_at
    }

    /// The earliest next update among the list of the lists and the
    /// national lists that read: the instant from which the anchors
    /// taken from them come from a stale list. `None` when every list
    /// is closed.
    #[must_use]
    pub fn valid_until(&self) -> Option<DateTime> {
        self.readable().filter_map(|list| list.next_update).min()
    }

    /// Whether any list the anchors come from is past its next update
    /// at `now`.
    #[must_use]
    pub fn is_stale(&self, now: DateTime) -> bool {
        self.readable().any(|list| list.is_stale(now))
    }

    /// The list of the lists and every national list that read.
    fn readable(&self) -> impl Iterator<Item = &TrustedList> {
        core::iter::once(&self.list_of_the_lists).chain(
            self.national
                .iter()
                .filter_map(|list| list.outcome.as_ref().ok()),
        )
    }
}

impl TrustAnchors {
    /// The anchors a relying party takes from `lists`: the pinned
    /// roots ([`Self::pinned`]) beside one anchor per certificate of
    /// every qualified certificate-issuing and time-stamping service
    /// the national lists carry, granted for the periods its status
    /// history grants ([`TrustService::granted_periods`]). The anchors
    /// are fetched at the lists' fetch time and valid until the
    /// earliest next update ([`TrustedLists::valid_until`]).
    #[must_use]
    pub fn from_trusted_lists(lists: &TrustedLists) -> Self {
        let mut anchors = Self::pinned().anchors().to_vec();
        for list in lists
            .national
            .iter()
            .filter_map(|list| list.outcome.as_ref().ok())
        {
            for service in &list.services {
                anchors.extend(service.anchors());
            }
        }
        let anchors = Self::new(anchors).fetched(lists.fetched_at);
        match lists.valid_until() {
            Some(until) => anchors.valid_until(until),
            None => anchors,
        }
    }
}

/// The certificates entitled to sign the list of the lists, from
/// [`LOTL_SIGNER_DER`].
#[must_use]
pub fn lotl_signers() -> Vec<OwnedCert> {
    LOTL_SIGNER_DER
        .iter()
        .filter_map(|(_label, der)| OwnedCert::from_der(der).ok())
        .collect()
}

/// [`LOTL_LOCATION`] as a URL.
///
/// # Panics
/// Never: the constant is a well-formed HTTPS URL.
fn lotl_location() -> Uri {
    Uri::parse(LOTL_LOCATION.to_owned()).expect("the LOTL location is a URL")
}

/// The bytes at `url` over the crate's HTTP transport, at most
/// [`MAX_LIST_BYTES`]; `None` when they do not arrive.
#[must_use]
pub fn fetch_over_http(url: &Uri) -> Option<Vec<u8>> {
    http::get(url, MAX_LIST_BYTES).ok()
}

/// The text of the one child `local` of `parent` in the trusted-list
/// namespace.
fn required_text(parent: ElementRef<'_>, local: &'static str) -> Result<String, TrustedListError> {
    parent
        .child(NAMESPACE_TSL, local)
        .map(|element| element.text().trim().to_owned())
        .ok_or(TrustedListError::Malformed(local))
}

/// Of the multilingual `Name` children of `names`, the English one,
/// else the first (TS 119 612 clause 5.1.4).
fn preferred_name(names: ElementRef<'_>) -> Option<String> {
    let mut candidates = names.children_named(NAMESPACE_TSL, ELEMENT_NAME);
    let first = candidates.next()?;
    let english = core::iter::once(first)
        .chain(candidates)
        .find(|name| name.xml_attribute(XML_LANG) == Some(LANGUAGE_ENGLISH));
    Some(english.unwrap_or(first).text().trim().to_owned())
}

/// The certificates of every `ServiceDigitalIdentity/DigitalId/
/// X509Certificate` under `parent`, at most `bound` of them, and how
/// many did not parse as certificates and were left out. One that is
/// not base64 is malformed; one that is base64 but not a certificate
/// this crate reads (the national lists carry decades-old ones) is
/// counted, since nothing can be anchored on it.
fn read_certificates(
    parent: ElementRef<'_>,
    bound: ListBound,
) -> Result<(Vec<OwnedCert>, usize), TrustedListError> {
    let limit = match bound {
        ListBound::PointerSigners => MAX_POINTER_SIGNERS,
        ListBound::IdentityCertificates => MAX_IDENTITY_CERTIFICATES,
        ListBound::Pointers | ListBound::Services | ListBound::History => 0,
    };
    let mut certificates = Vec::new();
    let mut unreadable = 0;
    for certificate in parent
        .descendants()
        .filter(|element| element.is(NAMESPACE_TSL, ELEMENT_DIGITAL_ID))
        .flat_map(|id| id.children_named(NAMESPACE_TSL, ELEMENT_TSL_X509_CERTIFICATE))
    {
        if certificates.len() + unreadable >= limit {
            return Err(TrustedListError::Bound(bound));
        }
        let der = base64::decode_wrapped(&certificate.text())
            .map_err(|_ignored| TrustedListError::Malformed("X509Certificate is not base64"))?;
        match OwnedCert::from_der(&der) {
            Ok(certificate) => certificates.push(certificate),
            Err(_unreadable) => unreadable += 1,
        }
    }
    Ok((certificates, unreadable))
}

/// Read one `OtherTSLPointer`.
fn read_pointer(pointer: ElementRef<'_>) -> Result<ListPointer, TrustedListError> {
    let identities = pointer
        .child(NAMESPACE_TSL, ELEMENT_SERVICE_DIGITAL_IDENTITIES)
        .ok_or(TrustedListError::Malformed(
            "pointer without ServiceDigitalIdentities",
        ))?;
    let (signers, unreadable_signers) = read_certificates(identities, ListBound::PointerSigners)?;
    let location = Uri::parse(required_text(pointer, ELEMENT_TSL_LOCATION)?).ok();
    let information: Vec<ElementRef<'_>> = pointer
        .child(NAMESPACE_TSL, ELEMENT_ADDITIONAL_INFORMATION)
        .into_iter()
        .flat_map(|additional| additional.children_named(NAMESPACE_TSL, ELEMENT_OTHER_INFORMATION))
        .flat_map(ElementRef::children)
        .collect();
    let find = |namespace: &str, local: &str| {
        information
            .iter()
            .find(|element| element.is(namespace, local))
            .map(|element| element.text().trim().to_owned())
    };
    let territory = find(NAMESPACE_TSL, ELEMENT_SCHEME_TERRITORY).ok_or(
        TrustedListError::Malformed("pointer without SchemeTerritory"),
    )?;
    let list_type = find(NAMESPACE_TSL, ELEMENT_TSL_TYPE)
        .ok_or(TrustedListError::Malformed("pointer without TSLType"))?;
    let format = match find(NAMESPACE_TSL_ADDITIONAL, ELEMENT_MIME_TYPE) {
        Some(mime) if mime == MIME_TYPE_TSL_XML => ListFormat::Xml,
        _ => ListFormat::Other,
    };
    Ok(ListPointer {
        location,
        territory,
        list_type: ListType::from_uri(&list_type),
        format,
        signers,
        unreadable_signers,
    })
}

/// Read the type, status and status starting time of a
/// `ServiceInformation` or `ServiceHistoryInstance`.
fn read_status_entry(information: ElementRef<'_>) -> Result<StatusEntry, TrustedListError> {
    let service_type = ServiceType::from_uri(&required_text(
        information,
        ELEMENT_SERVICE_TYPE_IDENTIFIER,
    )?);
    let status = ServiceStatus::from_uri(&required_text(information, ELEMENT_SERVICE_STATUS)?)
        .ok_or(TrustedListError::UnknownServiceStatus)?;
    let since = xml_date_time(&required_text(information, ELEMENT_STATUS_STARTING_TIME)?).ok_or(
        TrustedListError::Malformed("StatusStartingTime is not a dateTime"),
    )?;
    Ok(StatusEntry {
        status,
        since,
        service_type,
    })
}

/// Read one `TSPService` of the provider named `provider`.
fn read_service(service: ElementRef<'_>, provider: &str) -> Result<TrustService, TrustedListError> {
    let information = service
        .child(NAMESPACE_TSL, ELEMENT_SERVICE_INFORMATION)
        .ok_or(TrustedListError::Malformed(
            "service without ServiceInformation",
        ))?;
    let current = read_status_entry(information)?;
    let name = information
        .child(NAMESPACE_TSL, ELEMENT_SERVICE_NAME)
        .and_then(preferred_name)
        .ok_or(TrustedListError::Malformed("service without ServiceName"))?;
    let identity = information
        .child(NAMESPACE_TSL, ELEMENT_SERVICE_DIGITAL_IDENTITY)
        .ok_or(TrustedListError::Malformed(
            "service without ServiceDigitalIdentity",
        ))?;
    let (certificates, unreadable_certificates) =
        read_certificates(identity, ListBound::IdentityCertificates)?;
    if certificates.is_empty()
        && unreadable_certificates == 0
        && current.service_type.anchor_role().is_some()
    {
        return Err(TrustedListError::Malformed(
            "qualified service without a certificate",
        ));
    }
    let mut history = Vec::new();
    for instance in service
        .child(NAMESPACE_TSL, ELEMENT_SERVICE_HISTORY)
        .into_iter()
        .flat_map(|list| list.children_named(NAMESPACE_TSL, ELEMENT_SERVICE_HISTORY_INSTANCE))
    {
        if history.len() >= MAX_HISTORY {
            return Err(TrustedListError::Bound(ListBound::History));
        }
        history.push(read_status_entry(instance)?);
    }
    Ok(TrustService {
        provider: provider.to_owned(),
        name,
        service_type: current.service_type.clone(),
        certificates,
        unreadable_certificates,
        current,
        history,
    })
}

/// Verify the enveloped `XAdES` signature `signature` over `root`, the
/// list that envelops it, and return the signer certificate, one of
/// `signers`.
///
/// `ds:SignedInfo` carries exactly two `ds:Reference`s (annex B): one
/// to the list and one to the signed properties; any other count is
/// refused before anything is computed. The signer is the `ds:KeyInfo`
/// certificate the `SigningCertificate` property names (annex B.1.1),
/// and the `ds:SignedInfo` signature is verified under it before any
/// reference is recomputed. Then both references are: the one to the
/// list carries the enveloped-signature transform and then at most one
/// canonicalisation, and digests the list without the signature (annex
/// B.1 rule 2); the other, of the `SignedProperties` type, digests this
/// signature's signed properties under its canonicalisation. A
/// reference elsewhere cannot be recomputed and fails the signature.
fn verify_enveloped_signature(
    document: &XmlDocument,
    root: ElementRef<'_>,
    signature: ElementRef<'_>,
    signers: &[OwnedCert],
) -> Result<OwnedCert, TrustedListError> {
    let signed_info = signature
        .child(NAMESPACE_DSIG, ELEMENT_SIGNED_INFO)
        .ok_or(TrustedListError::Malformed("no SignedInfo"))?;
    let mut references = signed_info.children_named(NAMESPACE_DSIG, ELEMENT_REFERENCE);
    let references = match (references.next(), references.next(), references.next()) {
        (Some(list), Some(properties), None) => [list, properties],
        _ => {
            return Err(TrustedListError::Malformed(
                "SignedInfo does not carry exactly two references",
            ));
        }
    };
    let canonicalization = signed_info
        .child(NAMESPACE_DSIG, ELEMENT_CANONICALIZATION_METHOD)
        .and_then(canonicalization_method)
        .ok_or(TrustedListError::Unverifiable(
            "SignedInfo canonicalisation",
        ))?;
    let algorithm = signed_info
        .child(NAMESPACE_DSIG, ELEMENT_SIGNATURE_METHOD)
        .and_then(|method| method.attribute(ATTRIBUTE_ALGORITHM))
        .and_then(signature_method)
        .ok_or(TrustedListError::Unverifiable("signature algorithm"))?;
    let signature_value = base64::decode_wrapped(
        &signature
            .child(NAMESPACE_DSIG, ELEMENT_SIGNATURE_VALUE)
            .ok_or(TrustedListError::Malformed("no SignatureValue"))?
            .text(),
    )
    .map_err(|_ignored| TrustedListError::Malformed("SignatureValue is not base64"))?;

    let key_info: Vec<Vec<u8>> = signature
        .child(NAMESPACE_DSIG, ELEMENT_KEY_INFO)
        .into_iter()
        .flat_map(|key_info| key_info.children_named(NAMESPACE_DSIG, ELEMENT_X509_DATA))
        .flat_map(|data| data.children_named(NAMESPACE_DSIG, ELEMENT_X509_CERTIFICATE))
        .map(|certificate| base64::decode_wrapped(&certificate.text()))
        .collect::<Result<_, _>>()
        .map_err(|_ignored| TrustedListError::Malformed("X509Certificate is not base64"))?;
    let signed_properties = signature
        .children_named(NAMESPACE_DSIG, ELEMENT_OBJECT)
        .find_map(|object| object.child(NAMESPACE_XADES, ELEMENT_QUALIFYING_PROPERTIES))
        .and_then(|properties| properties.child(NAMESPACE_XADES, ELEMENT_SIGNED_PROPERTIES))
        .ok_or(TrustedListError::Malformed("no SignedProperties"))?;
    let binding = signed_properties
        .child(NAMESPACE_XADES, ELEMENT_SIGNED_SIGNATURE_PROPERTIES)
        .and_then(|properties| {
            properties
                .child(NAMESPACE_XADES, ELEMENT_SIGNING_CERTIFICATE_V2)
                .or_else(|| properties.child(NAMESPACE_XADES, ELEMENT_SIGNING_CERTIFICATE))
        })
        .ok_or(TrustedListError::Malformed("no SigningCertificate"))?;
    let binding = read_cert_digest(binding)?.ok_or(TrustedListError::Unverifiable(
        "SigningCertificate digest algorithm",
    ))?;
    let signer_der =
        key_info
            .iter()
            .find(|der| binding.matches(der))
            .ok_or(TrustedListError::Malformed(
                "SigningCertificate names no KeyInfo certificate",
            ))?;
    if !signers.iter().any(|signer| signer.as_der() == signer_der) {
        return Err(TrustedListError::SignerNotEntitled);
    }
    let signer = OwnedCert::from_der(signer_der)
        .map_err(|_ignored| TrustedListError::Malformed("signer certificate does not parse"))?;
    signer
        .view()
        .spki
        .verify_message_signature(
            algorithm,
            &signed_info.canonicalize(&canonicalization),
            &signature_value,
        )
        .map_err(|_ignored| TrustedListError::SignatureInvalid)?;

    let root_id = root.attribute(ATTRIBUTE_ID);
    let mut list_covered = false;
    let mut properties_covered = false;
    for reference in references {
        let digest = DigestValue::read(reference, "Reference without a readable DigestValue")?
            .ok_or(TrustedListError::Unverifiable("reference digest algorithm"))?;
        let uri = reference.attribute(ATTRIBUTE_URI).unwrap_or_default();
        let transforms: Vec<ElementRef<'_>> = reference
            .child(NAMESPACE_DSIG, ELEMENT_TRANSFORMS)
            .into_iter()
            .flat_map(ElementRef::children)
            .collect();
        let names_list = uri.is_empty()
            || uri
                .strip_prefix(FRAGMENT_MARK)
                .is_some_and(|id| root_id == Some(id));
        let enveloped = transforms.first().is_some_and(|transform| {
            transform.is(NAMESPACE_DSIG, ELEMENT_TRANSFORM)
                && transform.attribute(ATTRIBUTE_ALGORITHM) == Some(TRANSFORM_ENVELOPED_SIGNATURE)
        });
        let canonicalization_of = |transform: &ElementRef<'_>| {
            if transform.is(NAMESPACE_DSIG, ELEMENT_TRANSFORM) {
                canonicalization_method(*transform)
            } else {
                None
            }
        };
        let octets = if names_list && enveloped {
            if list_covered {
                return Err(TrustedListError::Malformed("two references to the list"));
            }
            let method = match transforms.get(1..) {
                Some([]) | None => default_canonicalization(),
                Some([transform]) => canonicalization_of(transform)
                    .ok_or(TrustedListError::Unverifiable("list reference transform"))?,
                Some(_) => return Err(TrustedListError::Unverifiable("list reference transform")),
            };
            list_covered = true;
            root.canonicalize_omitting(&method, signature)
        } else if let Some(id) = uri.strip_prefix(FRAGMENT_MARK)
            && reference.attribute(ATTRIBUTE_TYPE) == Some(TYPE_SIGNED_PROPERTIES)
        {
            let method = match transforms.as_slice() {
                [] => default_canonicalization(),
                [transform] => canonicalization_of(transform)
                    .ok_or(TrustedListError::Unverifiable("reference transform"))?,
                _ => return Err(TrustedListError::Unverifiable("reference transform")),
            };
            let element = document
                .elements()
                .find(|element| element.attribute(ATTRIBUTE_ID) == Some(id))
                .ok_or(TrustedListError::SignatureInvalid)?;
            if element != signed_properties || properties_covered {
                return Err(TrustedListError::SignatureInvalid);
            }
            properties_covered = true;
            element.canonicalize(&method)
        } else {
            return Err(TrustedListError::Unverifiable("reference outside the list"));
        };
        if !digest.matches(&octets) {
            return Err(TrustedListError::SignatureInvalid);
        }
    }
    if !list_covered {
        return Err(TrustedListError::Malformed("no reference to the list"));
    }
    if !properties_covered {
        return Err(TrustedListError::Malformed(
            "no reference to the SignedProperties",
        ));
    }
    Ok(signer)
}

#[cfg(test)]
mod tests;
