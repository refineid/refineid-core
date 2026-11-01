// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! Tests of the trusted-list reader over synthetic lists: a list of
//! the lists in the shape the Commission publishes, pointing at a
//! national list with a qualified certificate service and a qualified
//! time-stamping service, every signer a testkit key.

use super::{
    CachedList, LOTL_LOCATION, ListBound, ListFailure, ListType, MAX_HISTORY, ServiceStatus,
    ServiceType, StatusEntry, TrustAnchors, TrustService, TrustedList, TrustedListError,
    TrustedLists,
};
use crate::base64;
use crate::testkit::{
    CertificateSpec, KEY_USAGE_NON_REPUDIATION, KEY_USAGE_NON_REPUDIATION_UNUSED, TestCurve,
    TestKey, ca_extensions, certificate, day, key_usage, timestamping_extensions,
};
use crate::uri::Uri;
use crate::verification::trust::{
    AnchorRole, CertificationPath, GrantedPeriod, MaterialPool, When, judge,
};
use crate::verification::xml::{Canonicalization, Comments, XmlDocument};
use crate::xades::{
    CANONICALIZATION_EXCLUSIVE, DIGEST_METHOD_SHA256, NAMESPACE_DSIG, NAMESPACE_XADES,
    SIGNATURE_METHOD_ECDSA_SHA256, SIGNATURE_METHOD_RSA_SHA256, TYPE_SIGNED_PROPERTIES,
};
use refineid_cms::x509::{DateTime, OwnedCert};
use refineid_digest::Sha256;

/// Where the synthetic national list is published.
const NATIONAL_LOCATION: &str = "https://trusted-list.example/national.xml";
/// Where a national list nobody serves is published.
const UNSERVED_LOCATION: &str = "https://trusted-list.example/unserved.xml";
/// Where the human-readable form of the national list is published.
const NATIONAL_PDF_LOCATION: &str = "https://trusted-list.example/national.pdf";
/// A location that is not an HTTP URL.
const UNFETCHABLE_LOCATION: &str = "ldap://trusted-list.example/national";
/// The territory of the list of the lists.
const EU: &str = "EU";
/// The territory of the national list.
const TERRITORY: &str = "XX";
/// The territory of the list nobody serves.
const UNSERVED_TERRITORY: &str = "XY";
/// The territory of the list at an unfetchable location.
const UNFETCHABLE_TERRITORY: &str = "XZ";
/// The scheme operator of the list of the lists.
const LOTL_OPERATOR: &str = "Synthetic Commission";
/// The scheme operator of the national list.
const NATIONAL_OPERATOR: &str = "Synthetic Supervisory Body";
/// The listed provider.
const PROVIDER: &str = "Synthetic Trust Service Provider";
/// The listed certificate service.
const CA: &str = "Synthetic Listed Qualified CA";
/// The listed time-stamping service.
const TSU: &str = "Synthetic Listed Time Stamping Unit";
/// The signer the listed CA issues.
const SIGNER: &str = "Synthetic Signer";
/// A service type no anchor is taken from.
const OTHER_TYPE: &str = "http://uri.etsi.org/TrstSvc/Svctype/QESValidation/Q";
/// The media type of a machine-processable list.
const MIME_XML: &str = "application/vnd.etsi.tsl+xml";
/// The media type of the human-readable list.
const MIME_PDF: &str = "application/pdf";
/// The `Id` of the signed properties.
const PROPERTIES_ID: &str = "xades-props";
/// The `Id` of the signature.
const SIGNATURE_ID: &str = "sig";

/// Serial of the list-of-the-lists signer.
const LOTL_SERIAL: u8 = 1;
/// Serial of the national signer.
const NATIONAL_SERIAL: u8 = 2;
/// Serial of the listed CA.
const CA_SERIAL: u8 = 3;
/// Serial of the listed TSU.
const TSU_SERIAL: u8 = 4;
/// Serial of the signer the CA issues.
const SIGNER_SERIAL: u8 = 5;

/// Day every certificate starts.
const ISSUED: u8 = 1;
/// Day the CA was under supervision from.
const SUPERVISED: u8 = 2;
/// Day the CA and the TSU were granted from.
const GRANTED: u8 = 3;
/// A day inside every granted period.
const INSIDE: u8 = 5;
/// Day the TSU was withdrawn.
const WITHDRAWN: u8 = 10;
/// A day after the withdrawal.
const AFTER: u8 = 15;
/// The lists' next update.
const NEXT_UPDATE: u8 = 25;
/// When the lists are fetched.
const FETCHED: u8 = 20;
/// Day every certificate ends.
const ENDS: u8 = 28;

/// A year under Directive 1999/93/EC.
const DIRECTIVE_YEAR: u16 = 2015;
/// A year under Regulation (EU) No 910/2014.
const REGULATION_YEAR: u16 = 2017;
/// January.
const JANUARY: u8 = 1;
/// The first day of a month.
const FIRST: u8 = 1;

/// Midnight UTC on the first of January of `year`.
fn new_year(year: u16) -> DateTime {
    DateTime::new(year, JANUARY, FIRST, 0, 0, 0).expect("a calendar instant")
}

/// One status entry recorded under the service type `service_type`.
fn entry(status: ServiceStatus, since: DateTime, service_type: &str) -> StatusEntry {
    StatusEntry {
        status,
        since,
        service_type: ServiceType::from_uri(service_type),
    }
}

/// A service of the current entry's type with `history`, newest first
/// as a list carries it, and no certificate.
fn listed(current: StatusEntry, history: Vec<StatusEntry>) -> TrustService {
    TrustService {
        provider: PROVIDER.to_owned(),
        name: CA.to_owned(),
        service_type: current.service_type.clone(),
        certificates: Vec::new(),
        unreadable_certificates: 0,
        current,
        history,
    }
}

/// A granted period from `from` to `to`.
fn period(from: DateTime, to: Option<DateTime>) -> GrantedPeriod {
    GrantedPeriod::new(from, to).expect("a period")
}

/// Keys and certificates of one test world.
struct World {
    /// The list-of-the-lists signer, RSA.
    lotl_key: TestKey,
    /// Its certificate.
    lotl: Vec<u8>,
    /// The national list signer, P-256.
    national_key: TestKey,
    /// Its certificate.
    national: Vec<u8>,
    /// The listed CA.
    ca: Vec<u8>,
    /// The listed TSU.
    tsu: Vec<u8>,
    /// A signer the CA issued.
    signer: Vec<u8>,
}

/// A certificate valid from [`ISSUED`] to [`ENDS`].
fn spec<'a>(
    serial: u8,
    subject: &'a str,
    issuer: &'a str,
    extensions: Vec<Vec<u8>>,
) -> CertificateSpec<'a> {
    CertificateSpec {
        serial,
        subject,
        issuer,
        not_before: day(ISSUED),
        not_after: day(ENDS),
        extensions,
    }
}

impl World {
    fn new() -> Self {
        let lotl_key = TestKey::rsa_2048();
        let national_key = TestKey::derive(TestCurve::P256, b"national operator");
        let ca_key = TestKey::derive(TestCurve::P384, b"listed ca");
        let tsu_key = TestKey::derive(TestCurve::P256, b"listed tsu");
        let signer_key = TestKey::derive(TestCurve::P256, b"signer");
        Self {
            lotl: certificate(
                &spec(LOTL_SERIAL, LOTL_OPERATOR, LOTL_OPERATOR, Vec::new()),
                &lotl_key,
                &lotl_key,
            ),
            national: certificate(
                &spec(
                    NATIONAL_SERIAL,
                    NATIONAL_OPERATOR,
                    NATIONAL_OPERATOR,
                    Vec::new(),
                ),
                &national_key,
                &national_key,
            ),
            ca: certificate(&spec(CA_SERIAL, CA, CA, ca_extensions()), &ca_key, &ca_key),
            tsu: certificate(
                &spec(TSU_SERIAL, TSU, TSU, timestamping_extensions()),
                &tsu_key,
                &tsu_key,
            ),
            signer: certificate(
                &spec(
                    SIGNER_SERIAL,
                    SIGNER,
                    CA,
                    vec![key_usage(
                        KEY_USAGE_NON_REPUDIATION_UNUSED,
                        KEY_USAGE_NON_REPUDIATION,
                    )],
                ),
                &signer_key,
                &ca_key,
            ),
            lotl_key,
            national_key,
        }
    }

    fn lotl_cert(&self) -> OwnedCert {
        OwnedCert::from_der(&self.lotl).expect("the LOTL signer parses")
    }

    /// The signed list of the lists, with the national list's spec
    /// pointing at [`NATIONAL_LOCATION`].
    fn signed_lotl(&self, next_update: Option<u8>) -> Vec<u8> {
        sign_list(
            &lotl_xml(&self.national, next_update),
            &self.lotl_key,
            &self.lotl,
            SIGNATURE_METHOD_RSA_SHA256,
        )
    }

    /// The signed national list.
    fn signed_national(&self, services: &str) -> Vec<u8> {
        sign_list(
            &national_xml(services),
            &self.national_key,
            &self.national,
            SIGNATURE_METHOD_ECDSA_SHA256,
        )
    }

    /// The services the national list carries: the CA, granted since
    /// [`GRANTED`] after supervision since [`SUPERVISED`]; the TSU,
    /// withdrawn since [`WITHDRAWN`] after being granted since
    /// [`GRANTED`]; and a service of another type.
    fn services(&self) -> String {
        let ca = service(
            super::SERVICE_TYPE_CA_QC,
            CA,
            &self.ca,
            (ServiceStatus::Granted, GRANTED),
            &[(ServiceStatus::UnderSupervision, SUPERVISED)],
        );
        let tsu = service(
            super::SERVICE_TYPE_TSA_QTST,
            TSU,
            &self.tsu,
            (ServiceStatus::Withdrawn, WITHDRAWN),
            &[(ServiceStatus::Granted, GRANTED)],
        );
        let other = service(
            OTHER_TYPE,
            "Synthetic Validation Service",
            &self.tsu,
            (ServiceStatus::Granted, GRANTED),
            &[],
        );
        format!("{ca}{tsu}{other}")
    }

    /// Read the lists as a shell would after fetching both.
    fn lists(&self) -> (TrustedLists, Vec<CachedList>) {
        let national = self.signed_national(&self.services());
        TrustedLists::read(
            self.signed_lotl(Some(NEXT_UPDATE)),
            &[self.lotl_cert()],
            |location| (location.to_string() == NATIONAL_LOCATION).then(|| national.clone()),
            day(FETCHED),
        )
        .expect("the lists read")
    }
}

/// `time` as an `xsd:dateTime` in UTC.
fn stamp(time: DateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        time.year(),
        time.month(),
        time.day(),
        time.hour(),
        time.minutes(),
        time.seconds()
    )
}

/// The identifier of `status`.
fn status_uri(status: ServiceStatus) -> String {
    let name = match status {
        ServiceStatus::Granted => "granted",
        ServiceStatus::Withdrawn => "withdrawn",
        ServiceStatus::UnderSupervision => "undersupervision",
        ServiceStatus::Accredited => "accredited",
        _ => unreachable!("the fixtures use four statuses"),
    };
    format!("{}{name}", super::STATUS_PREFIX)
}

/// A `ServiceDigitalIdentity` over one certificate.
fn identity(certificate: &[u8]) -> String {
    format!(
        "<ServiceDigitalIdentity><DigitalId><X509Certificate>{}</X509Certificate></DigitalId></ServiceDigitalIdentity>",
        base64::encode(certificate)
    )
}

/// One `TSPService`.
fn service(
    service_type: &str,
    name: &str,
    certificate: &[u8],
    current: (ServiceStatus, u8),
    history: &[(ServiceStatus, u8)],
) -> String {
    let instances: String = history
        .iter()
        .map(|(status, since)| {
            format!(
                "<ServiceHistoryInstance><ServiceTypeIdentifier>{service_type}</ServiceTypeIdentifier><ServiceName><Name xml:lang=\"en\">{name}</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509SubjectName>CN={name}</X509SubjectName></DigitalId></ServiceDigitalIdentity><ServiceStatus>{}</ServiceStatus><StatusStartingTime>{}</StatusStartingTime></ServiceHistoryInstance>",
                status_uri(*status),
                stamp(day(*since))
            )
        })
        .collect();
    let history = if instances.is_empty() {
        String::new()
    } else {
        format!("<ServiceHistory>{instances}</ServiceHistory>")
    };
    format!(
        "<TSPService><ServiceInformation><ServiceTypeIdentifier>{service_type}</ServiceTypeIdentifier><ServiceName><Name xml:lang=\"fi\">Palvelu</Name><Name xml:lang=\"en\">{name}</Name></ServiceName>{}<ServiceStatus>{}</ServiceStatus><StatusStartingTime>{}</StatusStartingTime></ServiceInformation>{history}</TSPService>",
        identity(certificate),
        status_uri(current.0),
        stamp(day(current.1))
    )
}

/// The scheme information every list shares, in the shape the
/// Commission's list has.
fn scheme_information(
    list_type: &str,
    territory: &str,
    operator: &str,
    next_update: Option<u8>,
    pointers: &str,
) -> String {
    let next_update = match next_update {
        Some(due) => format!("<dateTime>{}</dateTime>", stamp(day(due))),
        None => String::new(),
    };
    format!(
        r#"
    <SchemeInformation>
        <TSLVersionIdentifier>6</TSLVersionIdentifier>
        <TSLSequenceNumber>1</TSLSequenceNumber>
        <TSLType>{list_type}</TSLType>
        <SchemeOperatorName>
            <Name xml:lang="fi">Toimija</Name>
            <Name xml:lang="en">{operator}</Name>
        </SchemeOperatorName>
        <SchemeOperatorAddress>
            <PostalAddresses>
                <PostalAddress xml:lang="en">
                    <StreetAddress>Example Street 1</StreetAddress>
                    <Locality>Example</Locality>
                    <PostalCode>00000</PostalCode>
                    <CountryName>{territory}</CountryName>
                </PostalAddress>
            </PostalAddresses>
            <ElectronicAddress>
                <URI xml:lang="en">mailto:scheme@trusted-list.example</URI>
            </ElectronicAddress>
        </SchemeOperatorAddress>
        <SchemeName>
            <Name xml:lang="en">{territory}:Synthetic trusted list</Name>
        </SchemeName>
        <SchemeInformationURI>
            <URI xml:lang="en">https://trusted-list.example/</URI>
        </SchemeInformationURI>
        <StatusDeterminationApproach>http://uri.etsi.org/TrstSvc/TrustedList/StatusDetn/EUappropriate</StatusDeterminationApproach>
        <SchemeTypeCommunityRules>
            <URI xml:lang="en">http://uri.etsi.org/TrstSvc/TrustedList/schemerules/EUcommon</URI>
        </SchemeTypeCommunityRules>
        <SchemeTerritory>{territory}</SchemeTerritory>
        <PolicyOrLegalNotice>
            <TSLLegalNotice xml:lang="en">Synthetic notice.</TSLLegalNotice>
        </PolicyOrLegalNotice>
        <HistoricalInformationPeriod>65535</HistoricalInformationPeriod>
        {pointers}
        <ListIssueDateTime>{}</ListIssueDateTime>
        <NextUpdate>{next_update}</NextUpdate>
        <DistributionPoints>
            <URI>https://trusted-list.example/{territory}.xml</URI>
        </DistributionPoints>
    </SchemeInformation>"#,
        stamp(day(ISSUED))
    )
}

/// One `OtherTSLPointer`, in the shape the Commission's list has.
fn pointer(location: &str, territory: &str, list_type: &str, mime: &str, signer: &[u8]) -> String {
    format!(
        r#"
            <OtherTSLPointer>
                <ServiceDigitalIdentities>
                    {}
                </ServiceDigitalIdentities>
                <TSLLocation>{location}</TSLLocation>
                <AdditionalInformation>
                    <OtherInformation>
                        <TSLType>{list_type}</TSLType>
                    </OtherInformation>
                    <OtherInformation>
                        <SchemeTerritory>{territory}</SchemeTerritory>
                    </OtherInformation>
                    <OtherInformation>
                        <ns3:MimeType>{mime}</ns3:MimeType>
                    </OtherInformation>
                    <OtherInformation>
                        <SchemeOperatorName>
                            <Name xml:lang="en">Operator of {territory}</Name>
                        </SchemeOperatorName>
                    </OtherInformation>
                </AdditionalInformation>
            </OtherTSLPointer>"#,
        identity(signer)
    )
}

/// The document element, with the namespace declarations the
/// Commission's list carries, around `body`.
fn document(body: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="no"?><TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" xmlns:ns2="{NAMESPACE_DSIG}" xmlns:ns3="http://uri.etsi.org/02231/v2/additionaltypes#" xmlns:ns4="{NAMESPACE_XADES}" xmlns:ns5="http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#" xmlns:ns6="http://uri.etsi.org/01903/v1.4.1#" Id="ID0001" TSLTag="http://uri.etsi.org/19612/TSLTag">{body}
</TrustServiceStatusList>"#
    )
}

/// An unsigned list of the lists pointing at itself, at the national
/// list signed by `national`, at its PDF form, at a list nobody serves
/// and at one with an unfetchable location.
fn lotl_xml(national: &[u8], next_update: Option<u8>) -> String {
    let pointers = format!(
        "<PointersToOtherTSL>{}{}{}{}{}</PointersToOtherTSL>",
        pointer(
            LOTL_LOCATION,
            EU,
            super::TSL_TYPE_EU_LIST_OF_THE_LISTS,
            MIME_XML,
            national
        ),
        pointer(
            NATIONAL_PDF_LOCATION,
            TERRITORY,
            super::TSL_TYPE_EU_GENERIC,
            MIME_PDF,
            national
        ),
        pointer(
            NATIONAL_LOCATION,
            TERRITORY,
            super::TSL_TYPE_EU_GENERIC,
            MIME_XML,
            national
        ),
        pointer(
            UNSERVED_LOCATION,
            UNSERVED_TERRITORY,
            super::TSL_TYPE_EU_GENERIC,
            MIME_XML,
            national
        ),
        pointer(
            UNFETCHABLE_LOCATION,
            UNFETCHABLE_TERRITORY,
            super::TSL_TYPE_EU_GENERIC,
            MIME_XML,
            national
        ),
    );
    document(&scheme_information(
        super::TSL_TYPE_EU_LIST_OF_THE_LISTS,
        EU,
        LOTL_OPERATOR,
        next_update,
        &pointers,
    ))
}

/// An unsigned national list carrying `services`.
fn national_xml(services: &str) -> String {
    let scheme = scheme_information(
        super::TSL_TYPE_EU_GENERIC,
        TERRITORY,
        NATIONAL_OPERATOR,
        Some(NEXT_UPDATE),
        "",
    );
    document(&format!(
        "{scheme}<TrustServiceProviderList><TrustServiceProvider><TSPInformation><TSPName><Name xml:lang=\"en\">{PROVIDER}</Name></TSPName></TSPInformation><TSPServices>{services}</TSPServices></TrustServiceProvider></TrustServiceProviderList>"
    ))
}

/// Exclusive canonicalisation without comments.
fn exclusive() -> Canonicalization {
    Canonicalization::exclusive(Comments::Omitted)
}

/// The exclusive canonical form of the element with `id` in `xml`, or
/// of its root.
fn canonical(xml: &str, id: Option<&str>) -> Vec<u8> {
    let document = XmlDocument::parse(xml.as_bytes().to_vec()).expect("fixture XML parses");
    let element = match id {
        Some(id) => document
            .elements()
            .find(|element| element.attribute("Id") == Some(id))
            .expect("the element exists"),
        None => document.root(),
    };
    element.canonicalize(&exclusive())
}

/// The SHA-256 of `octets`, base64.
fn digest(octets: &[u8]) -> String {
    base64::encode(Sha256::of(octets).as_bytes())
}

/// Sign `unsigned`, a complete list without a signature, with `key`
/// under `certificate`, as TS 119 612 annex B.1 says: an enveloped
/// reference to the list under the enveloped-signature transform and
/// exclusive canonicalisation, and a reference to the signed
/// properties.
fn sign_list(unsigned: &str, key: &TestKey, certificate: &[u8], method: &str) -> Vec<u8> {
    let list_digest = digest(&canonical(unsigned, None));
    let properties = format!(
        "<xades:SignedProperties Id=\"{PROPERTIES_ID}\"><xades:SignedSignatureProperties><xades:SigningTime>{}</xades:SigningTime><xades:SigningCertificateV2><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm=\"{DIGEST_METHOD_SHA256}\"/><ds:DigestValue>{}</ds:DigestValue></xades:CertDigest></xades:Cert></xades:SigningCertificateV2></xades:SignedSignatureProperties></xades:SignedProperties>",
        stamp(day(ISSUED)),
        digest(certificate)
    );
    let object = format!(
        "<ds:Object><xades:QualifyingProperties xmlns:xades=\"{NAMESPACE_XADES}\" Target=\"#{SIGNATURE_ID}\">{properties}</xades:QualifyingProperties></ds:Object>"
    );
    let properties_digest = digest(&canonical(
        &format!("<ds:Signature xmlns:ds=\"{NAMESPACE_DSIG}\">{object}</ds:Signature>"),
        Some(PROPERTIES_ID),
    ));
    let signed_info = format!(
        "<ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{CANONICALIZATION_EXCLUSIVE}\"/><ds:SignatureMethod Algorithm=\"{method}\"/><ds:Reference Id=\"ref-enveloped-signature\" URI=\"\"><ds:Transforms><ds:Transform Algorithm=\"{}\"/><ds:Transform Algorithm=\"{CANONICALIZATION_EXCLUSIVE}\"/></ds:Transforms><ds:DigestMethod Algorithm=\"{DIGEST_METHOD_SHA256}\"/><ds:DigestValue>{list_digest}</ds:DigestValue></ds:Reference><ds:Reference Type=\"{TYPE_SIGNED_PROPERTIES}\" URI=\"#{PROPERTIES_ID}\"><ds:Transforms><ds:Transform Algorithm=\"{CANONICALIZATION_EXCLUSIVE}\"/></ds:Transforms><ds:DigestMethod Algorithm=\"{DIGEST_METHOD_SHA256}\"/><ds:DigestValue>{properties_digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>",
        super::TRANSFORM_ENVELOPED_SIGNATURE
    );
    let signed_info_canonical = canonical(
        &format!("<ds:Signature xmlns:ds=\"{NAMESPACE_DSIG}\">{signed_info}</ds:Signature>"),
        None,
    );
    let document = XmlDocument::parse(signed_info_canonical).expect("canonical form parses");
    let signed_info_canonical = document
        .root()
        .children()
        .next()
        .expect("SignedInfo")
        .canonicalize(&exclusive());
    let value = base64::encode(&key.sign_raw(&signed_info_canonical));
    let signature = format!(
        "<ds:Signature xmlns:ds=\"{NAMESPACE_DSIG}\" Id=\"{SIGNATURE_ID}\">{signed_info}<ds:SignatureValue>{value}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>{object}</ds:Signature>",
        base64::encode(certificate)
    );
    let close = unsigned
        .rfind("</TrustServiceStatusList>")
        .expect("the list closes");
    let mut signed = unsigned.to_owned();
    signed.insert_str(close, &signature);
    signed.into_bytes()
}

/// The anchors `lists` yield beside the pinned roots.
fn listed_anchors(lists: &TrustedLists) -> TrustAnchors {
    TrustAnchors::from_trusted_lists(lists)
}

#[test]
fn a_synthetic_list_of_the_lists_reads_with_its_national_list() {
    let world = World::new();
    let (lists, cache) = world.lists();
    let lotl = lists.list_of_the_lists();
    assert_eq!(lotl.list_type(), ListType::EuListOfTheLists);
    assert_eq!(lotl.territory(), EU);
    assert_eq!(lotl.operator(), LOTL_OPERATOR);
    assert_eq!(lotl.issued_at(), day(ISSUED));
    assert_eq!(lotl.next_update(), Some(day(NEXT_UPDATE)));
    assert_eq!(lotl.signer().as_der(), world.lotl.as_slice());
    assert_eq!(lotl.pointers().len(), 5);
    assert_eq!(
        lotl.pointers()
            .iter()
            .filter(|pointer| pointer.names_national_list())
            .count(),
        3,
        "the pointers to the list itself and to the PDF are not followed"
    );

    let national = lists.national();
    assert_eq!(national.len(), 3);
    let list = national[0].outcome().expect("the national list reads");
    assert_eq!(national[0].territory(), TERRITORY);
    assert_eq!(list.list_type(), ListType::EuGeneric);
    assert_eq!(list.operator(), NATIONAL_OPERATOR);
    assert_eq!(list.services().len(), 3);
    let ca = &list.services()[0];
    assert_eq!(ca.provider(), PROVIDER);
    assert_eq!(ca.name(), CA);
    assert_eq!(*ca.service_type(), ServiceType::QualifiedCertificates);
    assert_eq!(ca.current().status(), ServiceStatus::Granted);
    assert_eq!(ca.current().since(), day(GRANTED));
    assert_eq!(ca.history().len(), 1);
    assert_eq!(ca.history()[0].status(), ServiceStatus::UnderSupervision);
    assert_eq!(ca.certificates()[0].as_der(), world.ca.as_slice());
    assert_eq!(
        *list.services()[2].service_type(),
        ServiceType::Other(OTHER_TYPE.to_owned())
    );
    assert_eq!(national[1].outcome(), Err(ListFailure::NotFetched));
    assert_eq!(national[1].territory(), UNSERVED_TERRITORY);
    assert_eq!(national[2].outcome(), Err(ListFailure::NoLocation));
    assert!(national[2].location().is_none());

    assert_eq!(lists.fetched_at(), day(FETCHED));
    assert_eq!(lists.valid_until(), Some(day(NEXT_UPDATE)));
    assert!(!lists.is_stale(day(FETCHED)));

    assert_eq!(cache.len(), 2, "one record per list that read");
    assert_eq!(cache[0].location().to_string(), LOTL_LOCATION);
    assert_eq!(cache[0].next_update(), Some(day(NEXT_UPDATE)));
    assert_eq!(cache[1].location().to_string(), NATIONAL_LOCATION);
    assert_eq!(cache[1].fetched_at(), day(FETCHED));
    let reread = TrustedLists::from_cache(&cache, &[world.lotl_cert()]).expect("the cache reads");
    assert_eq!(reread, lists);
}

#[test]
fn granted_periods_follow_the_status_history() {
    let world = World::new();
    let (lists, _cache) = world.lists();
    let list = lists.national()[0].outcome().expect("reads");
    let [ca, tsu, other] = list.services() else {
        panic!("three services");
    };
    assert_eq!(
        ca.granted_periods(),
        vec![GrantedPeriod::new(day(GRANTED), None).expect("a period")],
        "supervision starting after the Directive regime ended grants nothing"
    );
    assert_eq!(
        tsu.granted_periods(),
        vec![GrantedPeriod::new(day(GRANTED), Some(day(WITHDRAWN))).expect("a period")]
    );
    assert_eq!(
        other.granted_periods(),
        Vec::new(),
        "a type no anchor is taken from grants nothing"
    );

    let anchors = listed_anchors(&lists);
    let pinned = TrustAnchors::pinned().anchors().len();
    assert_eq!(anchors.anchors().len(), pinned + 2);
    assert_eq!(anchors.fetched_at(), Some(day(FETCHED)));
    assert_eq!(anchors.lists_valid_until(), Some(day(NEXT_UPDATE)));
}

#[test]
fn a_signer_under_a_listed_ca_is_anchored() {
    let world = World::new();
    let (lists, _cache) = world.lists();
    let anchors = listed_anchors(&lists);
    let mut pool = MaterialPool::new();
    pool.add_anchors(&anchors);
    let signer = OwnedCert::from_der(&world.signer).expect("the signer parses");
    let verdict = judge(
        &signer,
        &pool,
        &anchors,
        AnchorRole::CertificateIssuing,
        When {
            at: day(INSIDE),
            now: day(FETCHED),
        },
    );
    assert_eq!(
        verdict.path,
        CertificationPath::Anchored(vec![OwnedCert::from_der(&world.ca).expect("the CA parses")])
    );
    let before_supervision = judge(
        &signer,
        &pool,
        &anchors,
        AnchorRole::CertificateIssuing,
        When {
            at: day(ISSUED),
            now: day(FETCHED),
        },
    );
    assert!(
        !before_supervision.path.is_anchored(),
        "before the first granting status the CA anchors nothing"
    );
}

#[test]
fn a_withdrawn_time_stamping_service_anchors_only_until_its_withdrawal() {
    let world = World::new();
    let (lists, _cache) = world.lists();
    let anchors = listed_anchors(&lists);
    let pool = MaterialPool::new();
    let tsu = OwnedCert::from_der(&world.tsu).expect("the TSU parses");
    let judged_at = |at: u8| {
        judge(
            &tsu,
            &pool,
            &anchors,
            AnchorRole::TimeStamping,
            When {
                at: day(at),
                now: day(FETCHED),
            },
        )
        .path
    };
    assert_eq!(judged_at(INSIDE), CertificationPath::Anchored(Vec::new()));
    assert_eq!(judged_at(AFTER), CertificationPath::Partial(Vec::new()));
    assert_eq!(
        judge(
            &tsu,
            &pool,
            &anchors,
            AnchorRole::CertificateIssuing,
            When {
                at: day(INSIDE),
                now: day(FETCHED),
            },
        )
        .path,
        CertificationPath::Partial(Vec::new()),
        "a time-stamping service anchors no certificate issuing"
    );
}

#[test]
fn a_list_signed_by_an_unlisted_key_is_refused() {
    let world = World::new();
    let lotl_signed_by_the_national_key = sign_list(
        &lotl_xml(&world.national, Some(NEXT_UPDATE)),
        &world.national_key,
        &world.national,
        SIGNATURE_METHOD_ECDSA_SHA256,
    );
    assert_eq!(
        TrustedList::read(lotl_signed_by_the_national_key, &[world.lotl_cert()]).err(),
        Some(TrustedListError::SignerNotEntitled)
    );

    // The pointer carries the national signer; a list signed by the
    // LOTL key is not what the pointer entitles.
    let national_signed_by_the_lotl_key = sign_list(
        &national_xml(&world.services()),
        &world.lotl_key,
        &world.lotl,
        SIGNATURE_METHOD_RSA_SHA256,
    );
    let (lists, cache) = TrustedLists::read(
        world.signed_lotl(Some(NEXT_UPDATE)),
        &[world.lotl_cert()],
        |location| {
            (location.to_string() == NATIONAL_LOCATION)
                .then(|| national_signed_by_the_lotl_key.clone())
        },
        day(FETCHED),
    )
    .expect("the list of the lists reads");
    assert_eq!(
        lists.national()[0].outcome(),
        Err(ListFailure::Unreadable(TrustedListError::SignerNotEntitled))
    );
    assert_eq!(cache.len(), 1, "an unreadable list is not cached");
    assert_eq!(
        listed_anchors(&lists).anchors().len(),
        TrustAnchors::pinned().anchors().len(),
        "no anchor comes from a list that did not read"
    );
}

#[test]
fn a_changed_list_fails_its_signature() {
    let world = World::new();
    let signed = String::from_utf8(world.signed_national(&world.services())).expect("UTF-8");
    let withdrawn = status_uri(ServiceStatus::Withdrawn);
    let granted = status_uri(ServiceStatus::Granted);
    let tampered = signed.replacen(&granted, &withdrawn, 1);
    assert_ne!(tampered, signed);
    let national = OwnedCert::from_der(&world.national).expect("parses");
    assert_eq!(
        TrustedList::read(tampered.into_bytes(), core::slice::from_ref(&national)).err(),
        Some(TrustedListError::SignatureInvalid)
    );
    let without_signature = national_xml(&world.services());
    assert_eq!(
        TrustedList::read(without_signature.into_bytes(), &[national]).err(),
        Some(TrustedListError::NoSignature)
    );
}

#[test]
fn a_stale_list_still_anchors_and_says_so() {
    let world = World::new();
    let (lists, _cache) = world.lists();
    let after_next_update = day(ENDS);
    assert!(lists.is_stale(after_next_update));
    assert!(lists.list_of_the_lists().is_stale(after_next_update));
    let anchors = listed_anchors(&lists);
    assert_eq!(
        anchors.anchors().len(),
        TrustAnchors::pinned().anchors().len() + 2,
        "anchors from a stale list still count"
    );
    assert_eq!(anchors.lists_valid_until(), Some(day(NEXT_UPDATE)));

    let national = world.signed_national(&world.services());
    let (closed, _cache) = TrustedLists::read(
        world.signed_lotl(None),
        &[world.lotl_cert()],
        |location| (location.to_string() == NATIONAL_LOCATION).then(|| national.clone()),
        day(FETCHED),
    )
    .expect("reads");
    assert_eq!(closed.list_of_the_lists().next_update(), None);
    assert_eq!(
        closed.valid_until(),
        Some(day(NEXT_UPDATE)),
        "a closed list of the lists leaves the national list's next update"
    );
}

#[test]
fn a_national_list_read_as_the_list_of_the_lists_is_refused() {
    let world = World::new();
    let national = world.signed_national(&world.services());
    let national_cert = OwnedCert::from_der(&world.national).expect("parses");
    assert_eq!(
        TrustedLists::read(national, &[national_cert], |_location| None, day(FETCHED)).err(),
        Some(TrustedListError::NotListOfTheLists)
    );
    assert_eq!(
        TrustedLists::from_cache(&[], &[world.lotl_cert()]).err(),
        Some(TrustedListError::NotFetched)
    );
}

#[test]
fn a_service_with_too_long_a_history_is_refused() {
    let world = World::new();
    let history: Vec<(ServiceStatus, u8)> = (0..=MAX_HISTORY)
        .map(|_entry| (ServiceStatus::Accredited, SUPERVISED))
        .collect();
    let services = service(
        super::SERVICE_TYPE_CA_QC,
        CA,
        &world.ca,
        (ServiceStatus::Granted, GRANTED),
        &history,
    );
    let national = OwnedCert::from_der(&world.national).expect("parses");
    assert_eq!(
        TrustedList::read(world.signed_national(&services), &[national]).err(),
        Some(TrustedListError::Bound(ListBound::History))
    );
}

#[test]
fn the_pinned_commission_certificates_are_the_lotl_signers() {
    let signers = super::lotl_signers();
    assert_eq!(signers.len(), crate::trust::LOTL_SIGNER_DER.len());
    assert!(Uri::parse(LOTL_LOCATION.to_owned()).is_ok());
}

#[test]
fn a_certificate_this_core_does_not_read_is_counted_and_anchors_nothing() {
    let world = World::new();
    let not_a_certificate = b"not a certificate at all";
    let services = format!(
        "{}{}",
        service(
            super::SERVICE_TYPE_CA_QC,
            CA,
            not_a_certificate,
            (ServiceStatus::Granted, GRANTED),
            &[],
        ),
        service(
            super::SERVICE_TYPE_TSA_QTST,
            TSU,
            &world.tsu,
            (ServiceStatus::Granted, GRANTED),
            &[],
        )
    );
    let national = OwnedCert::from_der(&world.national).expect("parses");
    let list = TrustedList::read(world.signed_national(&services), &[national]).expect("reads");
    let [ca, tsu] = list.services() else {
        panic!("two services");
    };
    assert!(ca.certificates().is_empty());
    assert_eq!(ca.unreadable_certificates(), 1);
    assert_eq!(tsu.unreadable_certificates(), 0);
    assert_eq!(
        ca.granted_periods(),
        vec![GrantedPeriod::new(day(GRANTED), None).expect("a period")],
        "the status still reads; only the anchor is missing"
    );
    assert_eq!(ca.anchors().len(), 0);
    assert_eq!(tsu.anchors().len(), 1);
}

#[test]
fn an_entry_of_another_service_type_closes_a_granted_period() {
    let qc = super::SERVICE_TYPE_CA_QC;
    let service = listed(
        entry(ServiceStatus::Granted, day(WITHDRAWN), qc),
        vec![
            entry(ServiceStatus::Granted, day(INSIDE), OTHER_TYPE),
            entry(ServiceStatus::Granted, day(ISSUED), qc),
        ],
    );
    assert_eq!(
        service.granted_periods(),
        vec![
            period(day(ISSUED), Some(day(INSIDE))),
            period(day(WITHDRAWN), None),
        ],
        "the time the service was of another type is not granted"
    );
}

#[test]
fn a_directive_status_grants_a_certificate_service_until_the_regime_ended() {
    let qc = super::SERVICE_TYPE_CA_QC;
    let end = super::directive_regime_end();
    for status in [
        ServiceStatus::UnderSupervision,
        ServiceStatus::SupervisionInCessation,
        ServiceStatus::Accredited,
    ] {
        let last = listed(entry(status, new_year(DIRECTIVE_YEAR), qc), Vec::new());
        assert_eq!(
            last.granted_periods(),
            vec![period(new_year(DIRECTIVE_YEAR), Some(end))],
            "a Directive status as the last status grants until the regime ended"
        );
        let granted_later = listed(
            entry(ServiceStatus::Granted, new_year(REGULATION_YEAR), qc),
            vec![entry(status, new_year(DIRECTIVE_YEAR), qc)],
        );
        assert_eq!(
            granted_later.granted_periods(),
            vec![
                period(new_year(DIRECTIVE_YEAR), Some(end)),
                period(new_year(REGULATION_YEAR), None),
            ],
            "the gap between the regime's end and the later grant is not granted"
        );
        let after_the_regime = listed(entry(status, new_year(REGULATION_YEAR), qc), Vec::new());
        assert_eq!(after_the_regime.granted_periods(), Vec::new());
        let time_stamping = listed(
            entry(
                status,
                new_year(DIRECTIVE_YEAR),
                super::SERVICE_TYPE_TSA_QTST,
            ),
            Vec::new(),
        );
        assert_eq!(
            time_stamping.granted_periods(),
            Vec::new(),
            "a Directive status grants a time-stamping service nothing"
        );
    }
}

#[test]
fn of_statuses_at_one_instant_the_most_recent_counts() {
    let qc = super::SERVICE_TYPE_CA_QC;
    let withdrawn_after_a_same_instant_grant = listed(
        entry(ServiceStatus::Granted, day(AFTER), qc),
        vec![
            entry(ServiceStatus::Withdrawn, day(WITHDRAWN), qc),
            entry(ServiceStatus::Granted, day(WITHDRAWN), qc),
            entry(ServiceStatus::Granted, day(GRANTED), qc),
        ],
    );
    assert_eq!(
        withdrawn_after_a_same_instant_grant.granted_periods(),
        vec![
            period(day(GRANTED), Some(day(WITHDRAWN))),
            period(day(AFTER), None),
        ]
    );
    let withdrawn_at_its_grant = listed(
        entry(ServiceStatus::Withdrawn, day(GRANTED), qc),
        vec![entry(ServiceStatus::Granted, day(GRANTED), qc)],
    );
    assert_eq!(
        withdrawn_at_its_grant.granted_periods(),
        Vec::new(),
        "a status withdrawn at the instant it was granted grants nothing"
    );
}

/// The signed national list with `edit` applied to its text.
fn edited_national(world: &World, edit: impl Fn(&str) -> String) -> Vec<u8> {
    let signed = String::from_utf8(world.signed_national(&world.services())).expect("UTF-8");
    let edited = edit(&signed);
    assert_ne!(edited, signed);
    edited.into_bytes()
}

#[test]
fn a_signature_with_other_than_two_references_is_refused_before_anything_is_computed() {
    let world = World::new();
    let national = OwnedCert::from_der(&world.national).expect("parses");
    let with_a_third_reference = edited_national(&world, |signed| {
        let start = signed
            .find("<ds:Reference Type=")
            .expect("the properties reference");
        let end = start
            + signed[start..]
                .find("</ds:Reference>")
                .expect("the reference closes")
            + "</ds:Reference>".len();
        let mut edited = signed.to_owned();
        edited.insert_str(end, &signed[start..end]);
        edited
    });
    let refused = Some(TrustedListError::Malformed(
        "SignedInfo does not carry exactly two references",
    ));
    assert_eq!(
        TrustedList::read(
            with_a_third_reference.clone(),
            core::slice::from_ref(&national)
        )
        .err(),
        refused
    );
    assert_eq!(
        TrustedList::read(with_a_third_reference, &[world.lotl_cert()]).err(),
        refused,
        "the count is refused before the signer is even looked at"
    );
}

#[test]
fn the_signed_info_signature_is_verified_before_any_reference() {
    let world = World::new();
    let national = OwnedCert::from_der(&world.national).expect("parses");
    let exclusive_transform = format!("<ds:Transform Algorithm=\"{CANONICALIZATION_EXCLUSIVE}\"/>");
    let forged = edited_national(&world, |signed| {
        signed.replacen(
            &exclusive_transform,
            &format!("{exclusive_transform}{exclusive_transform}"),
            1,
        )
    });
    assert_eq!(
        TrustedList::read(forged, &[national]).err(),
        Some(TrustedListError::SignatureInvalid),
        "a forged SignedInfo fails its signature before its list reference is recomputed"
    );
}
