// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! Synchronous HTTP transport abstraction for revocation and timestamp fetch paths.
//!
//! Network I/O is abstracted across platforms (Windows, Unix, Android) via the
//! [`HttpTransport`] trait, keeping `refineid-doc-sign` purely Safe Rust.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::RwLock;

use crate::uri::{Scheme, Uri};

/// Honest `User-Agent`: project, crate version, contact URL.
pub const USER_AGENT: &str = concat!(
    "RefineID/",
    env!("CARGO_PKG_VERSION"),
    " (+https://www.refineid.fi/)"
);

/// Errors from `get` / `post` / `post_authority`. Same shape across platforms
/// so callers handle errors uniformly.
#[derive(Debug)]
pub enum HttpError {
    /// URL did not parse as a supported HTTP or HTTPS URL.
    BadUrl(&'static str),
    /// The URL used a scheme other than HTTP or HTTPS.
    UnsupportedScheme(String),
    /// TCP / I/O failure.
    Io(io::Error),
    /// HTTP status line wasn't well-formed.
    BadStatusLine(String),
    /// Non-2xx status.
    HttpStatus {
        /// HTTP status code returned by the server.
        code: u16,
        /// Reason-phrase from the status line.
        reason: String,
        /// Where the server said the resource moved to, when it
        /// said so.
        location: Option<String>,
    },
    /// Response had no readable body length.
    UnknownBodyLength,
    /// Chunked encoding chunk-size line wasn't valid hex.
    BadChunkSize(String),
    /// `Content-Length` exceeded the supplied `max_bytes`.
    BodyTooLarge {
        /// `Content-Length` value the server announced.
        content_length: usize,
        /// The caller-supplied `max_bytes` ceiling.
        limit: usize,
    },
    /// A certificate-published endpoint resolved to a
    /// non-public destination.
    UnsafeDestination(String),
    /// A redirect crossed a policy boundary or exceeded its hop
    /// budget.
    UnsafeRedirect(String),
    /// Authentication material was offered without
    /// server-authenticated TLS.
    InsecureCredentials,
    /// HTTPS failed in the TLS path.
    Https {
        /// Redacted transport detail.
        detail: String,
        /// Whether reconnecting may recover without changing
        /// policy or input.
        retryable: bool,
    },
}

impl core::fmt::Display for HttpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadUrl(s) => write!(f, "bad URL: {s}"),
            Self::UnsupportedScheme(s) => write!(f, "unsupported URL scheme: {s}"),
            Self::Io(e) => write!(f, "i/o: {e}"),
            Self::BadStatusLine(s) => write!(f, "bad HTTP status line: {s:?}"),
            Self::HttpStatus { code, reason, .. } => write!(f, "HTTP {code} {reason}"),
            Self::UnknownBodyLength => write!(
                f,
                "response had no Content-Length and was not chunked; refusing"
            ),
            Self::BadChunkSize(s) => write!(f, "bad chunk-size: {s:?}"),
            Self::BodyTooLarge {
                content_length,
                limit,
            } => write!(
                f,
                "Content-Length {content_length} exceeds caller limit {limit}"
            ),
            Self::UnsafeDestination(detail) => write!(f, "unsafe destination: {detail}"),
            Self::UnsafeRedirect(detail) => write!(f, "unsafe redirect: {detail}"),
            Self::InsecureCredentials => {
                f.write_str("timestamp credentials require an HTTPS authority")
            }
            Self::Https { detail, .. } => write!(f, "HTTPS: {detail}"),
        }
    }
}

impl core::error::Error for HttpError {}

impl From<io::Error> for HttpError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl HttpError {
    /// Whether a timestamp authority request may be repeated
    /// unchanged.
    #[must_use]
    pub fn is_retryable_authority_failure(&self) -> bool {
        match self {
            Self::Io(error) => matches!(
                error.kind(),
                io::ErrorKind::TimedOut
                    | io::ErrorKind::Interrupted
                    | io::ErrorKind::WouldBlock
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::NotConnected
                    | io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::BrokenPipe
            ),
            Self::HttpStatus { code, .. } => {
                matches!(*code, 408 | 425 | 429 | 500 | 502 | 503 | 504)
            }
            Self::Https { retryable, .. } => *retryable,
            Self::BadUrl(_)
            | Self::UnsupportedScheme(_)
            | Self::BadStatusLine(_)
            | Self::UnknownBodyLength
            | Self::BadChunkSize(_)
            | Self::BodyTooLarge { .. }
            | Self::UnsafeDestination(_)
            | Self::UnsafeRedirect(_)
            | Self::InsecureCredentials => false,
        }
    }
}

/// Pluggable HTTP transport interface for revocation and timestamp queries.
///
/// [`get`](Self::get) and [`post`](Self::post) serve URLs a certificate
/// published. They receive the addresses [`guard_destination`] vetted for
/// the URL's host: the transport connects to one of those addresses and
/// never resolves the host again, and it follows a redirect only to a URL
/// that itself passes [`guard_destination`], connecting to the addresses
/// that call returns.
pub trait HttpTransport: Send + Sync {
    /// Perform an HTTP GET request to one of the vetted `addresses`.
    fn get(
        &self,
        url: &Uri,
        addresses: &[SocketAddr],
        max_bytes: usize,
        user_agent: &str,
    ) -> Result<Vec<u8>, HttpError>;

    /// Perform an HTTP POST request to one of the vetted `addresses`.
    fn post(
        &self,
        url: &Uri,
        addresses: &[SocketAddr],
        content_type: &str,
        body: &[u8],
        max_bytes: usize,
        user_agent: &str,
    ) -> Result<Vec<u8>, HttpError>;

    /// Perform an HTTP POST request to an authority endpoint with optional credentials.
    fn post_authority(
        &self,
        url: &Uri,
        content_type: &str,
        body: &[u8],
        max_bytes: usize,
        user_agent: &str,
        auth_header: Option<&str>,
    ) -> Result<Vec<u8>, HttpError>;
}

/// Default HTTP transport stub when no platform transport has been registered.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultHttpTransport;

impl HttpTransport for DefaultHttpTransport {
    fn get(
        &self,
        _url: &Uri,
        _addresses: &[SocketAddr],
        _max_bytes: usize,
        _user_agent: &str,
    ) -> Result<Vec<u8>, HttpError> {
        Err(HttpError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "HTTP transport not configured for refineid-doc-sign",
        )))
    }

    fn post(
        &self,
        _url: &Uri,
        _addresses: &[SocketAddr],
        _content_type: &str,
        _body: &[u8],
        _max_bytes: usize,
        _user_agent: &str,
    ) -> Result<Vec<u8>, HttpError> {
        Err(HttpError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "HTTP transport not configured for refineid-doc-sign",
        )))
    }

    fn post_authority(
        &self,
        _url: &Uri,
        _content_type: &str,
        _body: &[u8],
        _max_bytes: usize,
        _user_agent: &str,
        _auth_header: Option<&str>,
    ) -> Result<Vec<u8>, HttpError> {
        Err(HttpError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "HTTP transport not configured for refineid-doc-sign",
        )))
    }
}

static GLOBAL_TRANSPORT: RwLock<Option<Box<dyn HttpTransport>>> = RwLock::new(None);

/// Register the global HTTP transport for document signing operations.
pub fn set_http_transport(transport: Box<dyn HttpTransport>) {
    if let Ok(mut lock) = GLOBAL_TRANSPORT.write() {
        *lock = Some(transport);
    }
}

/// Clear any registered global HTTP transport.
pub fn clear_http_transport() {
    if let Ok(mut lock) = GLOBAL_TRANSPORT.write() {
        *lock = None;
    }
}

/// GET a certificate-published `url` and return the response body,
/// capped at `max_bytes`. The host is vetted by [`guard_destination`]
/// before the transport is called.
///
/// # Errors
/// [`HttpError::UnsafeDestination`] when the host does not resolve to
/// public addresses only; otherwise URL parse failure, TCP failure,
/// non-2xx HTTP status, malformed HTTP framing, body exceeding
/// `max_bytes`.
pub fn get(url: &Uri, max_bytes: usize, user_agent: &str) -> Result<Vec<u8>, HttpError> {
    let addresses = guard_destination(url)?;
    if let Ok(guard) = GLOBAL_TRANSPORT.read()
        && let Some(transport) = guard.as_ref()
    {
        return transport.get(url, &addresses, max_bytes, user_agent);
    }
    DefaultHttpTransport.get(url, &addresses, max_bytes, user_agent)
}

/// POST `body` to a certificate-published `url` with the supplied
/// `content_type` header. Returns the response body capped at
/// `max_bytes`. The host is vetted by [`guard_destination`] before the
/// transport is called.
///
/// # Errors
/// As for [`get`].
pub fn post(
    url: &Uri,
    content_type: &str,
    body: &[u8],
    max_bytes: usize,
    user_agent: &str,
) -> Result<Vec<u8>, HttpError> {
    let addresses = guard_destination(url)?;
    if let Ok(guard) = GLOBAL_TRANSPORT.read()
        && let Some(transport) = guard.as_ref()
    {
        return transport.post(url, &addresses, content_type, body, max_bytes, user_agent);
    }
    DefaultHttpTransport.post(url, &addresses, content_type, body, max_bytes, user_agent)
}

/// POST to an explicitly configured timestamp authority.
///
/// Unlike certificate-controlled URLs, an authority may
/// intentionally be a service on a private development network.
/// Any redirect is constrained to the same origin or a same-host
/// HTTP-to-HTTPS upgrade.
pub fn post_authority(
    url: &Uri,
    content_type: &str,
    body: &[u8],
    max_bytes: usize,
    user_agent: &str,
    authorization: Option<&str>,
) -> Result<Vec<u8>, HttpError> {
    if authorization.is_some() && url.scheme() != Scheme::Https {
        return Err(HttpError::InsecureCredentials);
    }
    if let Ok(guard) = GLOBAL_TRANSPORT.read()
        && let Some(transport) = guard.as_ref()
    {
        return transport.post_authority(
            url,
            content_type,
            body,
            max_bytes,
            user_agent,
            authorization,
        );
    }
    DefaultHttpTransport.post_authority(
        url,
        content_type,
        body,
        max_bytes,
        user_agent,
        authorization,
    )
}

/// First octet of the RFC 6598 shared address space, 100.64.0.0/10.
const SHARED_ADDRESS_FIRST_OCTET: u8 = 100;
/// Mask over the second octet selecting the /10 prefix bits.
const SHARED_ADDRESS_SECOND_OCTET_MASK: u8 = 0xC0;
/// Second-octet prefix bits of 100.64.0.0/10.
const SHARED_ADDRESS_SECOND_OCTET_PREFIX: u8 = 0x40;

/// Whether `ip` is anything but a public unicast address. An
/// IPv4-mapped IPv6 address is judged as the IPv4 address it reaches.
fn is_non_public(ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    };
    match ip {
        IpAddr::V4(v4) => is_non_public_v4(v4),
        IpAddr::V6(v6) => is_non_public_v6(v6),
    }
}

fn is_non_public_v4(v4: Ipv4Addr) -> bool {
    let [first, second, ..] = v4.octets();
    let shared = first == SHARED_ADDRESS_FIRST_OCTET
        && second & SHARED_ADDRESS_SECOND_OCTET_MASK == SHARED_ADDRESS_SECOND_OCTET_PREFIX;
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_multicast()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_documentation()
        || shared
}

fn is_non_public_v6(v6: Ipv6Addr) -> bool {
    v6.is_loopback()
        || v6.is_unique_local()
        || v6.is_unicast_link_local()
        || v6.is_multicast()
        || v6.is_unspecified()
}

/// SSRF guard for certificate-published URLs: resolve the host and
/// refuse any answer that is not a public unicast address.
///
/// Returns the vetted socket addresses, so the transport connects to
/// exactly what was checked rather than resolving the name again.
/// Explicitly configured authority URLs do not pass through here: a
/// test timestamp authority may live on a private network.
///
/// # Errors
/// [`HttpError::UnsafeDestination`] when the host does not resolve,
/// resolves to nothing, or any answer is non-public.
pub fn guard_destination(url: &Uri) -> Result<Vec<SocketAddr>, HttpError> {
    let host = url.host().to_string();
    let answers: Vec<SocketAddr> = (host.as_str(), url.port())
        .to_socket_addrs()
        .map_err(|error| HttpError::UnsafeDestination(format!("resolve {host}: {error}")))?
        .collect();
    if answers.is_empty() {
        return Err(HttpError::UnsafeDestination(format!(
            "{host} resolved to no addresses"
        )));
    }
    if let Some(answer) = answers.iter().find(|answer| is_non_public(answer.ip())) {
        return Err(HttpError::UnsafeDestination(format!(
            "{host} resolves to non-public {}",
            answer.ip()
        )));
    }
    Ok(answers)
}

/// Authority redirects stay on the same origin, with a same-host
/// HTTP-to-HTTPS upgrade allowed.
pub fn authority_redirect_ok(from: &Uri, to: &Uri) -> bool {
    if from.host() != to.host() || from.port() != to.port() {
        return false;
    }
    to.scheme() == from.scheme() || (from.scheme() == Scheme::Http && to.scheme() == Scheme::Https)
}

#[cfg(test)]
mod tests {
    use super::{
        HttpError, HttpTransport, SocketAddr, Uri, clear_http_transport, get, guard_destination,
        is_non_public, set_http_transport,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Body cap passed by the tests; no body is ever read.
    const TEST_MAX_BYTES: usize = 1;
    /// A public unicast address (Quad9 resolver), for the positive case.
    const PUBLIC_V4: Ipv4Addr = Ipv4Addr::new(9, 9, 9, 9);
    /// An address in the RFC 6598 shared address space.
    const SHARED_V4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
    /// An address in the RFC 5737 documentation range TEST-NET-1.
    const DOCUMENTATION_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

    fn uri(text: &str) -> Uri {
        Uri::parse(text.to_owned()).expect("test URL parses")
    }

    #[test]
    fn loopback_name_is_refused() {
        assert!(matches!(
            guard_destination(&uri("http://localhost/")),
            Err(HttpError::UnsafeDestination(_))
        ));
    }

    #[test]
    fn loopback_literal_is_refused() {
        assert!(matches!(
            guard_destination(&uri("http://127.0.0.1/")),
            Err(HttpError::UnsafeDestination(_))
        ));
    }

    #[test]
    fn ipv4_mapped_loopback_is_refused() {
        let mapped = Ipv4Addr::LOCALHOST.to_ipv6_mapped();
        assert!(is_non_public(IpAddr::V6(mapped)));
        assert!(is_non_public(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn shared_and_documentation_ranges_are_refused() {
        assert!(is_non_public(IpAddr::V4(SHARED_V4)));
        assert!(is_non_public(IpAddr::V4(DOCUMENTATION_V4)));
        assert!(is_non_public(IpAddr::V4(Ipv4Addr::BROADCAST)));
        assert!(is_non_public(IpAddr::V6(SHARED_V4.to_ipv6_mapped())));
    }

    #[test]
    fn a_public_address_passes() {
        assert!(!is_non_public(IpAddr::V4(PUBLIC_V4)));
        assert!(!is_non_public(IpAddr::V6(PUBLIC_V4.to_ipv6_mapped())));
        let vetted = guard_destination(&uri("http://9.9.9.9/")).expect("a public literal passes");
        assert!(
            vetted
                .iter()
                .all(|address| address.ip() == IpAddr::V4(PUBLIC_V4))
        );
    }

    static TRANSPORT_CALLED: AtomicBool = AtomicBool::new(false);

    /// Records whether any certificate-URL method was reached.
    struct RecordingTransport;

    impl HttpTransport for RecordingTransport {
        fn get(
            &self,
            _url: &Uri,
            _addresses: &[SocketAddr],
            _max_bytes: usize,
            _user_agent: &str,
        ) -> Result<Vec<u8>, HttpError> {
            TRANSPORT_CALLED.store(true, Ordering::SeqCst);
            Ok(Vec::new())
        }

        fn post(
            &self,
            _url: &Uri,
            _addresses: &[SocketAddr],
            _content_type: &str,
            _body: &[u8],
            _max_bytes: usize,
            _user_agent: &str,
        ) -> Result<Vec<u8>, HttpError> {
            TRANSPORT_CALLED.store(true, Ordering::SeqCst);
            Ok(Vec::new())
        }

        fn post_authority(
            &self,
            _url: &Uri,
            _content_type: &str,
            _body: &[u8],
            _max_bytes: usize,
            _user_agent: &str,
            _auth_header: Option<&str>,
        ) -> Result<Vec<u8>, HttpError> {
            TRANSPORT_CALLED.store(true, Ordering::SeqCst);
            Ok(Vec::new())
        }
    }

    #[test]
    fn get_consults_guard_before_transport() {
        set_http_transport(Box::new(RecordingTransport));
        let result = get(&uri("http://127.0.0.1/"), TEST_MAX_BYTES, super::USER_AGENT);
        clear_http_transport();
        assert!(matches!(result, Err(HttpError::UnsafeDestination(_))));
        assert!(!TRANSPORT_CALLED.load(Ordering::SeqCst));
    }
}
