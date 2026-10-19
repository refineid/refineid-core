// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! Synchronous HTTP transport abstraction for revocation and timestamp fetch paths.
//!
//! Network I/O is abstracted across platforms (Windows, Unix, Android) via the
//! [`HttpTransport`] trait, keeping `refineid-doc-sign` purely Safe Rust.

use std::io;
use std::net::ToSocketAddrs;
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
pub trait HttpTransport: Send + Sync {
    /// Perform an HTTP GET request.
    fn get(&self, url: &Uri, max_bytes: usize, user_agent: &str) -> Result<Vec<u8>, HttpError>;

    /// Perform an HTTP POST request.
    fn post(
        &self,
        url: &Uri,
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
    fn get(&self, _url: &Uri, _max_bytes: usize, _user_agent: &str) -> Result<Vec<u8>, HttpError> {
        Err(HttpError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "HTTP transport not configured for refineid-doc-sign",
        )))
    }

    fn post(
        &self,
        _url: &Uri,
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

/// GET `url` and return the response body, capped at `max_bytes`.
///
/// # Errors
/// URL parse failure, TCP failure, non-2xx HTTP status, malformed
/// HTTP framing, body exceeding `max_bytes`.
pub fn get(url: &Uri, max_bytes: usize, user_agent: &str) -> Result<Vec<u8>, HttpError> {
    if let Ok(guard) = GLOBAL_TRANSPORT.read()
        && let Some(transport) = guard.as_ref()
    {
        return transport.get(url, max_bytes, user_agent);
    }
    DefaultHttpTransport.get(url, max_bytes, user_agent)
}

/// POST `body` to `url` with the supplied `content_type` header.
/// Returns the response body capped at `max_bytes`.
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
    if let Ok(guard) = GLOBAL_TRANSPORT.read()
        && let Some(transport) = guard.as_ref()
    {
        return transport.post(url, content_type, body, max_bytes, user_agent);
    }
    DefaultHttpTransport.post(url, content_type, body, max_bytes, user_agent)
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

/// SSRF guard for certificate-published URLs: the host must
/// resolve, and every answer must be a public address. Authority
/// URLs skip the check (a test TSA may live on a private
/// network).
pub fn guard_destination(url: &Uri, is_authority: bool) -> Result<(), HttpError> {
    if is_authority {
        return Ok(());
    }
    let host = url.host().to_string();
    let mut answers = (host.as_str(), url.port())
        .to_socket_addrs()
        .map_err(|error| HttpError::UnsafeDestination(format!("resolve {host}: {error}")))?
        .peekable();
    if answers.peek().is_none() {
        return Err(HttpError::UnsafeDestination(format!(
            "{host} resolved to no addresses"
        )));
    }
    for answer in answers {
        let ip = answer.ip();
        let non_public = match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_multicast()
                    || v4.is_unspecified()
            }
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unique_local()
                    || v6.is_unicast_link_local()
                    || v6.is_multicast()
                    || v6.is_unspecified()
            }
        };
        if non_public {
            return Err(HttpError::UnsafeDestination(format!(
                "{host} resolves to non-public {ip}"
            )));
        }
    }
    Ok(())
}

/// Authority redirects stay on the same origin, with a same-host
/// HTTP-to-HTTPS upgrade allowed.
pub fn authority_redirect_ok(from: &Uri, to: &Uri) -> bool {
    if from.host() != to.host() || from.port() != to.port() {
        return false;
    }
    to.scheme() == from.scheme() || (from.scheme() == Scheme::Http && to.scheme() == Scheme::Https)
}
