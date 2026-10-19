// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! URL refinement types: text validated to RFC 3986 and RFC 1123.

use core::fmt;

/// Maximum total length for an HTTP/HTTPS URI accepted here.
pub const MAX_URI_LEN: usize = 2048;

/// Maximum total length for a DNS host name in presentation format.
pub const MAX_HOST_LEN: usize = 253;

/// Maximum length of a single dot-separated DNS host label.
pub const MAX_LABEL_LEN: usize = 63;

/// Scheme default port for HTTP.
pub const DEFAULT_HTTP_PORT: u16 = 80;

/// Scheme default port for HTTPS.
pub const DEFAULT_HTTPS_PORT: u16 = 443;

/// Why a URI path or query byte was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UriCharError {
    /// A byte outside the allowed character set.
    IllegalByte {
        /// Byte offset in the input.
        position: usize,
        /// The rejected byte value.
        byte: u8,
    },
    /// A percent-escape that was not two hex digits.
    MalformedEscape {
        /// Offset of the `%` byte.
        position: usize,
    },
}

impl fmt::Display for UriCharError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IllegalByte { position, byte } => {
                write!(
                    f,
                    "byte {byte:#04X} at position {position} is not a URI character"
                )
            }
            Self::MalformedEscape { position } => {
                write!(f, "malformed percent-escape at position {position}")
            }
        }
    }
}

impl core::error::Error for UriCharError {}

/// Why a host is not a valid RFC 1123 / RFC 1035 DNS name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostError {
    /// The host was empty.
    Empty,
    /// The whole host exceeded `MAX_HOST_LEN` octets.
    TooLong {
        /// The rejected host length, in octets.
        len: usize,
    },
    /// A dot-separated label was empty.
    EmptyLabel,
    /// A label exceeded `MAX_LABEL_LEN` octets.
    LabelTooLong {
        /// The rejected label length, in octets.
        len: usize,
    },
    /// A label began or ended with `-`.
    LabelHyphenBoundary,
    /// A byte outside the DNS host charset `[a-z0-9.-]`.
    Byte {
        /// The offending byte.
        byte: u8,
    },
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty host"),
            Self::TooLong { len } => {
                write!(f, "host is {len} octets, over the {MAX_HOST_LEN} limit")
            }
            Self::EmptyLabel => f.write_str("empty host label (leading, trailing, or double dot)"),
            Self::LabelTooLong { len } => {
                write!(
                    f,
                    "host label is {len} octets, over the {MAX_LABEL_LEN} limit"
                )
            }
            Self::LabelHyphenBoundary => f.write_str("host label begins or ends with a hyphen"),
            Self::Byte { byte } => {
                write!(f, "byte {byte:#04X} is outside the host charset [a-z0-9.-]")
            }
        }
    }
}

impl core::error::Error for HostError {}

/// Why a string is not a valid `http(s)` URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UriError {
    /// Longer than `MAX_URI_LEN` bytes.
    TooLong {
        /// The rejected input length.
        len: usize,
    },
    /// No `http://` / `https://` prefix.
    Scheme,
    /// The authority carried userinfo (`user@host`), which is not accepted.
    Userinfo,
    /// A port that was not `*DIGIT` in `u16` range.
    BadPort,
    /// The host component was invalid.
    Host(HostError),
    /// The path component was invalid.
    Path(UriCharError),
    /// The query component was invalid.
    Query(UriCharError),
}

impl fmt::Display for UriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { len } => write!(f, "URI is {len} bytes, over the {MAX_URI_LEN} limit"),
            Self::Scheme => f.write_str("URI scheme is not http:// or https://"),
            Self::Userinfo => {
                f.write_str("URI authority carries userinfo (user@host), not accepted")
            }
            Self::BadPort => f.write_str("URI port is not a u16-range *DIGIT"),
            Self::Host(error) => write!(f, "URI host: {error}"),
            Self::Path(error) => write!(f, "URI path: {error}"),
            Self::Query(error) => write!(f, "URI query: {error}"),
        }
    }
}

impl core::error::Error for UriError {}

/// RFC 3986 §3.1 scheme: `http` or `https`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// The `http` scheme.
    Http,
    /// The `https` scheme.
    Https,
}

impl Scheme {
    /// The scheme-default port (RFC 7230): 80 for http, 443 for https.
    #[must_use]
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Http => DEFAULT_HTTP_PORT,
            Self::Https => DEFAULT_HTTPS_PORT,
        }
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Http => "http",
            Self::Https => "https",
        })
    }
}

const fn is_pchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
        )
}

struct PctScan;

impl PctScan {
    fn first_error(text: &str, allowed: fn(u8) -> bool) -> Option<UriCharError> {
        let full = text.as_bytes();
        let mut rest: &[u8] = full;
        loop {
            let position = full.len().saturating_sub(rest.len());
            match rest {
                [] => return None,
                [b'%', hi, lo, tail @ ..] if hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit() => {
                    rest = tail;
                }
                [b'%', ..] => return Some(UriCharError::MalformedEscape { position }),
                [first, tail @ ..] if allowed(*first) => rest = tail,
                [first, ..] => {
                    return Some(UriCharError::IllegalByte {
                        position,
                        byte: *first,
                    });
                }
            }
        }
    }
}

/// RFC 1123 / RFC 1035 DNS host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host(Box<str>);

impl Host {
    /// Validate `text` as a DNS host, lowercasing it in place first.
    pub(crate) fn parse(mut text: String) -> Result<Self, HostError> {
        text.make_ascii_lowercase();
        if text.is_empty() {
            return Err(HostError::Empty);
        }
        let total = text.len();
        if total > MAX_HOST_LEN {
            return Err(HostError::TooLong { len: total });
        }
        for label in text.split('.') {
            if label.is_empty() {
                return Err(HostError::EmptyLabel);
            }
            if label.len() > MAX_LABEL_LEN {
                return Err(HostError::LabelTooLong { len: label.len() });
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(HostError::LabelHyphenBoundary);
            }
            if let Some(byte) = label
                .bytes()
                .find(|byte| !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-'))
            {
                return Err(HostError::Byte { byte });
            }
        }
        Ok(Self(text.into_boxed_str()))
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// RFC 3986 `path-abempty` in origin form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path(Box<str>);

impl Path {
    pub(crate) fn parse(text: String) -> Result<Self, UriCharError> {
        if let Some(error) = PctScan::first_error(&text, |byte| is_pchar(byte) || byte == b'/') {
            return Err(error);
        }
        let normalised = if text.is_empty() {
            "/".to_owned()
        } else {
            text
        };
        Ok(Self(normalised.into_boxed_str()))
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// RFC 3986 `query` component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query(Box<str>);

impl Query {
    pub(crate) fn parse(text: String) -> Result<Self, UriCharError> {
        if let Some(error) =
            PctScan::first_error(&text, |byte| is_pchar(byte) || matches!(byte, b'/' | b'?'))
        {
            return Err(error);
        }
        Ok(Self(text.into_boxed_str()))
    }

    /// `true` when the URI carried no query at all.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for Query {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The validated URI type for HTTP/HTTPS requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uri {
    scheme: Scheme,
    host: Host,
    port: u16,
    path: Path,
    query: Query,
}

impl Uri {
    /// Deconstruct and validate `input` as an `http(s)` URL.
    pub fn parse(input: String) -> Result<Self, UriError> {
        if input.len() > MAX_URI_LEN {
            return Err(UriError::TooLong { len: input.len() });
        }
        let bytes = input.as_bytes();
        let (scheme, after_scheme) = if bytes
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"https://"))
        {
            (Scheme::Https, input.get(8..).unwrap_or_default())
        } else if bytes
            .get(..7)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"http://"))
        {
            (Scheme::Http, input.get(7..).unwrap_or_default())
        } else {
            return Err(UriError::Scheme);
        };
        let authority_end = after_scheme
            .find(['/', '?', '#'])
            .unwrap_or(after_scheme.len());
        let authority = after_scheme.get(..authority_end).unwrap_or_default();
        let after_authority = after_scheme.get(authority_end..).unwrap_or_default();
        if authority.contains('@') {
            return Err(UriError::Userinfo);
        }
        let (host_raw, port) = match authority.rsplit_once(':') {
            Some((host_raw, port_raw)) => {
                if port_raw.is_empty() || !port_raw.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(UriError::BadPort);
                }
                let port: u16 = port_raw.parse().map_err(|_error| UriError::BadPort)?;
                if port == 0 {
                    return Err(UriError::BadPort);
                }
                (host_raw, port)
            }
            None => (authority, scheme.default_port()),
        };
        let host = Host::parse(host_raw.to_owned()).map_err(UriError::Host)?;
        let without_fragment = after_authority.split('#').next().unwrap_or_default();
        let (path_raw, query_raw) = match without_fragment.split_once('?') {
            Some((path_raw, query_raw)) => (path_raw, query_raw),
            None => (without_fragment, ""),
        };
        let path = Path::parse(path_raw.to_owned()).map_err(UriError::Path)?;
        let query = Query::parse(query_raw.to_owned()).map_err(UriError::Query)?;
        Ok(Self {
            scheme,
            host,
            port,
            path,
            query,
        })
    }

    /// The scheme component.
    #[must_use]
    pub const fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// The host component.
    #[must_use]
    pub const fn host(&self) -> &Host {
        &self.host
    }

    /// The effective port: explicit, or the scheme default.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The path component.
    #[must_use]
    pub const fn path(&self) -> &Path {
        &self.path
    }

    /// The query component (empty when the URI carried no `?`).
    #[must_use]
    pub const fn query(&self) -> &Query {
        &self.query
    }

    /// Resolve a redirect `Location` against this URL.
    pub fn join(&self, location: String) -> Result<Self, UriError> {
        if location.starts_with("http://") || location.starts_with("https://") {
            return Self::parse(location);
        }
        if let Some(scheme_relative) = location.strip_prefix("//") {
            return Self::parse(format!("{}://{scheme_relative}", self.scheme));
        }
        let authority = self.authority_string();
        if location.starts_with('/') {
            return Self::parse(format!("{}://{authority}{location}", self.scheme));
        }
        let path = self.path.to_string();
        let dir_end = path.rfind('/').map_or(0, |index| index.saturating_add(1));
        let dir = path.get(..dir_end).unwrap_or("/");
        Self::parse(format!("{}://{authority}{dir}{location}", self.scheme))
    }

    /// `host[:port]`, with the scheme-default port elided.
    fn authority_string(&self) -> String {
        if self.port == self.scheme.default_port() {
            self.host.to_string()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

impl fmt::Display for Uri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}", self.scheme, self.authority_string())?;
        write!(f, "{}", self.path)?;
        if !self.query.is_empty() {
            write!(f, "?{}", self.query)?;
        }
        Ok(())
    }
}
