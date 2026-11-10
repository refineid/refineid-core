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

//! The SCS HTTP framing: one parsed request head, incremental
//! assembly, and the CORS-carrying responses.
//!
//! The SCS serves exactly one request per connection and closes it, so
//! the head plus a `Content-Length` body is the whole exchange. That
//! is a local framing choice rather than a specified one: the
//! specification's own examples use `Connection: keep-alive` (v1.3
//! sec.2.4), and single-use connections remove any question of one
//! request's bytes being read as another's.

use crate::values;

/// Bytes in the head/body separator.
const HEAD_SEPARATOR_LENGTH: usize = 4;

/// The head/body separator.
const HEAD_SEPARATOR: &[u8; HEAD_SEPARATOR_LENGTH] = b"\r\n\r\n";

/// The line separator inside the head.
const LINE_SEPARATOR: &str = "\r\n";

/// A request line names at least a method and a target.
const REQUEST_LINE_MINIMUM_PARTS: usize = 2;

/// One parsed SCS request head.
///
/// Only the fields the protocol acts on are kept: the method and path
/// route, the Origin binds challenges and CORS answers, the content
/// type selects the JSON or JWT branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The request method, verbatim.
    pub method: String,
    /// The request path with any query string removed.
    pub path: String,
    /// The Origin header, when the browser sent one.
    pub origin: Option<String>,
    /// The Content-Type header, when present.
    pub content_type: Option<String>,
    /// The Content-Length header, parsed; zero when absent.
    pub body_length: usize,
}

impl Request {
    /// Parse one head block (the bytes before the blank line).
    ///
    /// Returns `None` when the block is not UTF-8 or has no request
    /// line; unknown headers are ignored.
    #[must_use]
    pub fn parse(head: &[u8]) -> Option<Self> {
        let text = core::str::from_utf8(head).ok()?;
        let mut lines = text.split(LINE_SEPARATOR);
        let request_line = lines.next()?;
        let parts: Vec<&str> = request_line
            .split(' ')
            .filter(|part| !part.is_empty())
            .collect();
        if parts.len() < REQUEST_LINE_MINIMUM_PARTS {
            return None;
        }
        let method = parts[0];
        let target = parts[1];
        let path = target.split('?').next().unwrap_or(target).to_owned();
        let mut origin = None;
        let mut content_type = None;
        let mut body_length = 0_usize;
        for line in lines {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let name = name.trim();
            let value = value.trim();
            if name.eq_ignore_ascii_case("Origin") {
                origin = Some(value.to_owned());
            } else if name.eq_ignore_ascii_case("Content-Type") {
                content_type = Some(value.to_owned());
            } else if name.eq_ignore_ascii_case("Content-Length") {
                // A declared length that is not a non-negative
                // integer is a malformed head: falling back to zero
                // would accept garbage or an overflowing number as a
                // valid empty body, and a negative count would reach
                // the body assembly.
                body_length = value.parse::<usize>().ok()?;
            }
        }
        Some(Self {
            method: method.to_owned(),
            path,
            origin,
            content_type,
            body_length,
        })
    }
}

/// One completely received SCS request: the parsed head and its body,
/// ready to dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exchange {
    /// The parsed request head.
    pub request: Request,
    /// The request body, exactly `Content-Length` bytes.
    pub body: Vec<u8>,
}

/// Incremental assembly of one SCS HTTP exchange from transport
/// bytes.
///
/// The transport hands over whatever it has read so far; assembly
/// answers whether the buffer already holds the complete request. The
/// caller keeps accumulating until `Complete` or `Invalid` -- one
/// request per connection, which this implementation chooses so a
/// connection's bytes can only ever form one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Assembly {
    /// The buffer holds a complete request head and body.
    Complete(Exchange),
    /// The buffer can never become a valid request; close the
    /// connection.
    Invalid,
    /// The buffer is a valid prefix; read more bytes.
    NeedMoreData,
}

/// Classify the buffer as read so far.
#[must_use]
pub fn assemble(buffer: &[u8]) -> Assembly {
    let Some(boundary) = find_subslice(buffer, HEAD_SEPARATOR) else {
        if buffer.len() > values::HTTP_HEAD_MAXIMUM_LENGTH {
            return Assembly::Invalid;
        }
        return Assembly::NeedMoreData;
    };
    let Some(request) = Request::parse(&buffer[..boundary]) else {
        return Assembly::Invalid;
    };
    if request.body_length > values::HTTP_BODY_MAXIMUM_LENGTH {
        return Assembly::Invalid;
    }
    let body = &buffer[boundary + HEAD_SEPARATOR.len()..];
    let body_length = request.body_length;
    if body.len() < body_length {
        return Assembly::NeedMoreData;
    }
    Assembly::Complete(Exchange {
        request,
        body: body[..body_length].to_vec(),
    })
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// A JSON response with CORS headers.
#[must_use]
pub fn json(status: u16, body: &[u8], origin: Option<&str>) -> Vec<u8> {
    let mut headers = cors_headers(origin);
    headers.push(("Content-Type".to_owned(), "application/json".to_owned()));
    build(status, &headers, body)
}

/// A compact JWT/JWE response with CORS headers.
#[must_use]
pub fn jwt(compact: &str, origin: Option<&str>) -> Vec<u8> {
    let mut headers = cors_headers(origin);
    headers.push(("Content-Type".to_owned(), "application/jwt".to_owned()));
    build(values::HTTP_OK, &headers, compact.as_bytes())
}

/// A plain-text response with CORS headers.
#[must_use]
pub fn text(status: u16, body: &str, origin: Option<&str>) -> Vec<u8> {
    let mut headers = cors_headers(origin);
    headers.push((
        "Content-Type".to_owned(),
        "text/plain; charset=utf-8".to_owned(),
    ));
    build(status, &headers, body.as_bytes())
}

/// The CORS preflight acknowledgement.
#[must_use]
pub fn preflight(origin: Option<&str>) -> Vec<u8> {
    build(values::HTTP_OK, &cors_headers(origin), &[])
}

/// The CORS headers every response carries.
///
/// The specification requires the Access-Control-Allow-Origin header
/// on every response and fixes its value to `*` (DVV SCS
/// specification v1.3 sec.2.1); echoing the request's own Origin
/// instead is a narrowing of that, which is why `Vary: Origin`
/// accompanies it.
fn cors_headers(origin: Option<&str>) -> Vec<(String, String)> {
    vec![
        (
            "Access-Control-Allow-Origin".to_owned(),
            origin.unwrap_or("*").to_owned(),
        ),
        (
            "Access-Control-Allow-Methods".to_owned(),
            "GET, POST".to_owned(),
        ),
        (
            "Access-Control-Allow-Headers".to_owned(),
            "Accept, Content-Type".to_owned(),
        ),
        ("Access-Control-Max-Age".to_owned(), "3600".to_owned()),
        ("Vary".to_owned(), "Origin".to_owned()),
    ]
}

fn build(status: u16, headers: &[(String, String)], body: &[u8]) -> Vec<u8> {
    let mut head = format!("HTTP/1.1 {status} {}\r\n", reason(status));
    head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    head.push_str("Connection: close\r\n");
    for (name, value) in headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

fn reason(status: u16) -> &'static str {
    if status == values::HTTP_OK {
        "OK"
    } else if status == values::HTTP_NOT_FOUND {
        "Not Found"
    } else {
        "Status"
    }
}

#[cfg(test)]
mod tests {
    use super::{Assembly, Exchange, Request, assemble, json, jwt, preflight, text};
    use crate::values;

    /// The body length the parsed head fixture declares.
    const FIXTURE_BODY_LENGTH: usize = 12;

    /// Bytes that are never valid UTF-8.
    const NON_UTF8: &[u8] = &[0xFF, 0xFE];

    /// A head parses to its routing fields; the query string is cut.
    #[test]
    fn head_parses() {
        let request = Request::parse(
            b"POST /sign?x=1 HTTP/1.1\r\nOrigin: https://example.com\r\nContent-Type: application/json\r\nContent-Length: 12",
        );
        assert_eq!(
            request,
            Some(Request {
                method: "POST".to_owned(),
                path: "/sign".to_owned(),
                origin: Some("https://example.com".to_owned()),
                content_type: Some("application/json".to_owned()),
                body_length: FIXTURE_BODY_LENGTH,
            })
        );
    }

    /// Header names match case-insensitively; unknown ones are kept
    /// out.
    #[test]
    fn headers_match_case_insensitively() {
        let request =
            Request::parse(b"GET /version HTTP/1.1\r\noRiGiN: https://a.example\r\nX-Thing: 1")
                .expect("parses");
        assert_eq!(request.origin.as_deref(), Some("https://a.example"));
        assert_eq!(request.body_length, 0);
    }

    /// A declared length that is not a non-negative integer refuses
    /// the head.
    #[test]
    fn bad_content_length_refuses_the_head() {
        for head in [
            "POST /sign HTTP/1.1\r\nContent-Length: many",
            "POST /sign HTTP/1.1\r\nContent-Length: -1",
            "POST /sign HTTP/1.1\r\nContent-Length: 99999999999999999999999",
        ] {
            assert_eq!(Request::parse(head.as_bytes()), None, "{head:?}");
        }
        assert_eq!(Request::parse(b"BARELY"), None);
        assert_eq!(Request::parse(NON_UTF8), None);
    }

    /// Assembly answers need-more-data, then the exchange, and
    /// refuses an overlong head or body.
    #[test]
    fn assembly_classifies() {
        assert_eq!(assemble(b"POST /sign"), Assembly::NeedMoreData);
        let full = b"POST /sign HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc";
        let assembled = assemble(full);
        assert!(matches!(assembled, Assembly::Complete(_)), "{assembled:?}");
        let Assembly::Complete(Exchange { request, body }) = assembled else {
            return;
        };
        assert_eq!(request.method, "POST");
        assert_eq!(body, b"abc");
        let short = b"POST /sign HTTP/1.1\r\nContent-Length: 4\r\n\r\nabc";
        assert_eq!(assemble(short), Assembly::NeedMoreData);
        let long_head = vec![b'A'; values::HTTP_HEAD_MAXIMUM_LENGTH + 1];
        assert_eq!(assemble(&long_head), Assembly::Invalid);
        let long_body = format!(
            "POST /sign HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            values::HTTP_BODY_MAXIMUM_LENGTH + 1
        );
        assert_eq!(assemble(long_body.as_bytes()), Assembly::Invalid);
    }

    /// Responses carry the CORS set, the origin echo, and close the
    /// connection.
    #[test]
    fn responses_carry_cors_and_close() {
        let response = json(values::HTTP_OK, br#"{"a":1}"#, Some("https://a.example"));
        let rendered = core::str::from_utf8(&response).expect("ascii");
        assert!(rendered.starts_with("HTTP/1.1 200 OK\r\n"), "{rendered:?}");
        assert!(
            rendered.contains("Access-Control-Allow-Origin: https://a.example\r\n"),
            "{rendered:?}"
        );
        assert!(rendered.contains("Connection: close\r\n"), "{rendered:?}");
        assert!(rendered.ends_with(r#"{"a":1}"#), "{rendered:?}");

        let anonymous = preflight(None);
        let rendered = core::str::from_utf8(&anonymous).expect("ascii");
        assert!(
            rendered.contains("Access-Control-Allow-Origin: *\r\n"),
            "{rendered:?}"
        );
        assert!(
            rendered.contains("Access-Control-Allow-Methods: GET, POST\r\n"),
            "{rendered:?}"
        );

        let token = jwt("a.b.c", None);
        let rendered = core::str::from_utf8(&token).expect("ascii");
        assert!(
            rendered.contains("Content-Type: application/jwt\r\n"),
            "{rendered:?}"
        );

        let missing = text(values::HTTP_NOT_FOUND, "Not Found", None);
        let rendered = core::str::from_utf8(&missing).expect("ascii");
        assert!(
            rendered.starts_with("HTTP/1.1 404 Not Found\r\n"),
            "{rendered:?}"
        );
    }
}
