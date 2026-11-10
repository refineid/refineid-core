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

//! The origin-bound challenge rule for authentication-key signs.
//!
//! The authentication certificate is an authentication-purpose key, so
//! the SCS must refuse to sign arbitrary bytes with it: the content
//! must be `origin;nonce`, where `origin` matches the request's Origin
//! header byte for byte and the nonce is at least 64 octets of caller
//! randomness (DVV SCS specification v1.3 sec.2.1, sec.3.7). Without
//! this, any page the holder happens to visit could obtain an
//! authentication signature over bytes of its choosing and replay it
//! elsewhere.
//!
//! Lengths are octets: the nonce floor counts bytes, and the whole
//! request is capped at 1024 octets (v1.3 sec.2.1).

use crate::values;

/// Why `content` is not an acceptable challenge, or `None` when it
/// is.
#[must_use]
pub fn refusal(content: &[u8], origin: Option<&str>) -> Option<String> {
    let Some(origin) = origin else {
        return Some("missing Origin header".to_owned());
    };
    if content.len() > values::CHALLENGE_MAXIMUM_LENGTH {
        return Some(format!(
            "challenge longer than {} octets",
            values::CHALLENGE_MAXIMUM_LENGTH
        ));
    }
    let Ok(text) = core::str::from_utf8(content) else {
        return Some("challenge must be UTF-8 (origin;nonce)".to_owned());
    };
    let Some((challenge_origin, nonce)) = text.split_once(';') else {
        return Some("challenge missing ; separator (expected origin;nonce)".to_owned());
    };
    if challenge_origin != origin {
        return Some(format!(
            "challenge origin {challenge_origin} does not match request Origin {origin}"
        ));
    }
    if nonce.len() < values::NONCE_MINIMUM_LENGTH {
        return Some(format!(
            "challenge nonce too short ({} octets, {} required)",
            nonce.len(),
            values::NONCE_MINIMUM_LENGTH
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::refusal;
    use crate::values;

    /// Bytes that are never valid UTF-8.
    const NON_UTF8: &[u8] = &[0xFF, 0xFE];

    /// A 64-octet nonce over the request's origin is accepted.
    #[test]
    fn well_formed_challenge_is_accepted() {
        let nonce = "n".repeat(values::NONCE_MINIMUM_LENGTH);
        let challenge = format!("https://example.com;{nonce}");
        assert_eq!(
            refusal(challenge.as_bytes(), Some("https://example.com")),
            None
        );
    }

    /// Every deviation names its reason.
    #[test]
    fn deviations_are_refused() {
        assert_eq!(
            refusal(b"anything", None),
            Some("missing Origin header".to_owned())
        );
        assert_eq!(
            refusal(NON_UTF8, Some("https://example.com")),
            Some("challenge must be UTF-8 (origin;nonce)".to_owned())
        );
        assert_eq!(
            refusal(b"noseparator", Some("https://example.com")),
            Some("challenge missing ; separator (expected origin;nonce)".to_owned())
        );
        let nonce = "n".repeat(values::NONCE_MINIMUM_LENGTH);
        let challenge = format!("https://example.com;{nonce}");
        assert_eq!(
            refusal(challenge.as_bytes(), Some("https://other.example")),
            Some(
                "challenge origin https://example.com does not match request Origin https://other.example"
                    .to_owned()
            )
        );
        assert_eq!(
            refusal(b"https://example.com;short", Some("https://example.com")),
            Some("challenge nonce too short (5 octets, 64 required)".to_owned())
        );
    }
}
