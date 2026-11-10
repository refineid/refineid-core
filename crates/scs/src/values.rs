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

//! The SCS wire values, each cited to the DVV SCS specification v1.3.

/// The one TCP port the specification names (v1.3 sec.2.2).
pub const PORT: u16 = 53_952;

/// The protocol version this service implements and answers in every
/// response body.
pub const VERSION: &str = "1.3";

/// Smallest accepted authentication-challenge nonce, in octets
/// (v1.3 sec.3.7).
pub const NONCE_MINIMUM_LENGTH: usize = 64;

/// JWE initialization-vector length for A256GCM: 96 bits.
pub const JWE_INITIALIZATION_VECTOR_LENGTH: usize = 12;

/// JWE authentication-tag length for A256GCM: 128 bits.
pub const JWE_TAG_LENGTH: usize = 16;

/// Reason code: signature generated (v1.3 sec.2.6.3).
pub const REASON_OK: u16 = 200;

/// Reason code: malformed request.
pub const REASON_BAD_REQUEST: u16 = 400;

/// Reason code: end-user or credential refusal.
pub const REASON_UNAUTHORIZED: u16 = 401;

/// Reason code: request refused by policy (origin or challenge
/// binding).
pub const REASON_FORBIDDEN: u16 = 403;

/// Reason code: internal failure.
pub const REASON_INTERNAL_ERROR: u16 = 500;

/// Reason code: valid request for an unimplemented capability.
pub const REASON_NOT_IMPLEMENTED: u16 = 501;

/// HTTP status: OK.
///
/// The SCS answers 200 even for failed signs; the JSON reason triple
/// carries the outcome (v1.3 sec.3).
pub const HTTP_OK: u16 = 200;

/// HTTP status: no route.
pub const HTTP_NOT_FOUND: u16 = 404;

/// Longest accepted HTTP head, in bytes; a longer one is not a
/// well-formed SCS exchange.
pub const HTTP_HEAD_MAXIMUM_LENGTH: usize = 65_536;

/// Longest accepted HTTP body, in bytes.
///
/// Documents ride inline as base64, so the cap is generous but
/// present.
pub const HTTP_BODY_MAXIMUM_LENGTH: usize = 16_777_216;

/// Compact JWS segment count: header, payload, signature.
pub const JWS_SEGMENT_COUNT: usize = 3;

/// Compact JWS segment index of the signature.
pub const JWS_SIGNATURE_INDEX: usize = 2;

/// Compact JWE segment count: header, empty key, IV, ciphertext, tag
/// (direct encryption leaves the key segment empty).
pub const JWE_SEGMENT_COUNT: usize = 5;

/// Compact JWE segment index of the initialization vector.
pub const JWE_INITIALIZATION_VECTOR_INDEX: usize = 2;

/// Compact JWE segment index of the ciphertext.
pub const JWE_CIPHERTEXT_INDEX: usize = 3;

/// Compact JWE segment index of the authentication tag.
pub const JWE_TAG_INDEX: usize = 4;

/// KeyUsage bits of the localhost server certificate:
/// digitalSignature and keyEncipherment (v1.3 sec.2.3).
pub const SERVER_KEY_USAGE_BITS: u8 = 0xA0;

/// Unused trailing bits in the KeyUsage BIT STRING above.
pub const SERVER_KEY_USAGE_UNUSED_BITS: u8 = 5;

/// Octets in an IPv4 address.
pub const IPV4_LENGTH: usize = 4;

/// The loopback address named in the certificate's subjectAltName
/// (v1.3 sec.2.3): 127.0.0.1.
pub const LOOPBACK_ADDRESS: [u8; IPV4_LENGTH] = [127, 0, 0, 1];

/// Length of the agreed A256GCM transaction key, in bytes.
pub const TRANSACTION_KEY_LENGTH: usize = 32;

/// How long a generated localhost certificate stays valid, in
/// years; it is persisted and reused, so trust survives restarts.
pub const CERTIFICATE_VALIDITY_YEARS: i32 = 10;

/// Upper-case hex length of a SHA-1 digest: two characters per octet.
pub const SHA1_HEX_LENGTH: usize = refineid_digest::SHA1_LEN * 2;
