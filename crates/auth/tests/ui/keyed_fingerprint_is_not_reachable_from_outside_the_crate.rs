use refineid_auth::CachedPin;
use refineid_auth::credentials::{CachedPin as CredentialsCachedPin, PIN_MIN_LENGTH};
use refineid_auth::{Pin1, Pin2, UnvalidatedSecret};

/// Length of an HMAC-SHA-256 key in bytes, used to attempt an external call.
const HMAC_SHA256_KEY_LEN: usize = 32;

fn main() {
    let pin1 = Pin1::reconstruct(UnvalidatedSecret::from_owned_bytes(
        vec![b'0'; PIN_MIN_LENGTH],
    ))
    .expect("valid PIN1 fixture");
    let pin2 = Pin2::reconstruct(UnvalidatedSecret::from_owned_bytes(
        vec![b'0'; PIN_MIN_LENGTH],
    ))
    .expect("valid PIN2 fixture");
    let _ = pin1.keyed_fingerprint(b"", &[0_u8; HMAC_SHA256_KEY_LEN]);
    let _ = pin2.keyed_fingerprint(b"", &[0_u8; HMAC_SHA256_KEY_LEN]);
}
