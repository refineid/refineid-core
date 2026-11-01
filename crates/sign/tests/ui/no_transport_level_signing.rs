use refineid_apdu::CardTransport;
use refineid_sign::commands::SHA256_LEN;
use refineid_sign::{KeyRef, SignOps as _, SignScheme};

fn sign<T: CardTransport>(transport: &mut T, digest: [u8; SHA256_LEN]) {
    let _ = transport.sign_prehashed_sha256_rsa(SignScheme::Organizational, KeyRef::Sign, digest);
}

fn main() {}
