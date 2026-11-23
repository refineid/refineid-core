use refineid_apdu::CardTransport;
use refineid_sign::{SignScheme, SigningKey};

fn forged_key<K>() -> K {
    loop {}
}

fn qualified<T: CardTransport>(transport: &mut T) -> SigningKey<'_, T> {
    SigningKey {
        transport,
        scheme: SignScheme::Organizational,
        key: forged_key(),
    }
}

fn main() {}
