use refineid_apdu::CardTransport;
use refineid_sign::{KeyRef, SignScheme, SigningKey};

fn qualified<T: CardTransport>(transport: &mut T) -> SigningKey<'_, T> {
    SigningKey {
        transport,
        scheme: SignScheme::Organizational,
        key: KeyRef::Sign,
    }
}

fn main() {}
