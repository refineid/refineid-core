use refineid_apdu::CardTransport;
use refineid_sign::{QualifiedSignSession, SignScheme};

fn forged_session<T: CardTransport>(transport: T) -> QualifiedSignSession<T> {
    QualifiedSignSession {
        transport,
        scheme: SignScheme::Organizational,
    }
}

fn main() {}
