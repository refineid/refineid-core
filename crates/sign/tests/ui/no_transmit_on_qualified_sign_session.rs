use refineid_apdu::{CardTransport, CommandApdu};
use refineid_sign::QualifiedSignSession;

fn send_on_sealed_session<T: CardTransport>(
    session: &mut QualifiedSignSession<T>,
    command: &CommandApdu,
) {
    let _ = session.transmit(command);
}

fn main() {}
