use refineid_apdu::CardTransport;
use refineid_pace::{OpenedByCan, OpenedByPin2, PaceSession, SmTransport};

fn relabelled<T: CardTransport>(
    inner: T,
    session: PaceSession<OpenedByCan>,
) -> SmTransport<T, OpenedByPin2> {
    SmTransport::new(inner, session)
}

fn main() {}
