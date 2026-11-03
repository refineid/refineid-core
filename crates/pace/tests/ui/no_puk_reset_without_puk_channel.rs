use refineid_apdu::CardTransport;
use refineid_auth::{CardPinLengths, ChannelProof, Pin1, PukPaceChannelOps as _};
use refineid_pace::{OpenedByCan, OpenedByPin1, OpenedByPin2, SmTransport};

fn can<T: CardTransport>(channel: &mut SmTransport<T, OpenedByCan>, l: &CardPinLengths, new: Pin1) {
    let _ = channel.reset_pin1_after_puk_pace(l, new, ChannelProof::PaceHandshake);
}

fn pin1<T: CardTransport>(channel: &mut SmTransport<T, OpenedByPin1>, l: &CardPinLengths, new: Pin1) {
    let _ = channel.reset_pin1_after_puk_pace(l, new, ChannelProof::PaceHandshake);
}

fn pin2<T: CardTransport>(channel: &mut SmTransport<T, OpenedByPin2>, l: &CardPinLengths, new: Pin1) {
    let _ = channel.reset_pin1_after_puk_pace(l, new, ChannelProof::PaceHandshake);
}

fn plain<T: CardTransport>(transport: &mut T, l: &CardPinLengths, new: Pin1) {
    let _ = transport.reset_pin1_after_puk_pace(l, new, ChannelProof::PaceHandshake);
}

fn main() {}
