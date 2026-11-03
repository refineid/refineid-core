use refineid_apdu::CardTransport;
use refineid_auth::{CardPinLengths, ChannelProof, Pin1, Pin1PaceChannelOps as _};
use refineid_pace::{OpenedByCan, OpenedByPin2, OpenedByPuk, SmTransport};

fn can<T: CardTransport>(channel: &mut SmTransport<T, OpenedByCan>, l: &CardPinLengths, new: Pin1) {
    let _ = channel.change_pin1_after_pin1_pace(l, new, ChannelProof::PaceHandshake);
}

fn pin2<T: CardTransport>(channel: &mut SmTransport<T, OpenedByPin2>, l: &CardPinLengths, new: Pin1) {
    let _ = channel.change_pin1_after_pin1_pace(l, new, ChannelProof::PaceHandshake);
}

fn puk<T: CardTransport>(channel: &mut SmTransport<T, OpenedByPuk>, l: &CardPinLengths, new: Pin1) {
    let _ = channel.change_pin1_after_pin1_pace(l, new, ChannelProof::PaceHandshake);
}

fn plain<T: CardTransport>(transport: &mut T, l: &CardPinLengths, new: Pin1) {
    let _ = transport.change_pin1_after_pin1_pace(l, new, ChannelProof::PaceHandshake);
}

fn main() {}
