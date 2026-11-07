use refineid_apdu::CardTransport;
use refineid_auth::{CardPinLengths, ChannelProof, Pin2, Pin2PaceChannelOps as _};
use refineid_pace::{OpenedByCan, OpenedByPin1, OpenedByPuk, SmTransport};

fn can<T: CardTransport>(channel: &mut SmTransport<T, OpenedByCan>, l: &CardPinLengths, new: Pin2) {
    let _ = channel.change_pin2_after_pin2_pace(l, new, ChannelProof::PaceHandshake);
}

fn pin1<T: CardTransport>(channel: &mut SmTransport<T, OpenedByPin1>, l: &CardPinLengths, new: Pin2) {
    let _ = channel.change_pin2_after_pin2_pace(l, new, ChannelProof::PaceHandshake);
}

fn puk<T: CardTransport>(channel: &mut SmTransport<T, OpenedByPuk>, l: &CardPinLengths, new: Pin2) {
    let _ = channel.change_pin2_after_pin2_pace(l, new, ChannelProof::PaceHandshake);
}

fn plain<T: CardTransport>(transport: &mut T, l: &CardPinLengths, new: Pin2) {
    let _ = transport.change_pin2_after_pin2_pace(l, new, ChannelProof::PaceHandshake);
}

fn main() {}
