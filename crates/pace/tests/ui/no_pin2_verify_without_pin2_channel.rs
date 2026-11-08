use refineid_apdu::CardTransport;
use refineid_auth::{Pin2, Pin2PaceChannelOps as _};
use refineid_pace::{OpenedByCan, OpenedByPin1, OpenedByPuk, SmTransport};

fn can<T: CardTransport>(channel: &mut SmTransport<T, OpenedByCan>, pin: Pin2) {
    let _ = channel.verify_pin2_after_pin2_pace(pin);
}

fn pin1<T: CardTransport>(channel: &mut SmTransport<T, OpenedByPin1>, pin: Pin2) {
    let _ = channel.verify_pin2_after_pin2_pace(pin);
}

fn puk<T: CardTransport>(channel: &mut SmTransport<T, OpenedByPuk>, pin: Pin2) {
    let _ = channel.verify_pin2_after_pin2_pace(pin);
}

fn plain<T: CardTransport>(transport: &mut T, pin: Pin2) {
    let _ = transport.verify_pin2_after_pin2_pace(pin);
}

fn main() {}
