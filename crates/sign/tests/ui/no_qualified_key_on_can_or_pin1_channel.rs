use refineid_apdu::CardTransport;
use refineid_pace::{OpenedByCan, OpenedByPin1, SmTransport};
use refineid_sign::Pin2ChannelSignOps as _;

fn can<T: CardTransport>(channel: &mut SmTransport<T, OpenedByCan>) {
    let _ = channel.qualified_key_after_pin2_pace();
}

fn pin1<T: CardTransport>(channel: &mut SmTransport<T, OpenedByPin1>) {
    let _ = channel.qualified_key_after_pin2_pace();
}

fn main() {}
