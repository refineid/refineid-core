use refineid_auth::PinStatus;
use refineid_pace::{OpenedByPin1, OpenedByPuk};

fn forged_puk() -> OpenedByPuk {
    OpenedByPuk { counter: PinStatus::NoInfo }
}

fn forged_pin1() -> OpenedByPin1 {
    OpenedByPin1 { counter: PinStatus::NoInfo }
}

fn main() {}
