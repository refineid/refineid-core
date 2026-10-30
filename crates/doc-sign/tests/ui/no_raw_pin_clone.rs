use refineid_doc_sign::pin::PinBytes;

fn duplicate(pin: &PinBytes) -> PinBytes {
    pin.clone()
}

fn main() {
    let _ = duplicate;
}
