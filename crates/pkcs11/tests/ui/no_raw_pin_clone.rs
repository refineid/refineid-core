use refineid_pkcs11::pin::PinBytes;

fn duplicate(pin: &PinBytes) -> PinBytes {
    pin.clone()
}

fn main() {
    let _ = duplicate;
}
