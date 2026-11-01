// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Reviewed FINEID PIN role types and verification.
//!
//! Values crossing a trust boundary are deconstructed, validated once, and
//! reconstructed as types whose constructors preserve their invariants.
//! The verification chain consumes a validated PIN through a
//! crate-private path and ships it as a credential command, consumed
//! exactly once; the retry floor serves a PIN 1 or PIN 2 attempt only at
//! five, four or three tries left, the one floor every surface stops at.

pub mod activation;
pub mod credentials;
pub mod manage;
pub mod pace_password;
pub mod pin_lengths;
pub mod retry_risk;
pub mod verify;

pub use activation::{
    ActivationCode, ActivationReport, ActivationScheme, CardActivationNeeds,
    CredentialHealthReport, PinChangeRecord, pin_awaits_activation, read_pin_change_record,
    read_puk_status_from_container,
};
pub use credentials::{
    CACHE_FINGERPRINT_KEY_LEN, CACHE_FINGERPRINT_LEN, CachedPin, CredentialInputError,
    CredentialRole, Pin1, Pin2, Puk, UnvalidatedSecret,
};
pub use manage::{ManageOutcome, PinManageOps, classify_manage_sw};
pub use pace_password::{PACE_PASSWORD_KEY_LEN, PacePasswordKey};
pub use pin_lengths::{
    CardLengthSource, CardPinLengths, CredentialLengths, ListedLength, PinLengthRefusal,
};
pub use refineid_pkcs15::PasswordLengthRange;
pub use retry_risk::{
    FlooredCredential, PinRetryRisk, RetryFloorRefusal, check_retry_floor,
    pin1_status_permits_reusable_cache,
};
pub use verify::{
    AuthError, PIN_STORED_LENGTH, PIN1_REFERENCE, PIN1_REFERENCE_ORGANIZATIONAL, PIN2_REFERENCE,
    PIN2_REFERENCE_ORGANIZATIONAL, PUK_REFERENCE, PUK_REFERENCE_ORGANIZATIONAL, PinOps,
    PinReferenceScheme, PinSlot, PinStatus, VerifyOutcome, classify_pin_status_sw,
    classify_verify_sw,
};

#[cfg(test)]
mod public_contract_tests {
    use core::fmt::Display;

    use serde::{Serialize, de::DeserializeOwned};
    use zeroize::{Zeroize, ZeroizeOnDrop};

    use super::{ActivationCode, PacePasswordKey, Pin1, Pin2, Puk, UnvalidatedSecret};

    trait AmbiguousIfImplemented<Disambiguator, Marker> {
        fn marker() {}
    }

    impl<T: ?Sized, Marker> AmbiguousIfImplemented<(), Marker> for T {}

    struct CloneMarker;
    impl<T: Clone> AmbiguousIfImplemented<bool, CloneMarker> for T {}

    struct CopyMarker;
    impl<T: Copy> AmbiguousIfImplemented<bool, CopyMarker> for T {}

    struct ZeroizeMarker;
    impl<T: ?Sized + Zeroize> AmbiguousIfImplemented<bool, ZeroizeMarker> for T {}

    struct SerializeMarker;
    impl<T: ?Sized + Serialize> AmbiguousIfImplemented<bool, SerializeMarker> for T {}

    struct DeserializeMarker;
    impl<T: DeserializeOwned> AmbiguousIfImplemented<bool, DeserializeMarker> for T {}

    struct DisplayMarker;
    impl<T: ?Sized + Display> AmbiguousIfImplemented<bool, DisplayMarker> for T {}

    fn require_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    fn require_zeroizable_boundary<T: Zeroize + ZeroizeOnDrop>() {}

    #[test]
    fn sensitive_public_types_preserve_ownership_contracts() {
        require_zeroize_on_drop::<Pin1>();
        require_zeroize_on_drop::<Pin2>();
        require_zeroize_on_drop::<Puk>();
        require_zeroize_on_drop::<ActivationCode>();
        require_zeroize_on_drop::<PacePasswordKey>();
        require_zeroizable_boundary::<UnvalidatedSecret>();

        let _ = <ActivationCode as AmbiguousIfImplemented<_, CloneMarker>>::marker;
        let _ = <ActivationCode as AmbiguousIfImplemented<_, CopyMarker>>::marker;
        let _ = <ActivationCode as AmbiguousIfImplemented<_, ZeroizeMarker>>::marker;
        let _ = <ActivationCode as AmbiguousIfImplemented<_, SerializeMarker>>::marker;
        let _ = <ActivationCode as AmbiguousIfImplemented<_, DeserializeMarker>>::marker;
        let _ = <ActivationCode as AmbiguousIfImplemented<_, DisplayMarker>>::marker;

        let _ = <PacePasswordKey as AmbiguousIfImplemented<_, CloneMarker>>::marker;
        let _ = <PacePasswordKey as AmbiguousIfImplemented<_, CopyMarker>>::marker;
        let _ = <PacePasswordKey as AmbiguousIfImplemented<_, ZeroizeMarker>>::marker;
        let _ = <PacePasswordKey as AmbiguousIfImplemented<_, SerializeMarker>>::marker;
        let _ = <PacePasswordKey as AmbiguousIfImplemented<_, DeserializeMarker>>::marker;
        let _ = <PacePasswordKey as AmbiguousIfImplemented<_, DisplayMarker>>::marker;

        let _ = <Pin1 as AmbiguousIfImplemented<_, CloneMarker>>::marker;
        let _ = <Pin1 as AmbiguousIfImplemented<_, CopyMarker>>::marker;
        let _ = <Pin1 as AmbiguousIfImplemented<_, ZeroizeMarker>>::marker;
        let _ = <Pin1 as AmbiguousIfImplemented<_, SerializeMarker>>::marker;
        let _ = <Pin1 as AmbiguousIfImplemented<_, DeserializeMarker>>::marker;
        let _ = <Pin1 as AmbiguousIfImplemented<_, DisplayMarker>>::marker;

        let _ = <Pin2 as AmbiguousIfImplemented<_, CloneMarker>>::marker;
        let _ = <Pin2 as AmbiguousIfImplemented<_, CopyMarker>>::marker;
        let _ = <Pin2 as AmbiguousIfImplemented<_, ZeroizeMarker>>::marker;
        let _ = <Pin2 as AmbiguousIfImplemented<_, SerializeMarker>>::marker;
        let _ = <Pin2 as AmbiguousIfImplemented<_, DeserializeMarker>>::marker;
        let _ = <Pin2 as AmbiguousIfImplemented<_, DisplayMarker>>::marker;

        let _ = <Puk as AmbiguousIfImplemented<_, CloneMarker>>::marker;
        let _ = <Puk as AmbiguousIfImplemented<_, CopyMarker>>::marker;
        let _ = <Puk as AmbiguousIfImplemented<_, ZeroizeMarker>>::marker;
        let _ = <Puk as AmbiguousIfImplemented<_, SerializeMarker>>::marker;
        let _ = <Puk as AmbiguousIfImplemented<_, DeserializeMarker>>::marker;
        let _ = <Puk as AmbiguousIfImplemented<_, DisplayMarker>>::marker;

        let _ = <UnvalidatedSecret as AmbiguousIfImplemented<_, CloneMarker>>::marker;
        let _ = <UnvalidatedSecret as AmbiguousIfImplemented<_, CopyMarker>>::marker;
        let _ = <UnvalidatedSecret as AmbiguousIfImplemented<_, SerializeMarker>>::marker;
        let _ = <UnvalidatedSecret as AmbiguousIfImplemented<_, DeserializeMarker>>::marker;
        let _ = <UnvalidatedSecret as AmbiguousIfImplemented<_, DisplayMarker>>::marker;
    }
}
