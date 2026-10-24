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

//! The PACE secure channel for FINEID cards.
//!
//! The Card Access Number input type is the trust boundary for the
//! password; the handshake drives `id-PACE-ECDH-GM-AES-CBC-CMAC-256`
//! over brainpoolP384r1 and hands its session keys to the
//! secure-messaging layer, which is itself a card transport so the
//! layers above it stay unaware of the protection. Values crossing a
//! trust boundary are deconstructed, validated once, and reconstructed
//! as types whose constructors preserve their invariants.

pub mod can;
pub mod commands;
pub(crate) mod crypto;
pub mod handshake;
pub mod rng;
pub mod secure_messaging;

pub use can::{CAN_DIGITS, Can, CanError, UnvalidatedCan};
pub use handshake::{
    DOMAIN_REF_BRAINPOOL_P384_R1, PASSWORD_REF_CAN, PaceError, PaceSession, Ssc, run_pace_with_can,
};
pub use secure_messaging::{SmError, SmTransport};

#[cfg(test)]
mod public_contract_tests {
    use core::fmt::Display;

    use serde::{Serialize, de::DeserializeOwned};
    use zeroize::{Zeroize, ZeroizeOnDrop};

    use super::{Can, PaceSession, Ssc, UnvalidatedCan};
    use crate::crypto::brainpool_p384::AffinePoint;
    use crate::crypto::symmetric::Aes256Key;

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

    fn require_zeroize<T: Zeroize>() {}

    #[test]
    fn sensitive_public_types_preserve_ownership_contracts() {
        require_zeroize_on_drop::<Can>();
        require_zeroizable_boundary::<UnvalidatedCan>();

        let _ = <Can as AmbiguousIfImplemented<_, CloneMarker>>::marker;
        let _ = <Can as AmbiguousIfImplemented<_, CopyMarker>>::marker;
        let _ = <Can as AmbiguousIfImplemented<_, ZeroizeMarker>>::marker;
        let _ = <Can as AmbiguousIfImplemented<_, SerializeMarker>>::marker;
        let _ = <Can as AmbiguousIfImplemented<_, DeserializeMarker>>::marker;
        let _ = <Can as AmbiguousIfImplemented<_, DisplayMarker>>::marker;

        let _ = <UnvalidatedCan as AmbiguousIfImplemented<_, CloneMarker>>::marker;
        let _ = <UnvalidatedCan as AmbiguousIfImplemented<_, CopyMarker>>::marker;
        let _ = <UnvalidatedCan as AmbiguousIfImplemented<_, SerializeMarker>>::marker;
        let _ = <UnvalidatedCan as AmbiguousIfImplemented<_, DeserializeMarker>>::marker;
        let _ = <UnvalidatedCan as AmbiguousIfImplemented<_, DisplayMarker>>::marker;

        // A duplicated session reuses the send-sequence counter, which
        // voids the CBC/CMAC integrity of every message under the key.
        // The session must therefore be unique by construction: no Clone,
        // no Copy, and no serialisation that would let it be revived.
        let _ = <PaceSession as AmbiguousIfImplemented<_, CloneMarker>>::marker;
        let _ = <PaceSession as AmbiguousIfImplemented<_, CopyMarker>>::marker;
        let _ = <PaceSession as AmbiguousIfImplemented<_, SerializeMarker>>::marker;
        let _ = <PaceSession as AmbiguousIfImplemented<_, DeserializeMarker>>::marker;

        // The session key is custody, not data: it erases on drop and can
        // neither be copied nor serialised out of the crate.
        require_zeroize_on_drop::<Aes256Key>();
        let _ = <Aes256Key as AmbiguousIfImplemented<_, CloneMarker>>::marker;
        let _ = <Aes256Key as AmbiguousIfImplemented<_, CopyMarker>>::marker;
        let _ = <Aes256Key as AmbiguousIfImplemented<_, SerializeMarker>>::marker;
        let _ = <Aes256Key as AmbiguousIfImplemented<_, DeserializeMarker>>::marker;

        // The send sequence counter has one owner that advances with the
        // card; a copy could advance independently and reuse a counter
        // value, so it is neither Copy nor Clone.
        let _ = <Ssc as AmbiguousIfImplemented<_, CloneMarker>>::marker;
        let _ = <Ssc as AmbiguousIfImplemented<_, CopyMarker>>::marker;

        // A curve point computed from a private scalar is duplicated only
        // by an explicit clone and can be wiped on request, so the
        // handshake's secret-dependent points never spread by implicit
        // copy and die with their zeroizing owner.
        require_zeroize::<AffinePoint>();
        let _ = <AffinePoint as AmbiguousIfImplemented<_, CopyMarker>>::marker;
    }
}
