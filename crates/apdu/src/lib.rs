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

//! Typed ISO 7816-4 commands and the card transport port.
//!
//! Outgoing commands have exactly two ownership paths. Replay-safe public
//! commands are debuggable [`CommandApdu`] values built by typed
//! builders; credential-bearing commands are zeroizing, non-clonable
//! [`CredentialCommand`] values consumed exactly once by the transport.
//! Neither path accepts or exposes an unstructured byte blob, and the
//! [`CardTransport`] port carries only the typed forms.

/// The project version `YY.M.D.B`: the workspace version `YY.M.D`, the UTC
/// day the code last changed, and the build number `B` from this crate's
/// `build.rs` (`refineid-build-number`), the UTC time of day of the build as
/// hour * 100 + minute.
pub const BUILD_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    ".",
    env!("REFINEID_BUILD_NUMBER")
);

pub mod command;
pub mod iso7816;
pub mod primitives;
pub mod status_word;
pub mod transport;

pub use command::{
    APDU_HEADER_LEN, ApduClass, CREDENTIAL_APDU_MAX, CREDENTIAL_BODY_MAX, CREDENTIAL_WIRE_MAX,
    CommandApdu, CommandDataError, CommandHeader, CredentialBody, CredentialBodyError,
    CredentialCommand, SHORT_APDU_DATA_MAX, UnvalidatedCredentialBlock,
};
pub use primitives::{Aid, AidError, FileId, Sfi, SfiError};
pub use status_word::{PinRetries, StatusWord};
pub use transport::{
    CardTransport, ResponseApdu, TransportErrorExt, TransportErrorKind, TransportOutcome,
};

#[cfg(test)]
mod build_version_tests {
    use refineid_build_number::is_build_number;

    use super::BUILD_VERSION;

    #[test]
    fn build_version_is_the_crate_version_and_a_build_number() {
        let build = BUILD_VERSION
            .strip_prefix(env!("CARGO_PKG_VERSION"))
            .and_then(|rest| rest.strip_prefix('.'));
        assert!(
            build.is_some_and(is_build_number),
            "build version {BUILD_VERSION} must be the crate version, a dot and a build number"
        );
    }
}

#[cfg(test)]
mod public_contract_tests {
    use core::fmt::{Debug, Display};

    use serde::{Serialize, de::DeserializeOwned};
    use zeroize::{Zeroize, ZeroizeOnDrop};

    use super::{CommandApdu, CredentialBody, CredentialCommand, UnvalidatedCredentialBlock};

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

    fn require_debug<T: Debug>() {}

    #[test]
    fn credential_types_preserve_ownership_contracts() {
        require_zeroize_on_drop::<CredentialBody>();
        require_zeroize_on_drop::<CredentialCommand>();

        let _ = <CredentialBody as AmbiguousIfImplemented<_, CloneMarker>>::marker;
        let _ = <CredentialBody as AmbiguousIfImplemented<_, CopyMarker>>::marker;
        let _ = <CredentialBody as AmbiguousIfImplemented<_, ZeroizeMarker>>::marker;
        let _ = <CredentialBody as AmbiguousIfImplemented<_, SerializeMarker>>::marker;
        let _ = <CredentialBody as AmbiguousIfImplemented<_, DeserializeMarker>>::marker;
        let _ = <CredentialBody as AmbiguousIfImplemented<_, DisplayMarker>>::marker;

        let _ = <CredentialCommand as AmbiguousIfImplemented<_, CloneMarker>>::marker;
        let _ = <CredentialCommand as AmbiguousIfImplemented<_, CopyMarker>>::marker;
        let _ = <CredentialCommand as AmbiguousIfImplemented<_, ZeroizeMarker>>::marker;
        let _ = <CredentialCommand as AmbiguousIfImplemented<_, SerializeMarker>>::marker;
        let _ = <CredentialCommand as AmbiguousIfImplemented<_, DeserializeMarker>>::marker;
        let _ = <CredentialCommand as AmbiguousIfImplemented<_, DisplayMarker>>::marker;

        // The unvalidated border owns raw credential octets before the body
        // takes custody, so it must erase on drop and never be duplicated,
        // serialised, or rendered raw.
        require_zeroize_on_drop::<UnvalidatedCredentialBlock>();
        let _ = <UnvalidatedCredentialBlock as AmbiguousIfImplemented<_, CloneMarker>>::marker;
        let _ = <UnvalidatedCredentialBlock as AmbiguousIfImplemented<_, CopyMarker>>::marker;
        let _ = <UnvalidatedCredentialBlock as AmbiguousIfImplemented<_, ZeroizeMarker>>::marker;
        let _ = <UnvalidatedCredentialBlock as AmbiguousIfImplemented<_, SerializeMarker>>::marker;
        let _ =
            <UnvalidatedCredentialBlock as AmbiguousIfImplemented<_, DeserializeMarker>>::marker;
        let _ = <UnvalidatedCredentialBlock as AmbiguousIfImplemented<_, DisplayMarker>>::marker;
    }

    #[test]
    fn public_commands_are_debuggable_but_never_clonable() {
        require_debug::<CommandApdu>();

        let _ = <CommandApdu as AmbiguousIfImplemented<_, CloneMarker>>::marker;
        let _ = <CommandApdu as AmbiguousIfImplemented<_, CopyMarker>>::marker;
        let _ = <CommandApdu as AmbiguousIfImplemented<_, SerializeMarker>>::marker;
        let _ = <CommandApdu as AmbiguousIfImplemented<_, DeserializeMarker>>::marker;
        let _ = <CommandApdu as AmbiguousIfImplemented<_, DisplayMarker>>::marker;
    }
}
