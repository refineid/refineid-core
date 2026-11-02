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

//! The custodian's fresh announcements: a fresh instance name whenever
//! advertising starts or restarts (hierarchy specification section 4.2),
//! and the announcement owed once a card is back after its sessions closed
//! with `card_unavailable` (RAPP v26.11.2 section 8.4 item 5).

use super::{InstanceName, RandomUnavailable};

/// Fixed first part of a fresh service instance name (hierarchy
/// specification section 4.2).
pub const INSTANCE_NAME_PREFIX: &str = "refineid-";
/// Random bytes in a fresh service instance name; they follow the prefix
/// as eight lowercase hexadecimal digits (hierarchy specification section
/// 4.2).
pub const INSTANCE_NAME_RANDOM_SIZE: usize = 4;

/// A fresh random service instance name, `refineid-` and eight lowercase
/// hexadecimal digits, drawn from `random` (hierarchy specification
/// section 4.2). It derives from nothing stored.
///
/// # Errors
/// [`RandomUnavailable`] when `random` fails.
pub fn fresh_instance_name(
    random: impl FnOnce(&mut [u8]) -> Result<(), RandomUnavailable>,
) -> Result<InstanceName, RandomUnavailable> {
    let mut bytes = [0_u8; INSTANCE_NAME_RANDOM_SIZE];
    random(&mut bytes)?;
    let name = format!("{INSTANCE_NAME_PREFIX}{}", super::txt::lower_hex(&bytes));
    Ok(InstanceName::new(&name).expect("a fresh instance name is a valid instance portion"))
}

/// Whether the custodian owes its requesters a fresh announcement because
/// it closed sessions with `card_unavailable` (section 8.4 item 5, the
/// `card_available_again` event of `custodian_service`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CardAnnouncement {
    owed: bool,
}

impl CardAnnouncement {
    /// Nothing owed.
    #[must_use]
    pub const fn new() -> Self {
        Self { owed: false }
    }

    /// The custodian closed a session with `card_unavailable`.
    pub const fn closed_with_card_unavailable(&mut self) {
        self.owed = true;
    }

    /// The custodian registered a fresh instance for another reason
    /// (remote access turned on, launch, restored by the operating
    /// system): every requester sees it appear, so nothing is owed.
    pub const fn registered_fresh_instance(&mut self) {
        self.owed = false;
    }

    /// A card the custodian can serve is back. `true` when the custodian
    /// announces itself again now (`reannounce_service`): it is serving
    /// and closed sessions with `card_unavailable` since it last
    /// registered a fresh instance. It then registers its stream service
    /// under a [`fresh_instance_name`] in place of the current one,
    /// restarts its BLE advertisement, and reports the registration with
    /// [`Self::registered_fresh_instance`]; until then the announcement
    /// stays owed, so one that failed is made at the next call. Outside
    /// serving nothing is owed: serving again registers a fresh instance
    /// anyway.
    pub const fn card_available(&mut self, serving: bool) -> bool {
        if !serving {
            self.owed = false;
        }
        self.owed
    }
}

#[cfg(test)]
mod tests {
    use super::{CardAnnouncement, INSTANCE_NAME_PREFIX, fresh_instance_name};
    use crate::RandomUnavailable;

    const RANDOM_FILL: u8 = 0xa5;

    #[test]
    fn a_fresh_name_is_the_prefix_and_eight_lowercase_digits() {
        let name = fresh_instance_name(|bytes| {
            bytes.fill(RANDOM_FILL);
            Ok(())
        })
        .expect("a name");
        let text = core::str::from_utf8(name.as_bytes()).expect("utf-8");
        let digits = text
            .strip_prefix(INSTANCE_NAME_PREFIX)
            .expect("the prefix leads");
        assert_eq!(digits, "a5a5a5a5");
        assert_eq!(
            fresh_instance_name(|_| Err(RandomUnavailable)),
            Err(RandomUnavailable)
        );
    }

    #[test]
    fn a_card_back_after_card_unavailable_announces_once_while_serving() {
        let mut announcement = CardAnnouncement::new();
        assert!(!announcement.card_available(true), "nothing was closed");
        announcement.closed_with_card_unavailable();
        assert!(announcement.card_available(true));
        assert!(
            announcement.card_available(true),
            "owed until the registration is reported"
        );
        announcement.registered_fresh_instance();
        assert!(!announcement.card_available(true), "announced once");

        announcement.closed_with_card_unavailable();
        assert!(!announcement.card_available(false), "not serving");
        assert!(
            !announcement.card_available(true),
            "serving again registered afresh"
        );

        announcement.closed_with_card_unavailable();
        announcement.registered_fresh_instance();
        assert!(!announcement.card_available(true));
    }
}
