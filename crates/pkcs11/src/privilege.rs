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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! Whether this process is privileged on Unix.
//!
//! A root, set-user-id or set-group-id host process (a PAM stack under
//! `sudo`, a display manager) may have inherited its environment from an
//! unprivileged caller. The module consults this predicate before acting
//! on an environment variable that names a filesystem location, so such a
//! process never creates, writes or deletes files where that caller chose.

/// The real and effective user and group ids of a Unix process.
#[derive(Clone, Copy, Debug)]
struct ProcessIds {
    real_uid: rustix::process::Uid,
    effective_uid: rustix::process::Uid,
    real_gid: rustix::process::Gid,
    effective_gid: rustix::process::Gid,
}

/// Whether a process with these ids runs with privileges its environment
/// cannot be trusted to direct: effective uid root, or an effective user or
/// group id that differs from the real one (set-user-id, set-group-id).
const fn is_privileged_process(ids: ProcessIds) -> bool {
    ids.effective_uid.is_root()
        || ids.effective_uid.as_raw() != ids.real_uid.as_raw()
        || ids.effective_gid.as_raw() != ids.real_gid.as_raw()
}

/// Read the calling process's real and effective user and group ids.
fn current_process_ids() -> ProcessIds {
    ProcessIds {
        real_uid: rustix::process::getuid(),
        effective_uid: rustix::process::geteuid(),
        real_gid: rustix::process::getgid(),
        effective_gid: rustix::process::getegid(),
    }
}

/// Whether the calling process is privileged, by [`is_privileged_process`]
/// over its current ids.
pub(super) fn current_process_is_privileged() -> bool {
    is_privileged_process(current_process_ids())
}

#[cfg(test)]
mod tests {
    #[test]
    fn privileged_process_predicate() {
        use rustix::process::{Gid, RawGid, RawUid, Uid};

        const USER_ID: RawUid = 1000;
        const OTHER_USER_ID: RawUid = 1001;
        const GROUP_ID: RawGid = 100;
        const OTHER_GROUP_ID: RawGid = 101;

        let ids =
            |real_uid: RawUid, effective_uid: RawUid, real_gid: RawGid, effective_gid: RawGid| {
                super::ProcessIds {
                    real_uid: Uid::from_raw(real_uid),
                    effective_uid: Uid::from_raw(effective_uid),
                    real_gid: Gid::from_raw(real_gid),
                    effective_gid: Gid::from_raw(effective_gid),
                }
            };
        let root = Uid::ROOT.as_raw();
        let root_group = Gid::ROOT.as_raw();

        // An ordinary user process is not privileged.
        assert!(!super::is_privileged_process(ids(
            USER_ID, USER_ID, GROUP_ID, GROUP_ID
        )));
        // A user whose real and effective group is 0 is not privileged
        // by that alone.
        assert!(!super::is_privileged_process(ids(
            USER_ID, USER_ID, root_group, root_group
        )));
        // Root, whether started as root or through set-user-id root.
        assert!(super::is_privileged_process(ids(
            root, root, root_group, root_group
        )));
        assert!(super::is_privileged_process(ids(
            root, root, GROUP_ID, GROUP_ID
        )));
        assert!(super::is_privileged_process(ids(
            USER_ID, root, GROUP_ID, GROUP_ID
        )));
        // Set-user-id to another unprivileged user.
        assert!(super::is_privileged_process(ids(
            USER_ID,
            OTHER_USER_ID,
            GROUP_ID,
            GROUP_ID
        )));
        // Set-group-id, to group 0 or to another group.
        assert!(super::is_privileged_process(ids(
            USER_ID, USER_ID, GROUP_ID, root_group
        )));
        assert!(super::is_privileged_process(ids(
            USER_ID,
            USER_ID,
            GROUP_ID,
            OTHER_GROUP_ID
        )));
        // A root process that dropped its effective uid to a user while
        // its real uid stays root.
        assert!(super::is_privileged_process(ids(
            root, USER_ID, GROUP_ID, GROUP_ID
        )));
    }
}
