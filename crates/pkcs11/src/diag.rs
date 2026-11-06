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

//! Env-gated diagnostic logging for tracing the NSS call sequence.
//!
//! Off by default. `REFINEID_PKCS11_LOG=<path>` appends lines to an
//! operator-chosen file; otherwise `REFINEID_DEBUG=1` writes to
//! stderr; otherwise every call is a no-op. The environment is read
//! once per process (this cdylib lives as long as the browser, and a
//! long-lived module must not re-read its configuration per call).
//!
//! There is deliberately NO default file path: this code runs inside
//! the browser's address space, and an implicit well-known location
//! in a world-writable directory such as `/tmp` is a symlink-attack
//! surface. The operator names the file explicitly or gets no file.
//!
//! In a privileged Unix process -- effective uid root, or an effective
//! user or group id that differs from the real one -- the file sink is
//! unavailable and `REFINEID_PKCS11_LOG` is ignored: such a process (a
//! PAM stack under `sudo`, a display manager) may have inherited its
//! environment from an unprivileged caller, and must not create or
//! append to a file at a path that caller chose. The stderr sink stays
//! available there, so `REFINEID_DEBUG=1` still traces a privileged
//! host: stderr is a descriptor the host process already holds, not a
//! location the environment names, and the lines carry no secrets.
//!
//! On Unix a log file the module creates gets mode 0600
//! (`LOG_FILE_MODE`), narrowed further by the umask; an existing file
//! keeps its mode. The path is opened as given, following symlinks.
//!
//! PIN secrecy (AGENTS.md): call sites log function names, handles,
//! flag words, and byte lengths only -- never PIN bytes, never
//! attribute or signature values.

use std::io::Write as _;
use std::sync::{Mutex, OnceLock};

/// Mode of a log file the module creates on Unix: owner read and write
/// only.
#[cfg(unix)]
const LOG_FILE_MODE: u32 = 0o600;

/// The value of `REFINEID_DEBUG` that turns on the stderr sink.
const DEBUG_ON: &str = "1";

/// Where diagnostic lines go, decided once from the environment.
enum Sink {
    /// `REFINEID_DEBUG=1`: write to the process stderr.
    Stderr,
    /// `REFINEID_PKCS11_LOG=<path>`: append to the named file.
    File(Mutex<std::fs::File>),
}

/// The sink the environment selects, before any file is opened.
#[derive(Debug, PartialEq, Eq)]
enum SinkChoice<'path> {
    /// Write to the process stderr.
    Stderr,
    /// Append to the file at this path.
    File(&'path str),
}

/// Choose the sink from the values of `REFINEID_PKCS11_LOG` and
/// `REFINEID_DEBUG` (absent as `None`) and whether the process is
/// privileged. A non-empty log path selects the file sink unless the
/// process is privileged, in which case the path is ignored; otherwise
/// `REFINEID_DEBUG=1` selects stderr; otherwise logging is off.
fn choose_sink<'path>(
    log_path: Option<&'path str>,
    debug: Option<&str>,
    privileged: bool,
) -> Option<SinkChoice<'path>> {
    if let Some(path) = log_path
        && !path.is_empty()
        && !privileged
    {
        return Some(SinkChoice::File(path));
    }
    (debug == Some(DEBUG_ON)).then_some(SinkChoice::Stderr)
}

/// Whether the calling process is privileged. Only Unix has the notion
/// the file-sink gate uses; elsewhere no process counts as privileged.
fn process_is_privileged() -> bool {
    #[cfg(unix)]
    {
        crate::privilege::current_process_is_privileged()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Open the log file for appending, creating it if missing (mode
/// `LOG_FILE_MODE` on Unix).
fn open_log_file(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(LOG_FILE_MODE);
    }
    options.open(path)
}

/// The process-wide sink; `None` inside means logging is disabled.
static SINK: OnceLock<Option<Sink>> = OnceLock::new();

/// Resolve the sink, reading the environment on first use only. A file
/// that cannot be opened leaves logging off.
fn sink() -> Option<&'static Sink> {
    SINK.get_or_init(|| {
        let log_path = std::env::var("REFINEID_PKCS11_LOG").ok();
        let debug = std::env::var("REFINEID_DEBUG").ok();
        match choose_sink(
            log_path.as_deref(),
            debug.as_deref(),
            process_is_privileged(),
        )? {
            SinkChoice::Stderr => Some(Sink::Stderr),
            SinkChoice::File(path) => open_log_file(std::path::Path::new(path))
                .ok()
                .map(|file| Sink::File(Mutex::new(file))),
        }
    })
    .as_ref()
}

/// Whether diagnostic logging is active. Callers gate on this before
/// formatting so a disabled sink costs no allocation.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private root module helper is called from the sibling api module; plain pub would violate the public-surface typing grep"
)]
pub(super) fn enabled() -> bool {
    sink().is_some()
}

/// Append one line to the active sink. Every failure is swallowed: a
/// diagnostics problem must never disturb the hosting caller (NSS
/// expects deterministic returns from a passive module).
#[expect(
    clippy::redundant_pub_crate,
    reason = "private root module helper is called from the sibling api module; plain pub would violate the public-surface typing grep"
)]
pub(super) fn write_line(line: &str) {
    match sink() {
        Some(Sink::Stderr) => {
            let mut err = std::io::stderr().lock();
            let _ = writeln!(err, "refineid-pkcs11[{}]: {line}", std::process::id());
        }
        Some(Sink::File(file)) => {
            if let Ok(mut file) = file.lock() {
                let _ = writeln!(file, "refineid-pkcs11[{}]: {line}", std::process::id());
            }
        }
        None => {}
    }
}

/// Log one diagnostic line, formatting lazily (the arguments are
/// evaluated only when a sink is active). Never pass PIN bytes or
/// attribute values.
macro_rules! diag {
    ($($arg:tt)*) => {
        if crate::diag::enabled() {
            crate::diag::write_line(&format!($($arg)*));
        }
    };
}
pub(crate) use diag;

#[cfg(test)]
mod tests {
    use super::{SinkChoice, choose_sink};

    const LOG_PATH: &str = "operator.log";

    #[test]
    fn sink_choice_table() {
        for privileged in [false, true] {
            // Nothing set, an empty path, or a debug value other than
            // "1": logging stays off.
            assert_eq!(choose_sink(None, None, privileged), None);
            assert_eq!(choose_sink(Some(""), None, privileged), None);
            assert_eq!(choose_sink(None, Some("0"), privileged), None);
            assert_eq!(choose_sink(None, Some(""), privileged), None);
            // REFINEID_DEBUG=1 alone selects stderr, privileged or not.
            assert_eq!(
                choose_sink(None, Some("1"), privileged),
                Some(SinkChoice::Stderr)
            );
            assert_eq!(
                choose_sink(Some(""), Some("1"), privileged),
                Some(SinkChoice::Stderr)
            );
        }
        // An unprivileged process gets the named file, which wins over
        // stderr.
        assert_eq!(
            choose_sink(Some(LOG_PATH), None, false),
            Some(SinkChoice::File(LOG_PATH))
        );
        assert_eq!(
            choose_sink(Some(LOG_PATH), Some("1"), false),
            Some(SinkChoice::File(LOG_PATH))
        );
        // A privileged process ignores the path: off, or stderr when
        // REFINEID_DEBUG=1.
        assert_eq!(choose_sink(Some(LOG_PATH), None, true), None);
        assert_eq!(
            choose_sink(Some(LOG_PATH), Some("1"), true),
            Some(SinkChoice::Stderr)
        );
    }

    #[cfg(unix)]
    #[test]
    fn log_file_is_created_owner_only() {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;

        // The permission bits of `st_mode`: owner, group and other rwx.
        const PERMISSION_BITS: u32 = 0o777;

        let unique_name = format!("refineid-test-diag-log-mode-{}", std::process::id());
        let temp_dir = std::env::temp_dir().join(unique_name);
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).expect("create test base dir");

        let log_path = temp_dir.join(LOG_PATH);
        let mut file = super::open_log_file(&log_path).expect("open new log file");
        writeln!(file, "line").expect("write log line");
        drop(file);

        let mode = std::fs::metadata(&log_path)
            .expect("log file metadata")
            .permissions()
            .mode()
            & PERMISSION_BITS;
        assert_eq!(mode, super::LOG_FILE_MODE);

        // Reopening appends to the existing file.
        let mut file = super::open_log_file(&log_path).expect("reopen log file");
        writeln!(file, "line").expect("append log line");
        drop(file);
        let contents = std::fs::read_to_string(&log_path).expect("read log file");
        assert_eq!(contents, "line\nline\n");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
