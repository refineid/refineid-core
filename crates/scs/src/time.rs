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

//! Certificate times: UTCTime encoding and calendar-year offsets
//! backed by [`spki::der::DateTime`] and [`spki::der::asn1::UtcTime`].

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use spki::der::asn1::{GeneralizedTime, UtcTime};
use spki::der::{DateTime, EncodeValue as _, SliceWriter};

/// Seconds in one standard calendar day (24 * 60 * 60).
pub const SECONDS_PER_DAY: i64 = 86_400;

/// Calendar month number for February.
const MONTH_FEBRUARY: u8 = 2;

/// Days in February of a leap year.
const FEBRUARY_LEAP_DAYS: u8 = 29;

/// Days in February of a common year.
const FEBRUARY_COMMON_DAYS: u8 = 28;

/// UTCTime field length: `yyMMddHHmmssZ` (RFC 5280 sec.4.1.2.5.1).
const UTC_TIME_LENGTH: usize = 13;

/// DER tag: UTCTime, for writers wrapping an encoded time.
pub const UTC_TIME_TAG: u8 = 0x17;

/// GeneralizedTime field length: `yyyyMMddHHmmssZ` (RFC 5280 sec.4.1.2.5.2).
pub const GENERALIZED_TIME_LENGTH: usize = 15;

/// DER tag: GeneralizedTime, for writers wrapping an encoded time.
pub const GENERALIZED_TIME_TAG: u8 = 0x18;

/// RFC 5280 sec.4.1.2.5 year cutoff at which GeneralizedTime replaces UTCTime.
pub const GENERALIZED_TIME_CUTOFF_YEAR: u16 = 2050;

/// A time that is not representable, or a clock this software refuses
/// to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeError;

impl core::fmt::Display for TimeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("malformed certificate time")
    }
}

impl core::error::Error for TimeError {}

/// Add `years` calendar years to post-epoch unix seconds, clamping
/// February 29 to February 28 when the target year is not a leap year.
///
/// Backed by [`DateTime`], so inputs before the Unix epoch or targets
/// outside `1970..=9999` return [`TimeError`].
pub fn add_years(unix: i64, years: i32) -> Result<i64, TimeError> {
    let seconds = u64::try_from(unix).map_err(|_| TimeError)?;
    let dt = DateTime::from_unix_duration(Duration::from_secs(seconds)).map_err(|_| TimeError)?;
    let target_year = i32::from(dt.year())
        .checked_add(years)
        .and_then(|year| u16::try_from(year).ok())
        .ok_or(TimeError)?;
    let target = match DateTime::new(
        target_year,
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minutes(),
        dt.seconds(),
    ) {
        Ok(target) => target,
        Err(_) if dt.month() == MONTH_FEBRUARY && dt.day() == FEBRUARY_LEAP_DAYS => DateTime::new(
            target_year,
            dt.month(),
            FEBRUARY_COMMON_DAYS,
            dt.hour(),
            dt.minutes(),
            dt.seconds(),
        )
        .map_err(|_| TimeError)?,
        Err(_) => return Err(TimeError),
    };
    i64::try_from(target.unix_duration().as_secs()).map_err(|_| TimeError)
}

/// The system clock as unix seconds; clocks before the epoch are
/// refused.
pub fn system_unix(now: SystemTime) -> Result<i64, TimeError> {
    let seconds = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TimeError)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| TimeError)
}

/// The system clock truncated to whole UTC seconds as a [`DateTime`];
/// clocks before the epoch or past year 9999 are refused.
pub fn system_date_time(now: SystemTime) -> Result<DateTime, TimeError> {
    let seconds = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TimeError)?
        .as_secs();
    DateTime::from_unix_duration(Duration::from_secs(seconds)).map_err(|_| TimeError)
}

/// Format post-epoch unix seconds as UTCTime (`yyMMddHHmmssZ`), whole
/// seconds, Zulu.
///
/// RFC 5280 sec.4.1.2.5.1 defines UTCTime across `1950..=2049`; because
/// [`UtcTime`] is anchored at the Unix epoch, this formatter accepts
/// `1970-01-01T00:00:00Z` through `2049-12-31T23:59:59Z`.
pub fn format_utc_time(unix: i64) -> Result<[u8; UTC_TIME_LENGTH], TimeError> {
    let seconds = u64::try_from(unix).map_err(|_| TimeError)?;
    let utc = UtcTime::from_unix_duration(Duration::from_secs(seconds)).map_err(|_| TimeError)?;
    let mut out = [0_u8; UTC_TIME_LENGTH];
    let mut writer = SliceWriter::new(&mut out);
    utc.encode_value(&mut writer).map_err(|_| TimeError)?;
    if writer.finish().map_err(|_| TimeError)?.len() != UTC_TIME_LENGTH {
        return Err(TimeError);
    }
    Ok(out)
}

/// Add `days` calendar days to post-epoch unix seconds.
pub fn add_days(unix: i64, days: i64) -> Result<i64, TimeError> {
    if unix < 0 {
        return Err(TimeError);
    }
    let day_seconds = days.checked_mul(SECONDS_PER_DAY).ok_or(TimeError)?;
    let target = unix.checked_add(day_seconds).ok_or(TimeError)?;
    if target < 0 {
        return Err(TimeError);
    }
    Ok(target)
}

/// Subtract `seconds` from post-epoch unix seconds, ensuring non-negative result.
pub fn sub_seconds(unix: i64, seconds: i64) -> Result<i64, TimeError> {
    if unix < 0 {
        return Err(TimeError);
    }
    let target = unix.checked_sub(seconds).ok_or(TimeError)?;
    if target < 0 {
        return Err(TimeError);
    }
    Ok(target)
}

/// Format post-epoch unix seconds per RFC 5280 sec.4.1.2.5:
/// UTCTime through the cutoff year, GeneralizedTime thereafter.
pub fn format_rfc5280_time(unix: i64) -> Result<(u8, Vec<u8>), TimeError> {
    let seconds = u64::try_from(unix).map_err(|_| TimeError)?;
    let dt = DateTime::from_unix_duration(Duration::from_secs(seconds)).map_err(|_| TimeError)?;
    if dt.year() >= GENERALIZED_TIME_CUTOFF_YEAR {
        let gt = GeneralizedTime::from_unix_duration(Duration::from_secs(seconds))
            .map_err(|_| TimeError)?;
        let mut out = [0_u8; GENERALIZED_TIME_LENGTH];
        let mut writer = SliceWriter::new(&mut out);
        gt.encode_value(&mut writer).map_err(|_| TimeError)?;
        if writer.finish().map_err(|_| TimeError)?.len() != GENERALIZED_TIME_LENGTH {
            return Err(TimeError);
        }
        Ok((GENERALIZED_TIME_TAG, out.to_vec()))
    } else {
        let utc = format_utc_time(unix)?;
        Ok((UTC_TIME_TAG, utc.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        UTC_TIME_TAG, add_days, add_years, format_utc_time, sub_seconds, system_date_time,
        system_unix,
    };
    use spki::der::Decode as _;
    use spki::der::asn1::UtcTime;
    use std::time::{Duration, UNIX_EPOCH};

    /// One day, in seconds.
    const DAY_SECONDS: u64 = 86_400;

    /// Non-zero subsecond nanoseconds present on real system clocks.
    const SUBSECOND_NANOS: u32 = 500_000_000;

    /// Unix seconds of 2023-11-14T22:13:20Z.
    const SOME_TUESDAY: i64 = 1_700_000_000;

    /// Unix seconds of 2024-02-28T12:34:56Z (common-year reverse offset).
    const FEB_28_2024: i64 = 1_709_123_696;

    /// Unix seconds of 2024-02-29T12:34:56Z (a leap day).
    const LEAP_DAY_2024: i64 = 1_709_210_096;

    /// Unix seconds of 2025-02-28T12:34:56Z (clamped common-year target).
    const CLAMPED_2025: i64 = 1_740_746_096;

    /// Unix seconds of 2028-02-29T12:34:56Z (preserved leap-year target).
    const LEAP_DAY_2028: i64 = 1_835_440_496;

    /// Unix seconds of 2026-01-01T00:00:00Z.
    const NEW_YEAR_2026: i64 = 1_767_225_600;

    /// Unix seconds of 2049-12-31T23:59:59Z, the last RFC 5280 UTCTime second.
    const LAST_UTC_TIME_SECOND: i64 = 2_524_607_999;

    /// Unix seconds of 2050-01-01T00:00:00Z, the first GeneralizedTime-only second.
    const FIRST_POST_UTC_TIME_SECOND: i64 = 2_524_608_000;

    /// Unix seconds of 1900-01-01T00:00:00Z, below the representable window.
    const BEFORE_WINDOW: i64 = -2_208_988_800;

    /// Days after the epoch whose date line is asserted.
    const TWENTY_THOUSAND_DAYS: u64 = 20_000;

    /// Single-year offset for common-year clamping tests.
    const ONE_YEAR: i32 = 1;

    /// Four-year offset across one leap cycle.
    const FOUR_YEARS: i32 = 4;

    /// Formatting round-trips through `spki::der::asn1::UtcTime` across
    /// the RFC 5280 UTCTime window and rejects out-of-range timestamps.
    #[test]
    fn format_round_trips_and_enforces_bounds() {
        for unix in [0_i64, SOME_TUESDAY, NEW_YEAR_2026, LAST_UTC_TIME_SECOND] {
            let text = format_utc_time(unix).expect("formats");
            let tlv = crate::der::tagged(UTC_TIME_TAG, &text).expect("wraps TLV");
            let decoded = UtcTime::from_der(&tlv).expect("decodes as DER UtcTime");
            assert_eq!(
                i64::try_from(decoded.to_unix_duration().as_secs()).expect("fits i64"),
                unix
            );
        }
        assert_eq!(&format_utc_time(0).expect("epoch"), b"700101000000Z");
        assert_eq!(
            &format_utc_time(LAST_UTC_TIME_SECOND).expect("2049 ceiling"),
            b"491231235959Z"
        );
        assert!(format_utc_time(-1).is_err());
        assert!(format_utc_time(BEFORE_WINDOW).is_err());
        assert!(format_utc_time(FIRST_POST_UTC_TIME_SECOND).is_err());
    }

    /// The day count matches the system clock's date line.
    #[test]
    fn days_match_the_calendar() {
        let unix = UNIX_EPOCH + Duration::new(DAY_SECONDS * TWENTY_THOUSAND_DAYS, SUBSECOND_NANOS);
        let seconds = system_unix(unix).expect("after epoch");
        let dt = system_date_time(unix).expect("truncates subseconds");
        assert_eq!(
            i64::try_from(dt.unix_duration().as_secs()).expect("fits i64"),
            seconds
        );
        let text = format_utc_time(seconds).expect("formats");
        assert_eq!(&text, b"241004000000Z");
        assert!(system_unix(UNIX_EPOCH - Duration::from_secs(1)).is_err());
        assert!(system_date_time(UNIX_EPOCH - Duration::from_secs(1)).is_err());
    }

    /// Expected unix timestamp after adding thirty days to SOME_TUESDAY.
    const THIRTY_DAYS_COUNT: i64 = 30;
    const SOME_TUESDAY_PLUS_THIRTY_DAYS: i64 =
        SOME_TUESDAY + (DAY_SECONDS as i64) * THIRTY_DAYS_COUNT;

    /// Sixty seconds subtracted for clock skew test.
    const CLOCK_SKEW_SECONDS: i64 = 60;
    const SOME_TUESDAY_MINUS_CLOCK_SKEW: i64 = SOME_TUESDAY - CLOCK_SKEW_SECONDS;

    /// Adding calendar years clamps February 29 on common target years,
    /// keeps February 29 on leap target years, and rejects overflows.
    #[test]
    fn add_years_handles_leap_days_and_bounds() {
        assert_eq!(add_years(LEAP_DAY_2024, ONE_YEAR), Ok(CLAMPED_2025));
        assert_eq!(add_years(LEAP_DAY_2024, FOUR_YEARS), Ok(LEAP_DAY_2028));
        assert_eq!(add_years(CLAMPED_2025, -ONE_YEAR), Ok(FEB_28_2024));
        assert!(add_years(0, -ONE_YEAR).is_err());
        assert!(add_years(-1, ONE_YEAR).is_err());
        assert!(add_years(SOME_TUESDAY, i32::MAX).is_err());
    }

    /// Adding days advances unix seconds by exact 86,400-second days.
    #[test]
    fn add_days_advances_seconds() {
        assert_eq!(
            add_days(SOME_TUESDAY, THIRTY_DAYS_COUNT),
            Ok(SOME_TUESDAY_PLUS_THIRTY_DAYS)
        );
        assert!(add_days(-1, THIRTY_DAYS_COUNT).is_err());
        assert!(add_days(SOME_TUESDAY, i64::MAX).is_err());
    }

    /// Subtracting seconds pulls unix timestamp back and checks underflow.
    #[test]
    fn sub_seconds_reduces_timestamp() {
        assert_eq!(
            sub_seconds(SOME_TUESDAY, CLOCK_SKEW_SECONDS),
            Ok(SOME_TUESDAY_MINUS_CLOCK_SKEW)
        );
        assert!(sub_seconds(0, CLOCK_SKEW_SECONDS).is_err());
    }

    /// RFC 5280 formatting switches from UTCTime to GeneralizedTime at year 2050.
    #[test]
    fn format_rfc5280_selects_tag_and_encodes() {
        let (utc_tag, utc_bytes) =
            super::format_rfc5280_time(SOME_TUESDAY).expect("formats UTCTime");
        assert_eq!(utc_tag, super::UTC_TIME_TAG);
        assert_eq!(
            utc_bytes.as_slice(),
            &format_utc_time(SOME_TUESDAY).expect("formats")
        );

        let (gt_tag, gt_bytes) = super::format_rfc5280_time(FIRST_POST_UTC_TIME_SECOND)
            .expect("formats GeneralizedTime");
        assert_eq!(gt_tag, super::GENERALIZED_TIME_TAG);
        assert_eq!(gt_bytes.as_slice(), b"20500101000000Z");

        assert!(super::format_rfc5280_time(-1).is_err());
    }
}
