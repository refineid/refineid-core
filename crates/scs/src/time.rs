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

//! Certificate times: UTCTime encoding and Time parsing against unix
//! seconds.
//!
//! The civil-date conversions are Howard Hinnant's public-domain
//! `days_from_civil` / `civil_from_days` algorithms, with every
//! constant named.

use std::time::{SystemTime, UNIX_EPOCH};

/// Days in a 400-year era.
const ERA_DAYS: i64 = 146_097;

/// Days from 0000-03-01 to 1970-01-01.
const DAYS_TO_UNIX_EPOCH: i64 = 719_468;

/// Years in an era.
const YEARS_PER_ERA: i64 = 400;

/// Days in a 5-month span of the March-based year.
const MONTHS_TO_DAYS_NUMERATOR: i64 = 153;

/// Denominator of the month-to-day span.
const MONTHS_TO_DAYS_DENOMINATOR: i64 = 5;

/// Days in a common year.
const DAYS_PER_YEAR: i64 = 365;

/// Months in a year.
const MONTHS_PER_YEAR: i64 = 12;

/// March-based month offset for January and February.
const JANUARY_FEBRUARY_OFFSET: i64 = 9;

/// March-based month offset past February.
const MARCH_ONWARDS_OFFSET: i64 = -3;

/// Day-of-year to month numerator.
const DAY_TO_MONTH_NUMERATOR: i64 = 5;

/// Day-of-year to month denominator.
const DAY_TO_MONTH_DENOMINATOR: i64 = 153;

/// Rounding term of the day-of-year to month division.
const DAY_TO_MONTH_ROUNDING: i64 = 2;

/// Month threshold below which three months are added back.
const MARCH_BASED_OCTOBER: i64 = 10;

/// Months added back below October in the March-based year.
const MONTHS_ADD_BACK: i64 = 3;

/// Months subtracted past September in the March-based year.
const MONTHS_SUBTRACT: i64 = -9;

/// Leap-cycle divisor of the year-of-era inversion.
const YEAR_OF_ERA_LEAP_DIVISOR: i64 = 1460;

/// Century divisor of the year-of-era inversion.
const YEAR_OF_ERA_CENTURY_DIVISOR: i64 = 36_524;

/// Era divisor of the year-of-era inversion.
const YEAR_OF_ERA_ERA_DIVISOR: i64 = 146_096;

/// Years in a leap cycle.
const LEAP_CYCLE_YEARS: i64 = 4;

/// Years in a century.
const CENTURY_YEARS: i64 = 100;

/// Years in a leap century.
const LEAP_CENTURY_YEARS: i64 = 400;

/// Days in February of a leap year.
const FEBRUARY_LEAP_DAYS: i64 = 29;

/// Days in February of a common year.
const FEBRUARY_DAYS: i64 = 28;

/// Days in a long month.
const LONG_MONTH_DAYS: i64 = 31;

/// Days in a short month.
const SHORT_MONTH_DAYS: i64 = 30;

/// January.
const MONTH_JANUARY: i64 = 1;

/// February.
const MONTH_FEBRUARY: i64 = 2;

/// March.
const MONTH_MARCH: i64 = 3;

/// April.
const MONTH_APRIL: i64 = 4;

/// May.
const MONTH_MAY: i64 = 5;

/// June.
const MONTH_JUNE: i64 = 6;

/// July.
const MONTH_JULY: i64 = 7;

/// August.
const MONTH_AUGUST: i64 = 8;

/// September.
const MONTH_SEPTEMBER: i64 = 9;

/// October.
const MONTH_OCTOBER: i64 = 10;

/// November.
const MONTH_NOVEMBER: i64 = 11;

/// December.
const MONTH_DECEMBER: i64 = 12;

/// Seconds in a minute.
const SECONDS_PER_MINUTE: i64 = 60;

/// Minutes in an hour.
const MINUTES_PER_HOUR: i64 = 60;

/// Hours in a day.
const HOURS_PER_DAY: i64 = 24;

/// Seconds in a day.
const SECONDS_PER_DAY: i64 = 86_400;

/// Decimal radix for time fields.
const DECIMAL_RADIX: u32 = 10;

/// Decimal digit base for time fields.
const DECIMAL_DIGIT_BASE: u8 = 10;

/// Digits in one time field.
const FIELD_WIDTH: usize = 2;

/// Digits in a GeneralizedTime year.
const GENERALIZED_YEAR_WIDTH: usize = 4;

/// UTCTime field length: `yyMMddHHmmssZ`.
const UTC_TIME_LENGTH: usize = 13;

/// GeneralizedTime field length: `yyyyMMddHHmmssZ`.
const GENERALIZED_TIME_LENGTH: usize = 15;

/// UTCTime years at or above this are 19xx, below it 20xx (RFC 5280
/// sec.4.1.2.5.1).
const UTC_TIME_CENTURY_SPLIT: i64 = 50;

/// Century base for UTCTime years at or above the split.
const CENTURY_1900: i64 = 1900;

/// Century base for UTCTime years below the split.
const CENTURY_2000: i64 = 2000;

/// DER tag: UTCTime.
const TAG_UTC_TIME: u16 = 0x17;

/// DER tag: GeneralizedTime.
const TAG_GENERALIZED_TIME: u16 = 0x18;

/// The Zulu suffix.
const ZULU: u8 = b'Z';

/// A time that is not well-formed, or a clock this software refuses
/// to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeError;

impl core::fmt::Display for TimeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("malformed certificate time")
    }
}

impl core::error::Error for TimeError {}

/// Days from 1970-01-01 to the civil date, proleptic Gregorian.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let adjusted_year = if month <= MONTH_FEBRUARY {
        year - 1
    } else {
        year
    };
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - (YEARS_PER_ERA - 1)
    } / YEARS_PER_ERA;
    let year_of_era = adjusted_year - era * YEARS_PER_ERA;
    let month_offset = if month > MONTH_FEBRUARY {
        MARCH_ONWARDS_OFFSET
    } else {
        JANUARY_FEBRUARY_OFFSET
    };
    let day_of_year = (MONTHS_TO_DAYS_NUMERATOR * (month + month_offset) + DAY_TO_MONTH_ROUNDING)
        / MONTHS_TO_DAYS_DENOMINATOR
        + day
        - 1;
    let day_of_era = year_of_era * DAYS_PER_YEAR + year_of_era / LEAP_CYCLE_YEARS
        - year_of_era / CENTURY_YEARS
        + day_of_year;
    era * ERA_DAYS + day_of_era - DAYS_TO_UNIX_EPOCH
}

/// The civil date `days` after 1970-01-01, proleptic Gregorian, as
/// year, month, day.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + DAYS_TO_UNIX_EPOCH;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - (ERA_DAYS - 1)
    } / ERA_DAYS;
    let day_of_era = shifted - era * ERA_DAYS;
    let year_of_era = (day_of_era - day_of_era / YEAR_OF_ERA_LEAP_DIVISOR
        + day_of_era / YEAR_OF_ERA_CENTURY_DIVISOR
        - day_of_era / YEAR_OF_ERA_ERA_DIVISOR)
        / DAYS_PER_YEAR;
    let year = year_of_era + era * YEARS_PER_ERA;
    let day_of_year = day_of_era
        - (DAYS_PER_YEAR * year_of_era + year_of_era / LEAP_CYCLE_YEARS
            - year_of_era / CENTURY_YEARS);
    let month_prime =
        (DAY_TO_MONTH_NUMERATOR * day_of_year + DAY_TO_MONTH_ROUNDING) / DAY_TO_MONTH_DENOMINATOR;
    let day = day_of_year
        - (MONTHS_TO_DAYS_NUMERATOR * month_prime + DAY_TO_MONTH_ROUNDING)
            / MONTHS_TO_DAYS_DENOMINATOR
        + 1;
    let month = month_prime
        + if month_prime < MARCH_BASED_OCTOBER {
            MONTHS_ADD_BACK
        } else {
            MONTHS_SUBTRACT
        };
    (
        if month <= MONTH_FEBRUARY {
            year + 1
        } else {
            year
        },
        month,
        day,
    )
}

/// Unix seconds of the UTC clock reading.
fn unix_seconds(year: i64, month: i64, day: i64, hour: i64, minute: i64, second: i64) -> i64 {
    days_from_civil(year, month, day) * SECONDS_PER_DAY
        + hour * MINUTES_PER_HOUR * SECONDS_PER_MINUTE
        + minute * SECONDS_PER_MINUTE
        + second
}

/// Whether the civil date exists on the proleptic Gregorian calendar.
fn valid_date(year: i64, month: i64, day: i64) -> bool {
    if !(MONTH_JANUARY..=MONTHS_PER_YEAR).contains(&month) || day < MONTH_JANUARY {
        return false;
    }
    let leap = year % LEAP_CYCLE_YEARS == 0
        && (year % CENTURY_YEARS != 0 || year % LEAP_CENTURY_YEARS == 0);
    let february_days = if leap {
        FEBRUARY_LEAP_DAYS
    } else {
        FEBRUARY_DAYS
    };
    let month_days = match month {
        MONTH_JANUARY | MONTH_MARCH | MONTH_MAY | MONTH_JULY | MONTH_AUGUST | MONTH_OCTOBER
        | MONTH_DECEMBER => LONG_MONTH_DAYS,
        MONTH_APRIL | MONTH_JUNE | MONTH_SEPTEMBER | MONTH_NOVEMBER => SHORT_MONTH_DAYS,
        _ => february_days,
    };
    day <= month_days
}

/// Whether the clock reading is a whole-seconds UTC time.
fn valid_clock(hour: i64, minute: i64, second: i64) -> bool {
    (0..HOURS_PER_DAY).contains(&hour)
        && (0..MINUTES_PER_HOUR).contains(&minute)
        && (0..SECONDS_PER_MINUTE).contains(&second)
}

/// Parse one ASCII digit pair.
fn two_digits(pair: &[u8]) -> Result<i64, TimeError> {
    if pair.len() != FIELD_WIDTH {
        return Err(TimeError);
    }
    let text = core::str::from_utf8(pair).map_err(|_| TimeError)?;
    i64::from_str_radix(text, DECIMAL_RADIX).map_err(|_| TimeError)
}

/// Split the digit body into field pairs.
fn field_pairs(body: &[u8]) -> Result<Vec<&[u8]>, TimeError> {
    if !body.len().is_multiple_of(FIELD_WIDTH) {
        return Err(TimeError);
    }
    Ok(body.chunks(FIELD_WIDTH).collect())
}

/// Parse a UTCTime value (`yyMMddHHmmssZ`) to unix seconds.
fn parse_utc_time(value: &[u8]) -> Result<i64, TimeError> {
    if value.len() != UTC_TIME_LENGTH || value[UTC_TIME_LENGTH - 1] != ZULU {
        return Err(TimeError);
    }
    let fields = field_pairs(&value[..UTC_TIME_LENGTH - 1])?;
    let [year_two, month, day, hour, minute, second] = fields.as_slice() else {
        return Err(TimeError);
    };
    let year_two = two_digits(year_two)?;
    let year = if year_two >= UTC_TIME_CENTURY_SPLIT {
        CENTURY_1900 + year_two
    } else {
        CENTURY_2000 + year_two
    };
    let month = two_digits(month)?;
    let day = two_digits(day)?;
    let hour = two_digits(hour)?;
    let minute = two_digits(minute)?;
    let second = two_digits(second)?;
    if !valid_date(year, month, day) || !valid_clock(hour, minute, second) {
        return Err(TimeError);
    }
    Ok(unix_seconds(year, month, day, hour, minute, second))
}

/// Parse a GeneralizedTime value (`yyyyMMddHHmmssZ`) to unix seconds.
fn parse_generalized_time(value: &[u8]) -> Result<i64, TimeError> {
    if value.len() != GENERALIZED_TIME_LENGTH || value[GENERALIZED_TIME_LENGTH - 1] != ZULU {
        return Err(TimeError);
    }
    let year_text =
        core::str::from_utf8(&value[..GENERALIZED_YEAR_WIDTH]).map_err(|_| TimeError)?;
    let year = i64::from_str_radix(year_text, DECIMAL_RADIX).map_err(|_| TimeError)?;
    let fields = field_pairs(&value[GENERALIZED_YEAR_WIDTH..GENERALIZED_TIME_LENGTH - 1])?;
    let [month, day, hour, minute, second] = fields.as_slice() else {
        return Err(TimeError);
    };
    let month = two_digits(month)?;
    let day = two_digits(day)?;
    let hour = two_digits(hour)?;
    let minute = two_digits(minute)?;
    let second = two_digits(second)?;
    if !valid_date(year, month, day) || !valid_clock(hour, minute, second) {
        return Err(TimeError);
    }
    Ok(unix_seconds(year, month, day, hour, minute, second))
}

/// DER tag: UTCTime, for writers wrapping an encoded time.
pub const UTC_TIME_TAG: u8 = 0x17;

/// Parse a DER Time value of `tag` to unix seconds.
pub fn parse_time(tag: u16, value: &[u8]) -> Result<i64, TimeError> {
    if tag == TAG_UTC_TIME {
        parse_utc_time(value)
    } else if tag == TAG_GENERALIZED_TIME {
        parse_generalized_time(value)
    } else {
        Err(TimeError)
    }
}

/// Add `years` calendar years to unix seconds, clamping February
/// 29 to February 28 when the target year is not a leap year.
pub fn add_years(unix: i64, years: i32) -> Result<i64, TimeError> {
    let days = unix.div_euclid(SECONDS_PER_DAY);
    let day_seconds = unix.rem_euclid(SECONDS_PER_DAY);
    let (year, month, mut day) = civil_from_days(days);
    let target = year + i64::from(years);
    if !valid_date(target, month, day) {
        if month == MONTH_FEBRUARY && day == FEBRUARY_LEAP_DAYS {
            day = FEBRUARY_DAYS;
        } else {
            return Err(TimeError);
        }
    }
    let hour = day_seconds / (MINUTES_PER_HOUR * SECONDS_PER_MINUTE);
    let minute = (day_seconds / SECONDS_PER_MINUTE) % MINUTES_PER_HOUR;
    let second = day_seconds % SECONDS_PER_MINUTE;
    Ok(unix_seconds(target, month, day, hour, minute, second))
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

/// Format unix seconds as UTCTime (`yyMMddHHmmssZ`), whole seconds,
/// Zulu.
///
/// Only years the UTCTime century rule round-trips are formatted.
pub fn format_utc_time(unix: i64) -> Result<[u8; UTC_TIME_LENGTH], TimeError> {
    let days = unix.div_euclid(SECONDS_PER_DAY);
    let day_seconds = unix.rem_euclid(SECONDS_PER_DAY);
    let (year, month, day) = civil_from_days(days);
    if !(CENTURY_1900 + UTC_TIME_CENTURY_SPLIT..CENTURY_2000 + UTC_TIME_CENTURY_SPLIT)
        .contains(&year)
    {
        return Err(TimeError);
    }
    let fields = [
        (year % CENTURY_YEARS) as u8,
        month as u8,
        day as u8,
        (day_seconds / (MINUTES_PER_HOUR * SECONDS_PER_MINUTE)) as u8,
        ((day_seconds / SECONDS_PER_MINUTE) % MINUTES_PER_HOUR) as u8,
        (day_seconds % SECONDS_PER_MINUTE) as u8,
    ];
    let mut out = [b'0'; UTC_TIME_LENGTH];
    let mut cursor = 0_usize;
    for value in fields {
        out[cursor] = b'0' + value / DECIMAL_DIGIT_BASE;
        out[cursor + 1] = b'0' + value % DECIMAL_DIGIT_BASE;
        cursor += FIELD_WIDTH;
    }
    out[UTC_TIME_LENGTH - 1] = ZULU;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{format_utc_time, parse_time};
    use std::time::{Duration, UNIX_EPOCH};

    /// DER tag: UTCTime.
    const TAG_UTC_TIME: u16 = 0x17;

    /// DER tag: GeneralizedTime.
    const TAG_GENERALIZED_TIME: u16 = 0x18;

    /// A tag that is never a Time.
    const TAG_INTEGER: u16 = 0x02;

    /// One day, in seconds.
    const DAY_SECONDS: u64 = 86_400;

    /// Unix seconds of 2023-11-14T22:13:20Z.
    const SOME_TUESDAY: i64 = 1_700_000_000;

    /// Unix seconds of 2026-01-01T00:00:00Z.
    const NEW_YEAR_2026: i64 = 1_767_225_600;

    /// Unix seconds of 1900-01-01T00:00:00Z, below the window.
    const BEFORE_WINDOW: i64 = -2_208_988_800;

    /// Unix seconds of 2060-01-01T00:00:00Z, past the window.
    const AFTER_WINDOW: i64 = 2_840_140_800;

    /// Days after the epoch whose date line is asserted.
    const TWENTY_THOUSAND_DAYS: u64 = 20_000;

    /// The epoch parses to zero, and a leap day round-trips.
    #[test]
    fn times_parse_to_unix() {
        assert_eq!(parse_time(TAG_UTC_TIME, b"700101000000Z"), Ok(0));
        assert_eq!(
            parse_time(TAG_GENERALIZED_TIME, b"20240229120000Z"),
            parse_time(TAG_UTC_TIME, b"240229120000Z")
        );
        // 2024-02-29 is a Thursday; the day before is not a leap day.
        assert!(parse_time(TAG_UTC_TIME, b"230229000000Z").is_err());
        assert!(parse_time(TAG_UTC_TIME, b"700101000000z").is_err());
        assert!(parse_time(TAG_INTEGER, b"700101000000Z").is_err());
    }

    /// Formatting inverts parsing across the representable range.
    #[test]
    fn format_inverts_parse() {
        for unix in [0_i64, SOME_TUESDAY, NEW_YEAR_2026] {
            let text = format_utc_time(unix).expect("formats");
            assert_eq!(parse_time(TAG_UTC_TIME, &text), Ok(unix));
        }
        assert!(format_utc_time(BEFORE_WINDOW).is_err());
        assert!(format_utc_time(AFTER_WINDOW).is_err());
    }

    /// The day count matches the system clock's date line.
    #[test]
    fn days_match_the_calendar() {
        let unix = UNIX_EPOCH + Duration::from_secs(DAY_SECONDS * TWENTY_THOUSAND_DAYS);
        let seconds = unix.duration_since(UNIX_EPOCH).expect("after").as_secs() as i64;
        let text = format_utc_time(seconds).expect("formats");
        assert_eq!(&text, b"241004000000Z");
    }
}
