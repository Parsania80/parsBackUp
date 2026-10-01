//! The one timestamp form a published artifact records: a fixed-precision UTC string,
//! `YYYY-MM-DDTHH:MM:SSZ`.
//!
//! A manifest is signed bytes, so a timestamp in it is a claim about when the dump ran
//! that a future reader has to be able to check without a calendar library and without
//! accepting an ambiguous offset. Fixing the form to second precision and a literal `Z`
//! is what makes the field comparable (`completed_at_utc >= started_at_utc` is a string
//! comparison) and the writer and the reader agree by construction rather than by care.

use crate::protocol::UTC_TIMESTAMP_CHARS;
use anyhow::{Result, bail};

/// Formats epoch milliseconds as the artifact timestamp form, truncating to whole
/// seconds. A negative epoch is refused rather than clamped: no configured clock produces
/// one, and silently mapping it to 1970 would write a plausible-looking lie.
pub fn format_utc(unix_ms: i128) -> Result<String> {
    if unix_ms < 0 {
        bail!("artifact timestamps cannot represent a time before the Unix epoch");
    }
    let seconds = (unix_ms / 1000) as i64;
    let days = seconds.div_euclid(86_400);
    let time = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        time / 3600,
        (time % 3600) / 60,
        time % 60
    ))
}

/// Whether `text` is exactly that form and a real calendar instant.
///
/// The check is total rather than a prefix match because the field is read from a file
/// an attacker may have edited: a manifest saying `2026-02-30T00:00:00Z` is corrupt, not
/// interpretable. A second is refused above 59 — RFC 3339 permits a leap second, but this
/// writer never emits one, so accepting it would mean tolerating a value that cannot
/// round-trip.
pub fn is_utc_timestamp(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != UTC_TIMESTAMP_CHARS {
        return false;
    }
    let digits = |range: std::ops::Range<usize>| -> Option<u32> {
        bytes.get(range)?.iter().try_fold(0u32, |value, byte| {
            // `checked_sub` rather than a subtraction: this parses a field a hostile file
            // can fill with any byte, and a non-digit must be a refusal, not a panic.
            let digit = byte.checked_sub(b'0')?;
            if digit < 10 {
                Some(value * 10 + u32::from(digit))
            } else {
                None
            }
        })
    };
    let (Some(year), Some(month), Some(day)) = (digits(0..4), digits(5..7), digits(8..10)) else {
        return false;
    };
    let (Some(hour), Some(minute), Some(second)) = (digits(11..13), digits(14..16), digits(17..19))
    else {
        return false;
    };
    if bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' || bytes[19] != b'Z' {
        return false;
    }
    if hour > 23 || minute > 59 || second > 59 {
        return false;
    }
    (1..=12).contains(&month) && day >= 1 && day <= days_in_month(year as i64, month)
}

fn is_leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
    }
}

/// civil-from-days: converts a day number relative to 1970-01-01 into a proleptic
/// Gregorian date. The 400-year era arithmetic is what makes negative days (BCE-era
/// numbers) come out right without a lookup table.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_shifted = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_shifted + 2) / 5 + 1) as u32;
    let month = if month_shifted < 10 {
        month_shifted + 3
    } else {
        month_shifted - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The epochs are the boundaries a writer hits in practice: the epoch itself, a
    /// leap day, the century and quad-century leap rules, and a millisecond value that
    /// must truncate rather than round.
    #[test]
    fn formatting_matches_the_gregorian_calendar() {
        assert_eq!(format_utc(0).unwrap(), "1970-01-01T00:00:00Z");
        assert_eq!(
            format_utc(1_759_000_000_000).unwrap(),
            "2025-09-27T19:06:40Z"
        );
        assert_eq!(format_utc(951_782_400_000).unwrap(), "2000-02-29T00:00:00Z");
        assert_eq!(
            format_utc(1_167_609_600_000).unwrap(),
            "2007-01-01T00:00:00Z"
        );
        assert_eq!(
            format_utc(1_009_756_800_000).unwrap(),
            "2001-12-31T00:00:00Z"
        );
        assert_eq!(format_utc(1_000).unwrap(), "1970-01-01T00:00:01Z");
        assert_eq!(format_utc(1_999).unwrap(), "1970-01-01T00:00:01Z");
        assert_eq!(
            format_utc(2_147_483_647_000).unwrap(),
            "2038-01-19T03:14:07Z"
        );
        assert_eq!(
            format_utc(4_102_444_800_000).unwrap(),
            "2100-01-01T00:00:00Z"
        );
        assert!(format_utc(-1).is_err());
    }

    #[test]
    fn formatted_instants_are_accepted_by_the_reader() {
        for unix_ms in [
            0,
            1_000,
            951_782_400_000,
            1_759_000_000_000,
            4_102_444_800_000,
        ] {
            let text = format_utc(unix_ms).unwrap();
            assert!(is_utc_timestamp(&text), "{text}");
        }
    }

    #[test]
    fn impossible_and_misshapen_timestamps_are_refused() {
        for text in [
            "2026-02-30T00:00:00Z",
            "2025-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-01-32T00:00:00Z",
            "2026-01-01T24:00:00Z",
            "2026-01-01T12:60:00Z",
            "2026-01-01T12:00:60Z",
            "2026-01-01 12:00:00Z",
            "2026-01-01T12:00:00",
            "2026-01-01T12:00:00+00:00",
            "2026-01-01T12:00:00.000Z",
            "20260-01-01T12:00:0Z",
            "2026-0a-01T12:00:00Z",
            "",
        ] {
            assert!(!is_utc_timestamp(text), "accepted {text}");
        }
        // 2000 is a leap year; 2100 is not.
        assert!(is_utc_timestamp("2000-02-29T00:00:00Z"));
        assert!(!is_utc_timestamp("2100-02-29T00:00:00Z"));
    }
}
