//! Small time helpers: SOPS metadata timestamps are RFC 3339, second
//! precision, UTC (`time.RFC3339` in Go).

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch.
fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Civil (year, month, day) from days since the Unix epoch.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn pad2(n: i64) -> String {
    if n < 10 {
        format!("0{n}")
    } else {
        n.to_string()
    }
}

/// Current UTC time as `YYYY-MM-DDTHH:MM:SSZ` (SOPS `time.RFC3339`).
pub fn rfc3339_now() -> String {
    let secs = unix_seconds();
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = civil_from_days(days);
    format!(
        "{:04}-{}-{}T{}:{}:{}Z",
        y,
        pad2(mo as i64),
        pad2(d as i64),
        pad2(h),
        pad2(m),
        pad2(s)
    )
}

/// Current UTC date as `YYYY-MM-DD` (for generated key headers).
pub fn date_utc_today() -> String {
    let days = unix_seconds().div_euclid(86_400);
    let (y, mo, d) = civil_from_days(days);
    format!("{:04}-{:02}-{:02}", y, mo, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_shape() {
        let s = rfc3339_now();
        assert_eq!(s.len(), 20, "{s}");
        assert!(s.ends_with('Z'));
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[10..11], "T");
    }
}
