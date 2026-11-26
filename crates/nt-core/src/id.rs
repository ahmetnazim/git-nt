use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::CoreError;

#[derive(Debug, Default)]
struct UuidV7State {
    last_ms: u64,
    seq: u16,
}

static UUID_V7_STATE: Mutex<UuidV7State> = Mutex::new(UuidV7State { last_ms: 0, seq: 0 });

/// Generates a lowercase hyphenated RFC 9562 UUIDv7 identifier that is
/// lexicographically time-sortable and strictly monotonic within a process.
pub fn generate_uuid_v7() -> Result<String, CoreError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CoreError::ClockError)?;
    let now_ms = u64::try_from(duration.as_millis()).map_err(|_| CoreError::ClockError)?;
    if now_ms > 0x0000_FFFF_FFFF_FFFF {
        return Err(CoreError::ClockError);
    }

    let mut rand_bytes = [0u8; 10];
    getrandom::fill(&mut rand_bytes).map_err(|err| CoreError::Randomness(err.to_string()))?;

    let (ts_ms, seq) = {
        let mut state = UUID_V7_STATE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if now_ms > state.last_ms {
            state.last_ms = now_ms;
            state.seq = u16::from_be_bytes([rand_bytes[0], rand_bytes[1]]) & 0x0FFF;
        } else if state.seq < 0x0FFF {
            state.seq += 1;
        } else {
            let next_ms = state.last_ms.checked_add(1).ok_or(CoreError::ClockError)?;
            if next_ms > 0x0000_FFFF_FFFF_FFFF {
                return Err(CoreError::ClockError);
            }
            state.last_ms = next_ms;
            state.seq = 0;
        }
        (state.last_ms, state.seq)
    };

    let mut bytes = [0u8; 16];
    let ts_be = ts_ms.to_be_bytes();
    bytes[0..6].copy_from_slice(&ts_be[2..8]);
    // Version 7 (0111) + upper 4 bits of 12-bit monotonic rand_a.
    bytes[6] = 0x70 | (((seq >> 8) as u8) & 0x0F);
    // Lower 8 bits of rand_a.
    bytes[7] = (seq & 0xFF) as u8;
    // RFC 9562 variant (10xx) + 62 bits of CSPRNG rand_b.
    bytes[8] = 0x80 | (rand_bytes[2] & 0x3F);
    bytes[9..16].copy_from_slice(&rand_bytes[3..10]);

    Ok(format_uuid_bytes(&bytes))
}

fn format_uuid_bytes(bytes: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(36);
    for (idx, &b) in bytes.iter().enumerate() {
        if matches!(idx, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

/// Returns `true` if `s` is a canonical lowercase hyphenated UUID (`8-4-4-4-12`).
pub fn is_valid_uuid(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (idx, &b) in bytes.iter().enumerate() {
        if matches!(idx, 8 | 13 | 18 | 23) {
            if b != b'-' {
                return false;
            }
        } else if !matches!(b, b'0'..=b'9' | b'a'..=b'f') {
            return false;
        }
    }
    true
}

/// Returns `true` if `s` is a canonical lowercase hyphenated RFC 9562 UUIDv7.
pub fn is_valid_uuid_v7(s: &str) -> bool {
    if !is_valid_uuid(s) {
        return false;
    }
    let bytes = s.as_bytes();
    bytes[14] == b'7' && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
}

/// Formats `time` as an RFC 3339 UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`) using pure `std`.
pub fn format_rfc3339_utc(time: SystemTime) -> Result<String, CoreError> {
    let secs = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CoreError::ClockError)?
        .as_secs();

    let days = i64::try_from(secs / 86_400).map_err(|_| CoreError::ClockError)?;
    let rem = secs % 86_400;
    let hour = rem / 3_600;
    let minute = (rem % 3_600) / 60;
    let second = rem % 60;

    let (year, month, day) = civil_from_days(days);
    if !(0..=9999).contains(&year) {
        return Err(CoreError::ClockError);
    }

    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

/// Returns the current UTC time formatted as RFC 3339 (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn now_rfc3339_utc() -> Result<String, CoreError> {
    format_rfc3339_utc(SystemTime::now())
}

/// Validates a strict RFC 3339 UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn is_valid_rfc3339_utc(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 20 {
        return false;
    }
    if b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return false;
    }
    let Some(year) = parse_ascii_digits(&b[0..4]) else {
        return false;
    };
    let Some(month) = parse_ascii_digits(&b[5..7]) else {
        return false;
    };
    let Some(day) = parse_ascii_digits(&b[8..10]) else {
        return false;
    };
    let Some(hour) = parse_ascii_digits(&b[11..13]) else {
        return false;
    };
    let Some(minute) = parse_ascii_digits(&b[14..16]) else {
        return false;
    };
    let Some(second) = parse_ascii_digits(&b[17..19]) else {
        return false;
    };

    if !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return false;
    }
    let max_day = days_in_month(year, month);
    (1..=max_day).contains(&day)
}

fn parse_ascii_digits(bytes: &[u8]) -> Option<u32> {
    let mut val: u32 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        val = val.checked_mul(10)?.checked_add(u32::from(b - b'0'))?;
    }
    Some(val)
}

/// Howard Hinnant's civil-from-days conversion (days since 1970-01-01).
fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
    let year = y + i64::from(m <= 2);
    (year, m, d)
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}
