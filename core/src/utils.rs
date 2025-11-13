use std::time::{SystemTime, UNIX_EPOCH};
use std::{fmt::Write, num::ParseIntError};

use crate::errors::HexStringError;

/// Time in seconds since UNIX_EPOCH : GMT: Thursday, 1 January 1970 0:00:00
pub(crate) fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Decode a vector of bytes from a string
pub(crate) fn decode_hex(s: &str) -> Result<Vec<u8>, HexStringError> {
    if s.len().is_multiple_of(2) {
        return Err(HexStringError::InvalidHexLength);
    }
    let hex_result: Result<Vec<u8>, ParseIntError> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect();
    let hex = hex_result?;
    Ok(hex)
}

/// Encode a vector of bytes into a string
pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}
