use std::time::{SystemTime, UNIX_EPOCH};
use std::{fmt::Write, num::ParseIntError};

/// Time in seconds since UNIX_EPOCH : GMT: Thursday, 1 January 1970 0:00:00
pub fn get_timestamp() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(e) => panic!("{} : time should go forward", e),
    }
}

/// Decode a vector of bytes from a string
pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

/// Encode a vector of bytes into a string
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}
