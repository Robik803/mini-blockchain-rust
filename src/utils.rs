use std::time::{SystemTime, UNIX_EPOCH};

pub fn get_timestamp() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(e) => panic!("{} : time should go forward",e)        
    }
}