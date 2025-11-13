use crate::transactions::SignedTransaction;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub enum Instruction {
    Transfer(SignedTransaction),
}
