use serde::{Serialize, Deserialize};
use crate::transactions::SignedTransaction;

#[derive(Serialize, Deserialize)]
pub enum Instruction {
    Transfer(SignedTransaction),
}
