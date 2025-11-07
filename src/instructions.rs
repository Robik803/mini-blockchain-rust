use crate::transactions::SignedTransaction;

pub enum Instruction {
    Transfer(SignedTransaction)
}