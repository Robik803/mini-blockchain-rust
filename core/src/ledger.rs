use std::collections::HashMap;
use serde::{self, Serialize, Deserialize};
use std::{
    fs,
    path::Path,
};

use crate::accounts::Account;
use crate::errors::BlockchainError;
use crate::keys::{PublicKey, pubkey_to_hex};
use crate::transactions::{Message, SignedTransaction};
use crate::instructions::Instruction;
use crate::constants::CONTEXT;

/// Ledger containing the list of active accounts and the history of transactions
#[derive(Serialize, Deserialize)]
pub struct Ledger {
    accounts: HashMap<String, Account>,
    history: Vec<SignedTransaction>,
}

impl Ledger {
    pub fn accounts(&self) -> &HashMap<String, Account> {
        &self.accounts
    }

    pub fn history(&self) -> &Vec<SignedTransaction> {
        &self.history
    }

    pub fn new(new_accounts: Vec<Account>) -> Result<Self, BlockchainError>{
        let mut accounts = HashMap::new();
        for account in &new_accounts{
            let account_pubkey_hex = pubkey_to_hex(&account.public_key());
            if accounts.contains_key(&account_pubkey_hex){
                return Err(BlockchainError::LedgerCreationError);
            }
            accounts.insert(account_pubkey_hex, account.clone());
        }
        Ok(Ledger{
            accounts,
            history: Vec::new(),
        })
    }

    fn check_nonce(&self, sender_pubkey: &PublicKey, nonce: u64) -> bool {
        let pubkey_hex = pubkey_to_hex(sender_pubkey);
        self.accounts[&pubkey_hex].nonce() + 1 == nonce
    }

    pub(crate) fn reward_validator(&mut self, public_key: &PublicKey, amount: u64) -> Result<(), BlockchainError>{
        let pubkey_hex = pubkey_to_hex(public_key);
        if !self.accounts.contains_key(&pubkey_hex) {
            return Err(BlockchainError::InvalidSenderAccount);
        }
        self.accounts.get_mut(&pubkey_hex).unwrap().deposit(amount)?;
        Ok(())
    }

    // Verifies if the transaction is valid and updates ledger
    pub(crate) fn process_transaction(
        &mut self,
        transaction: SignedTransaction,
    ) -> Result<(), BlockchainError> {
        let amount = transaction.amount();
        let sender_pubkey = *transaction.sender();
        let receiver_pubkey = *transaction.receiver();

        let sender_pubkey_hex = pubkey_to_hex(&sender_pubkey);
        let receiver_pubkey_hex = pubkey_to_hex(&receiver_pubkey);

        if !self.accounts.contains_key(&sender_pubkey_hex) {
            return Err(BlockchainError::InvalidSenderAccount);
        } else if !self.check_nonce(&sender_pubkey, transaction.nonce()) {
            return Err(BlockchainError::InvalidNonce);
        } else if amount == 0 {
            return Err(BlockchainError::InvalidNullAmount);
        } else if sender_pubkey == receiver_pubkey {
            return Err(BlockchainError::TransactionIntoSameAccount);
        }
        sender_pubkey.verify_prehashed(
            transaction.prehashed(),
            Some(CONTEXT),
            &transaction.signature(),
        )?;

        self.accounts.get_mut(&sender_pubkey_hex).unwrap().withdraw(amount)?;
        self.accounts.get_mut(&sender_pubkey_hex).unwrap().increment_nonce();

        self.accounts
            .entry(receiver_pubkey_hex)
            .or_insert(Account::with_balance(receiver_pubkey, 0))
            .deposit(amount)?;

        self.history.push(transaction);

        Ok(())
    }

    /// Executes instruction
    pub fn execute_instruction(&mut self, instruction: Instruction) -> Result<(), BlockchainError> {
        match instruction {
            Instruction::Transfer(transaction) => self.process_transaction(transaction),
        }
    }

    /// Save serialized ledger to file
    pub fn save_to_file(&self, path: &Path) -> Result<(), BlockchainError> {
        let serialized = serde_json::to_string_pretty(self)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serialized)?;
        Ok(())
    }

    /// Load serialized ledger to file
    pub fn load_from_file(path: &Path) -> Result<Self, BlockchainError> {
        let data = fs::read_to_string(path)?;
        let deserialized = serde_json::from_str(&data)?;
        Ok(deserialized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use std::path::Path;
    
    use crate::keys::KeyPair;
    use crate::transactions::UnsignedTransaction;

    #[test]
    fn test_ledger_transaction_process(){
        let alice_keypair: KeyPair = KeyPair::generate(&mut OsRng);
        let mut alice = Account::from_private_key(alice_keypair.as_bytes());
        let bob_keypair: KeyPair = KeyPair::generate(&mut OsRng);
        let bob = Account::from_private_key(bob_keypair.as_bytes());

        let alice_pubkey_hex = pubkey_to_hex(&alice.public_key());
        let bob_pubkey_hex = pubkey_to_hex(&bob.public_key());

        let _ = alice.deposit(300);
        let accounts = vec![alice.clone()];

        let mut ledger = Ledger::new(accounts).unwrap();

        let unsigned_tx = UnsignedTransaction::new(&alice.public_key(), &bob.public_key(), 50, 1).unwrap();
        let signature = alice_keypair
            .sign_prehashed(unsigned_tx.prehashed(), Some(CONTEXT))
            .unwrap();
        let signed_tx = SignedTransaction::new(unsigned_tx, signature).unwrap();

        ledger.process_transaction(signed_tx).unwrap();

        assert!(ledger.accounts.contains_key(&alice_pubkey_hex));
        assert!(ledger.accounts.contains_key(&bob_pubkey_hex));
        assert_eq!(
            ledger.accounts[&alice_pubkey_hex].public_key(),
            alice.public_key()
        );
        assert_eq!(ledger.accounts[&bob_pubkey_hex].public_key(), bob.public_key());
        assert_eq!(ledger.accounts[&alice_pubkey_hex].torvalds(), 250);
        assert_eq!(ledger.accounts[&bob_pubkey_hex].torvalds(), 50);
        assert_eq!(ledger.history.last().unwrap().sender(), &alice.public_key());
        assert_eq!(ledger.history.last().unwrap().receiver(), &bob.public_key());
        assert_eq!(ledger.history.last().unwrap().amount(), 50);
    }

    #[test]
    fn test_save_and_load_ledger(){
        let alice_keypair: KeyPair = KeyPair::generate(&mut OsRng);
        let mut alice = Account::from_private_key(alice_keypair.as_bytes());
        let bob_keypair: KeyPair = KeyPair::generate(&mut OsRng);
        let bob = Account::from_private_key(bob_keypair.as_bytes());

        let _ = alice.deposit(300);
        let accounts = vec![alice.clone()];

        let mut ledger = Ledger::new(accounts).unwrap();

        let unsigned_tx = UnsignedTransaction::new(&alice.public_key(), &bob.public_key(), 50, 1).unwrap();
        let signature = alice_keypair
            .sign_prehashed(unsigned_tx.prehashed(), Some(CONTEXT))
            .unwrap();
        let signed_tx = SignedTransaction::new(unsigned_tx, signature).unwrap();

        ledger.process_transaction(signed_tx).unwrap();

        let path = Path::new("test_ledger.json");
        ledger.save_to_file(path).unwrap();
        let restored = Ledger::load_from_file(Path::new("test_ledger.json")).unwrap();

        assert_eq!(ledger.accounts.len(), restored.accounts.len());
        assert!(restored.history.len() > 0);

        let _ = fs::remove_file(path);
    }
}
