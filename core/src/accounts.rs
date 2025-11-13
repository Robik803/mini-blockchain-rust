use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::errors::{BlockchainError, KeyError};
use crate::keys::{PublicKey, generate_and_save, load_key, pubkey_to_hex, public_key_from_private};
use crate::serialization::pubkey;

/// Account containing a public key and a balance in torvalds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    #[serde(with = "pubkey")]
    public_key: PublicKey,
    torvalds: u64,
    nonce: u64,
}

impl Account {
    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    pub fn torvalds(&self) -> u64 {
        self.torvalds
    }

    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Create a new account with a generated keypair and zero balance. Returns as second argument the path where the encyrpted private key is stored.
    pub fn new(password: &str) -> Result<(Self, PathBuf), KeyError> {
        // Generate a new keypair and save private key encrypted in a JSON file
        let (public_key, path) = generate_and_save(password)?;

        Ok((
            Self {
                public_key,
                torvalds: 0,
                nonce: 0,
            },
            path,
        ))
    }

    /// Create an account from an existing private key
    pub fn from_private_key(private_key_bytes: &[u8; 32]) -> Self {
        let public_key = public_key_from_private(private_key_bytes);

        Self {
            public_key,
            torvalds: 0,
            nonce: 0,
        }
    }

    pub fn with_balance(public_key: PublicKey, amount: u64) -> Self {
        Self {
            public_key,
            torvalds: amount,
            nonce: 0,
        }
    }

    /// Creates a new account from an encrypted private key stored in a JSON
    pub fn import_from_json(path: &Path, password: &str) -> Result<Self, KeyError> {
        let private_key = load_key(password, path)?;
        Ok(Account::from_private_key(&private_key))
    }

    /// Deposit an amount into the account
    pub(crate) fn deposit(&mut self, amount: u64) -> Result<(), BlockchainError> {
        if amount == 0 {
            return Err(BlockchainError::InvalidNullAmount);
        }
        self.torvalds += amount;
        Ok(())
    }

    /// Withdraw an amount from account
    pub(crate) fn withdraw(&mut self, amount: u64) -> Result<(), BlockchainError> {
        if amount == 0 {
            return Err(BlockchainError::InvalidNullAmount);
        }
        match self.torvalds.checked_sub(amount) {
            Some(new_torvalds) => {
                self.torvalds = new_torvalds;
                Ok(())
            }
            None => Err(BlockchainError::InsufficientFunds),
        }
    }

    pub(crate) fn increment_nonce(&mut self) {
        self.nonce += 1;
    }
}

// Adding the trait Display to Account
impl std::fmt::Display for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Account {{ public_key: {} -> balance: {} torvalds}}",
            pubkey_to_hex(&self.public_key),
            self.torvalds
        )
    }
}

// Unit tests for the Account struct and its methods
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_account_creation() {
        let (account, path) = Account::new("123").unwrap();
        assert_eq!(account.torvalds, 0);
        assert_eq!(account.public_key.as_bytes().len(), 32);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_account_from_private_key() {
        let private_key_bytes: [u8; 32] = [0u8; 32];
        let account1 = Account::from_private_key(&private_key_bytes);
        let account2 = Account::from_private_key(&private_key_bytes);
        assert_eq!(account1.public_key, account2.public_key);
        assert_eq!(account2.torvalds, 0);
    }

    #[test]
    fn test_import_account_from_json() {
        let (account1, path1) = Account::new("123").unwrap();
        let account2 = Account::import_from_json(&path1, "123").unwrap();
        assert_eq!(account1.public_key, account2.public_key);
        assert_eq!(account2.torvalds, 0);

        let _ = fs::remove_file(path1);
    }

    #[test]
    fn test_deposit() {
        let private_key_bytes: [u8; 32] = [0u8; 32];
        let mut account = Account::from_private_key(&private_key_bytes);

        assert!(account.deposit(0).is_err());
        assert_eq!(account.torvalds, 0);

        account.deposit(30).unwrap();
        assert_eq!(account.torvalds, 30);

        account.deposit(50).unwrap();
        assert_eq!(account.torvalds, 80);
    }

    #[test]
    fn test_withdraw() {
        let private_key_bytes: [u8; 32] = [0u8; 32];
        let mut account = Account::from_private_key(&private_key_bytes);

        account.deposit(100).unwrap();
        assert!(account.withdraw(0).is_err());
        assert_eq!(account.torvalds, 100);

        account.withdraw(50).unwrap();
        assert_eq!(account.torvalds, 50);

        assert!(account.withdraw(120).is_err());
        assert_eq!(account.torvalds, 50);
    }

    #[test]
    fn test_multiaccount_transactions() {
        let private_key_bytes: [u8; 32] = [0u8; 32];
        let mut alice = Account::from_private_key(&private_key_bytes);
        let mut bob = Account::from_private_key(&private_key_bytes);

        alice.deposit(20).unwrap();
        bob.deposit(30).unwrap();
        assert_eq!(alice.torvalds, 20);
        assert_eq!(bob.torvalds, 30);

        assert!(alice.deposit(0).is_err());
        assert!(alice.withdraw(0).is_err());
        assert_eq!(alice.torvalds, 20);

        alice.deposit(50).unwrap();
        alice.withdraw(45).unwrap();
        assert_eq!(alice.torvalds, 25);

        let transfer: u64 = 7;
        alice.deposit(transfer).unwrap();
        bob.withdraw(transfer).unwrap();
        assert_eq!(alice.torvalds, 32);
        assert_eq!(bob.torvalds, 23);
    }
}
