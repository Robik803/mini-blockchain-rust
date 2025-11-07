use std::path::{Path, PathBuf};
use rand::rngs::OsRng;
use crate::keys::{KeyPair, PublicKey, ensure_keys_dir_exists, load_key, pubkey_to_hex, save_key};
use crate::errors::{KeyError, BlockchainError};

/// Account containing a public key and a balance in torvalds
#[derive(Debug, Clone)]
pub struct Account {
    pub public_key: PublicKey,
    pub torvalds: u64,
    pub nonce: u64,
}

impl Account {
    /// Create a new account with a generated keypair and zero balance. Returns as second argument the path where the encyrpted private key is stored.
    pub fn new(password: &str) -> Result<(Self, PathBuf), KeyError> {
        // Generate a new keypair
        let mut csprng = OsRng;
        let keypair: KeyPair = KeyPair::generate(&mut csprng);

        // Extract the public and private keys
        let private_key = keypair.to_bytes();
        let public_key: PublicKey = keypair.verifying_key();

        // Convert the public key into a hex to name the JSON file where the encrypted private key is sotred
        let pubkey_hex = pubkey_to_hex(&public_key);

        // Verify that the path where the JSON file will be saved exists
        let dir = ensure_keys_dir_exists()?;
        let path = dir.join(format!("{pubkey_hex}.json"));
        
        //
        save_key(password, &path, &private_key)?;

        Ok((Self{public_key, torvalds: 0, nonce: 0}, path))
    }

    /// Create an account from an existing private key
    pub fn from_private_key(private_key_bytes: &[u8; 32]) -> Self {
        let signing_key: KeyPair = KeyPair::from_bytes(private_key_bytes);
        let public_key = signing_key.verifying_key();

        Self {
            public_key,
            torvalds: 0,
            nonce : 0
        }
    }

    /// Creates a new account from an encrypted private key stored in a JSON
    pub fn import_from_json(path : &Path, password: &str) -> Result<Self, KeyError>{
        let private_key = load_key(password, &path)?;
        Ok(Account::from_private_key(&private_key))
    }

    /// Deposit an amount into the account
    pub fn deposit(&mut self, amount: u64) -> Result<(), BlockchainError> {
        if amount == 0 {
            return Err(BlockchainError::InvalidNullAmount);
        }
        self.torvalds += amount;
        Ok(())
    }

    /// Withdraw an amount from account
    pub fn withdraw(&mut self, amount: u64) -> Result<(), BlockchainError> {
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

    use crate::utils::encode_hex;

    #[test]
    fn test_account_creation() {
        let (account, path) = Account::new("123").unwrap();
        assert_eq!(account.torvalds, 0);
        assert_eq!(account.public_key.as_bytes().len(), 32); // Ed25519 public keys are 32 bytes

        #[allow(unused)]
        fs::remove_file(path);
    }

    #[test]
    fn test_account_from_private_key() {
        let private_key_bytes: [u8; 32] = [0u8; 32]; // Example private key (not secure)
        let account1 = Account::from_private_key(&private_key_bytes);
        let account2 = Account::from_private_key(&private_key_bytes);
        assert_eq!(
            account1.public_key.as_bytes(),
            account2.public_key.as_bytes()
        );
        assert_eq!(account2.torvalds, 0);
    }

    #[test]
    fn test_import_account_from_json(){
        let (account1, path1) = Account::new("123").unwrap();

        let pubkey_hex = encode_hex(&account1.public_key.to_bytes()).replace(&['[', ']', ',', ' '][..], "");
        let dir = ensure_keys_dir_exists().unwrap();
        let path = dir.join(format!("{pubkey_hex}.json"));

        let account2 = Account::import_from_json(&path, "123").unwrap();

        assert_eq!(
            account1.public_key.as_bytes(),
            account2.public_key.as_bytes()
        );
        assert_eq!(account2.torvalds, 0);

        #[allow(unused)]
        fs::remove_file(path1);
    }

    #[test]
    fn test_deposit() {
        let (mut account, path) = Account::new("123").unwrap();

        assert!(account.deposit(0).is_err());
        assert_eq!(account.torvalds, 0);

        account.deposit(30).unwrap();
        assert_eq!(account.torvalds, 30);

        account.deposit(50).unwrap();
        assert_eq!(account.torvalds, 80);

        #[allow(unused)]
        fs::remove_file(path);
    }

    #[test]
    fn test_withdraw() {
        let (mut account, path) = Account::new("123").unwrap();

        account.deposit(100).unwrap();
        assert!(account.withdraw(0).is_err());
        assert_eq!(account.torvalds, 100);

        account.withdraw(50).unwrap();
        assert_eq!(account.torvalds, 50);

        assert!(account.withdraw(120).is_err());
        assert_eq!(account.torvalds, 50);

        #[allow(unused)]
        fs::remove_file(path);
    }

    #[test]
    fn test_multiaccount_transactions() {
        let (mut alice, alice_path) = Account::new("123").unwrap();
        let (mut bob, bob_path) = Account::new("123").unwrap();

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

        #[allow(unused)]
        {fs::remove_file(alice_path);
        fs::remove_file(bob_path);}
    }

}
