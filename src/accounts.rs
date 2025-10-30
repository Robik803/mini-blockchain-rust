use std::path::Path;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use crate::keys::{encode_hex, ensure_keys_dir_exists, save_key, load_key};

#[derive(Debug, Clone)]
pub struct Account {
    pub public_key: VerifyingKey,
    pub balance: u64,
}

impl Account {
    /// Create a new account with a generated keypair and zero balance
    pub fn new(password: &str) -> Self {
        // Generate a new keypair
        let mut csprng = OsRng;
        let keypair: SigningKey = SigningKey::generate(&mut csprng);

        // Extract the public and private keys
        let private_key = keypair.to_bytes();
        let public_key: VerifyingKey = keypair.verifying_key();

        // Convert the public key into a hex to name the JSON file where the encrypted private key is sotred
        let pubkey_hex = encode_hex(&public_key.to_bytes()).replace(&['[', ']', ',', ' '][..], "");

        // Verify that the path where the JSON file will be saved exists
        let dir = ensure_keys_dir_exists().unwrap();
        let path = dir.join(format!("{pubkey_hex}.json"));
        
        //
        match save_key(password, &path, &private_key){
            Ok(msg) => println!("{}",msg),
            Err(msg) => panic!("Couldn't save file : {}",msg)
        }

        Self {
            public_key,
            balance: 0,
        }
    }

    /// Create an account from an existing private key
    pub fn from_private_key(private_key_bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(private_key_bytes);
        let public_key = signing_key.verifying_key();

        Self {
            public_key,
            balance: 0,
        }
    }

    pub fn import_from_json(path : &Path, password: &str) -> Self{
        let private_key = match load_key(password, &path){
            Ok(pk) => pk,
            Err(e) => panic!("{e}")
        };
        Account::from_private_key(&private_key)
    }

    /// Display account information
    pub fn show(&self) {
        println!("Account Public Key: {:?}", self.public_key.as_bytes());
        println!("Account Balance: {}", self.balance);
    }

    /// Deposit an amount into the account
    pub fn deposit(&mut self, amount: u64) -> Result<(u64, &VerifyingKey, &u64), &'static str> {
        if amount == 0 {
            return Err("Cannot deposit a null amount.");
        }
        self.balance += amount;
        Ok((amount, &self.public_key, &self.balance))
    }

    /// Withdraw an amount from account
    pub fn withdraw(&mut self, amount: u64) -> Result<(u64, &VerifyingKey, &u64), &'static str> {
        if amount == 0 {
            return Err("Cannot withdraw a null amount.");
        }
        match self.balance.checked_sub(amount) {
            Some(new_balance) => {
                self.balance = new_balance;
                Ok((amount, &self.public_key, &self.balance))
            }
            None => Err("Insufficient funds..."),
        }
    }
}

///Make a deposit of an amount into an account
pub fn make_deposit(account: &mut Account, amount: u64) {
    match account.deposit(amount) {
        Ok((amount, public_key, balance)) => {
            println!(
                "Transaction completed. {} RBK deposited into the account {:?}",
                amount,
                public_key.as_bytes()
            );
            println!("New balance : {} RBK", balance)
        }
        Err(e) => println!("error in transaction : {e:?}"),
    }
}

///Make a withdraw of an amount from an account
pub fn make_withdraw(account: &mut Account, amount: u64) {
    match account.withdraw(amount) {
        Ok((amount, public_key, balance)) => {
            println!(
                "Transaction completed. {} RBK withdrawn from the account {:?}",
                amount,
                public_key.as_bytes()
            );
            println!("New balance : {} RBK", balance)
        }
        Err(e) => println!("error in transaction : {e:?}"),
    }
}

//Adding the trait Display to Account
impl std::fmt::Display for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Account {{ public_key: {:?} -> balance: {} }}",
            self.public_key.as_bytes(),
            self.balance
        )
    }
}

// Unit tests for the Account struct and its methods
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn delete_private_key_file(public_key: VerifyingKey){
        let pubkey_hex = encode_hex(&public_key.to_bytes()).replace(&['[', ']', ',', ' '][..], "");
        let dir = ensure_keys_dir_exists().unwrap();
        let path = dir.join(format!("{pubkey_hex}.json"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_account_creation() {
        let account = Account::new("123");
        assert_eq!(account.balance, 0);
        assert_eq!(account.public_key.as_bytes().len(), 32); // Ed25519 public keys are 32 bytes

        delete_private_key_file(account.public_key);
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
        assert_eq!(account2.balance, 0);

        delete_private_key_file(account1.public_key);
        delete_private_key_file(account2.public_key);
    }

    #[test]
    fn test_import_account_from_json(){
        let account1 = Account::new("123");

        let pubkey_hex = encode_hex(&account1.public_key.to_bytes()).replace(&['[', ']', ',', ' '][..], "");
        let dir = ensure_keys_dir_exists().unwrap();
        let path = dir.join(format!("{pubkey_hex}.json"));

        let account2 = Account::import_from_json(&path, "123");

        assert_eq!(
            account1.public_key.as_bytes(),
            account2.public_key.as_bytes()
        );
        assert_eq!(account2.balance, 0);

        delete_private_key_file(account1.public_key);
    }

    #[test]
    fn test_deposit() {
        let mut account = Account::new("123");

        make_deposit(&mut account, 0);
        assert_eq!(account.balance, 0);

        make_deposit(&mut account, 30);
        assert_eq!(account.balance, 30);

        make_deposit(&mut account, 50);
        assert_eq!(account.balance, 80);

        delete_private_key_file(account.public_key);
    }

    #[test]
    fn test_withdraw() {
        let mut account = Account::new("123");

        make_deposit(&mut account, 100);
        make_withdraw(&mut account, 0);
        assert_eq!(account.balance, 100);

        make_withdraw(&mut account, 50);
        assert_eq!(account.balance, 50);

        make_withdraw(&mut account, 120);
        assert_eq!(account.balance, 50);

        delete_private_key_file(account.public_key);
    }

    #[test]
    fn test_multiaccount_transactions() {
        let mut alice = Account::new("123");
        let mut bob = Account::new("123");

        make_deposit(&mut alice, 20);
        make_deposit(&mut bob, 30);
        assert_eq!(alice.balance, 20);
        assert_eq!(bob.balance, 30);

        make_deposit(&mut alice, 0);
        make_withdraw(&mut alice, 0);
        assert_eq!(alice.balance, 20);

        make_deposit(&mut alice, 50);
        make_withdraw(&mut alice, 45);
        assert_eq!(alice.balance, 25);

        let transfer: u64 = 7;
        make_deposit(&mut alice, transfer);
        make_withdraw(&mut bob, transfer);
        assert_eq!(alice.balance, 32);
        assert_eq!(bob.balance, 23);

        delete_private_key_file(alice.public_key);
        delete_private_key_file(bob.public_key);
    }
}
