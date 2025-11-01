use std::collections::HashMap;
use std::cmp::{PartialEq};
use sha2::Sha512;
use rand::{RngCore, rngs::OsRng};
use ed25519_dalek::{Signature, Digest};

use crate::accounts::{Account, PublicKey, KeyPair};
use crate::utils::get_timestamp;

const CONTEXT : &[u8] = b"Robik803MiniBlochainTxnSigning";


fn random_nonce() -> u64{
    let mut b = [0u8; 8];
    OsRng.fill_bytes(&mut b);
    u64::from_be_bytes(b)
}

#[derive(Debug, Clone)]
pub struct Transaction{
    from : PublicKey,
    to : PublicKey,
    amount : u64,
    nonce : u64,
    timestamp : u64,
    signature : Signature,
    hash : Sha512
}

impl Transaction{

    fn build_message_bytes(from: &PublicKey, to: &PublicKey, amount: u64, nonce: u64, timestamp: u64) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(from.as_bytes());
        out.extend_from_slice(to.as_bytes());
        out.extend_from_slice(&amount.to_be_bytes());
        out.extend_from_slice(&nonce.to_be_bytes());
        out.extend_from_slice(&timestamp.to_be_bytes());
        out
    }

    fn hash_message(bytes: &[u8]) -> Sha512 {
        let mut hash = Sha512::new();
        hash.update(bytes);
        hash
    }

    pub fn new(from: &KeyPair, to: &PublicKey, amount: u64) -> Result<Self, &'static str>{

        if amount == 0{
            return Err("Cannot transfer a null amount.");
        }

        let sender_public_key = from.verifying_key();
        let receiver_public_key = to.clone();

        if sender_public_key == receiver_public_key{
            return Err("Cannot make transactions within the same account.");
        }

        let nonce = random_nonce();

        let timestamp = get_timestamp();

        let message_bytes = Transaction::build_message_bytes(&sender_public_key, to, amount, nonce, timestamp);

        let hash = Transaction::hash_message(&message_bytes);

        let signature = match from.sign_prehashed(hash.clone(), Some(CONTEXT)){
            Ok(s) => s,
            Err(_) => return Err("Error during signature.")
        };

        Ok(Transaction{
            from: sender_public_key,
            to: receiver_public_key,
            amount,
            nonce,
            timestamp,
            signature,
            hash
        })

    }

}

impl PartialEq for Transaction{
    fn eq(&self, other: &Self) -> bool {
        let same_sender = self.from.eq(&other.from);
        let same_receiver = self.to.eq(&other.to);
        let same_amount = self.amount == other.amount;
        let same_nonce = self.nonce == other.nonce;
        let same_timestamp = self.timestamp == other.timestamp;
        same_sender & same_receiver & same_amount & same_nonce & same_timestamp
    }
}

#[derive(Debug, Clone)]
pub struct Ledger{
    accounts: HashMap<PublicKey, Account>,
    history: Vec<Transaction>
}

impl Ledger  {

    pub fn process_transaction(&mut self, transaction : &Transaction) -> Result<&'static str, &'static str>{

        let amount = transaction.amount;
        let sender_pubkey = transaction.from;
        let receiver_pubkey = transaction.to;

        if !sender_pubkey.verify_prehashed(transaction.hash.clone(), Some(CONTEXT), &transaction.signature).is_ok(){
            return Err("Invalid transaction");
        } else if amount == 0 {
            return Err("Cannot tranfer a null amount.");
        } else if !self.accounts.contains_key(&sender_pubkey) {
            return Err("Sender account doesn't exists.");
        } 

        match self.accounts[&sender_pubkey].balance.checked_sub(transaction.amount){
            Some(new_sender_balance) => self.accounts.entry(sender_pubkey).and_modify(|account| account.balance = new_sender_balance),
            None => return Err("Insufficient funds in sender account to make this transaction")
        };

        self.accounts.entry(receiver_pubkey).and_modify(|account| account.balance += amount).or_insert(Account { public_key: receiver_pubkey, balance: amount });

        self.history.push(transaction.clone());
        
        Ok("Transaction completed.")

    }

}

#[cfg(test)]
mod tests{
    use std::collections::HashMap;
    use std::fs;

    use crate::keys::load_key;
    use crate::ledger::CONTEXT;
    use crate::{accounts::{Account, KeyPair, make_deposit}, ledger::{Ledger, Transaction}};


    #[test]
    fn test_transaction(){
        let (mut alice, alice_path) = Account::new("123");
        let (bob, bob_path) = Account::new("123");

        make_deposit(&mut alice, 300);

        let alice_private_key = load_key("123", &alice_path).unwrap();
        let alice_keypair = KeyPair::from_bytes(&alice_private_key);

        let transaction = Transaction::new(&alice_keypair, &bob.public_key, 50).unwrap();
        assert!(alice.public_key.verify_prehashed(transaction.hash.clone(), Some(CONTEXT), &transaction.signature).is_ok());

        assert!(transaction.eq(&transaction));

        let transaction = Transaction::new(&alice_keypair, &alice.public_key, 50);
        assert!(transaction.is_err());
        
        #[allow(unused)]
        {fs::remove_file(alice_path);
        fs::remove_file(bob_path);}

    }

    #[test]
    fn test_transfer(){
        let (mut alice, alice_path) = Account::new("123");
        let (bob, bob_path) = Account::new("123");
        let (charlie, charlie_path) = Account::new("123");

        make_deposit(&mut alice, 300);

        let mut ledger = Ledger{accounts: HashMap::new(), history: Vec::new()};

        ledger.accounts.entry(alice.public_key).or_insert(alice.clone());

        let alice_private_key = load_key("123", &alice_path).unwrap();
        let alice_keypair = KeyPair::from_bytes(&alice_private_key);

        let bob_private_key = load_key("123", &bob_path).unwrap();
        let bob_keypair = KeyPair::from_bytes(&bob_private_key);

        let charlie_private_key = load_key("123", &charlie_path).unwrap();
        let charlie_keypair = KeyPair::from_bytes(&charlie_private_key);

        let transaction = Transaction::new(&alice_keypair, &bob.public_key, 50).unwrap();
        let transfer = ledger.process_transaction(&transaction);
        assert_eq!(transfer, Ok("Transaction completed."));
        assert!(ledger.accounts.contains_key(&alice.public_key));
        assert!(ledger.accounts.contains_key(&bob.public_key));
        assert_eq!(ledger.accounts[&alice.public_key].public_key, alice.public_key);
        assert_eq!(ledger.accounts[&bob.public_key].public_key, bob.public_key);
        assert_eq!(ledger.accounts[&alice.public_key].balance, 250);
        assert_eq!(ledger.accounts[&bob.public_key].balance, 50);
        assert!(ledger.history.contains(&transaction));

        let transaction = Transaction::new(&charlie_keypair, &bob.public_key, 30).unwrap();
        let transfer = ledger.process_transaction(&transaction);
        assert_eq!(transfer, Err("Sender account doesn't exists."));
        assert!(!ledger.accounts.contains_key(&charlie.public_key));
        assert!(ledger.accounts.contains_key(&bob.public_key));
        assert_eq!(ledger.accounts[&bob.public_key].public_key, bob.public_key);
        assert_eq!(ledger.accounts[&bob.public_key].balance, 50);
        assert!(!ledger.history.contains(&transaction));

        let transaction = Transaction::new(&bob_keypair, &charlie.public_key, 30).unwrap();
        let transfer = ledger.process_transaction(&transaction);
        assert_eq!(transfer, Ok("Transaction completed."));
        assert!(ledger.accounts.contains_key(&charlie.public_key));
        assert!(ledger.accounts.contains_key(&bob.public_key));
        assert_eq!(ledger.accounts[&charlie.public_key].public_key, charlie.public_key);
        assert_eq!(ledger.accounts[&bob.public_key].public_key, bob.public_key);
        assert_eq!(ledger.accounts[&charlie.public_key].balance, 30);
        assert_eq!(ledger.accounts[&bob.public_key].balance, 20);

        let transaction = Transaction::new(&bob_keypair, &charlie.public_key, 30).unwrap();
        let transfer = ledger.process_transaction(&transaction);
        assert_eq!(transfer, Err("Insufficient funds in sender account to make this transaction"));
        assert!(ledger.accounts.contains_key(&charlie.public_key));
        assert!(ledger.accounts.contains_key(&bob.public_key));
        assert_eq!(ledger.accounts[&charlie.public_key].public_key, charlie.public_key);
        assert_eq!(ledger.accounts[&bob.public_key].public_key, bob.public_key);
        assert_eq!(ledger.accounts[&charlie.public_key].balance, 30);
        assert_eq!(ledger.accounts[&bob.public_key].balance, 20);

        #[allow(unused)]
        {fs::remove_file(alice_path);
        fs::remove_file(bob_path);
        fs::remove_file(charlie_path);}

    }

}