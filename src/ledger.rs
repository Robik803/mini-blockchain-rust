use std::collections::HashMap;

use crate::accounts::{self, Account};
use crate::keys::PublicKey;
use crate::transactions::{SignedTransaction, Message,CONTEXT};

/// Ledger containing the list of active accounts and the history of transactions
pub struct Ledger{
    accounts: HashMap<PublicKey, Account>,
    history: Vec<SignedTransaction>
}

impl Ledger  {

    fn accounts(&self) -> &HashMap<PublicKey, Account>{
        &self.accounts
    }

    fn history(&self) -> &Vec<SignedTransaction>{
        &self.history
    }

    fn check_nonce(&self, sender_pubkey: &PublicKey, nonce: u64) -> bool{
        self.accounts[sender_pubkey].nonce + 1 == nonce
    }

    /// Verifies if the transaction is valid and updates ledger
    pub fn process_transaction(&mut self, transaction : SignedTransaction) -> Result<&'static str, &'static str>{

        let amount = transaction.amount;
        let sender_pubkey = transaction.from;
        let receiver_pubkey = transaction.to;

        if !sender_pubkey.verify_prehashed(transaction.prehashed(), Some(CONTEXT), &transaction.signature).is_ok(){
            return Err("Invalid transaction");
        } else if amount == 0 {
            return Err("Cannot tranfer a null amount.");
        } else if !self.accounts.contains_key(&sender_pubkey) {
            return Err("Sender account doesn't exists.");
        } else if !self.check_nonce(&sender_pubkey, transaction.nonce){
            return Err("Invalid nonce.");
        }

        match self.accounts[&sender_pubkey].rbk.checked_sub(transaction.amount){
            Some(new_sender_rbk) => self.accounts.entry(sender_pubkey).and_modify(|account| {account.rbk = new_sender_rbk; account.nonce += 1}),
            None => return Err("Insufficient funds in sender account to make this transaction")
        };

        self.accounts.entry(receiver_pubkey).and_modify(|account| {account.rbk += amount }).or_insert(Account { public_key: receiver_pubkey, rbk: amount, nonce: 0 });

        self.history.push(transaction);
        
        Ok("Transaction completed.")

    }

}


#[cfg(test)]
mod tests{
    use std::collections::HashMap;
    use std::fs;

    use crate::keys::{KeyPair, load_key};
    use crate::accounts::{Account, make_deposit};
    use crate::ledger::Ledger;
    use crate::transactions::{UnsignedTransaction, SignedTransaction, Message, CONTEXT};

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

        // Transaction 1 : valid
        let unsigned_tx = UnsignedTransaction::new(&alice.public_key, &bob.public_key, 50, 1).unwrap();
        let signature = alice_keypair.sign_prehashed(unsigned_tx.prehashed(), Some(CONTEXT)).unwrap();
        let signed_tx = SignedTransaction{from: unsigned_tx.from, to: unsigned_tx.to, amount: unsigned_tx.amount, nonce: unsigned_tx.nonce, timestamp: unsigned_tx.timestamp, signature};

        let transfer = ledger.process_transaction(signed_tx);

        assert_eq!(transfer, Ok("Transaction completed."));
        assert!(ledger.accounts.contains_key(&alice.public_key));
        assert!(ledger.accounts.contains_key(&bob.public_key));
        assert_eq!(ledger.accounts[&alice.public_key].public_key, alice.public_key);
        assert_eq!(ledger.accounts[&bob.public_key].public_key, bob.public_key);
        assert_eq!(ledger.accounts[&alice.public_key].rbk, 250);
        assert_eq!(ledger.accounts[&bob.public_key].rbk, 50);
        assert_eq!(ledger.history.last().unwrap().from, alice.public_key);
        assert_eq!(ledger.history.last().unwrap().to, bob.public_key);
        assert_eq!(ledger.history.last().unwrap().amount, 50);

        // Transaction 2 : invalid
        let unsigned_tx = UnsignedTransaction::new(&charlie.public_key, &bob.public_key, 30, 1).unwrap();
        let signature = charlie_keypair.sign_prehashed(unsigned_tx.prehashed(), Some(CONTEXT)).unwrap();
        let signed_tx = SignedTransaction{from: unsigned_tx.from, to: unsigned_tx.to, amount: unsigned_tx.amount, nonce: unsigned_tx.nonce, timestamp: unsigned_tx.timestamp, signature};

        let transfer = ledger.process_transaction(signed_tx);

        assert_eq!(transfer, Err("Sender account doesn't exists."));
        assert!(!ledger.accounts.contains_key(&charlie.public_key));
        assert!(ledger.accounts.contains_key(&bob.public_key));
        assert_eq!(ledger.accounts[&bob.public_key].public_key, bob.public_key);
        assert_eq!(ledger.accounts[&bob.public_key].rbk, 50);

        // Transaction 3 : valid
        let unsigned_tx = UnsignedTransaction::new(&bob.public_key, &charlie.public_key, 30, 1).unwrap();
        let signature = bob_keypair.sign_prehashed(unsigned_tx.prehashed(), Some(CONTEXT)).unwrap();
        let signed_tx = SignedTransaction{from: unsigned_tx.from, to: unsigned_tx.to, amount: unsigned_tx.amount, nonce: unsigned_tx.nonce, timestamp: unsigned_tx.timestamp, signature};

        let transfer = ledger.process_transaction(signed_tx);
        
        assert_eq!(transfer, Ok("Transaction completed."));
        assert!(ledger.accounts.contains_key(&charlie.public_key));
        assert!(ledger.accounts.contains_key(&bob.public_key));
        assert_eq!(ledger.accounts[&charlie.public_key].public_key, charlie.public_key);
        assert_eq!(ledger.accounts[&bob.public_key].public_key, bob.public_key);
        assert_eq!(ledger.accounts[&charlie.public_key].rbk, 30);
        assert_eq!(ledger.accounts[&bob.public_key].rbk, 20);

        //Transaction 4 : invalid
        let unsigned_tx = UnsignedTransaction::new(&bob.public_key, &charlie.public_key, 30, 2).unwrap();
        let signature = bob_keypair.sign_prehashed(unsigned_tx.prehashed(), Some(CONTEXT)).unwrap();
        let signed_tx = SignedTransaction{from: unsigned_tx.from, to: unsigned_tx.to, amount: unsigned_tx.amount, nonce: unsigned_tx.nonce, timestamp: unsigned_tx.timestamp, signature};

        let transfer = ledger.process_transaction(signed_tx);
        
        assert_eq!(transfer, Err("Insufficient funds in sender account to make this transaction"));
        assert!(ledger.accounts.contains_key(&charlie.public_key));
        assert!(ledger.accounts.contains_key(&bob.public_key));
        assert_eq!(ledger.accounts[&charlie.public_key].public_key, charlie.public_key);
        assert_eq!(ledger.accounts[&bob.public_key].public_key, bob.public_key);
        assert_eq!(ledger.accounts[&charlie.public_key].rbk, 30);
        assert_eq!(ledger.accounts[&bob.public_key].rbk, 20);

        //Transaction 5 : valid
        let unsigned_tx = UnsignedTransaction::new(&bob.public_key, &charlie.public_key, 5, 2).unwrap();
        let signature = bob_keypair.sign_prehashed(unsigned_tx.prehashed(), Some(CONTEXT)).unwrap();
        let signed_tx = SignedTransaction{from: unsigned_tx.from, to: unsigned_tx.to, amount: unsigned_tx.amount, nonce: unsigned_tx.nonce, timestamp: unsigned_tx.timestamp, signature};

        let transfer = ledger.process_transaction(signed_tx);
        
        assert_eq!(transfer, Ok("Transaction completed."));
        assert!(ledger.accounts.contains_key(&charlie.public_key));
        assert!(ledger.accounts.contains_key(&bob.public_key));
        assert_eq!(ledger.accounts[&charlie.public_key].public_key, charlie.public_key);
        assert_eq!(ledger.accounts[&bob.public_key].public_key, bob.public_key);
        assert_eq!(ledger.accounts[&charlie.public_key].rbk, 35);
        assert_eq!(ledger.accounts[&bob.public_key].rbk, 15);

        //Transaction 6 : invalid
        let unsigned_tx = UnsignedTransaction::new(&bob.public_key, &charlie.public_key, 5, 5).unwrap();
        let signature = bob_keypair.sign_prehashed(unsigned_tx.prehashed(), Some(CONTEXT)).unwrap();
        let signed_tx = SignedTransaction{from: unsigned_tx.from, to: unsigned_tx.to, amount: unsigned_tx.amount, nonce: unsigned_tx.nonce, timestamp: unsigned_tx.timestamp, signature};

        let transfer = ledger.process_transaction(signed_tx);
        
        assert_eq!(transfer, Err("Invalid nonce."));
        assert!(ledger.accounts.contains_key(&charlie.public_key));
        assert!(ledger.accounts.contains_key(&bob.public_key));
        assert_eq!(ledger.accounts[&charlie.public_key].public_key, charlie.public_key);
        assert_eq!(ledger.accounts[&bob.public_key].public_key, bob.public_key);
        assert_eq!(ledger.accounts[&charlie.public_key].rbk, 35);
        assert_eq!(ledger.accounts[&bob.public_key].rbk, 15);

        #[allow(unused)]
        {fs::remove_file(alice_path);
        fs::remove_file(bob_path);
        fs::remove_file(charlie_path);}

    }

}