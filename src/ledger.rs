use std::collections::HashMap;

use crate::accounts::Account;
use crate::keys::PublicKey;
use crate::transactions::{Transaction, CONTEXT};

/// Ledger containing the list of active accounts and the history of transactions
#[derive(Debug, Clone)]
pub struct Ledger{
    accounts: HashMap<PublicKey, Account>,
    history: Vec<Transaction>
}

impl Ledger  {

    /// Verifies if the transaction is valid and updates ledger
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

        match self.accounts[&sender_pubkey].rbk.checked_sub(transaction.amount){
            Some(new_sender_rbk) => self.accounts.entry(sender_pubkey).and_modify(|account| account.rbk = new_sender_rbk),
            None => return Err("Insufficient funds in sender account to make this transaction")
        };

        self.accounts.entry(receiver_pubkey).and_modify(|account| account.rbk += amount).or_insert(Account { public_key: receiver_pubkey, rbk: amount });

        self.history.push(transaction.clone());
        
        Ok("Transaction completed.")

    }

}

#[cfg(test)]
mod tests{
    use std::collections::HashMap;
    use std::fs;

    use crate::keys::{KeyPair, load_key};
    use crate::accounts::{Account, make_deposit};
    use crate::ledger::{Ledger, Transaction};

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
        assert_eq!(ledger.accounts[&alice.public_key].rbk, 250);
        assert_eq!(ledger.accounts[&bob.public_key].rbk, 50);
        assert!(ledger.history.contains(&transaction));

        let transaction = Transaction::new(&charlie_keypair, &bob.public_key, 30).unwrap();
        let transfer = ledger.process_transaction(&transaction);
        assert_eq!(transfer, Err("Sender account doesn't exists."));
        assert!(!ledger.accounts.contains_key(&charlie.public_key));
        assert!(ledger.accounts.contains_key(&bob.public_key));
        assert_eq!(ledger.accounts[&bob.public_key].public_key, bob.public_key);
        assert_eq!(ledger.accounts[&bob.public_key].rbk, 50);
        assert!(!ledger.history.contains(&transaction));

        let transaction = Transaction::new(&bob_keypair, &charlie.public_key, 30).unwrap();
        let transfer = ledger.process_transaction(&transaction);
        assert_eq!(transfer, Ok("Transaction completed."));
        assert!(ledger.accounts.contains_key(&charlie.public_key));
        assert!(ledger.accounts.contains_key(&bob.public_key));
        assert_eq!(ledger.accounts[&charlie.public_key].public_key, charlie.public_key);
        assert_eq!(ledger.accounts[&bob.public_key].public_key, bob.public_key);
        assert_eq!(ledger.accounts[&charlie.public_key].rbk, 30);
        assert_eq!(ledger.accounts[&bob.public_key].rbk, 20);

        let transaction = Transaction::new(&bob_keypair, &charlie.public_key, 30).unwrap();
        let transfer = ledger.process_transaction(&transaction);
        assert_eq!(transfer, Err("Insufficient funds in sender account to make this transaction"));
        assert!(ledger.accounts.contains_key(&charlie.public_key));
        assert!(ledger.accounts.contains_key(&bob.public_key));
        assert_eq!(ledger.accounts[&charlie.public_key].public_key, charlie.public_key);
        assert_eq!(ledger.accounts[&bob.public_key].public_key, bob.public_key);
        assert_eq!(ledger.accounts[&charlie.public_key].rbk, 30);
        assert_eq!(ledger.accounts[&bob.public_key].rbk, 20);

        #[allow(unused)]
        {fs::remove_file(alice_path);
        fs::remove_file(bob_path);
        fs::remove_file(charlie_path);}

    }

}