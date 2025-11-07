use std::collections::HashMap;

use crate::accounts::Account;
use crate::errors::BlockchainError;
use crate::keys::PublicKey;
use crate::transactions::{CONTEXT, Message, SignedTransaction};

/// Ledger containing the list of active accounts and the history of transactions
pub struct Ledger {
    accounts: HashMap<PublicKey, Account>,
    history: Vec<SignedTransaction>,
}

impl Ledger {
    fn accounts(&self) -> &HashMap<PublicKey, Account> {
        &self.accounts
    }

    fn history(&self) -> &Vec<SignedTransaction> {
        &self.history
    }

    fn check_nonce(&self, sender_pubkey: &PublicKey, nonce: u64) -> bool {
        self.accounts[sender_pubkey].nonce + 1 == nonce
    }

    /// Verifies if the transaction is valid and updates ledger
    pub fn process_transaction(
        &mut self,
        transaction: SignedTransaction,
    ) -> Result<(), BlockchainError> {
        let amount = transaction.amount;
        let sender_pubkey = transaction.from;
        let receiver_pubkey = transaction.to;

        sender_pubkey.verify_prehashed(
            transaction.prehashed(),
            Some(CONTEXT),
            &transaction.signature,
        )?;

        if amount == 0 {
            return Err(BlockchainError::InvalidNullAmount);
        } else if !self.accounts.contains_key(&sender_pubkey) {
            return Err(BlockchainError::InvalidSenderAccount);
        } else if !self.check_nonce(&sender_pubkey, transaction.nonce) {
            return Err(BlockchainError::InvalidNonce);
        }

        match self.accounts[&sender_pubkey]
            .torvalds
            .checked_sub(transaction.amount)
        {
            Some(new_sender_torvalds) => self.accounts.entry(sender_pubkey).and_modify(|account| {
                account.torvalds = new_sender_torvalds;
                account.nonce += 1
            }),
            None => return Err(BlockchainError::InsufficientFunds),
        };

        self.accounts
            .entry(receiver_pubkey)
            .and_modify(|account| account.torvalds += amount)
            .or_insert(Account {
                public_key: receiver_pubkey,
                torvalds: amount,
                nonce: 0,
            });

        self.history.push(transaction);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;

    use crate::accounts::Account;
    use crate::keys::{KeyPair, load_key};
    use crate::ledger::Ledger;
    use crate::transactions::{CONTEXT, Message, SignedTransaction, UnsignedTransaction};

    #[test]
    fn test_transfer() {
        let (mut alice, alice_path) = Account::new("123").unwrap();
        let (bob, bob_path) = Account::new("123").unwrap();
        let (charlie, charlie_path) = Account::new("123").unwrap();

        alice.deposit(300).unwrap();

        let mut ledger = Ledger {
            accounts: HashMap::new(),
            history: Vec::new(),
        };

        ledger
            .accounts
            .entry(alice.public_key)
            .or_insert(alice.clone());

        let alice_private_key = load_key("123", &alice_path).unwrap();
        let alice_keypair = KeyPair::from_bytes(&alice_private_key);

        let bob_private_key = load_key("123", &bob_path).unwrap();
        let bob_keypair = KeyPair::from_bytes(&bob_private_key);

        let charlie_private_key = load_key("123", &charlie_path).unwrap();
        let charlie_keypair = KeyPair::from_bytes(&charlie_private_key);

        // Transaction 1 : valid
        let unsigned_tx =
            UnsignedTransaction::new(&alice.public_key, &bob.public_key, 50, 1).unwrap();
        let signature = alice_keypair
            .sign_prehashed(unsigned_tx.prehashed(), Some(CONTEXT))
            .unwrap();
        let signed_tx = SignedTransaction {
            from: unsigned_tx.from,
            to: unsigned_tx.to,
            amount: unsigned_tx.amount,
            nonce: unsigned_tx.nonce,
            timestamp: unsigned_tx.timestamp,
            signature,
        };

        ledger.process_transaction(signed_tx).unwrap();

        assert!(ledger.accounts.contains_key(&alice.public_key));
        assert!(ledger.accounts.contains_key(&bob.public_key));
        assert_eq!(
            ledger.accounts[&alice.public_key].public_key,
            alice.public_key
        );
        assert_eq!(ledger.accounts[&bob.public_key].public_key, bob.public_key);
        assert_eq!(ledger.accounts[&alice.public_key].torvalds, 250);
        assert_eq!(ledger.accounts[&bob.public_key].torvalds, 50);
        assert_eq!(ledger.history.last().unwrap().from, alice.public_key);
        assert_eq!(ledger.history.last().unwrap().to, bob.public_key);
        assert_eq!(ledger.history.last().unwrap().amount, 50);

        // Transaction 2 : invalid
        let unsigned_tx =
            UnsignedTransaction::new(&charlie.public_key, &bob.public_key, 30, 1).unwrap();
        let signature = charlie_keypair
            .sign_prehashed(unsigned_tx.prehashed(), Some(CONTEXT))
            .unwrap();
        let signed_tx = SignedTransaction {
            from: unsigned_tx.from,
            to: unsigned_tx.to,
            amount: unsigned_tx.amount,
            nonce: unsigned_tx.nonce,
            timestamp: unsigned_tx.timestamp,
            signature,
        };

        assert!(ledger.process_transaction(signed_tx).is_err());

        assert!(!ledger.accounts.contains_key(&charlie.public_key));
        assert!(ledger.accounts.contains_key(&bob.public_key));
        assert_eq!(ledger.accounts[&bob.public_key].public_key, bob.public_key);
        assert_eq!(ledger.accounts[&bob.public_key].torvalds, 50);

        // Transaction 3 : valid
        let unsigned_tx =
            UnsignedTransaction::new(&bob.public_key, &charlie.public_key, 30, 1).unwrap();
        let signature = bob_keypair
            .sign_prehashed(unsigned_tx.prehashed(), Some(CONTEXT))
            .unwrap();
        let signed_tx = SignedTransaction {
            from: unsigned_tx.from,
            to: unsigned_tx.to,
            amount: unsigned_tx.amount,
            nonce: unsigned_tx.nonce,
            timestamp: unsigned_tx.timestamp,
            signature,
        };

        ledger.process_transaction(signed_tx).unwrap();

        assert!(ledger.accounts.contains_key(&charlie.public_key));
        assert!(ledger.accounts.contains_key(&bob.public_key));
        assert_eq!(
            ledger.accounts[&charlie.public_key].public_key,
            charlie.public_key
        );
        assert_eq!(ledger.accounts[&bob.public_key].public_key, bob.public_key);
        assert_eq!(ledger.accounts[&charlie.public_key].torvalds, 30);
        assert_eq!(ledger.accounts[&bob.public_key].torvalds, 20);

        //Transaction 4 : invalid
        let unsigned_tx =
            UnsignedTransaction::new(&bob.public_key, &charlie.public_key, 30, 2).unwrap();
        let signature = bob_keypair
            .sign_prehashed(unsigned_tx.prehashed(), Some(CONTEXT))
            .unwrap();
        let signed_tx = SignedTransaction {
            from: unsigned_tx.from,
            to: unsigned_tx.to,
            amount: unsigned_tx.amount,
            nonce: unsigned_tx.nonce,
            timestamp: unsigned_tx.timestamp,
            signature,
        };

        assert!(ledger.process_transaction(signed_tx).is_err());

        assert!(ledger.accounts.contains_key(&charlie.public_key));
        assert!(ledger.accounts.contains_key(&bob.public_key));
        assert_eq!(
            ledger.accounts[&charlie.public_key].public_key,
            charlie.public_key
        );
        assert_eq!(ledger.accounts[&bob.public_key].public_key, bob.public_key);
        assert_eq!(ledger.accounts[&charlie.public_key].torvalds, 30);
        assert_eq!(ledger.accounts[&bob.public_key].torvalds, 20);

        //Transaction 5 : valid
        let unsigned_tx =
            UnsignedTransaction::new(&bob.public_key, &charlie.public_key, 5, 2).unwrap();
        let signature = bob_keypair
            .sign_prehashed(unsigned_tx.prehashed(), Some(CONTEXT))
            .unwrap();
        let signed_tx = SignedTransaction {
            from: unsigned_tx.from,
            to: unsigned_tx.to,
            amount: unsigned_tx.amount,
            nonce: unsigned_tx.nonce,
            timestamp: unsigned_tx.timestamp,
            signature,
        };

        ledger.process_transaction(signed_tx).unwrap();

        assert!(ledger.accounts.contains_key(&charlie.public_key));
        assert!(ledger.accounts.contains_key(&bob.public_key));
        assert_eq!(
            ledger.accounts[&charlie.public_key].public_key,
            charlie.public_key
        );
        assert_eq!(ledger.accounts[&bob.public_key].public_key, bob.public_key);
        assert_eq!(ledger.accounts[&charlie.public_key].torvalds, 35);
        assert_eq!(ledger.accounts[&bob.public_key].torvalds, 15);

        //Transaction 6 : invalid
        let unsigned_tx =
            UnsignedTransaction::new(&bob.public_key, &charlie.public_key, 5, 5).unwrap();
        let signature = bob_keypair
            .sign_prehashed(unsigned_tx.prehashed(), Some(CONTEXT))
            .unwrap();
        let signed_tx = SignedTransaction {
            from: unsigned_tx.from,
            to: unsigned_tx.to,
            amount: unsigned_tx.amount,
            nonce: unsigned_tx.nonce,
            timestamp: unsigned_tx.timestamp,
            signature,
        };

        assert!(ledger.process_transaction(signed_tx).is_err());

        assert!(ledger.accounts.contains_key(&charlie.public_key));
        assert!(ledger.accounts.contains_key(&bob.public_key));
        assert_eq!(
            ledger.accounts[&charlie.public_key].public_key,
            charlie.public_key
        );
        assert_eq!(ledger.accounts[&bob.public_key].public_key, bob.public_key);
        assert_eq!(ledger.accounts[&charlie.public_key].torvalds, 35);
        assert_eq!(ledger.accounts[&bob.public_key].torvalds, 15);

        #[allow(unused)]
        {
            fs::remove_file(alice_path);
            fs::remove_file(bob_path);
            fs::remove_file(charlie_path);
        }
    }
}
