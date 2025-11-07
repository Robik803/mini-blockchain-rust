use ed25519_dalek::{Digest, Signature};
use sha2::Sha512;
use std::cmp::PartialEq;

use crate::errors::BlockchainError;
use crate::keys::{PublicKey, pubkey_to_hex};
use crate::utils::get_timestamp;

pub const CONTEXT: &[u8] = b"Robik803MiniBlochainTxnSigning";

pub trait Message {
    fn sender(&self) -> &PublicKey;
    fn receiver(&self) -> &PublicKey;
    fn amount(&self) -> u64;
    fn nonce(&self) -> u64;
    fn timestamp(&self) -> u64;

    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.sender().as_bytes());
        out.extend_from_slice(self.receiver().as_bytes());
        out.extend_from_slice(&self.amount().to_be_bytes());
        out.extend_from_slice(&self.nonce().to_be_bytes());
        out.extend_from_slice(&self.timestamp().to_be_bytes());
        out
    }

    fn prehashed(&self) -> Sha512 {
        let mut hash = Sha512::new();
        hash.update(self.to_bytes());
        hash
    }
}

pub struct UnsignedTransaction {
    pub from: PublicKey,
    pub to: PublicKey,
    pub amount: u64,
    pub nonce: u64,
    pub timestamp: u64,
}

impl UnsignedTransaction {
    pub fn new(
        from: &PublicKey,
        to: &PublicKey,
        amount: u64,
        nonce: u64,
    ) -> Result<Self, BlockchainError> {
        if amount == 0 {
            return Err(BlockchainError::InvalidNullAmount);
        } else if from == to {
            return Err(BlockchainError::TransactionIntoSameAccount);
        }

        let timestamp = get_timestamp();

        Ok(UnsignedTransaction {
            from: *from,
            to: *to,
            amount,
            nonce,
            timestamp,
        })
    }
}

impl Message for UnsignedTransaction {
    fn sender(&self) -> &PublicKey {
        &self.from
    }
    fn receiver(&self) -> &PublicKey {
        &self.to
    }
    fn amount(&self) -> u64 {
        self.amount
    }
    fn nonce(&self) -> u64 {
        self.nonce
    }
    fn timestamp(&self) -> u64 {
        self.timestamp
    }
}

/// Transaction between two accounts
pub struct SignedTransaction {
    pub from: PublicKey,
    pub to: PublicKey,
    pub amount: u64,
    pub nonce: u64,
    pub timestamp: u64,
    pub signature: Signature,
}

impl Message for SignedTransaction {
    fn sender(&self) -> &PublicKey {
        &self.from
    }
    fn receiver(&self) -> &PublicKey {
        &self.to
    }
    fn amount(&self) -> u64 {
        self.amount
    }
    fn nonce(&self) -> u64 {
        self.nonce
    }
    fn timestamp(&self) -> u64 {
        self.timestamp
    }
}

impl PartialEq for SignedTransaction {
    fn eq(&self, other: &Self) -> bool {
        let same_sender = self.from.eq(&other.from);
        let same_receiver = self.to.eq(&other.to);
        let same_amount = self.amount == other.amount;
        let same_nonce = self.nonce == other.nonce;
        let same_timestamp = self.timestamp == other.timestamp;
        same_sender && same_receiver && same_amount && same_nonce && same_timestamp
    }
}

impl std::fmt::Display for SignedTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Transaction : {{ from: {} -> to: {}, amount : {} RBK, at timestamp({})}}",
            pubkey_to_hex(&self.from),
            pubkey_to_hex(&self.to),
            self.amount,
            self.timestamp
        )
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::accounts::Account;
    use crate::keys::{KeyPair, load_key};
    use crate::transactions::{CONTEXT, Message, SignedTransaction, UnsignedTransaction};

    #[test]
    fn test_transaction() {
        let (mut alice, alice_path) = Account::new("123").unwrap();
        let (bob, bob_path) = Account::new("123").unwrap();

        alice.deposit(300);

        let alice_private_key = load_key("123", &alice_path).unwrap();
        let alice_keypair = KeyPair::from_bytes(&alice_private_key);

        let unsigned_tx =
            UnsignedTransaction::new(&alice.public_key, &bob.public_key, 50, alice.nonce).unwrap();

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

        assert!(
            alice
                .public_key
                .verify_prehashed(signed_tx.prehashed(), Some(CONTEXT), &signed_tx.signature)
                .is_ok()
        );
        assert!(signed_tx.eq(&signed_tx));

        let transaction =
            UnsignedTransaction::new(&alice.public_key, &alice.public_key, 50, alice.nonce);
        assert!(transaction.is_err());

        #[allow(unused)]
        {
            fs::remove_file(alice_path);
            fs::remove_file(bob_path);
        }
    }
}
