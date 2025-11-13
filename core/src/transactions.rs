use crate::serialization::{pubkey, signature};
use ed25519_dalek::{Digest, Signature};
use serde::{self, Deserialize, Serialize};
use sha2::Sha512;
use std::cmp::PartialEq;

use crate::constants::CONTEXT;
use crate::errors::BlockchainError;
use crate::keys::{PublicKey, pubkey_to_hex};
use crate::utils::{encode_hex, get_timestamp};

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

    fn hash(&self) -> [u8; 64] {
        let pre = self.prehashed();
        pre.finalize().into()
    }
}

pub struct UnsignedTransaction {
    from: PublicKey,
    to: PublicKey,
    amount: u64,
    nonce: u64,
    timestamp: u64,
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
#[derive(Serialize, Deserialize)]
pub struct SignedTransaction {
    #[serde(with = "pubkey")]
    from: PublicKey,
    #[serde(with = "pubkey")]
    to: PublicKey,
    amount: u64,
    nonce: u64,
    timestamp: u64,
    #[serde(with = "signature")]
    signature: Signature,
}

impl SignedTransaction {
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    pub fn new(
        unsigned_tx: UnsignedTransaction,
        signature: Signature,
    ) -> Result<Self, BlockchainError> {
        unsigned_tx
            .from
            .verify_prehashed(unsigned_tx.prehashed(), Some(CONTEXT), &signature)?;
        Ok(SignedTransaction {
            from: unsigned_tx.from,
            to: unsigned_tx.to,
            amount: unsigned_tx.amount,
            nonce: unsigned_tx.nonce,
            timestamp: unsigned_tx.timestamp,
            signature,
        })
    }
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
            "Transaction {} : {{ from: {} -> to: {}, amount : {} torvalds, at timestamp({})}}",
            encode_hex(&self.hash()),
            pubkey_to_hex(&self.from),
            pubkey_to_hex(&self.to),
            self.amount,
            self.timestamp
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    use crate::keys::KeyPair;

    #[test]
    fn test_transaction() {
        let alice_keypair: KeyPair = KeyPair::generate(&mut OsRng);
        let alice_pubkey = alice_keypair.verifying_key();

        let bob_keypair: KeyPair = KeyPair::generate(&mut OsRng);
        let bob_pubkey = bob_keypair.verifying_key();

        let unsigned_tx = UnsignedTransaction::new(&alice_pubkey, &bob_pubkey, 50, 0).unwrap();

        let signature = alice_keypair
            .sign_prehashed(unsigned_tx.prehashed(), Some(CONTEXT))
            .unwrap();

        let signed_tx = SignedTransaction::new(unsigned_tx, signature).unwrap();

        assert!(
            alice_pubkey
                .verify_prehashed(signed_tx.prehashed(), Some(CONTEXT), &signed_tx.signature)
                .is_ok()
        );
        assert!(signed_tx.eq(&signed_tx));

        let transaction = UnsignedTransaction::new(&alice_pubkey, &alice_pubkey, 50, 0);
        assert!(matches!(
            transaction,
            Err(BlockchainError::TransactionIntoSameAccount)
        ));
    }

    #[test]
    fn test_transaction_hash() {
        let alice_keypair: KeyPair = KeyPair::generate(&mut OsRng);
        let alice_pubkey = alice_keypair.verifying_key();

        let bob_keypair: KeyPair = KeyPair::generate(&mut OsRng);
        let bob_pubkey = bob_keypair.verifying_key();

        let unsigned_tx_1 = UnsignedTransaction::new(&alice_pubkey, &bob_pubkey, 50, 0).unwrap();
        let unsigned_tx_2 = UnsignedTransaction::new(&alice_pubkey, &bob_pubkey, 50, 0).unwrap();

        assert_eq!(unsigned_tx_1.hash(), unsigned_tx_2.hash())
    }
}
