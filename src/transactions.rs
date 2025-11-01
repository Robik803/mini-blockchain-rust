use std::cmp::{PartialEq};
use sha2::Sha512;
use rand::{RngCore, rngs::OsRng};
use ed25519_dalek::{Signature, Digest};

use crate::accounts::{PublicKey, KeyPair, pubkey_to_hex};
use crate::utils::get_timestamp;

pub const CONTEXT : &[u8] = b"Robik803MiniBlochainTxnSigning";

fn random_nonce() -> u64{
    let mut b = [0u8; 8];
    OsRng.fill_bytes(&mut b);
    u64::from_be_bytes(b)
}

#[derive(Debug, Clone)]
pub struct Transaction{
    pub from : PublicKey,
    pub to : PublicKey,
    pub amount : u64,
    pub nonce : u64,
    pub timestamp : u64,
    pub signature : Signature,
    pub hash : Sha512
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

impl std::fmt::Display for Transaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Tranaction : {{ from: {} -> to: {}, amount : {} RBK, at timestamp({})}}",
            pubkey_to_hex(&self.from),
            pubkey_to_hex(&self.to),
            self.amount,
            self.timestamp
        )
    }
}


#[cfg(test)]
mod tests{
    use std::fs;

    use crate::keys::load_key;
    use crate::transactions::CONTEXT;
    use crate::accounts::{Account, KeyPair, make_deposit};
    use crate::transactions::Transaction;


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

        println!("{}",transaction);

        let transaction = Transaction::new(&alice_keypair, &alice.public_key, 50);
        assert!(transaction.is_err());
        
        #[allow(unused)]
        {fs::remove_file(alice_path);
        fs::remove_file(bob_path);}

    }
}