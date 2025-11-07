use argon2::Error as EncryptionKeyError;
use chacha20poly1305::aead::Error as CryptographyError;
use ed25519_dalek::SignatureError;
use serde_json::Error as SerializationError;
use std::{fmt, num::ParseIntError};

#[derive(Debug)]
pub enum BlockchainError {
    // Ledger errors
    InvalidTransaction(SignatureError),
    InvalidNonce,
    InvalidSenderAccount,

    // Transaction errors
    InvalidNullAmount,
    InsufficientFunds,
    TransactionIntoSameAccount,
}

impl fmt::Display for BlockchainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            BlockchainError::InvalidTransaction(e) => {
                return write!(f, "Invalid transaction, signature does not match: {e}");
            }
            BlockchainError::InvalidNonce => "Nonce in transaction does not match nonce in ledger",
            BlockchainError::InvalidSenderAccount => "Account does not exist in ledger",
            BlockchainError::InvalidNullAmount => "Cannot transfer a null amount",
            BlockchainError::InsufficientFunds => "Insufficient funds to conduct the transaction",
            BlockchainError::TransactionIntoSameAccount => {
                "Cannot conduct a transaction with the same sender and receiver"
            }
        })
    }
}

impl std::error::Error for BlockchainError {}

impl From<SignatureError> for BlockchainError {
    fn from(err: SignatureError) -> Self {
        BlockchainError::InvalidTransaction(err)
    }
}

#[derive(Debug)]
pub enum KeyError {
    InvalidDataDirectory,
    InvalidPath(std::io::Error),
    KeyOverwrite,
    KeyNotFound,
    KeyDerivationError(EncryptionKeyError),
    EncryptionError(CryptographyError),
    DecryptionError(CryptographyError),
    KeySerializeError(SerializationError),
    KeyStoreError(ParseIntError),
    InvalidNonce,
    InvalidPrivateKey,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            KeyError::InvalidDataDirectory => "Could not access data directory",
            KeyError::InvalidPath(e) => return write!(f, "Invalid path: {e}"),
            KeyError::KeyOverwrite => "File already exists",
            KeyError::KeyNotFound => "File does not exist",
            KeyError::KeyDerivationError(e) => return write!(f, "Invalid password: {e}"),
            KeyError::EncryptionError(e) => return write!(f, "Could not encrypt private key: {e}"),
            KeyError::DecryptionError(e) => return write!(f, "Could not decrypt private key: {e}"),
            KeyError::KeySerializeError(e) => return write!(f, "Error in key serialization: {e}"),
            KeyError::KeyStoreError(e) => {
                return write!(
                    f,
                    "Data found in file does not match a valid private key encrypted data: {e}"
                );
            }
            KeyError::InvalidNonce => "Invalid decryption nonce in private key file",
            KeyError::InvalidPrivateKey => "Invalid private key found in file",
        })
    }
}

impl std::error::Error for KeyError {}

impl From<std::io::Error> for KeyError {
    fn from(err: std::io::Error) -> Self {
        KeyError::InvalidPath(err)
    }
}

impl From<EncryptionKeyError> for KeyError {
    fn from(err: EncryptionKeyError) -> Self {
        KeyError::KeyDerivationError(err)
    }
}

impl From<ParseIntError> for KeyError {
    fn from(err: ParseIntError) -> Self {
        KeyError::KeyStoreError(err)
    }
}

impl From<SerializationError> for KeyError {
    fn from(err: SerializationError) -> Self {
        KeyError::KeySerializeError(err)
    }
}
