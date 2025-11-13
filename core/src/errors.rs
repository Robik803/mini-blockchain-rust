use argon2::Error as EncryptionKeyError;
use chacha20poly1305::aead::Error as CryptographyError;
use ed25519_dalek::SignatureError;
use serde_json::Error as SerializationError;
use std::{fmt, num::ParseIntError};

#[derive(Debug)]
pub enum BlockchainError {
    // Ledger errors
    LedgerCreationError,
    InvalidTransaction(SignatureError),
    InvalidNonce,
    InvalidSenderAccount,
    InvalidPath(std::io::Error),
    LedgerSerializationError(SerializationError),

    // Transaction errors
    InvalidNullAmount,
    InsufficientFunds,
    TransactionIntoSameAccount,
}

impl fmt::Display for BlockchainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            BlockchainError::LedgerCreationError => "Cannot create a ledger where the same account appears multiple times in definition",
            BlockchainError::InvalidTransaction(err) => {
                return write!(f, "Invalid transaction, signature does not match: {err}");
            },
            BlockchainError::InvalidNonce => "Nonce in transaction does not match nonce in ledger",
            BlockchainError::InvalidSenderAccount => "Account does not exist in ledger",
            BlockchainError::InvalidPath(err) => {
                return write!(f, "Invalid path: {err}");
            },
            BlockchainError::LedgerSerializationError(err) => {
                return write!(f, "Error in ledger serialization: {err}");
            },
            BlockchainError::InvalidNullAmount => "Cannot transfer a null amount",
            BlockchainError::InsufficientFunds => "Insufficient funds to conduct the transaction",
            BlockchainError::TransactionIntoSameAccount => {
                "Cannot conduct a transaction with the same sender and receiver"
            }
        })
    }
}

impl std::error::Error for BlockchainError {}

impl From<std::io::Error> for BlockchainError {
    fn from(err: std::io::Error) -> Self {
        BlockchainError::InvalidPath(err)
    }
}

impl From<SignatureError> for BlockchainError {
    fn from(err: SignatureError) -> Self {
        BlockchainError::InvalidTransaction(err)
    }
}

impl From<SerializationError> for BlockchainError{
    fn from(err: SerializationError) -> Self {
        BlockchainError::LedgerSerializationError(err)
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
    InvalidKeystoreFormat(HexStringError),
    InvalidNonce,
    InvalidPrivateKey,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            KeyError::InvalidDataDirectory => "Could not access data directory",
            KeyError::InvalidPath(err) => return write!(f, "Invalid path: {err}"),
            KeyError::KeyOverwrite => "File already exists",
            KeyError::KeyNotFound => "File does not exist",
            KeyError::KeyDerivationError(err) => return write!(f, "Invalid password: {err}"),
            KeyError::EncryptionError(err) => return write!(f, "Could not encrypt private key: {err}"),
            KeyError::DecryptionError(err) => return write!(f, "Could not decrypt private key: {err}"),
            KeyError::KeySerializeError(err) => return write!(f, "Error in key serialization: {err}"),
            KeyError::InvalidKeystoreFormat(err) => {
                return write!(
                    f,
                    "Data found in file does not match a valid private key encrypted data: {err}"
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

impl From<HexStringError> for KeyError {
    fn from(err: HexStringError) -> Self {
        KeyError::InvalidKeystoreFormat(err)
    }
}

impl From<SerializationError> for KeyError {
    fn from(err: SerializationError) -> Self {
        KeyError::KeySerializeError(err)
    }
}

#[derive(Debug)]
pub enum HexStringError {
    InvalidHexLength,
    InvalidHex(ParseIntError)
}

impl fmt::Display for HexStringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
         HexStringError::InvalidHex(err) => return write!(f, "Invalid hex string: {err}"),
         HexStringError::InvalidHexLength => "Hex string must have even length"
        })
    }
}

impl From<ParseIntError> for HexStringError{
    fn from(err: ParseIntError) -> Self {
        HexStringError::InvalidHex(err)
    }
}