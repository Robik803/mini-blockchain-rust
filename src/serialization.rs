use ed25519_dalek::Signature;
use serde::{Deserialize, Serializer, Deserializer};
use serde::de::Error;

use crate::keys::PublicKey;

pub mod pubkey {
    use super::*;

    pub fn serialize<S>(key: &PublicKey, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        s.serialize_bytes(key.as_bytes())
    }

    pub fn deserialize<'de, D>(d: D) -> Result<PublicKey, D::Error>
    where D: Deserializer<'de> {
        let bytes: Vec<u8> = Deserialize::deserialize(d)?;
        let public_key: [u8; 32] = bytes.try_into().map_err(|_| D::Error::custom("Invalid public key"))?;
        PublicKey::from_bytes(&public_key).map_err(D::Error::custom)
    }
}

pub mod signature {
    use super::*;

    pub fn serialize<S>(sig: &Signature, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        s.serialize_bytes(&sig.to_bytes())
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Signature, D::Error>
    where D: Deserializer<'de> {
        let bytes: Vec<u8> = Deserialize::deserialize(d)?;
        let signature_bytes: [u8; 64] = bytes.try_into().map_err(|_| D::Error::custom("Invalid signature"))?;
        Ok(Signature::from_bytes(&signature_bytes))
    }
}