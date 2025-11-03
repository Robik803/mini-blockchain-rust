use argon2::{
    Argon2,
    password_hash::{SaltString}
};
#[allow(deprecated)]
use chacha20poly1305::{aead::{Aead, KeyInit, generic_array::GenericArray}, ChaCha20Poly1305};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::{fs, path::{Path,PathBuf}};
use std::num::ParseIntError;

use crate::utils::{get_timestamp, decode_hex, encode_hex};

/// Implemented as an alias of ed25519_dalek::VerifyingKey
pub type PublicKey = VerifyingKey;
/// Implemented as an alias of ed25519_dalek::SigningKey
pub type KeyPair = SigningKey;

/// Turns a public key into a hex String
pub fn pubkey_to_hex(public_key: &PublicKey) -> String{
    encode_hex(&public_key.to_bytes()).replace(&['[', ']', ',', ' '][..], "")
}

// Getting an encryption key from a password
fn derive_key_from_password(password: &str, salt: &[u8]) -> [u8; 32] {
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, argon2::Params::new(19456, 2, 1, Some(32)).unwrap());
    let mut key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut key).unwrap();
    key
}

// Encrypt the plaintext with Chacha20Poly1305
#[allow(deprecated)]
fn encrypt_chacha(key: &[u8; 32], plaintext: &[u8]) -> (Vec<u8>, [u8;12]) {
    let cypher = ChaCha20Poly1305::new_from_slice(key).unwrap();
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let cyphertext = cypher.encrypt(GenericArray::from_slice(&nonce), plaintext)
                           .expect("encryption failure!");
    (cyphertext, nonce)
}

// Decrypt the plaintext with Chacha20Poly1305
#[allow(deprecated)]
fn decrypt_chacha(key: &[u8; 32], nonce: &[u8; 12], cyphertext: &[u8]) -> Vec<u8> {
    let cypher = ChaCha20Poly1305::new_from_slice(key).unwrap();
    cypher.decrypt(GenericArray::from_slice(nonce), cyphertext)
          .expect("decryption failure!")
}

// Struct conatining the data to decrypt the private key.
#[derive(Serialize, Deserialize)]
struct Keystore{
    version: u32,
    algorithm: String,
    pubkey_hex: String,
    cyphertext_hex: String,
    nonce_hex: String,
    kdf: KdfInfo,
    created_at: u64,
}

#[derive(Serialize, Deserialize)]
struct KdfInfo {
    name: String,
    salt_hex: String,
    params: KdfParams,
}

#[derive(Serialize, Deserialize)]
struct KdfParams { m: u32, t: u32, p: u32 }

impl Keystore{

    // Create a new Keystore
    fn default(pubkey: &[u8], cyphertext: &[u8], nonce: &[u8; 12], salt: &[u8]) -> Self{
        let time = get_timestamp();
        Keystore{
            version : 1,
            algorithm: "chacha20poly1305".to_string(),
            pubkey_hex: encode_hex(pubkey),
            cyphertext_hex: encode_hex(cyphertext),
            nonce_hex: encode_hex(nonce),
            kdf: KdfInfo{
                name: "argon2id".to_string(),
                salt_hex: encode_hex(salt),
                params: KdfParams { m: 19456, t: 2, p: 1 }
            },
            created_at: time
        }
    }

    // Extract decryption data from KeyStore
    fn load_decryption_data(&self) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), ParseIntError>{

        let cyphertext = match decode_hex(&self.cyphertext_hex){
            Ok(c) => c,
            Err(e) => return Err(e)
        };

        let nonce = match decode_hex(&self.nonce_hex){
            Ok(n) => n,
            Err(e) => return Err(e)
        };

        let salt = match decode_hex(&self.kdf.salt_hex){
            Ok(s) => s,
            Err(e) => return Err(e)
        };

        Ok((cyphertext, nonce, salt))
    }
}

// Save a Keystore into a JSON file
fn save_json(path: &Path, ks: &Keystore) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(ks).unwrap();
    fs::write(path, json)
}

// Load a Keystore from a JSON file
fn load_json(path: &Path) -> std::io::Result<Keystore> {
    let data = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&data).unwrap())
}

// Get key storage directory
fn get_keys_dir() -> Option<PathBuf> {
    dirs::data_dir().map(|base| base.join("MiniBlockchain").join("keys"))
}

/// Ensure key storage directory exists
pub fn ensure_keys_dir_exists() -> std::io::Result<std::path::PathBuf> {
    let path = get_keys_dir().expect("Couldn't check data directory of user.");
    fs::create_dir_all(&path)?;
    Ok(path)
}


/// Save the private key encrypted in a JSON file saved in the path given.
pub fn save_key(password: &str, path: &Path, private_key: &[u8;32]) -> Result<&'static str, &'static str> {

    // Check if there already a file with that name
    if fs::exists(path).expect("Can't check if this account already exists."){
        return Err("There already is an file with this name.");
    }

    // Create the salt to derive the encryption key from the password
    let salt_string = SaltString::generate(&mut OsRng);
    let salt = salt_string.as_str().as_bytes();

    // Generate an ecnryption key
    let encryption_key = derive_key_from_password(password, salt);

    // Encrypt the private key
    let (cyphertext, nonce) = encrypt_chacha(&encryption_key, private_key);

    // Get the public key from the private key
    let public_key = KeyPair::from_bytes(private_key).verifying_key().to_bytes();

    // Creating the Keystore to serialize
    let to_store = Keystore::default(&public_key, &cyphertext, &nonce, salt);

    // Saving the serialized KeyStore in a JSON file
    match save_json(path, &to_store){
        Ok(_) => Ok("Private key saved successfully."),
        Err(_)=> Err("Couldn't save private key.")
    }
}

/// Load the private key encrypted in the JSON file saved in the path given.
pub fn load_key(password: &str, path: &Path) -> Result<[u8;32], &'static str>{

    // Check if the file exists
    if !fs::exists(path).expect("Can't check if this account already exists."){
        return Err("This file doesn't exist.");
    }

    // Load data from JSON file
    let data_stored = match load_json(path){
        Ok(data) => data,
        Err(_) => return Err("Couldn't load the decryption data from the file.")
    };

    // Extract the decryption data
    let (cyphertext, nonce_vec, salt) = match data_stored.load_decryption_data() {
        Ok(values) => values,
        Err(_) => return Err("The data stored isn't valid")
    };

    // Verify if nonce has a valid length
    let nonce: [u8; 12] = match nonce_vec.try_into() {
        Ok(n) => n,
        Err(_) => return Err("Invalid nonce in JSON file.")
    };

    // Derive encryption key from password
    let encryption_key = derive_key_from_password(password, &salt);

    // Get the private key in Vec
    let private_key_vec = decrypt_chacha(&encryption_key, &nonce, &cyphertext);

    // Verify if private key has a valid length
    let private_key: [u8; 32] = match private_key_vec.try_into() {
        Ok(priv_key) => priv_key,
        Err(_) => return Err("Invalid private key in JSON file.")
    };
    println!("Private key loaded successfully.");
    Ok(private_key)

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keystore_serialization_roundtrip() {

        let password = "1234prueba";

        let keypair: KeyPair = KeyPair::generate(&mut OsRng);
        let private_key = keypair.to_bytes();

        let salt_string = SaltString::generate(&mut OsRng);
        let salt = salt_string.as_str().as_bytes();
        let encryption_key = derive_key_from_password(password, salt);
        let (cyphertext, nonce) = encrypt_chacha(&encryption_key, &private_key);
        let public_key = KeyPair::from_bytes(&private_key).verifying_key().to_bytes();

        let ks1 = Keystore::default(&public_key, &cyphertext, &nonce, salt);

        let json = serde_json::to_string_pretty(&ks1).unwrap();
        let ks2: Keystore = serde_json::from_str(&json).unwrap();

        assert_eq!(ks1.version, ks2.version);
        assert_eq!(ks1.algorithm, ks2.algorithm);
        assert_eq!(ks1.kdf.name, ks2.kdf.name);
    }

    #[test]
    fn test_save_and_load_key(){

        let password = "1234prueba";

        let keypair: KeyPair = KeyPair::generate(&mut OsRng);
        let private_key = keypair.to_bytes();

        let public_key: PublicKey = keypair.verifying_key();
        let pubkey_hex = encode_hex(&public_key.to_bytes()).replace(&['[', ']', ',', ' '][..], "");

        let dir = ensure_keys_dir_exists().unwrap();
        let path = dir.join(format!("{pubkey_hex}.json"));

        match save_key(password, &path, &private_key){
            Ok(msg) => println!("{}",msg),
            Err(msg) => println!("{}",msg)
        }

        let private_key_2 = match load_key(password, &path){
            Ok(pk) => pk,
            Err(e) => {println!("{}",e); [0u8;32]}
        };

        assert_eq!(private_key,private_key_2);

        let _ = fs::remove_file(path);

    }

}