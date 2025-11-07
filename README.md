# Mini Blockchain Simulator in Rust 🦀🔗

This project is a personal learning experiment to understand blockchain internals by **rebuilding the essential components from scratch** in Rust — inspired by Solana's account model and cryptography.

## Overview
A hands-on Rust project to understand blockchain fundamentals by developing a small, modular simulator.  
Focus areas: ownership, traits, error handling, serialization, and CLI design.

---

## ✅ Current Features

### 🔐 Key Management (Off-chain)

Secure keystore system with:
- Private key encryption using Argon2id + Chacha20Poly1305
- JSON keystore format (public key, ciphertext, nonce, salt, metadata)
- Key derivation from password
- Load/save functions with error propagation
- Platform-safe storage directory resolution

**Aliases**
- `PublicKey` : Implemented as an alias of `ed25519_dalek::VerifyingKey`
- `Keypair` : Implemented as an alias of `ed25519_dalek::SigningKey`

**Public API**
- `save_key(password: &str, path: &Path, private_key: &[u8;32]) -> Result<&'static str, &'static str>`
- `load_key(password: &str, path: &Path) -> Result<[u8;32], &'static str>`
- `pubkey_to_hex(public_key: &PublicKey) -> String`
- `ensure_keys_dir_exists`

---

### 💼 Account System (State Layer)

Imitates blockchain account model.

**Struct**
- `Account`

**Core methods**
- `new(password: &str) -> (Account, PathBuf)`
- `from_private_key(private_key_bytes: &[u8;32]) -> Account`
- `import_from_json(path: &Path, password: &str) -> Account`
- `show(&self)`
- `deposit(...)`
- `withdraw(...)`

Implements `Display` for human-readable output.

---

### 💱 Transactions

System allowing to verify transactions validity.

**Traits**
- `Message`

**Structs**
- `UnsignedTransaction{from, to, amount, nonce, timestamp} impl Messasge`
- `SignedTransaction{from, to, amount, nonce, timestamp, signature} impl Message`

**Core methods**
- `Message::`
    - `sender(&self)-> &PublicKey`
    - `receiver(&self) -> &PublicKey`
    - `amount(&self) -> u64`
    - `nonce(&self) -> u64`
    - `timestamp(&self) -> u64`
    - `to_bytes(&self) -> Vec<u8>`
    - `prehashed(&self) -> Sha512`
- `UnsignedTransaction::new(from: &PublicKey, to: &PublicKey, amount: u64, nonce: u64)`
---

### 📜 Ledger (Execution Layer)

Early ledger system laying groundwork for blockchain transaction flow.

**Structs**
- `Ledger`

**Core methods**
- `Ledger::process_transaction(...)`

---

### 🛠️ Utils

**Core methods**
- `get_timestamp() -> u64`
- `encode_hex` / `decode_hex`

---

### 🧪 Testing

All modules have tests verifying:
- Key save/load round-trip
- Account creation & balance changes
- JSON keystore validity
- Transaction creation
- Transaction processing by Ledger

**All tests currently passing ✅**

---

## 🧩 Project Structure

```text
src/
├─ accounts.rs # Account model & basic local transfers
├─ keys.rs # Key storage & encryption
├─ ledger.rs # Ledger skeleton
├─ transactions.rs # Transaction structure
├─ utils.rs # Utilities
├─ errors.rs # Error handling
└─ lib.rs
```

## 🎯 Roadmap

### Done ✅
- Secure keystore
- Account system
- Local balance ops
- Transaction struct + hashing + validation rules
- Ledger signature verification
- Add nonce tracking per account

### Next Steps 🚧
- Build CLI for wallet commands
- Persist ledger state

### Later 🚀
- Blocks or PoH-like history
- Networking (validator simulation)
- CLI wallet UX polish
- RPC-style interface for sending txs
- Web UI explorer
---

## 📚 Purpose

This is not a cryptocurrency — it’s a **hands-on educational blockchain simulator**, building core concepts step-by-step to deeply understand practical development before moving to on-chain programs with Anchor on Solana.

## 🧠 Status

> **Actively being built.**  
Core cryptography, accounts and first ledger prototype complete.  
Now entering **Instructions implementation** phase.