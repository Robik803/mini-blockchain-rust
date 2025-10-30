# Mini Blockchain (Rust)

Learning blockchain structure through building a small simulator with Rust.

## Overview
A hands-on Rust project to understand blockchain fundamentals by developing a small, modular simulator.  
Focus areas: ownership, traits, error handling, serialization, and CLI design.

---

## Structure
- `accounts.rs` → account models and balances
- `keys.rs` → encryption, serialization and save/load of private keys
- `instructions.rs` → core operations (`transfer`, `mint`, `burn`)  
- `errors.rs` → custom error definitions  
- `main.rs` → program entrypoint

---

## Current status

### `Account` Struct

The struct `Account` contains the Public Key of the account and the Balance.

#### Implementations `impl Account`

```rust
pub fn new() -> Self
```
Creates a new account with a generated keypair and zero balance. It saves the private key encrypted and Serialize in a JSON file.

```rust
pub fn from_private_key(private_key_bytes: &[u8; 32]) -> Self
```
Creates an account from an existing private key.

```rust
pub fn import_from_json(path : &Path, password: &str) -> Self
```
Creates an account from an existing private key stored in a JSON file.

```rust
pub fn show(&self)
```
Displays account information

```rust
pub fn deposit(&mut self, amount:u64) -> Result<(u64, &VerifyingKey, &u64), &'static str>
```
Deposits an amount into the account. Returns a `Result` with either a tuple with the deposit information or and error message.

```rust
pub fn withdraw(&mut self, amount: u64) -> Result<(u64, &VerifyingKey, &u64), &'static str>
```
Withdraw an amount from account. Returns a `Result` with either a tuple with the withdraw information or and error message.

### Crate `keys`

Allows to encrypt a private key, save the encryption data into a struct `KeyStore` that is then serialized, and saved into a JSON file.
User can afterwards retrieve said private key from the JSON file.

---

## Goal
To master Rust through practical development before moving to on-chain programs with Anchor on Solana.