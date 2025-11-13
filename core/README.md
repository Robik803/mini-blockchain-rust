# 📘 mini-blockchain-core

`mini-blockchain-core` is the foundational Rust library powering a minimal, deterministic blockchain system.
It provides secure account handling, signed transactions, instruction execution, custom keystore encryption, and a deterministic ledger model.

This crate implements the minimal execution layer of a blockchain:
- account ownership via Ed25519 keys  
- deterministic state transitions  
- transaction verification (signature + nonce)  
- replay protection  
- deterministic ledger mutation  
- safe serialization for persistence  

Everything else — consensus, networking, validators, RPC — is intentionally out of scope.


---

## 🚀 Features

- Ed25519 accounts with deterministic serialization.
- Argon2id + ChaCha20Poly1305 keystore for encrypted private-key storage.
- Unsigned + signed transactions with SHA-512 prehashing.
- Strict nonce validation (replay attack prevention).
- Deterministic ledger based on HashMap<pubkey_hex, Account>.
- Instruction execution layer (Instruction::Transfer).
- Full serialization & storage via serde.
- Clean API surface: only the modules meant to be public are exposed.

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
- `save_key(password: &str, path: &Path, private_key: &[u8;32]) -> Result<(), KeyError>`
- `load_key(password: &str, path: &Path) -> Result<[u8;32], KeyError>`
- `generate_and_save(password: &str) -> Result<(PublicKey, PathBuf), KeyError>`
- `pubkey_to_hex(public_key: &PublicKey) -> String`
- `ensure_keys_dir_exists()`

### 💼 Account System (State Layer)

Implements a simple account model similar to what major blockchains use (public key, balance, nonce).

**Struct**
- `Account`

**Core methods**
- `new(password: &str) -> (Account, PathBuf)`
- `from_private_key(private_key_bytes: &[u8;32]) -> Account`
- `import_from_json(path: &Path, password: &str) -> Account`
- `deposit(...)`
- `withdraw(...)`

Implements `Display` for human-readable output.

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
- `SignedTransaction::new(unsigned_tx: UnsignedTransaction, signature: Signature)` Verifies signature internally

### 📝 Instructions

Defines the interface through which actions are executed on the ledger.

**Enums**
- `Instruction{Transfer(SignedTransaction)}`

### 📜 Ledger (Execution Layer)

Early ledger system laying groundwork for blockchain transaction flow.

**Structs**
- `Ledger`

**Core methods**
- `Ledger::execute_instruction(instruction: Instruction)` — public entry point for all ledger actions (currently delegates to internal process_transaction).


### 🛠️ Utils

**Core methods**
- `get_timestamp() -> u64`
- `encode_hex` / `decode_hex`

---

## 🧱 Project Structure

```text
core/
├── src/
│   ├── accounts.rs        # Account model & balance logic
│   ├── instructions.rs    # Instruction enum
│   ├── transactions.rs    # Unsigned/SignedTransaction
│   ├── ledger.rs          # Deterministic ledger
│   ├── keys.rs            # Key generation, keystore, encryption
│   ├── serialization.rs   # Custom serde helpers
│   ├── utils.rs           # Timestamp & hex utilities
│   └── errors.rs          # Core error definitions
└── tests/
    └── integration_test.rs
```

---

## 🧪 Testing

The project includes:
- unit tests inside each module
- integration tests under core/tests/
- full flow test (create accounts → create ledger → send tx → validate result)
Run all tests:
```bash
cargo test
```

---

## 📄 License

MIT License — free for personal or commercial use.