# 🌐 mini-blockchain-rust (Workspace) [![CI](https://github.com/Robik803/mini-blockchain-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/Robik803/mini-blockchain-rust/actions/workflows/ci.yml)

This repository contains a modular Rust workspace implementing a minimal, deterministic blockchain prototype.
The project is intentionally split into multiple crates to mirror the structure of real-world blockchain ecosystems:
- `core/` — Execution engine (accounts, transactions, ledger, keystore, etc.)
- *_(Coming next)_* `validator/` — Validator node (consensus, slot processing, reward logic)
- *_(Coming next)_* `cli/` — Command-line wallet & transaction tool
- *_(Coming next)_* `rpc/` — Lightweight HTTP RPC server for clients

The goal of this workspace is to build a fully functional blockchain prototype, step by step, following a clean modular architecture.

---

## 🧱 Workspace Structure

```text
.
├── core/                    # mini-blockchain-core crate
│   ├── src/
│   └── Cargo.toml
├── validator/               # (to be created)
├── cli/                     # (to be created)
├── rpc/                     # (to be created)
├── Cargo.toml               # workspace definition
└── README.md                # this file

```

---

## 🚀 Current Status
### ✔️ Completed
- Cryptographic keypairs (Ed25519)
- Keystore encryption (Argon2id + ChaCha20Poly1305)
- Accounts: balances + controlled mutation
- Unsigned & signed transactions
- Nonce-based replay-protection
- Instruction layer
- Deterministic ledger with full serialization
- Comprehensive unit & integration tests

### 🔧 In Progress (next phases)
- Validator implementation
- CLI wallet
- RPC server
- Networking model
- Reward/staking mechanics

---

## 🧪 Running all workspace tests

```bash
cargo test --workspace
```

---

## 📄 License

All crates licensed under [MIT license](http://opensource.org/licenses/MIT).