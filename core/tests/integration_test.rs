use std::fs;
use std::path::Path;

use mini_blockchain_core::accounts::*;
use mini_blockchain_core::keys::*;
use mini_blockchain_core::ledger::*;
use mini_blockchain_core::transactions::*;
use mini_blockchain_core::instructions::*;
use mini_blockchain_core::constants::*;

#[test]
fn test_full_ledger_flow() {
    let password = "password123";
    let (alice, alice_path) = Account::new(password).unwrap();
    let (bob, bob_path) = Account::new(password).unwrap();
    let (charlie, charlie_path) = Account::new(password).unwrap();

    let alice = Account::with_balance(alice.public_key(), 300);

    let accounts = vec![alice, bob];

    let mut ledger = Ledger::new(accounts).unwrap();

    let alice = Account::import_from_json(&alice_path, password).unwrap();
    let bob = Account::import_from_json(&bob_path, password).unwrap();

    let alice_pubkey_hex = pubkey_to_hex(&alice.public_key());
    let bob_pubkey_hex = pubkey_to_hex(&bob.public_key());
    let charlie_pubkey_hex = pubkey_to_hex(&charlie.public_key());

    assert_eq!(ledger.accounts()[&alice_pubkey_hex].public_key(), alice.public_key());
    assert_eq!(ledger.accounts()[&bob_pubkey_hex].public_key(), bob.public_key());
    assert_eq!(ledger.accounts()[&alice_pubkey_hex].torvalds(), 300);
    assert_eq!(ledger.accounts()[&bob_pubkey_hex].torvalds(), 0);
    assert_eq!(ledger.accounts()[&alice_pubkey_hex].nonce(), 0);
    assert_eq!(ledger.accounts()[&bob_pubkey_hex].nonce(), 0);

    let alice_private_key = load_key(password, &alice_path).unwrap();
    let alice_keypair = KeyPair::from_bytes(&alice_private_key);
    let bob_private_key = load_key(password, &bob_path).unwrap();
    let bob_keypair = KeyPair::from_bytes(&bob_private_key);

    // Transfer 1
    let unsigned_tx = UnsignedTransaction::new(&alice.public_key(), &bob.public_key(), 50, 1).unwrap();
    let signature = alice_keypair
            .sign_prehashed(unsigned_tx.prehashed(), Some(CONTEXT))
            .unwrap();
    let signed_tx = SignedTransaction::new(unsigned_tx, signature).unwrap();

    let transfer = Instruction::Transfer(signed_tx);

    ledger.execute_instruction(transfer).unwrap();

    assert_eq!(ledger.accounts()[&alice_pubkey_hex].torvalds(), 250);
    assert_eq!(ledger.accounts()[&bob_pubkey_hex].torvalds(), 50);
    assert_eq!(ledger.accounts()[&alice_pubkey_hex].nonce(), 1);
    assert_eq!(ledger.accounts()[&bob_pubkey_hex].nonce(), 0);

    // Transfer 2
    let unsigned_tx = UnsignedTransaction::new(&bob.public_key(), &alice.public_key(), 30, 1).unwrap();
    let signature = bob_keypair
            .sign_prehashed(unsigned_tx.prehashed(), Some(CONTEXT))
            .unwrap();
    let signed_tx = SignedTransaction::new(unsigned_tx, signature).unwrap();

    let transfer = Instruction::Transfer(signed_tx);

    ledger.execute_instruction(transfer).unwrap();

    assert_eq!(ledger.accounts()[&alice_pubkey_hex].torvalds(), 280);
    assert_eq!(ledger.accounts()[&bob_pubkey_hex].torvalds(), 20);
    assert_eq!(ledger.accounts()[&alice_pubkey_hex].nonce(), 1);
    assert_eq!(ledger.accounts()[&bob_pubkey_hex].nonce(), 1);

    // Transfer 3
    let unsigned_tx = UnsignedTransaction::new(&alice.public_key(), &charlie.public_key(), 30, 2).unwrap();
    let signature = alice_keypair
            .sign_prehashed(unsigned_tx.prehashed(), Some(CONTEXT))
            .unwrap();
    let signed_tx = SignedTransaction::new(unsigned_tx, signature).unwrap();

    let transfer = Instruction::Transfer(signed_tx);

    ledger.execute_instruction(transfer).unwrap();

    assert_eq!(ledger.accounts()[&charlie_pubkey_hex].public_key(), charlie.public_key());
    assert_eq!(ledger.accounts()[&alice_pubkey_hex].torvalds(), 250);
    assert_eq!(ledger.accounts()[&charlie_pubkey_hex].torvalds(), 30);
    assert_eq!(ledger.accounts()[&alice_pubkey_hex].nonce(), 2);
    assert_eq!(ledger.accounts()[&charlie_pubkey_hex].nonce(), 0);

    // Ledger

    let path = Path::new("test_ledger.json");
    ledger.save_to_file(path).unwrap();
    let restored = Ledger::load_from_file(Path::new("test_ledger.json")).unwrap();

    assert_eq!(ledger.accounts().len(), restored.accounts().len());
    assert!(restored.history().len() > 0);

    #[allow(unused)]
    {
        fs::remove_file(alice_path);
        fs::remove_file(bob_path);
        fs::remove_file(charlie_path);
        fs::remove_file(path);
    }
}
