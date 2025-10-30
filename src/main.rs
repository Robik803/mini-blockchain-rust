mod accounts;
mod errors;
mod instructions;
mod keys;
use accounts::{Account, make_deposit, make_withdraw};
use keys::{load_key, ensure_keys_dir_exists, encode_hex};

fn main() {

    
    let password = "password123"; //for test

    let mut alice = Account::new(password);
    alice.show();
    let private_key = alice.public_key.as_bytes();
    let mut bob = Account::from_private_key(private_key);
    bob.show();
    println!("{}", alice);
    println!("{}", bob);
    make_deposit(&mut alice, 50);
    make_deposit(&mut bob, 80);
    make_withdraw(&mut alice, 25);
    
    let pubkey_hex = encode_hex(&alice.public_key.to_bytes()).replace(&['[', ']', ',', ' '][..], "");

    let dir = ensure_keys_dir_exists().unwrap();
    let path = dir.join(format!("{pubkey_hex}.json"));

    let private_key_alice = match load_key(password, &path){
        Ok(pk) => pk,
        Err(e) => {println!("{}",e); [0u8;32]}
    };

    let alice_copy1 = Account::from_private_key(&private_key_alice);

    let alice_copy2 = Account::import_from_json(&path, password);

    alice.show();
    alice_copy1.show();
    alice_copy2.show();

}
