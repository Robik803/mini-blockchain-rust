mod accounts;
mod errors;
mod instructions;
use accounts::{Account, make_deposit, make_withdraw};

fn main() {
    let mut alice = Account::new();
    alice.show();
    let private_key = alice.public_key.as_bytes();
    let mut bob = Account::from_private_key(private_key);
    bob.show();
    println!("{}", alice);
    println!("{}", bob);
    make_deposit(&mut alice, 50);
    make_deposit(&mut bob, 80);
    make_withdraw(&mut alice, 25);
}
