mod accounts;
mod errors;
mod instructions;
use accounts::Account;

fn main() {
    let alice = Account::new();
    alice.show();
    let private_key = alice.public_key.as_bytes();
    let bob = Account::from_private_key(private_key);
    bob.show();
    println!("{}", alice);
    println!("{}", bob);
}
