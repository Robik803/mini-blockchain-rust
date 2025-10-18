mod accounts;
mod errors;
mod instructions;
use accounts::Account;

fn make_deposit(account: &mut Account, amount: u64) {
    match account.deposit(amount) {
        Ok((amount, public_key, balance)) => {
            println!(
                "Transaction completed. {} RBK deposited into the account {:?}",
                amount,
                public_key.as_bytes()
            );
            println!("New balance : {} RBK", balance)
        }
        Err(e) => println!("error in transaction : {e:?}"),
    }
}

fn make_withdraw(account: &mut Account, amount: u64) {
    match account.withdraw(amount) {
        Ok((amount, public_key, balance)) => {
            println!(
                "Transaction completed. {} RBK withdrawn from the account {:?}",
                amount,
                public_key.as_bytes()
            );
            println!("New balance : {} RBK", balance)
        }
        Err(e) => println!("error in transaction : {e:?}"),
    }
}

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
