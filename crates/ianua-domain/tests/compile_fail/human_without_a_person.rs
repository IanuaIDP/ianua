//! A human is always stored with the person behind the account, so a
//! two-person rule never compares accounts alone.

use ianua_domain::types::{Human, HumanAccount, PersonKey};

fn take_apart(human: Human) -> (HumanAccount, PersonKey) {
    let Human { account, person } = human;
    (account, person)
}

fn main() {}
