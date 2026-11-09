//! Bob, the platform's operator, on the operator plane: he signs in with
//! his password for a key and works with it; a company Ann closed stays
//! closed even to him; and Mallory guessing his password locks her own
//! network out, never Bob.

use std::net::{IpAddr, Ipv4Addr};

use ianua_scenarios::api::{operators, organizations, sessions};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::operators::OperatorSignIn;
use ianua_scenarios::wire::sign_in::PasswordSignIn;
use ianua_scenarios::world::World;

use crate::support::{BOBS_OFFICE, bob_signed_in, bobs_password};

/// The network Mallory guesses from, in a documentation range of its own.
const MALLORYS_LAPTOP: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 66));

/// Wrong passwords that lock a network out of an operator's address: the
/// strict policy operators are held to.
const GUESSES_BEFORE_LOCKOUT: usize = 3;

/// A wrong guess at Bob's password: a sentence, so no scanner takes it for
/// a key.
const WRONG_GUESS: &str = "Not the operator password at all 4127";

/// Bob signs in with his password and works with the key he gets: he
/// reads his own account. After Ann closes her company, Bob cannot reopen
/// it, and Ann's password still opens nothing there.
#[tokio::test]
async fn bob_works_with_his_key_but_cannot_reopen_a_closed_company() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;

    let bob = bob_signed_in(&stack).await;
    let account = operators::get(&bob.id).send(&bob.client).await.ok();
    assert_eq!(
        account.email,
        stack.operator().email(),
        "Bob's key reads his own account"
    );
    assert_eq!(account.status, "Active", "Bob's account is active");

    organizations::close(world.org())
        .send(world.owner().client())
        .await
        .ok();
    organizations::reactivate(world.org())
        .send(&bob.client)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    let sign_in = PasswordSignIn {
        organization: Some(world.org().slug().to_owned()),
        ..PasswordSignIn::of(world.owner().email(), world.owner().password())
    };
    sessions::member_sign_in(&sign_in)
        .send(world.anonymous().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Mallory guesses Bob's password from her laptop three times,
/// and then tries his real password from it. Every try is answered alike,
/// and the real password from her laptop gets her nothing. Bob, from his
/// office, signs in as usual.
#[tokio::test]
async fn guessing_bobs_password_locks_out_the_guessers_network_and_never_bob() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mallory = Client::at(&stack, "Mallory, guessing", MALLORYS_LAPTOP).expect("a client");
    let guess = OperatorSignIn {
        password: WRONG_GUESS.to_owned(),
        ..bobs_password(&stack)
    };

    for _ in 0..GUESSES_BEFORE_LOCKOUT {
        operators::sign_in(&guess)
            .send(&mallory)
            .await
            .refused(Status::NOT_FOUND, "not_found");
    }
    operators::sign_in(&bobs_password(&stack))
        .send(&mallory)
        .await
        .refused(Status::NOT_FOUND, "not_found");

    let office = Client::at(&stack, "Bob, at his office", BOBS_OFFICE).expect("a client");
    let made = operators::sign_in(&bobs_password(&stack))
        .send(&office)
        .await
        .ok();
    assert!(
        made.key_prefix.starts_with("opk_"),
        "Bob's sign-in from his office makes him an operator key"
    );

    stack.stop().await.expect("the stack stops cleanly");
}
