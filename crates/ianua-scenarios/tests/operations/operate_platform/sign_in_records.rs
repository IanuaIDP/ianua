//! Every operator sign-in leaves a record in the platform's log, which
//! only an operator reads: a key made for the operator who signed in, or
//! a refusal naming the address typed, why it was refused and where it
//! came from. The refusals all answer alike; only the record tells them
//! apart, and no record holds a password.

use std::net::{IpAddr, Ipv4Addr};

use ianua_scenarios::api::{audit, operators};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::audit::AuditEntry;
use ianua_scenarios::wire::operators::{NewOperator, OperatorSignIn};
use ianua_scenarios::world::World;

use crate::support::{Bob, bob_signed_in, bobs_password};

/// The network Mallory guesses from, in a documentation range of its own.
const MALLORYS_LAPTOP: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 91));

/// The network Carol signs in from.
const CAROLS_DESK: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 21));

/// Wrong passwords that lock a network out of an operator's address.
const GUESSES_BEFORE_LOCKOUT: usize = 3;

/// A wrong guess at Bob's password: a sentence, so no scanner takes it for
/// a key.
const WRONG_GUESS: &str = "Not the operator password either 5830";

/// Carol's password: a sentence, so no scanner takes it for a key.
const CAROLS_PASSWORD: &str = "Carol keeps the night shift lantern 7714";

/// The record a refused operator sign-in leaves.
const SIGN_IN_FAILED: &str = "operator.operator_sign_in_failed";

/// The record a key made for an operator leaves.
const KEY_CREATED: &str = "operator.operator_api_key_created";

/// One refusal as the platform's log should hold it: the address typed,
/// why, and the network it came from.
struct Refusal<'a> {
    email: &'a str,
    reason: &'a str,
    from: IpAddr,
}

/// Bob makes Carol an operator; she signs in once, and Bob disables her.
/// Her right password then gets her nothing. Mallory, from her laptop,
/// tries an address no operator holds, guesses Bob's password three times
/// and then tries his real one. Every refusal answers the same not found.
/// In the platform's log Bob reads one record for each refusal, naming the
/// address typed, the true reason (no such operator, a wrong password
/// three times, a network locked out, a disabled account) and the network
/// it came from. Bob's and Carol's sign-ins that worked are recorded as
/// keys made for each of them. No record holds a password, and Tess, who
/// administers a tenant, may not read the platform's log.
#[tokio::test]
async fn every_refused_operator_sign_in_is_recorded_with_its_reason() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let bob = bob_signed_in(&stack).await;
    let carol = world.address("carol");
    let carols_id = carol_disabled_after_one_sign_in(&stack, &bob, &carol).await;
    let nobody = world.address("nobody");
    mallory_guesses(&stack, &nobody).await;

    let refusals = platform_records(&bob, &[("event_type", SIGN_IN_FAILED)]).await;
    let bobs_address = stack.operator().email();
    let expected = [
        Refusal {
            email: &nobody,
            reason: "user_not_found",
            from: MALLORYS_LAPTOP,
        },
        Refusal {
            email: bobs_address,
            reason: "account_locked",
            from: MALLORYS_LAPTOP,
        },
        Refusal {
            email: &carol,
            reason: "account_deactivated",
            from: CAROLS_DESK,
        },
    ];
    for refusal in &expected {
        assert_eq!(
            matching(&refusals, refusal),
            1,
            "one {} refusal of {} is recorded",
            refusal.reason,
            refusal.email
        );
    }
    let guessed = Refusal {
        email: bobs_address,
        reason: "bad_password",
        from: MALLORYS_LAPTOP,
    };
    assert_eq!(
        matching(&refusals, &guessed),
        GUESSES_BEFORE_LOCKOUT,
        "each of Mallory's wrong guesses is recorded"
    );
    assert_eq!(
        refusals.len(),
        expected.len() + GUESSES_BEFORE_LOCKOUT,
        "nothing else is recorded as a refused sign-in"
    );

    assert_keys_recorded(&bob, &carols_id).await;
    assert_no_password_recorded(&stack, &bob).await;
    audit::platform_log_where(&[("event_type", SIGN_IN_FAILED)])
        .send(world.admin().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Carol, made an operator by Bob at the address `carol`, signs in once
/// from her desk, is disabled by Bob, and is refused with her right
/// password afterwards. Her operator id.
async fn carol_disabled_after_one_sign_in(stack: &Stack, bob: &Bob, carol: &str) -> String {
    let made = operators::create(&NewOperator {
        email: carol.to_owned(),
        password: CAROLS_PASSWORD.to_owned(),
    })
    .send(&bob.client)
    .await
    .ok();
    let desk = Client::at(stack, "Carol, at her desk", CAROLS_DESK).expect("a client for Carol");
    let carols_sign_in = OperatorSignIn {
        email: carol.to_owned(),
        password: CAROLS_PASSWORD.to_owned(),
    };
    operators::sign_in(&carols_sign_in).send(&desk).await.ok();
    operators::disable(&made.id).send(&bob.client).await.ok();
    operators::sign_in(&carols_sign_in)
        .send(&desk)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    made.id
}

/// Mallory, from her laptop, tries the address `nobody` no operator
/// holds, guesses Bob's password until his address is locked against her
/// network, then tries his real password. Each try is refused alike.
async fn mallory_guesses(stack: &Stack, nobody: &str) {
    let mallory = Client::at(stack, "Mallory, guessing", MALLORYS_LAPTOP).expect("a client");
    let unknown = OperatorSignIn {
        email: nobody.to_owned(),
        password: WRONG_GUESS.to_owned(),
    };
    operators::sign_in(&unknown)
        .send(&mallory)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    let guess = OperatorSignIn {
        password: WRONG_GUESS.to_owned(),
        ..bobs_password(stack)
    };
    for _ in 0..GUESSES_BEFORE_LOCKOUT {
        operators::sign_in(&guess)
            .send(&mallory)
            .await
            .refused(Status::NOT_FOUND, "not_found");
    }
    operators::sign_in(&bobs_password(stack))
        .send(&mallory)
        .await
        .refused(Status::NOT_FOUND, "not_found");
}

/// The platform's records `filters` pick, as Bob reads them.
async fn platform_records(bob: &Bob, filters: &[(&str, &str)]) -> Vec<AuditEntry> {
    audit::platform_log_where(filters)
        .send(&bob.client)
        .await
        .ok()
        .items
}

/// How many of `records` are the refusal `refusal`.
fn matching(records: &[AuditEntry], refusal: &Refusal<'_>) -> usize {
    let from = refusal.from.to_string();
    records
        .iter()
        .filter(|record| {
            record.details["email"] == refusal.email
                && record.details["reason"] == refusal.reason
                && record.details["ip_address"] == from.as_str()
        })
        .count()
}

/// Bob's sign-in is recorded as a key made by him, and Carol's one
/// sign-in as one key made by her.
async fn assert_keys_recorded(bob: &Bob, carols_id: &str) {
    let bobs_actor = format!("operator:{}", bob.id);
    let bobs = platform_records(
        bob,
        &[("event_type", KEY_CREATED), ("actor", bobs_actor.as_str())],
    )
    .await;
    assert!(
        !bobs.is_empty(),
        "Bob's sign-in is recorded as a key made by him"
    );
    let carols_actor = format!("operator:{carols_id}");
    let carols = platform_records(
        bob,
        &[
            ("event_type", KEY_CREATED),
            ("actor", carols_actor.as_str()),
        ],
    )
    .await;
    assert_eq!(
        carols.len(),
        1,
        "Carol's one sign-in that worked is recorded once"
    );
}

/// No operator record holds Bob's password, Mallory's guess or Carol's
/// password.
async fn assert_no_password_recorded(stack: &Stack, bob: &Bob) {
    let records = platform_records(bob, &[("event_type", "operator.")]).await;
    let written = serde_json::to_string(
        &records
            .iter()
            .map(|record| &record.details)
            .collect::<Vec<_>>(),
    )
    .expect("the records' details as JSON");
    for secret in [stack.operator().password(), WRONG_GUESS, CAROLS_PASSWORD] {
        assert!(
            !written.contains(secret),
            "no operator record holds a password"
        );
    }
}
