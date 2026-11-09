//! Ann's authenticator codes at sign-in: a code she typed is spent, so it
//! finishes no second sign-in; and Mallory, with Ann's password but not
//! her phone, finds the factor locked long before a guess could land.

use ianua_scenarios::actors::{FOUNDER_PASSWORD, Founder};
use ianua_scenarios::api::{OrgPath, member_factors, members, sessions};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::factors::FactorCode;
use ianua_scenarios::wire::sign_in::{Owed, PasswordSignIn, Session, SignedIn};

/// Codes Mallory tries: more than the platform's five wrong codes before
/// the factor locks.
const GUESSED_CODES: [&str; 7] = [
    "000000", "111111", "222222", "333333", "444444", "555555", "666666",
];

/// Ann set up an authenticator app and signs in with its code. On her
/// tablet she signs in again and types the same code: it was spent, so it
/// is refused and the sign-in still reads nothing. The next code the app
/// shows lets her in. Only the application clock moves between codes;
/// the spent code is retried in the same step in which it succeeded.
#[tokio::test]
async fn a_code_is_spent_once() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let ann = Founder::named(&stack, "Ann");
    let founded = ann.founded(&stack, "Acme").await;
    let org = OrgPath::new(&founded.org_slug);
    let first = ann.signed_in(&stack).await;
    let mut phone = ann.set_up_authenticator(&founded.org_slug, &first).await;
    ann.signed_in_with(&stack, &mut phone).await;

    let mut tablet = Client::new(&stack, "Ann, on her tablet").expect("a client");
    let waiting = owing_a_code(&tablet, ann.email()).await;
    tablet.authorize(&waiting.refresh_token);
    let spent = FactorCode {
        code: phone.last_code_again(),
    };
    assert_spent_code(&tablet, &org, &spent).await;

    let fresh = FactorCode {
        code: phone.code().await,
    };
    member_factors::verify(&org, &fresh)
        .send(&tablet)
        .await
        .ok();
    members::me(&org).send(&tablet).await.ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// Replaying an accepted code leaves the tablet's pending session unable to read Ann's account.
async fn assert_spent_code(tablet: &Client, org: &OrgPath, spent: &FactorCode) {
    member_factors::verify(org, spent)
        .send(tablet)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    members::me(org)
        .send(tablet)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// Mallory, with Ann's password but not her phone, is asked for the
/// code and guesses: each wrong code is refused, and before her guesses
/// get far the factor locks and answers no more. Her sign-in reads
/// nothing throughout.
#[tokio::test]
async fn guessing_codes_locks_the_factor() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let ann = Founder::named(&stack, "Ann");
    let founded = ann.founded(&stack, "Acme").await;
    let org = OrgPath::new(&founded.org_slug);
    let first = ann.signed_in(&stack).await;
    ann.set_up_authenticator(&founded.org_slug, &first).await;

    let mut mallory = Client::new(&stack, "Mallory, guessing codes").expect("a client");
    let waiting = owing_a_code(&mallory, ann.email()).await;
    mallory.authorize(&waiting.refresh_token);
    assert_guesses_lock(&mallory, &org).await;
    members::me(&org)
        .send(&mallory)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    stack.stop().await.expect("the stack stops cleanly");
}

/// The configured guess sequence reaches the factor lock before all guesses can be checked.
async fn assert_guesses_lock(mallory: &Client, org: &OrgPath) {
    let mut locked = None;
    for guess in GUESSED_CODES {
        let code = FactorCode {
            code: guess.to_owned(),
        };
        let answer = member_factors::verify(org, &code).send(mallory).await;
        if answer.status() == Status::TOO_MANY_REQUESTS {
            locked = Some(answer);
            break;
        }
        answer.refused(Status::FORBIDDEN, "forbidden");
    }
    let Some(locked) = locked else {
        panic!("{} wrong codes were all answered", GUESSED_CODES.len());
    };
    locked.refused(Status::TOO_MANY_REQUESTS, "account_locked");
}

/// The session Ann's password opens through `client`, on a device she
/// never remembered, so it owes the code from her phone.
async fn owing_a_code(client: &Client, email: &str) -> Session {
    let answer = sessions::member_sign_in(&PasswordSignIn::of(email, FOUNDER_PASSWORD))
        .send(client)
        .await
        .ok();
    let SignedIn::Authenticated(session) = answer else {
        panic!("Ann is in one organization, so no choice is offered");
    };
    assert_eq!(
        session.owed(),
        Owed::FactorCode,
        "a device never remembered is asked for the code"
    );
    session
}
