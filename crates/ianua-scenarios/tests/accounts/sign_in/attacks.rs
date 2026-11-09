//! Sign-in as an attacker tries it: telling a real address from a made-up
//! one, guessing a password over and over, guessing from many networks at
//! once, using a session after its owner signed out, and a session token
//! tampered with or put in the address.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ianua_scenarios::actors::{FOUNDER_PASSWORD, Founder};
use ianua_scenarios::api::OrgPath;
use ianua_scenarios::api::sessions::member_sign_out;
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::{Trail, eventually, no_secret_leaked};
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::sign_in::{Owed, PasswordSignIn, Session, SignOut};
use ianua_scenarios::wire::{Answer, Status};
use serde::de::IgnoredAny;
use tokio::task::JoinSet;

use crate::support::WRONG_GUESS;

/// One address's initial burst allowance and tokens refilled per minute:
/// the platform's default, which the standard stack keeps.
const SIGN_INS_A_MINUTE: usize = 20;

/// How many addresses Mallory's bots guess from: twice the ten failures
/// the organization allows one address, which is the count of failing
/// networks that marks an account under attack, and two more so the mark
/// is passed whichever sign-in looks.
const BOTS: u8 = 22;

/// Outcomes of one address's concurrent guesses, used to check admission and retry guidance.
struct GuessResults {
    /// A rate-limit refusal retained for its retry header.
    slowed: Option<Answer<IgnoredAny>>,
    /// Guesses admitted to password checking.
    admitted: usize,
}

/// Mallory tries Ann's real address with a wrong password, and an address
/// nobody holds: both answers are the same status, code and words, so
/// neither tells her Ann has an account.
#[tokio::test]
async fn a_real_address_and_a_made_up_one_answer_alike() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let ann = Founder::named(&stack, "Ann");
    ann.founded(&stack, "Acme").await;
    let mallory = Client::new(&stack, "Mallory, probing addresses").expect("a client");

    let real = mallory
        .post::<IgnoredAny>(
            "/api/v1/login",
            &PasswordSignIn::of(ann.email(), WRONG_GUESS),
        )
        .await
        .refused(Status::NOT_FOUND, "not_found");
    let nobody = format!("nobody@{}", stack.base_domain());
    let made_up = mallory
        .post::<IgnoredAny>("/api/v1/login", &PasswordSignIn::of(&nobody, WRONG_GUESS))
        .await
        .refused(Status::NOT_FOUND, "not_found");
    assert_eq!(
        real.message(),
        made_up.message(),
        "the same words either way"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Mallory bursts guesses from one address beyond its initial allowance and
/// a whole minute's refill. Admissions stay within that allowance plus elapsed
/// refill, and a refusal says when to try again.
/// Ann, at her own address, still signs in: the guessing locks out the
/// guesser, not the person guessed at.
#[tokio::test]
async fn guessing_slows_the_guesser_and_never_locks_out_the_owner() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let ann = Founder::named(&stack, "Ann");
    ann.founded(&stack, "Acme").await;
    let mallory = Arc::new(Client::new(&stack, "Mallory, guessing").expect("a client"));
    let guess = PasswordSignIn::of(ann.email(), WRONG_GUESS);
    let started = Instant::now();
    let mut guesses = JoinSet::new();
    for _ in 0..=(SIGN_INS_A_MINUTE * 2) {
        let mallory = Arc::clone(&mallory);
        let guess = guess.clone();
        guesses.spawn(async move { mallory.post::<IgnoredAny>("/api/v1/login", &guess).await });
    }

    let results = collect_guesses(guesses).await;
    assert_guess_limits(results, started.elapsed());

    ann.signed_in(&stack).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Every completed guess is either rate limited or refused as an incorrect password.
async fn collect_guesses(mut guesses: JoinSet<Answer<IgnoredAny>>) -> GuessResults {
    let mut results = GuessResults {
        slowed: None,
        admitted: 0,
    };
    while let Some(result) = guesses.join_next().await {
        let answer = result.expect("each guess finishes");
        if answer.status() == Status::TOO_MANY_REQUESTS {
            results.slowed.get_or_insert(answer);
            continue;
        }
        assert_eq!(
            answer.status(),
            Status::NOT_FOUND,
            "a wrong guess: {}",
            answer.summary()
        );
        results.admitted += 1;
    }
    results
}

/// The burst stays within the refill allowance and a rate-limit response gives positive retry time.
fn assert_guess_limits(results: GuessResults, elapsed: Duration) {
    assert!(
        elapsed < Duration::from_secs(60),
        "the guessing burst must finish within one refill period: {elapsed:?}"
    );
    let refilled = usize::try_from(elapsed.as_secs() / 3)
        .expect("less than a minute refills fewer than twenty tokens");
    let admitted = results.admitted;
    assert!(
        admitted <= SIGN_INS_A_MINUTE + refilled,
        "{admitted} guesses exceeded the initial allowance and refill in {elapsed:?}"
    );
    let slowed = results
        .slowed
        .expect("a burst beyond the initial allowance and refill is refused");
    let retry_after = slowed
        .header("retry-after")
        .and_then(|seconds| seconds.parse::<u64>().ok());
    assert!(
        retry_after.is_some_and(|seconds| seconds > 0),
        "the rate-limit refusal says when to try again: {}",
        slowed.summary()
    );
}

/// Mallory's bots guess Ann's password from many addresses at once, each
/// too few times to be locked out on its own. The platform notices the
/// account under attack and records it, with no password in the record.
/// Ann, on the laptop she remembered, signs in with her password alone
/// and notices nothing; a bot arriving late is still answered as a wrong
/// password is, so the attack locks nobody out of the account.
#[tokio::test]
async fn guessing_from_many_networks_is_noticed_and_never_touches_the_owners_laptop() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let founded = ann.founded(&stack, "Acme").await;
    let first = ann.signed_in(&stack).await;
    let mut phone = ann.set_up_authenticator(&founded.org_slug, &first).await;
    let proved = ann.signed_in_with(&stack, &mut phone).await;
    ann.remember_device(&founded.org_slug, &proved).await.ok();

    let guess = PasswordSignIn::of(ann.email(), WRONG_GUESS);
    run_independent_bots(&stack, &guess).await;

    assert_remembered_access(&mut ann, &founded.org_slug, &proved).await;
    bot(&stack, BOTS + 1)
        .post::<IgnoredAny>("/api/v1/login", &guess)
        .await
        .refused(Status::NOT_FOUND, "not_found");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann's remembered laptop remains usable while the attack is recorded without its secrets.
async fn assert_remembered_access(ann: &mut Founder, org_slug: &str, proved: &Session) {
    let from_laptop = ann.password_sign_in().await;
    assert_eq!(
        from_laptop.owed(),
        Owed::Nothing,
        "Ann's remembered laptop is asked for nothing more"
    );
    ann.client_mut().authorize(&from_laptop.refresh_token);
    let trail = Trail::of_organization(ann.client(), org_slug);
    let noticed = trail
        .recorded("organization.org_account_under_attack")
        .await;
    no_secret_leaked(
        &noticed.details.to_string(),
        &[FOUNDER_PASSWORD, WRONG_GUESS, &proved.refresh_token],
    );
}

/// Independent networks finish their concurrent wrong guesses without opening any session.
async fn run_independent_bots(stack: &Stack, guess: &PasswordSignIn) {
    let mut guesses = JoinSet::new();
    for host in 1..=BOTS {
        let bot = bot(stack, host);
        let guess = guess.clone();
        guesses.spawn(async move {
            answered_past_busy(&bot, &guess)
                .await
                .refused(Status::NOT_FOUND, "not_found");
        });
    }
    while let Some(result) = guesses.join_next().await {
        result.expect("each independent bot finishes its refused sign-in");
    }
}

/// The answer `bot`'s guess gets once the server is not too busy to check
/// it: a crowd arriving at once may first be told to come back shortly,
/// and a bot does, as a real one would.
async fn answered_past_busy(bot: &Client, guess: &PasswordSignIn) -> Answer<IgnoredAny> {
    eventually("the server to check the bot's guess", || async {
        let answer = bot.post::<IgnoredAny>("/api/v1/login", guess).await;
        (answer.status() != Status::TOO_MANY_REQUESTS).then_some(answer)
    })
    .await
}

/// Mallory's bot number `host`, at an address of its own in the range
/// set aside for benchmarking, which no other client stands for.
fn bot(stack: &Stack, host: u8) -> Client {
    let address = IpAddr::V4(Ipv4Addr::new(198, 18, 0, host));
    Client::at(stack, &format!("Mallory's bot {host}"), address).expect("a client")
}

/// Ann signs out. Mallory, who copied Ann's session token before that,
/// finds it dead: it reads nothing any more.
#[tokio::test]
async fn a_session_is_dead_once_its_owner_signs_out() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let founded = ann.founded(&stack, "Acme").await;
    let session = ann.signed_in(&stack).await;
    ann.client_mut().authorize(&session.refresh_token);
    let members = format!("/api/v1/organizations/{}/users", founded.org_slug);

    let mut mallory = Client::new(&stack, "Mallory, with a copied token").expect("a client");
    mallory.authorize(&session.refresh_token);
    let before = mallory.send::<IgnoredAny>(Call::get(&members)).await;
    assert_eq!(before.status(), Status::OK, "the copied token works before");

    let sign_out = SignOut {
        session_id: session.session_id.clone(),
    };
    let signed_out = member_sign_out(&OrgPath::new(&founded.org_slug), &sign_out)
        .send(ann.client())
        .await;
    assert!(
        signed_out.status().is_success(),
        "Ann signs out: {}",
        signed_out.summary()
    );

    mallory
        .send::<IgnoredAny>(Call::get(&members))
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Mallory tampers with Ann's session token, and tries it where no
/// client should put it, in the address: neither reads anything.
#[tokio::test]
async fn a_tampered_token_or_one_in_the_address_reads_nothing() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let ann = Founder::named(&stack, "Ann");
    let founded = ann.founded(&stack, "Acme").await;
    let session = ann.signed_in(&stack).await;
    let members = format!("/api/v1/organizations/{}/users", founded.org_slug);

    let mut tampered = Client::new(&stack, "Mallory, with a tampered token").expect("a client");
    tampered.authorize(&format!("{}x", session.refresh_token));
    tampered
        .send::<IgnoredAny>(Call::get(&members))
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    let in_the_address =
        Client::new(&stack, "Mallory, with a token in the address").expect("a client");
    for parameter in ["access_token", "token", "session"] {
        in_the_address
            .send::<IgnoredAny>(Call::get(format!(
                "{members}?{parameter}={}",
                session.refresh_token
            )))
            .await
            .refused(Status::UNAUTHORIZED, "unauthenticated");
    }

    stack.stop().await.expect("the stack stops cleanly");
}
