//! A crowd of bots guessing one person's password at once, as a targeted
//! attack does. Every guess is answered in good time, as a wrong guess, a
//! "come back later" or a puzzle, never a server error; and nobody else
//! notices: Max, working beside it, is served throughout.

use std::sync::Arc;
use std::time::Duration;

use ianua_scenarios::api::{members, sessions};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::sign_in::PasswordSignIn;
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::error::Elapsed;
use tokio::time::timeout;

/// How many guesses the bots make at Ann's password.
const GUESSES: usize = 200;

/// How many guesses are in flight at once: more than the ten database
/// connections a node keeps, so guesses that held one while waiting would
/// leave none for anybody else.
const IN_FLIGHT: usize = 24;

/// How many addresses the bots guess from.
const ADDRESSES: usize = 50;

/// How long any one request may take to be answered.
const ANSWERED_WITHIN: Duration = Duration::from_secs(30);

/// How many times Max reads his members while the bots guess.
const MAXS_READS: usize = 20;

/// The wait between two of Max's reads: a person clicking around.
const BETWEEN_READS: Duration = Duration::from_millis(250);

/// The password the bots try: a sentence, so no scanner takes it for a
/// key.
const GUESS: &str = "Not Ann's password at all 4127";

/// A completed guess keeps its status and diagnostic text for the assertion.
struct GuessAnswer {
    status: Status,
    acceptable: bool,
    summary: String,
}

/// Mallory's bots guess Ann's password two hundred times, twenty-four at
/// once, from fifty addresses. Each guess is answered within half a
/// minute as a wrong guess, a "come back later" or a puzzle, never a
/// server error. Max reads his members all the while and every read is
/// served. Ann, from her own laptop, signs in afterwards.
#[tokio::test]
async fn guessing_one_account_from_many_networks_harms_nobody_else() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut world = World::new(&stack).await;
    let bots: Vec<Arc<Client>> = (0..ADDRESSES)
        .map(|at| Arc::new(Client::new(&stack, &format!("Mallory's bot {at}")).expect("a client")))
        .collect();
    let guess = PasswordSignIn::of(world.owner().email(), GUESS);
    let attack = start_guesses(&bots, &guess);
    assert_max_served(&world).await;
    assert_guesses_answered(attack).await;
    world.owner_mut().sign_in(&stack).await;
    members::me(world.org())
        .send(world.owner().client())
        .await
        .ok();
    stack.stop().await.expect("the stack stops cleanly");
}

/// Starts every guess under the same concurrency and per-request deadline.
fn start_guesses(
    bots: &[Arc<Client>],
    guess: &PasswordSignIn,
) -> JoinSet<Result<GuessAnswer, Elapsed>> {
    let mut attack = JoinSet::new();
    let slots = Arc::new(Semaphore::new(IN_FLIGHT));
    for at in 0..GUESSES {
        let bot = Arc::clone(&bots[at % ADDRESSES]);
        let slots = Arc::clone(&slots);
        let call = sessions::member_sign_in(guess).call();
        attack.spawn(async move {
            timeout(ANSWERED_WITHIN, async move {
                let _slot = slots.acquire().await.expect("the attack stays open");
                let answer = bot.send::<IgnoredAny>(call).await;
                GuessAnswer {
                    status: answer.status(),
                    acceptable: acceptable_guess_answer(&answer),
                    summary: answer.summary(),
                }
            })
            .await
        });
    }
    attack
}

/// Max's concurrent directory reads remain successful throughout the guesses.
async fn assert_max_served(world: &World<'_>) {
    let mut clicking = tokio::time::interval(BETWEEN_READS);
    for _ in 0..MAXS_READS {
        clicking.tick().await;
        let read = members::list(world.org(), None)
            .send(world.member().client())
            .await;
        assert_eq!(
            read.status(),
            Status::OK,
            "Max is served while the bots guess: {}",
            read.summary()
        );
    }
}

/// Every task finishes before its deadline with an expected refusal or challenge.
async fn assert_guesses_answered(mut attack: JoinSet<Result<GuessAnswer, Elapsed>>) {
    while let Some(done) = attack.join_next().await {
        let answered = done.expect("the guess's task ends");
        let Ok(GuessAnswer {
            status,
            acceptable,
            summary,
        }) = answered
        else {
            panic!("a guess was not answered within {ANSWERED_WITHIN:?}");
        };
        assert!(
            acceptable,
            "a guess gets a wrong guess, a come back later or a puzzle, not {status}: {summary}"
        );
    }
}

/// Whether `answer` is one a guess may get: refused as a wrong guess,
/// told to come back later, or asked for the sign-in puzzle.
fn acceptable_guess_answer(answer: &Answer<IgnoredAny>) -> bool {
    let code = answer.problem().map(|problem| problem.code().to_owned());
    let status = answer.status();
    status == Status::TOO_MANY_REQUESTS
        || (status == Status::NOT_FOUND && code.as_deref() == Some("not_found"))
        || (status == Status::UNAUTHORIZED && code.as_deref() == Some("challenge_required"))
}
