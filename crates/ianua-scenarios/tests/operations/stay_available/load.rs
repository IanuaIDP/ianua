//! A burst of requests all at once, as a busy morning or a crowd of bots
//! sends them. Every one is answered, and in good time: served, refused,
//! or told to come back later. None is an unexpected failure, none hangs,
//! and once the burst is over Ann, who uses the platform, is served at
//! once.

use std::sync::Arc;
use std::time::Duration;

use ianua_scenarios::api::{members, sessions};
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::sign_in::PasswordSignIn;
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::error::Elapsed;
use tokio::time::timeout;

/// How many requests make up the bounded burst.
const BURST: usize = 300;

/// Concurrent requests the shared scenario database budget is sized to
/// serve.
const IN_FLIGHT: usize = 24;

/// How many addresses they come from.
const ADDRESSES: usize = 50;

/// How long any one of them may take to be answered.
const ANSWERED_WITHIN: Duration = Duration::from_secs(30);

/// The password the crowd's wrong sign-ins try: a sentence, so no scanner
/// takes it for a key.
const NOBODYS_PASSWORD: &str = "Not anybody's password at all 4127";

/// What the crowd's wrong sign-ins are called in the failure messages.
const WRONG_SIGN_IN: &str = "a wrong sign-in";

/// The response facts needed to judge a request after the burst completes.
struct BurstAnswer {
    status: Status,
    puzzle: bool,
    summary: String,
}

/// A request's expected outcome paired with its timed response.
struct BurstResult {
    what: &'static str,
    expected: Status,
    answered: Result<BurstAnswer, Elapsed>,
}

/// Whether `answer` asks for a sign-in puzzle: what the platform answers
/// an address once its wrong sign-ins pass the failure threshold, as a
/// crowd guessing from fifty addresses soon does.
fn asks_for_a_puzzle(answer: &Answer<IgnoredAny>) -> bool {
    answer.status() == Status::UNAUTHORIZED
        && answer
            .problem()
            .is_some_and(|problem| problem.code() == "challenge_required")
}

/// Three hundred requests, at most twenty-four in flight, from fifty
/// addresses: health checks, sign-ins with wrong passwords, and reads by
/// nobody signed in. Each is answered within half a minute with what it
/// should get or a "come back later", never a server error. Ann reads
/// her members straight after.
#[tokio::test]
async fn a_burst_is_answered_in_time_and_harms_nobody_after_it() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let crowd: Vec<Arc<Client>> = (0..ADDRESSES)
        .map(|at| {
            let client = Client::new(&stack, &format!("the crowd, {at}")).expect("a client");
            Arc::new(client)
        })
        .collect();
    let burst = start_burst(&world, &crowd);
    assert_burst_answered(burst).await;
    members::list(world.org(), None)
        .send(world.owner().client())
        .await
        .ok();
    stack.stop().await.expect("the stack stops cleanly");
}

/// Starts the mixed requests with their shared bound on concurrent work.
fn start_burst(world: &World<'_>, crowd: &[Arc<Client>]) -> JoinSet<BurstResult> {
    let mut burst = JoinSet::new();
    let slots = Arc::new(Semaphore::new(IN_FLIGHT));
    for at in 0..BURST {
        let client = Arc::clone(&crowd[at % ADDRESSES]);
        let slots = Arc::clone(&slots);
        let (what, call, expected) = burst_request(world, at);
        burst.spawn(async move {
            let answer = timeout(ANSWERED_WITHIN, async move {
                let _slot = slots.acquire().await.expect("the burst stays open");
                client.send::<IgnoredAny>(call).await
            })
            .await;
            BurstResult {
                what,
                expected,
                answered: answer.map(|answer| {
                    let puzzle = asks_for_a_puzzle(&answer);
                    BurstAnswer {
                        status: answer.status(),
                        puzzle,
                        summary: answer.summary(),
                    }
                }),
            }
        });
    }
    burst
}

/// Alternates health, invalid sign-in and anonymous directory requests.
fn burst_request(world: &World<'_>, at: usize) -> (&'static str, Call, Status) {
    match at % 3 {
        0 => ("a health check", Call::get("/health"), Status::OK),
        1 => (
            WRONG_SIGN_IN,
            sessions::member_sign_in(&PasswordSignIn::of(
                &world.address(&format!("unknown-{at}")),
                NOBODYS_PASSWORD,
            ))
            .call(),
            Status::NOT_FOUND,
        ),
        _ => (
            "a read by nobody signed in",
            members::list(world.org(), None).call(),
            Status::UNAUTHORIZED,
        ),
    }
}

/// Each task finishes in time with its expected status, throttling or a puzzle.
async fn assert_burst_answered(mut burst: JoinSet<BurstResult>) {
    while let Some(done) = burst.join_next().await {
        let BurstResult {
            what,
            expected,
            answered,
        } = done.expect("the request's task ends");
        let Ok(BurstAnswer {
            status,
            puzzle,
            summary,
        }) = answered
        else {
            panic!("{what} was not answered within {ANSWERED_WITHIN:?}");
        };
        assert!(
            status == expected
                || status == Status::TOO_MANY_REQUESTS
                || (what == WRONG_SIGN_IN && puzzle),
            "{what} got what it should, a come back later, or a puzzle, not {summary}"
        );
    }
}
