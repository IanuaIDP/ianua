//! Sign-in under pressure: after too many failures from one address the
//! platform asks that browser for a puzzle before it checks another
//! password. Max solves his; the solution admits one sign-in, from his
//! browser alone, and that sign-in still owes his mailbox. Mallory, from
//! another address, gets nothing from Max's solution.

use ianua_scenarios::api::{members, sessions};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::sign_in::{
    ConfirmSignIn, PasswordSignIn, Session, SignInPuzzle, SignedIn,
};
use ianua_scenarios::world::World;
use sha2::{Digest as _, Sha256};

use crate::support::{WRONG_GUESS, mail_linking_to};

/// Failed sign-ins from one address before the platform asks it for a
/// puzzle: set low, so a handful of guesses reaches it.
const FAILURES_BEFORE_A_PUZZLE: usize = 10;

/// The zero bits a solution's hash must start with: one whole byte, so
/// the search checks the hash's first byte and ends within the budget.
const PUZZLE_BITS: u8 = 8;

/// The most counters tried for a solution: a one-byte puzzle is solved
/// in two hundred and fifty-six tries on average, so a search this long
/// failing means the puzzle is not the one advertised.
const SEARCH_BUDGET: u64 = 1_000_000;

/// Max's browser guesses wrong at ten addresses nobody holds, and his own
/// right password is then refused until the browser solves a puzzle.
/// Mallory, from another address, sends Max's solution with his password
/// and is still asked for a puzzle of her own. Max's browser signs in
/// with it, once: the same solution again is refused, and the sign-in it
/// admitted reads nothing until the mailed link finishes it, when Max
/// reads his own record.
#[tokio::test]
async fn a_solved_puzzle_admits_one_sign_in_from_its_own_browser_which_still_owes_its_mailbox() {
    let stack = Stack::start(
        Profile::standard()
            .with(
                "SIGN_IN_FAILURE_THRESHOLD",
                &FAILURES_BEFORE_A_PUZZLE.to_string(),
            )
            .with("SIGN_IN_PUZZLE_DIFFICULTY_BITS", &PUZZLE_BITS.to_string()),
    )
    .await
    .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut browser = Client::new(&stack, "Max, solving a sign-in puzzle").expect("a client");

    trigger_puzzle(&world, &browser).await;
    let sign_in = PasswordSignIn::of(world.member().email(), world.member().password());
    sessions::member_sign_in(&sign_in)
        .send(&browser)
        .await
        .refused(Status::UNAUTHORIZED, "challenge_required");

    let puzzle = sessions::sign_in_puzzle().send(&browser).await.ok();
    let solved = sign_in.clone().solving(&solution_of(&puzzle));
    let mallory = Client::new(&stack, "Mallory, with Max's solution").expect("a client");
    sessions::member_sign_in(&solved)
        .send(&mallory)
        .await
        .refused(Status::UNAUTHORIZED, "challenge_required");

    let waiting = admit_once(&world, &mut browser, &solved).await;
    confirm_admitted_session(&world, &browser, waiting).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// A burst of nonexistent-account guesses makes this browser owe a puzzle.
async fn trigger_puzzle(world: &World<'_>, browser: &Client) {
    for guess in 0..FAILURES_BEFORE_A_PUZZLE {
        sessions::member_sign_in(&PasswordSignIn::of(
            &world.address(&format!("absent-{guess}")),
            WRONG_GUESS,
        ))
        .send(browser)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    }
}

/// The solution opens one waiting session and cannot bypass mailbox proof or be reused.
async fn admit_once(world: &World<'_>, browser: &mut Client, solved: &PasswordSignIn) -> Session {
    let answer = sessions::member_sign_in(solved).send(browser).await.ok();
    let SignedIn::Authenticated(waiting) = answer else {
        panic!("Max is in one organization, so no choice is offered");
    };
    browser.authorize(&waiting.refresh_token);
    members::me(world.org())
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    sessions::member_sign_in(solved)
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "challenge_required");
    waiting
}

/// Max's mailed proof completes exactly the session admitted by the solved puzzle.
async fn confirm_admitted_session(world: &World<'_>, browser: &Client, waiting: Session) {
    let mail = mail_linking_to(world.stack(), world.member().email(), "/confirm-sign-in").await;
    sessions::confirm_member_sign_in(&ConfirmSignIn {
        token: mail.token_in("/confirm-sign-in"),
        refresh_token: waiting.refresh_token,
    })
    .send(browser)
    .await
    .ok();
    assert_eq!(
        members::me(world.org()).send(browser).await.ok().id,
        world.member().id(),
        "the mailed link finishes the sign-in the puzzle admitted"
    );
}

/// The solution to `puzzle`, `challenge.counter`, found the way the API
/// documents it and nowhere near the platform's own code: the first
/// counter whose SHA-256 of `challenge:counter` starts with a zero byte.
fn solution_of(puzzle: &SignInPuzzle) -> String {
    assert_eq!(
        puzzle.difficulty_bits, PUZZLE_BITS,
        "the puzzle asks for the configured difficulty"
    );
    for counter in 0..SEARCH_BUDGET {
        let hash = Sha256::digest(format!("{}:{counter}", puzzle.challenge));
        if hash[0] == 0 {
            return format!("{}.{counter}", puzzle.challenge);
        }
    }
    panic!("the one-byte puzzle has no solution within {SEARCH_BUDGET} tries");
}
