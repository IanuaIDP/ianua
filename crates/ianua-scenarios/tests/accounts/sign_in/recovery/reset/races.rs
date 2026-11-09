//! Max follows one reset link in two browsers at once and chooses a
//! different password in each: one reset wins and the other is refused,
//! only the winning password signs him in, and neither the loser nor
//! Mallory's later replay of the link overwrites it.

use ianua_scenarios::api::{members, sessions};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::sign_in::{PasswordSignIn, ResetLinkToken};
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;

use crate::recovery::reset::support::{
    CHANGED, access_after_reset, reset, reset_link, single_change,
};
use crate::support::settled_sign_in;

/// The two passwords Max chooses, one in each browser: different, so the
/// refused one overwriting the winner would show.
const PASSWORDS: [&str; 2] = [
    "Scenario chosen orchard lantern 6729",
    "Scenario chosen meadow harbour 8413",
];

/// Which of Max's two passwords the race kept and which it refused.
struct PasswordChoices {
    kept: &'static str,
    refused: &'static str,
}

/// Max follows one reset link on his laptop and his phone at the same
/// moment, choosing a different password on each. One reset wins: it
/// ends his old session and records one change, and only its password
/// signs him in. The losing reset cannot overwrite that password, and
/// Mallory's later replay neither changes it nor ends his fresh session. Ann,
/// Tess and Sam keep their access, and the record shows no secret.
#[tokio::test]
async fn simultaneous_password_resets_change_the_password_once() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    assert_access_before_race(&world).await;
    let token = reset_link(&world).await;

    let choices = competing_resets(&world, &token).await;
    access_after_reset(&world).await;
    let mut secrets = world.cast_secrets();
    secrets.extend(PASSWORDS.map(str::to_owned));
    secrets.push(token.clone());
    let changed = single_change(&world, &secrets).await;

    let mut browser = Client::new(&stack, "Max, with the winning password").expect("a client");
    secrets.push(signed_in_with_winner(&world, &mut browser, &choices).await);

    let mallory = Client::new(&stack, "Mallory, replaying Max's reset link").expect("a client");
    reject_replayed_reset(&world, &mallory, &token, &choices).await;
    assert_replay_access(&world, &browser, &mallory).await;
    access_after_reset(&world).await;
    assert_eq!(
        single_change(&world, &secrets).await,
        changed,
        "the replayed link changed nothing more"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// The race begins with no password changes and a usable member session.
async fn assert_access_before_race(world: &World<'_>) {
    assert_eq!(
        world.trail().count(CHANGED).await,
        0,
        "no password was changed before the race"
    );
    members::me(world.org())
        .send(world.member().client())
        .await
        .ok();
}

/// Replaying the spent link cannot install the losing password or sign Mallory in.
async fn reject_replayed_reset(
    world: &World<'_>,
    mallory: &Client,
    token: &str,
    choices: &PasswordChoices,
) {
    sessions::confirm_member_password_reset(&reset(token, choices.refused))
        .send(mallory)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    sessions::member_sign_in(&PasswordSignIn::of(world.member().email(), choices.refused))
        .send(mallory)
        .await
        .refused(Status::NOT_FOUND, "not_found");
}

/// The winner keeps account access and the replaying browser remains signed out.
async fn assert_replay_access(world: &World<'_>, browser: &Client, mallory: &Client) {
    Matrix::new(
        "reading one's own account after a replayed reset link",
        members::me(world.org()).call(),
    )
    .allowed(browser)
    .refused(mallory, Status::UNAUTHORIZED, "unauthenticated")
    .run()
    .await;
}

/// Max's laptop and phone send the two resets through `token` at the same
/// moment: one is accepted, the other refused as an unknown link, neither
/// signs in, and the link then reads as used. Which password won.
async fn competing_resets(world: &World<'_>, token: &str) -> PasswordChoices {
    let laptop = Client::new(world.stack(), "Max, resetting on his laptop").expect("a client");
    let phone = Client::new(world.stack(), "Max, resetting on his phone").expect("a client");
    let first = sessions::confirm_member_password_reset(&reset(token, PASSWORDS[0]));
    let second = sessions::confirm_member_password_reset(&reset(token, PASSWORDS[1]));
    let (first, second) = tokio::join!(first.send(&laptop), second.send(&phone));
    let mut answers = [first, second];
    let winner = answers
        .iter()
        .position(|answer| answer.status().is_success())
        .expect("one of the two resets is accepted");
    answers.sort_by_key(Answer::status);
    let [accepted, refused] = answers;
    accepted.ok();
    refused.refused(Status::NOT_FOUND, "not_found");
    assert_reset_browsers_signed_out(world, &laptop, &phone).await;
    assert_link_spent(&laptop, token).await;
    PasswordChoices {
        kept: PASSWORDS[winner],
        refused: PASSWORDS[1 - winner],
    }
}

/// Resetting alone authenticates neither competing browser.
async fn assert_reset_browsers_signed_out(world: &World<'_>, laptop: &Client, phone: &Client) {
    Matrix::new(
        "reading one's own account after resetting a password",
        members::me(world.org()).call(),
    )
    .refused(laptop, Status::UNAUTHORIZED, "unauthenticated")
    .refused(phone, Status::UNAUTHORIZED, "unauthenticated")
    .run()
    .await;
}

/// The winning reset leaves the shared link marked as already used.
async fn assert_link_spent(laptop: &Client, token: &str) {
    let asked = ResetLinkToken {
        token: token.to_owned(),
    };
    let worth = sessions::member_reset_link_status(&asked)
        .send(laptop)
        .await
        .ok();
    assert_eq!(worth.status, "AlreadyUsed", "the spent link reads as used");
}

/// Max's old password and the refused choice sign nobody in and read
/// nothing; the kept one signs him in through `browser`, to his own
/// company only. The session's token, for the leak checks.
async fn signed_in_with_winner(
    world: &World<'_>,
    browser: &mut Client,
    choices: &PasswordChoices,
) -> String {
    for password in [world.member().password(), choices.refused] {
        sessions::member_sign_in(&PasswordSignIn::of(world.member().email(), password))
            .send(browser)
            .await
            .refused(Status::NOT_FOUND, "not_found");
        members::me(world.org())
            .send(browser)
            .await
            .refused(Status::UNAUTHORIZED, "unauthenticated");
    }
    let sign_in = PasswordSignIn::of(world.member().email(), choices.kept);
    let session = settled_sign_in(world.stack(), browser, &sign_in).await;
    browser.authorize(&session.refresh_token);
    assert_eq!(
        members::me(world.org()).send(browser).await.ok().email,
        world.member().email(),
        "the kept password signs Max in"
    );
    members::me(world.stranger().org())
        .send(browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    session.refresh_token
}
