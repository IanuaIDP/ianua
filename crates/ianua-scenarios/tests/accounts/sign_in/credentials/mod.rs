//! Max's password replaced: by Max with his current one, or by Ann, who
//! may reset another member's. A replacement is complete only when the
//! session Max held and his old password stop working, a reset link still
//! in his mailbox is worth nothing, and the new password signs him in; a
//! refused change leaves all of that as it was. Under pressure, a sign-in
//! must first solve a puzzle, which counts once and for one browser only.
//!
//! - `passwords`: Max changes his password; a refused change keeps his
//!   session and reset link; only Ann resets another member's password,
//!   never her own; a generated replacement really signs him in.
//! - `pressure`: a puzzle asked for after too many failures admits one
//!   sign-in from the browser that solved it, which still owes its mailbox.

mod passwords;
mod pressure;

use ianua_scenarios::api::{members, sessions};
use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::net::Client;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::sign_in::{MemberPasswordResetFor, PasswordSignIn, ResetLinkToken};
use ianua_scenarios::world::World;

use crate::factors::member::others_keep_access;
use crate::support::{mail_linking_to, settled_sign_in};

/// The replacement Max's password is changed to: a sentence that meets
/// the standard company's password rules, which no scanner takes for a
/// key.
const REPLACEMENT: &str = "Scenario mountain orchard lantern 7294";

/// The token of a reset link mailed to Max and left unspent, so a later
/// change of his password can be seen to spend it.
async fn unspent_reset_token(world: &World<'_>) -> String {
    sessions::request_member_password_reset(&MemberPasswordResetFor {
        email: world.member().email().to_owned(),
    })
    .send(world.anonymous().client())
    .await
    .ok();
    mail_linking_to(world.stack(), world.member().email(), "/reset-password")
        .await
        .token_in("/reset-password")
}

/// Fails unless Max's password is replaced by `password` through and
/// through: the session he held reads nothing, his old password is
/// refused, the reset link `reset_token` is worth nothing, the new
/// password signs him in to his own record, and his colleagues keep
/// exactly their own access.
async fn password_replaced(world: &World<'_>, password: &str, reset_token: &str) {
    members::me(world.org())
        .send(world.member().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    sessions::member_sign_in(&PasswordSignIn::of(
        world.member().email(),
        world.member().password(),
    ))
    .send(world.anonymous().client())
    .await
    .refused(Status::NOT_FOUND, "not_found");
    let link = sessions::member_reset_link_status(&ResetLinkToken {
        token: reset_token.to_owned(),
    })
    .send(world.anonymous().client())
    .await
    .ok();
    assert_eq!(
        link.status, "Expired",
        "the reset link mailed before the change is worth nothing"
    );
    assert_replacement_access(world, password).await;
    others_keep_access(world).await;
}

/// Max's replacement password opens a fresh browser session for his own account.
async fn assert_replacement_access(world: &World<'_>, password: &str) {
    let mut browser =
        Client::new(world.stack(), "Max, with his replacement password").expect("a client");
    let session = settled_sign_in(
        world.stack(),
        &browser,
        &PasswordSignIn::of(world.member().email(), password),
    )
    .await;
    browser.authorize(&session.refresh_token);
    assert_eq!(
        members::me(world.org()).send(&browser).await.ok().email,
        world.member().email(),
        "the replacement signs Max in to his own record"
    );
}

/// Fails unless the trail holds exactly one record of `event`, made by
/// `actor`, with none of `secrets` anywhere in it.
async fn recorded_once(world: &World<'_>, event: &str, actor: &str, secrets: &[&str]) {
    let records: Vec<_> = world
        .trail()
        .entries(event)
        .await
        .into_iter()
        .filter(|entry| entry.event_type == event)
        .collect();
    let [record] = records.as_slice() else {
        panic!("{event} is recorded once, not {} times", records.len());
    };
    assert!(
        record.actor.contains(actor),
        "{event} is recorded in {actor}'s name, not {}",
        record.actor
    );
    no_secret_leaked(&format!("{record:?}"), secrets);
}
