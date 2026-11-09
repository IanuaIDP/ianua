//! Ann suspends her company while Max is midway through a sign-in: every
//! session and waiting sign-in is ended, and lifting the suspension
//! brings none of them back. Ann signs in afresh to lift it herself, Max
//! signs in afresh after, and Sam's company is untouched throughout.

use ianua_scenarios::api::{members, organizations, sessions};
use ianua_scenarios::expect::Trail;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::sign_in::{ConfirmSignIn, PasswordSignIn, SignedIn};
use ianua_scenarios::world::World;

use crate::support::{mail_linking_to, settled_sign_in};

/// Max's password is accepted and his sign-in waits for his mailbox when
/// Ann suspends the company. Ann's own session is ended by that, Max's
/// mailed link finishes nothing, and his password is refused. Ann signs
/// in afresh and lifts the suspension: Max's old link still finishes
/// nothing and his waiting sign-in reads nothing, a fresh sign-in opens
/// his account, Sam still reads in his own company, and the suspension
/// and its lifting are both recorded.
#[tokio::test]
async fn suspension_ends_pending_access_and_only_fresh_sign_in_returns_after_reactivation() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut browser =
        Client::new(&stack, "Max, signing in before the suspension").expect("a client");
    let sign_in = PasswordSignIn::of(world.member().email(), world.member().password());
    let proof = begin_pending_sign_in(&world, &mut browser, &sign_in).await;
    suspend_pending_access(&world, &browser, &proof, &sign_in).await;
    let ann = reactivate_without_old_access(&world, &browser, &proof).await;

    let fresh = settled_sign_in(&stack, &browser, &sign_in).await;
    browser.authorize(&fresh.refresh_token);
    assert_eq!(
        members::me(world.org()).send(&browser).await.ok().id,
        world.member().id(),
        "a fresh sign-in after the suspension opens Max's own account"
    );
    members::me(world.stranger().org())
        .send(world.stranger().client())
        .await
        .ok();
    assert_eq!(
        Trail::of_organization(&ann, world.org().slug())
            .count("organization.status_changed")
            .await,
        2,
        "the suspension and its lifting are each recorded"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Max holds the mailed confirmation for the session that the suspension will interrupt.
async fn begin_pending_sign_in(
    world: &World<'_>,
    browser: &mut Client,
    sign_in: &PasswordSignIn,
) -> ConfirmSignIn {
    let answer = sessions::member_sign_in(sign_in).send(browser).await.ok();
    let SignedIn::Authenticated(waiting) = answer else {
        panic!("Max is in one organization, so no choice is offered");
    };
    let mail = mail_linking_to(world.stack(), world.member().email(), "/confirm-sign-in").await;
    let proof = ConfirmSignIn {
        token: mail.token_in("/confirm-sign-in"),
        refresh_token: waiting.refresh_token.clone(),
    };
    browser.authorize(&waiting.refresh_token);
    proof
}

/// Suspending the company ends Ann's session, invalidates Max's proof and refuses his password.
async fn suspend_pending_access(
    world: &World<'_>,
    browser: &Client,
    proof: &ConfirmSignIn,
    sign_in: &PasswordSignIn,
) {
    organizations::suspend(world.org())
        .send(world.owner().client())
        .await
        .ok();
    members::me(world.org())
        .send(world.owner().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    sessions::confirm_member_sign_in(proof)
        .send(browser)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    sessions::member_sign_in(sign_in)
        .send(browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// Ann reactivates through a fresh session, but Max's old link and session remain dead.
async fn reactivate_without_old_access(
    world: &World<'_>,
    browser: &Client,
    proof: &ConfirmSignIn,
) -> Client {
    let mut ann = Client::new(world.stack(), "Ann, lifting the suspension").expect("a client");
    let anns = settled_sign_in(
        world.stack(),
        &ann,
        &PasswordSignIn::of(world.owner().email(), world.owner().password()),
    )
    .await;
    ann.authorize(&anns.refresh_token);
    organizations::reactivate(world.org()).send(&ann).await.ok();
    sessions::confirm_member_sign_in(proof)
        .send(browser)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    members::me(world.org())
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    ann
}
