//! A founder's first sign-in, as the dashboard leads them through it, and
//! what only a member may read refused to everyone else.

use ianua_scenarios::actors::{FOUNDER_PASSWORD, Founder};
use ianua_scenarios::expect::{Matrix, Trail, no_secret_leaked};
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::organization::Member;
use ianua_scenarios::wire::sign_in::PasswordSignIn;
use ianua_scenarios::wire::{Page, Status};
use serde::de::IgnoredAny;

use crate::support::WRONG_GUESS;

/// Ann, who founded her company, signs in, confirming from her mailbox
/// when asked. She reads her organization's members; nobody signed in,
/// and Mallory who guessed her password wrong, are refused the same read.
/// Her sign-in is in the audit trail, with no secret in it.
#[tokio::test]
async fn a_founder_signs_in_and_only_members_read_the_members() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let founded = ann.founded(&stack, "Acme").await;

    let session = ann.signed_in(&stack).await;
    ann.client_mut().authorize(&session.refresh_token);
    let members_path = format!("/api/v1/organizations/{}/users", founded.org_slug);
    let members = ann.client().get::<Page<Member>>(&members_path).await.ok();
    assert!(
        members
            .items
            .iter()
            .any(|member| member.email == ann.email()),
        "Ann is among her organization's members"
    );

    assert_member_listing_access(&stack, &ann, &members_path).await;
    let trail = Trail::of_organization(ann.client(), &founded.org_slug);
    let signed_in_record = trail.recorded("organization.org_login_succeeded").await;
    no_secret_leaked(
        &signed_in_record.details.to_string(),
        &[FOUNDER_PASSWORD, &session.refresh_token],
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Only Ann's authenticated browser can list members after Mallory's failed password attempt.
async fn assert_member_listing_access(stack: &Stack, ann: &Founder, members_path: &str) {
    let anonymous = Client::new(stack, "nobody signed in").expect("an anonymous client");
    let mallory = Client::new(stack, "Mallory, with a wrong password").expect("a client");
    mallory
        .post::<IgnoredAny>(
            "/api/v1/login",
            &PasswordSignIn::of(ann.email(), WRONG_GUESS),
        )
        .await
        .refused(Status::NOT_FOUND, "not_found");
    Matrix::new(
        "reading the organization's members",
        Call::get(members_path),
    )
    .allowed(ann.client())
    .refused(&anonymous, Status::UNAUTHORIZED, "unauthenticated")
    .refused(&mallory, Status::UNAUTHORIZED, "unauthenticated")
    .run()
    .await;
}
