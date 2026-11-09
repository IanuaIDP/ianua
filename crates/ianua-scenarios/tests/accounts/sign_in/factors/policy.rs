//! Max's sign-in is waiting for his mailbox when Ann changes Acme's policy.
//! The mailed link is judged by the policy in force when it is followed:
//! under a raised baseline it finishes nothing, and under a newly required
//! factor it leaves the factor owed. A fresh sign-in under the policy as
//! it stands then gets Max in.

use ianua_scenarios::api::{member_factors, members, organizations, sessions};
use ianua_scenarios::authenticators::TotpApp;
use ianua_scenarios::clock::Clock;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::factors::ConfirmFactor;
use ianua_scenarios::wire::organization::ReplaceOrgSignInSettings;
use ianua_scenarios::wire::sign_in::{
    ConfirmSignIn, MemberProof, Owed, PasswordSignIn, Session, SignedIn,
};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::factors::member::{others_keep_access, require_factor};
use crate::support::{mail_linking_to, settled_sign_in};

/// Max's sign-in waits for his mailbox when Ann raises Acme's baseline to
/// two factors, without requiring anyone to set one up. The mailed link
/// cannot finish the sign-in under the stronger baseline. Its refusal
/// explains this, Max reads nothing and no factor is recorded as
/// answered. Ann restores the baseline, and a fresh sign-in gets Max in.
#[tokio::test]
async fn a_mailed_link_is_refused_by_a_baseline_raised_while_it_was_on_its_way() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut browser = Client::new(&stack, "Max, under a raised baseline").expect("a client");
    let waiting = waiting_for_the_mailbox(&world, &browser).await;
    let mail = mail_linking_to(&stack, world.member().email(), "/confirm-sign-in").await;
    browser.authorize(&waiting.refresh_token);
    let trail = world.trail();
    let before = trail.count("organization.org_mfa_verified").await;

    baseline(&world, "Aal2").await;
    let proof = ConfirmSignIn {
        token: mail.token_in("/confirm-sign-in"),
        refresh_token: waiting.refresh_token,
    };
    assert_raised_baseline(&world, &browser, &proof, before).await;

    baseline(&world, "Aal1").await;
    assert_restored_baseline(&world, &mut browser, before).await;
    others_keep_access(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// The stronger baseline refuses the pending proof without access or a verification record.
async fn assert_raised_baseline(
    world: &World<'_>,
    browser: &Client,
    proof: &ConfirmSignIn,
    before: usize,
) {
    let refused = sessions::confirm_member_sign_in(proof)
        .send(browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    assert_eq!(
        refused.message(),
        "This confirmation does not finish the sign-in"
    );
    members::me(world.org())
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    assert_eq!(
        world.trail().count("organization.org_mfa_verified").await,
        before,
        "the refused link is not recorded as a factor answered"
    );
}

/// A fresh sign-in under the restored baseline opens Max's account and records its mailbox proof.
async fn assert_restored_baseline(world: &World<'_>, browser: &mut Client, before: usize) {
    let sign_in = PasswordSignIn::of(world.member().email(), world.member().password());
    let session = settled_sign_in(world.stack(), browser, &sign_in).await;
    browser.authorize(&session.refresh_token);
    assert_eq!(
        members::me(world.org()).send(browser).await.ok().id,
        world.member().id(),
        "a fresh sign-in under the restored baseline reads Max's account"
    );
    assert_eq!(
        world.trail().count("organization.org_mfa_verified").await,
        before + 1,
        "the fresh sign-in's mailed link is recorded as answered"
    );
}

/// Max's sign-in waits for his mailbox when Ann requires a factor of
/// everyone. The mailed link cannot finish the sign-in without a factor,
/// and Max reads nothing. He signs in again: the link is
/// taken, the sign-in owes a factor, and the first code from the
/// authenticator he sets up on that sign-in lets him in. One setup is
/// recorded.
#[tokio::test]
async fn a_sign_in_waiting_for_the_mailbox_owes_a_factor_required_meanwhile() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut browser = Client::new(&stack, "Max, under a changed policy").expect("a client");
    let waiting = waiting_for_the_mailbox(&world, &browser).await;
    let mail = mail_linking_to(&stack, world.member().email(), "/confirm-sign-in").await;
    browser.authorize(&waiting.refresh_token);

    require_factor(&world).await;
    let proof = ConfirmSignIn {
        token: mail.token_in("/confirm-sign-in"),
        refresh_token: waiting.refresh_token,
    };
    assert_old_sign_in_refused(&world, &browser, &proof).await;

    enroll_current_factor(&world, &mut browser).await;
    assert_eq!(
        members::me(world.org()).send(&browser).await.ok().id,
        world.member().id(),
        "the sign-in that set the factor up reads Max's account"
    );
    others_keep_access(&world).await;
    assert_eq!(
        world.trail().count("organization.org_mfa_enrolled").await,
        1,
        "one authenticator was set up"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// The mailbox proof issued before the new factor requirement cannot complete the old session.
async fn assert_old_sign_in_refused(world: &World<'_>, browser: &Client, proof: &ConfirmSignIn) {
    sessions::confirm_member_sign_in(proof)
        .send(browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    members::me(world.org())
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// A fresh mailbox-confirmed sign-in satisfies the newly required factor through enrollment.
async fn enroll_current_factor(world: &World<'_>, browser: &mut Client) {
    let again = waiting_for_the_mailbox(world, browser).await;
    browser.authorize(&again.refresh_token);
    let mail = mail_linking_to(world.stack(), world.member().email(), "/confirm-sign-in").await;
    let proof = ConfirmSignIn {
        token: mail.token_in("/confirm-sign-in"),
        refresh_token: again.refresh_token.clone(),
    };
    sessions::confirm_member_sign_in(&proof)
        .send(browser)
        .await
        .ok();
    let begun = member_factors::begin_required_totp(world.org())
        .send(browser)
        .await
        .ok();
    let mut phone = TotpApp::scanning(&begun.otpauth_uri);
    let confirm = ConfirmFactor {
        code: phone.code().await,
        session_id: Some(again.session_id),
    };
    member_factors::confirm_totp(world.org(), &confirm)
        .send(browser)
        .await
        .ok();
}

/// The session Max's password opens through `browser`, waiting for the
/// link mailed to him.
async fn waiting_for_the_mailbox(world: &World<'_>, browser: &Client) -> Session {
    let sign_in = PasswordSignIn::of(world.member().email(), world.member().password());
    let answer = sessions::member_sign_in(&sign_in).send(browser).await.ok();
    let SignedIn::Authenticated(session) = answer else {
        panic!("Max is in one organization, so no choice is offered");
    };
    assert_eq!(
        session.owed(),
        Owed::MailedConfirmation,
        "a browser Max never remembered waits for his mailbox"
    );
    session
}

/// Ann sets Acme's baseline to `required`, `Aal1` or `Aal2`, and nothing
/// else, with her password typed again.
async fn baseline(world: &World<'_>, required: &str) {
    let mut settings = organizations::sign_in_settings(world.org())
        .send(world.owner().client())
        .await
        .ok();
    settings.rest.get_mut("step_up").expect("step-up policy")["baseline_aal"] = json!(required);
    let replace = ReplaceOrgSignInSettings {
        settings,
        proof: MemberProof {
            password: world.owner().password().to_owned(),
            code: None,
        },
    };
    organizations::replace_sign_in_settings(world.org(), &replace)
        .send(world.owner().client())
        .await
        .ok();
}
