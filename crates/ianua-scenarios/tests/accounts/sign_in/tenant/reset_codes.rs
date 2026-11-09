//! Pat's second factor is a code sent to her, and she forgets her
//! password: following the mailed link she has a code sent, the reset takes
//! it, and a wrong one, or none, sets nothing. Mallory, who has the link
//! but not the code, gets nowhere; a made-up link and an authenticator
//! factor are sent no code at all.

use std::time::Duration;

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::sessions;
use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::sign_in::{Owed, ResetLinkToken};
use ianua_scenarios::wire::tenant_sign_in::ConfirmPasswordReset;
use ianua_scenarios::world::World;

use crate::support::{QUIET, past_lifetime};
use crate::tenant::support::{
    Delivery, device, enroll_delivered_factor, opened_session, person, received,
    sent_factors_offered,
};

/// The password Pat chooses with the reset.
const NEW_PASSWORD: &str = "Scenario restored orchard harbour 2946";

/// A well-formed code nobody was sent.
const WRONG_CODE: &str = "000000";

/// The record a sent code leaves.
const CODE_SENT: &str = "authentication.mfa_code_sent";

/// The record a finished reset leaves.
const RESET_COMPLETED: &str = "authentication.password_reset_completed";

/// How long a stack waits between one sent code and the next, when a
/// scenario tests that wait.
const SEND_WAIT: Duration = Duration::from_secs(3);

/// The standard profile with no wait between sent codes.
fn sending_codes_at_once() -> Profile {
    Profile::standard().with("MFA_SENT_CODE_RESEND_SECONDS", "0")
}

/// Pat's reset in progress: where it happens and the link it follows.
struct PatsReset<'a, 'w> {
    world: &'a World<'w>,
    pat: &'a Person,
    token: &'a str,
}

/// `token` asking for the code a reset owes.
fn asked(token: &str) -> ResetLinkToken {
    ResetLinkToken {
        token: token.to_owned(),
    }
}

/// `token` setting [`NEW_PASSWORD`], carrying `code` when there is one.
fn confirming(token: &str, code: Option<&str>) -> ConfirmPasswordReset {
    ConfirmPasswordReset {
        token: token.to_owned(),
        new_password: NEW_PASSWORD.to_owned(),
        mfa_code: code.map(str::to_owned),
    }
}

/// Pat sets up a mailed code, forgets her password and follows the mailed
/// link: with no code the reset asks for one and changes nothing. Mallory,
/// who has the link, is refused a guess at the code, and the old password
/// still opens the same sign-in. Pat has a code sent to her mailbox and
/// resets with it: her new password opens her account, still owing the
/// code. The used link and code do nothing more, and neither the sent
/// code nor the reset is recorded with the code in it.
#[tokio::test]
async fn a_mailed_code_carries_pat_through_her_reset_and_a_wrong_one_does_not() {
    let stack = Stack::start(sending_codes_at_once())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = person(&world, "pat").await;
    sent_factors_offered(&world).await;
    enroll_delivered_factor(&world, &pat, Delivery::Mail).await;
    let token = pat.reset_link(&stack).await;
    let trail = world.trail();
    let seen = trail.ids().await;
    let before = trail.count(CODE_SENT).await;

    let mallory = device(&stack, "Mallory, holding Pat's link");
    refuse_without_the_right_code(&world, &pat, &mallory, &token).await;
    let reset = PatsReset {
        world: &world,
        pat: &pat,
        token: &token,
    };
    let code = code_sent_to_pat(&reset, Delivery::Mail, before).await;
    finish_reset(&reset, &mallory, &code).await;

    let recorded = trail.recorded_after(&seen, RESET_COMPLETED).await;
    no_secret_leaked(&recorded.details.to_string(), &[&code, &token]);
    let sent = trail.entries(CODE_SENT).await;
    no_secret_leaked(&format!("{sent:?}"), &[&code, &token]);

    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat's second factor is a text to her phone. She resets with the code
/// texted to her, and her new password opens her account, owing the code.
#[tokio::test]
async fn a_texted_code_reaches_pat_s_phone_for_her_reset() {
    let stack = Stack::start(sending_codes_at_once())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = person(&world, "pat").await;
    sent_factors_offered(&world).await;
    enroll_delivered_factor(&world, &pat, Delivery::Text).await;
    let token = pat.reset_link(&stack).await;
    let before = world.trail().count(CODE_SENT).await;

    let reset = PatsReset {
        world: &world,
        pat: &pat,
        token: &token,
    };
    let code = code_sent_to_pat(&reset, Delivery::Text, before).await;
    let mallory = device(&stack, "Mallory, holding Pat's link");
    finish_reset(&reset, &mallory, &code).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat has a code sent for her reset and presses again at once: she is
/// told to wait and no second code leaves.
#[tokio::test]
async fn asking_for_another_reset_code_at_once_is_told_to_wait() {
    let profile = Profile::standard().with(
        "MFA_SENT_CODE_RESEND_SECONDS",
        &SEND_WAIT.as_secs().to_string(),
    );
    let stack = Stack::start(profile).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = person(&world, "pat").await;
    sent_factors_offered(&world).await;
    enroll_delivered_factor(&world, &pat, Delivery::Mail).await;
    past_lifetime(SEND_WAIT).await;
    let token = pat.reset_link(&stack).await;
    let before = world.trail().count(CODE_SENT).await;
    let reset = PatsReset {
        world: &world,
        pat: &pat,
        token: &token,
    };
    let _code = code_sent_to_pat(&reset, Delivery::Mail, before).await;

    sessions::send_reset_code(world.tenant(), &asked(&token))
        .send(world.anonymous().client())
        .await
        .refused(Status::TOO_MANY_REQUESTS, "rate_limit_exceeded");
    stack.mailbox().nothing_for(pat.email(), QUIET).await;
    assert_eq!(
        world.trail().count(CODE_SENT).await,
        before + 1,
        "only the first code was sent"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Mallory presses for a code with a made-up link, and Uma, whose factor
/// is an authenticator app, presses with her real reset link: each gets
/// the same empty answer, nobody is mailed a code, and no code is
/// recorded as sent. A blank token is refused outright.
#[tokio::test]
async fn a_forged_link_and_an_app_factor_are_sent_no_code() {
    let stack = Stack::start(sending_codes_at_once())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut uma = person(&world, "uma").await;
    assert_eq!(
        stack.mailbox().next_for(uma.email()).await.subject(),
        "Your account is ready",
        "joining told Uma her account is ready"
    );
    uma.set_up_authenticator().await;
    let uma_token = uma.reset_link(&stack).await;
    let before = world.trail().count(CODE_SENT).await;

    sessions::send_reset_code(world.tenant(), &asked("mallory made this link up"))
        .send(world.anonymous().client())
        .await
        .ok();
    sessions::send_reset_code(world.tenant(), &asked(&uma_token))
        .send(uma.client())
        .await
        .ok();
    sessions::send_reset_code(world.tenant(), &asked(""))
        .send(world.anonymous().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    stack.mailbox().nothing_for(uma.email(), QUIET).await;
    assert_eq!(
        world.trail().count(CODE_SENT).await,
        before,
        "no code was sent to anyone"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Without a code the reset asks for one; Mallory's guess is refused;
/// neither changes the password, which still opens Pat's account.
async fn refuse_without_the_right_code(
    world: &World<'_>,
    pat: &Person,
    mallory: &Client,
    token: &str,
) {
    sessions::confirm_password_reset(world.tenant(), &confirming(token, None))
        .send(mallory)
        .await
        .refused(Status::FORBIDDEN, "step_up_required");
    sessions::confirm_password_reset(world.tenant(), &confirming(token, Some(WRONG_CODE)))
        .send(mallory)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let opened = opened_session(world, mallory, pat.email(), pat.password()).await;
    assert_eq!(
        opened.owed(),
        Owed::FactorCode,
        "the old password still opens the sign-in, still owing the code"
    );
    assert_eq!(
        world.trail().count(RESET_COMPLETED).await,
        0,
        "a guess changed no password"
    );
}

/// Pat presses for her code with the link in hand, which is recorded
/// once, and answers the code received by `delivery`.
async fn code_sent_to_pat(reset: &PatsReset<'_, '_>, delivery: Delivery, before: usize) -> String {
    let world = reset.world;
    sessions::send_reset_code(world.tenant(), &asked(reset.token))
        .send(world.anonymous().client())
        .await
        .ok();
    let code = received(world.stack(), delivery, reset.pat.email()).await;
    assert_eq!(
        world.trail().count(CODE_SENT).await,
        before + 1,
        "the sent code is recorded once"
    );
    code
}

/// Pat resets with her right `code`; her new password opens the account,
/// still owing the code; the used link and code do nothing more.
async fn finish_reset(reset: &PatsReset<'_, '_>, mallory: &Client, code: &str) {
    let PatsReset { world, pat, token } = *reset;
    sessions::confirm_password_reset(world.tenant(), &confirming(token, Some(code)))
        .send(mallory)
        .await
        .ok();
    let opened = opened_session(world, mallory, pat.email(), NEW_PASSWORD).await;
    assert_eq!(
        opened.owed(),
        Owed::FactorCode,
        "the new password opens the sign-in, still owing the code"
    );
    sessions::confirm_password_reset(world.tenant(), &confirming(token, Some(code)))
        .send(mallory)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    assert_eq!(
        world.trail().count(RESET_COMPLETED).await,
        1,
        "one change is recorded"
    );
}
