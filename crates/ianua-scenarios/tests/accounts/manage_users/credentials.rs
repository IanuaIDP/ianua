//! Tess helps Pat with her sign-in without ever learning a secret of
//! hers: she mails Pat a link to choose her own password, welcomes her by
//! mail, clears the authenticator Pat lost, reads Pat's sign-in history
//! and finally switches Pat's account off. Uma, Max, Sam and nobody
//! signed in can do none of it, and nothing is mailed or recorded for
//! what they tried.

use ianua_scenarios::actors::SignedInWith;
use ianua_scenarios::api::people;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::mail::Mail;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::world::World;

use crate::support::person;

/// The password Pat chooses herself from the mailed link.
const PATS_OWN_PASSWORD: &str = "Scenario chosen lantern harbour 6731";

/// The record a mailed reset link leaves.
const RESET_REQUESTED: &str = "authentication.password_reset_requested";

/// The record a welcome mail leaves once the mail service took it.
const WELCOMED: &str = "identity.welcome_email_sent";

/// The record cleared second factors leave.
const FACTORS_RESET: &str = "authentication.factors_reset";

/// The record a switched-off account leaves.
const STATUS_CHANGED: &str = "identity.user_status_changed";

/// The path a reset link opens.
const RESET_PAGE: &str = "/reset-password";

/// How long a refused request is watched for a mail it must not send.
const QUIET: std::time::Duration = std::time::Duration::from_secs(3);

/// The next mail for `address` that links to a page under `prefix`,
/// passing over up to three others, such as a new device's link.
async fn mail_linking(world: &World<'_>, address: &str, prefix: &str) -> Mail {
    for _ in 0..4 {
        let mail = world.stack().mailbox().next_for(address).await;
        if mail
            .links()
            .iter()
            .any(|link| link.path().starts_with(prefix))
        {
            return mail;
        }
    }
    panic!("{address} got no mail linking to {prefix}");
}

/// Tess asks for a reset link for Pat and is told only that it is on its
/// way. Pat finds the link in her mail and chooses her own password with
/// it; the session she held on her laptop ends. She signs in with the
/// password she chose, and the request is on record without the link.
#[tokio::test]
async fn tess_mails_pat_a_link_and_pat_chooses_her_own_password() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = person(&world, "pat").await;
    let (laptop, _) = pat.on_another_device(&stack, "on her laptop").await;
    let seen = world.trail().ids().await;

    people::send_reset_link(world.tenant(), pat.id())
        .send(world.admin().client())
        .await
        .ok();
    let mail = mail_linking(&world, pat.email(), RESET_PAGE).await;
    let token = mail.token_in(RESET_PAGE);
    pat.confirm_reset(&token, PATS_OWN_PASSWORD).await.ok();
    people::me(world.tenant())
        .send(&laptop)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    assert_eq!(pat.sign_in(&stack).await, SignedInWith::Password);
    people::me(world.tenant()).send(pat.client()).await.ok();
    let recorded = world.trail().recorded_after(&seen, RESET_REQUESTED).await;
    assert!(
        !recorded.details.to_string().contains(&token),
        "the record does not carry the link"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess welcomes Pat: Pat is mailed that her account exists, with no
/// password in it, and the welcome is on record. Tess reads Pat's sign-in
/// history and finds the sign-in Pat made; Pat reads her own history too,
/// but Uma may not read Pat's.
#[tokio::test]
async fn tess_welcomes_pat_and_reads_her_sign_ins() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let uma = person(&world, "uma").await;
    let seen = world.trail().ids().await;

    people::send_welcome(world.tenant(), pat.id())
        .send(world.admin().client())
        .await
        .ok();
    let welcome = stack.mailbox().next_for(pat.email()).await;
    let text = welcome.text().unwrap_or_default();
    assert!(
        !text.contains(pat.password()),
        "the welcome carries no password"
    );
    world.trail().recorded_after(&seen, WELCOMED).await;

    let history = people::sign_ins(world.tenant(), pat.id())
        .send(world.admin().client())
        .await
        .ok();
    assert!(!history.items.is_empty(), "Tess finds the sign-in Pat made");
    let own = people::sign_ins(world.tenant(), pat.id())
        .send(pat.client())
        .await
        .ok();
    assert_eq!(
        own.items.len(),
        history.items.len(),
        "Pat reads the same history"
    );
    people::sign_ins(world.tenant(), pat.id())
        .send(uma.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat set up an authenticator and lost her phone. Tess clears it: one
/// second factor turned off, no passkey removed. The session Pat held
/// ends, she signs in with her password alone, and the clearing is on
/// record.
#[tokio::test]
async fn tess_clears_the_authenticator_pat_lost() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = person(&world, "pat").await;
    pat.set_up_authenticator().await;
    let _lost = pat.lose_phone();
    let seen = world.trail().ids().await;

    let cleared = people::reset_factors(world.tenant(), pat.id())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(
        cleared.enrollments_turned_off, 1,
        "her authenticator is off"
    );
    assert_eq!(cleared.passkeys_removed, 0, "she had no passkey");
    people::me(world.tenant())
        .send(pat.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    assert_eq!(pat.sign_in(&stack).await, SignedInWith::Password);
    world.trail().recorded_after(&seen, FACTORS_RESET).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess switches Pat's account off: the session Pat held ends at once,
/// Pat's record reads deactivated to Tess, and the change is on record.
/// Uma, untouched, works on.
#[tokio::test]
async fn tess_switches_pat_s_account_off() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let uma = person(&world, "uma").await;
    let seen = world.trail().ids().await;

    people::deactivate(world.tenant(), pat.id())
        .send(world.admin().client())
        .await
        .ok();
    people::me(world.tenant())
        .send(pat.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let record = people::get(world.tenant(), pat.id())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(record.status, "Deactivated");
    world.trail().recorded_after(&seen, STATUS_CHANGED).await;
    people::me(world.tenant()).send(uma.client()).await.ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// Uma, an ordinary user of the tenant, Max, a member with no
/// administrator's rights, Sam from the other company and nobody signed
/// in are each refused mailing Pat a reset link, welcoming her, clearing
/// her factors and switching her off. Past the welcome her own joining
/// mailed, Pat is mailed nothing, keeps her session, and none of it is
/// recorded.
#[tokio::test]
async fn nobody_without_the_right_helps_pat_or_shuts_her_out() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let uma = person(&world, "uma").await;
    assert_eq!(
        stack.mailbox().next_for(pat.email()).await.subject(),
        "Your account is ready",
        "accepting her invitation told Pat her account is ready"
    );
    let seen = world.trail().ids().await;

    for request in [
        people::send_reset_link(world.tenant(), pat.id()).call(),
        people::send_welcome(world.tenant(), pat.id()).call(),
        people::reset_factors(world.tenant(), pat.id()).call(),
        people::deactivate(world.tenant(), pat.id()).call(),
    ] {
        Matrix::new("helping Pat sign in or shutting her out", request)
            .refused(uma.client(), Status::FORBIDDEN, "forbidden")
            .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
            .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
            .refused(
                world.anonymous().client(),
                Status::UNAUTHORIZED,
                "unauthenticated",
            )
            .run()
            .await;
    }

    stack.mailbox().nothing_for(pat.email(), QUIET).await;
    people::me(world.tenant()).send(pat.client()).await.ok();
    for event_type in [RESET_REQUESTED, WELCOMED, FACTORS_RESET, STATUS_CHANGED] {
        world.trail().nothing_after(&seen, event_type).await;
    }

    stack.stop().await.expect("the stack stops cleanly");
}
