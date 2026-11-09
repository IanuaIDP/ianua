//! What the pages around Pat's sign-in read: the tenant's sign-in page,
//! offered to anybody and changing the moment Ann changes what is
//! switched on, and Pat's second-factor page, showing her alone what she
//! may set up, what she holds and what a waiting sign-in still owes.

use ianua_scenarios::api::{factors, sessions, tenants};
use ianua_scenarios::authenticators::TotpApp;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::factors::{ConfirmFactor, FactorSetup, Proof};
use ianua_scenarios::wire::sign_in::Owed;
use ianua_scenarios::wire::tenant_sign_in::SignInOptions;
use ianua_scenarios::wire::tenants::{PasswordAgain, ReplaceSignInSettings};
use ianua_scenarios::world::World;

use crate::tenant::support::{person, sent_factors_offered, sign_in_owing};

/// Nobody signed in reads the sign-in page: passkeys on, mailed links off
/// and no provider buttons, as a new tenant starts. Ann switches
/// mailed links on and passkeys off: the page says so at once, while Sam's
/// tenant still offers what it did.
#[tokio::test]
async fn the_sign_in_page_offers_only_what_is_switched_on_for_its_tenant() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;

    let before = sign_in_options(&world, world.anonymous().client()).await;
    assert!(before.passkey, "a new tenant offers passkeys");
    assert!(!before.magic_link, "a new tenant offers no mailed link");
    assert!(before.connections.is_empty(), "and no provider button");

    switch_on_mailed_links_off_passkeys(&world).await;

    let after = sign_in_options(&world, world.anonymous().client()).await;
    assert!(after.magic_link, "the page now offers a mailed link");
    assert!(!after.passkey, "and no longer a passkey");
    let twin = sessions::sign_in_options(world.twin())
        .send(world.anonymous().client())
        .await
        .ok();
    assert!(twin.passkey, "Sam's tenant still offers passkeys");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat, signed in with nothing set up, reads what she may set up. She
/// begins an authenticator: it reads as pending. She confirms it with a
/// code: it reads as in force. Her own page never reports anything owed,
/// because she is signed in.
#[tokio::test]
async fn pat_reads_what_she_may_set_up_as_she_sets_it_up() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    sent_factors_offered(&world).await;

    let start = factors::options(world.tenant(), None)
        .send(pat.client())
        .await
        .ok();
    for kind in ["totp", "email_code", "sms_code"] {
        assert!(
            start.offered.iter().any(|offered| offered == kind),
            "{kind} is offered"
        );
    }
    assert_eq!(start.held.state, "none", "Pat holds nothing yet");
    assert!(!start.mfa_required, "a signed-in Pat owes nothing");

    let setup = FactorSetup {
        proof: Some(Proof::Password {
            password: pat.password().to_owned(),
            code: None,
        }),
    };
    let begun = factors::enroll_totp(world.tenant(), &setup)
        .send(pat.client())
        .await
        .ok();
    let pending = factors::options(world.tenant(), None)
        .send(pat.client())
        .await
        .ok();
    assert_eq!(pending.held.state, "pending", "it waits to be confirmed");
    assert_eq!(pending.held.method.as_deref(), Some("totp"));

    let mut phone = TotpApp::scanning(&begun.otpauth_uri);
    let confirm = ConfirmFactor {
        code: phone.code().await,
        session_id: None,
    };
    factors::confirm_totp(world.tenant(), &confirm)
        .send(pat.client())
        .await
        .ok();
    let in_force = factors::options(world.tenant(), None)
        .send(pat.client())
        .await
        .ok();
    assert_eq!(in_force.held.state, "in_force", "the factor is in force");
    assert!(!in_force.mfa_required, "a signed-in Pat still owes nothing");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat has an authenticator and signs in on a new browser: that waiting
/// sign-in reads that it owes a factor and holds her authenticator. Uma,
/// signed in as herself, is refused for naming Pat's waiting sign-in, and
/// nobody signed in is refused outright.
#[tokio::test]
async fn a_waiting_sign_in_reads_what_it_owes_and_nobody_else_reads_it() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = person(&world, "pat").await;
    let uma = person(&world, "uma").await;
    pat.set_up_authenticator().await;
    let waiting = sign_in_owing(&world, &pat, "Pat on a new browser", Owed::FactorCode).await;

    let owed = factors::options(world.tenant(), Some(waiting.session.session_id.as_str()))
        .send(&waiting.client)
        .await
        .ok();
    assert!(owed.mfa_required, "the sign-in owes its factor");
    assert_eq!(
        owed.held.state, "in_force",
        "Pat's authenticator is in force"
    );

    factors::options(world.tenant(), Some(waiting.session.session_id.as_str()))
        .send(uma.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    factors::options(world.tenant(), Some(waiting.session.session_id.as_str()))
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    stack.stop().await.expect("the stack stops cleanly");
}

/// What the tenant's sign-in page offers `client`.
async fn sign_in_options(world: &World<'_>, client: &Client) -> SignInOptions {
    sessions::sign_in_options(world.tenant())
        .send(client)
        .await
        .ok()
}

/// Ann switches mailed links on and passkeys off, proving who she is
/// with her password.
async fn switch_on_mailed_links_off_passkeys(world: &World<'_>) {
    let mut settings = tenants::sign_in_settings(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    settings
        .enabled_methods
        .retain(|method| method != "Passkey");
    settings.enabled_methods.push("MagicLink".to_owned());
    let replace = ReplaceSignInSettings {
        settings,
        proof: PasswordAgain {
            password: world.owner().password().to_owned(),
            code: None,
        },
    };
    tenants::replace_sign_in_settings(world.tenant(), &replace)
        .send(world.owner().client())
        .await
        .ok();
}
