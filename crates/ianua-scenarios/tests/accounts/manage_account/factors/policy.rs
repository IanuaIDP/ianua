//! The tenant's thresholds met half way through Pat's sign-in: an
//! assurance level raised to hardware refuses her authenticator's code
//! until it is lowered again; a risk threshold set low asks even a safe
//! sign-in for the mailbox; a denial threshold set low turns Pat away
//! until Ann raises it.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{audit, factors, people, sessions, tenants};
use ianua_scenarios::authenticators::TotpApp;
use ianua_scenarios::clock::Clock;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::factors::SessionCode;
use ianua_scenarios::wire::sign_in::Owed;
use ianua_scenarios::wire::tenant_sign_in::{
    ConfirmTenantSignIn, TenantPasswordSignIn, TenantSession, TenantSignedIn,
};
use ianua_scenarios::wire::tenants::{PasswordAgain, ReplaceSignInSettings, SignInSettings};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::support::{
    SignedDevice, device, invited_and_signed_in, mail_linking_to, still_signed_in, tenant_records,
};

/// Pat, with an authenticator and a passkey, signs in on a new browser and
/// owes the code. Ann raises the tenant's assurance to hardware: the code
/// is refused as not reaching it, the browser reads nothing, and no
/// verification is recorded. Ann lowers it to a second factor again: the
/// next code finishes the same sign-in, which reads Pat in her tenant and
/// nothing in the twin, and one verification is recorded with no code in
/// it. Her passkey signs her in at that level too.
#[tokio::test]
async fn a_code_is_refused_once_the_tenant_demands_hardware_and_accepted_once_it_relents() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited_and_signed_in(&world, "pat").await;
    pat.set_up_authenticator().await;
    pat.add_passkey(&stack, "Pat's synced passkey").await;
    let mut phone = pat.lose_phone();
    let waiting = pending_factor_sign_in(&world, &pat).await;
    verify_under_changed_policy(&world, &pat, &waiting, &mut phone).await;
    pat.sign_in_with_passkey().await;
    still_signed_in(&world, &pat).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Start a new browser session that still owes Pat's enrolled factor.
async fn pending_factor_sign_in(world: &World<'_>, pat: &Person) -> SignedDevice {
    let mut browser = device(world.stack(), "Pat under a raised assurance level");
    let waiting = signed_in_from(world, &browser, pat.email(), pat.password()).await;
    assert_eq!(
        waiting.owed(),
        Owed::FactorCode,
        "a new browser owes the code"
    );
    browser.authorize(&waiting.refresh_token);
    SignedDevice {
        client: browser,
        session: waiting,
    }
}

/// Raise and lower assurance around the same pending session and count only its accepted proof.
async fn verify_under_changed_policy(
    world: &World<'_>,
    pat: &Person,
    waiting: &SignedDevice,
    phone: &mut TotpApp,
) {
    let before = tenant_records(world, "authentication.mfa_verified", &[]).await;
    assurance_required(world, "Aal3").await;
    let under_hardware = SessionCode {
        session_id: waiting.session.session_id.clone(),
        code: phone.code().await,
    };
    refuse_below_hardware(world, &waiting.client, &under_hardware, before).await;
    assurance_required(world, "Aal2").await;
    let under_second_factor = SessionCode {
        code: phone.code().await,
        ..under_hardware
    };
    accept_second_factor(world, pat, &waiting.client, &under_second_factor).await;
    assert_eq!(
        tenant_records(
            world,
            "authentication.mfa_verified",
            &[&under_second_factor.code]
        )
        .await,
        before + 1,
        "the accepted code records one verification"
    );
}

/// Hardware assurance refuses the phone code, leaves access pending and records no verification.
async fn refuse_below_hardware(
    world: &World<'_>,
    browser: &Client,
    code: &SessionCode,
    before: usize,
) {
    let refused = factors::verify(world.tenant(), code)
        .send(browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    assert_eq!(
        refused.message(),
        "The sign-in does not reach the required assurance"
    );
    people::me(world.tenant())
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    assert_eq!(
        tenant_records(world, "authentication.mfa_verified", &[]).await,
        before,
        "a refused code records no verification"
    );
}

/// Lowered assurance accepts the fresh code for Pat in her tenant and denies access to the twin.
async fn accept_second_factor(
    world: &World<'_>,
    pat: &Person,
    browser: &Client,
    code: &SessionCode,
) {
    factors::verify(world.tenant(), code)
        .send(browser)
        .await
        .ok();
    let own = people::me(world.tenant()).send(browser).await.ok();
    assert_eq!(own.id, pat.id(), "the accepted code lets Pat in");
    people::me(world.twin())
        .send(browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// Ann sets the tenant to ask even low-risk sign-ins for more, with its
/// new-device and new-country rules off. Pat's correct password alone
/// cannot grant access: her sign-in waits for her mailbox and reads
/// nothing; the link mailed to her finishes that same sign-in, which then
/// reads her record.
#[tokio::test]
async fn a_low_risk_threshold_asks_pat_for_her_mailbox() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = invited_and_signed_in(&world, "pat").await;
    thresholds(&world, "Low", "Critical").await;

    let mut browser = device(&stack, "Pat answering a risk-driven challenge");
    let waiting = signed_in_from(&world, &browser, pat.email(), pat.password()).await;
    assert_eq!(
        waiting.owed(),
        Owed::MailedConfirmation,
        "a low risk threshold asks for the mailbox"
    );
    browser.authorize(&waiting.refresh_token);
    people::me(world.tenant())
        .send(&browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    confirm_risk_challenge(&world, &pat, &browser, waiting).await;
    still_signed_in(&world, &pat).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// The mailbox proof settles the risk challenge and unlocks Pat's own account record.
async fn confirm_risk_challenge(
    world: &World<'_>,
    pat: &Person,
    browser: &Client,
    waiting: TenantSession,
) {
    let mail = mail_linking_to(world.stack(), pat.email(), "/confirm-sign-in").await;
    let confirm = ConfirmTenantSignIn {
        link: mail.token_in("/confirm-sign-in"),
        session_token: waiting.refresh_token,
    };
    let confirmed = sessions::confirm_sign_in(world.tenant(), &confirm)
        .send(browser)
        .await
        .ok();
    assert_eq!(
        confirmed.owed(),
        Owed::Nothing,
        "the mailed link settles everything the sign-in owed"
    );
    let own = people::me(world.tenant()).send(browser).await.ok();
    assert_eq!(own.id, pat.id(), "the sign-in now reads Pat's record");
}

/// Ann sets the tenant to refuse even low-risk sign-ins. Pat's correct
/// password cannot open a session: the sign-in is refused outright and reads
/// nothing, and the failed sign-in's record names the risk. Ann raises
/// the threshold again, and the same password signs Pat in, owing
/// nothing.
#[tokio::test]
async fn a_low_denial_threshold_turns_pat_away_until_it_is_raised() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = invited_and_signed_in(&world, "pat").await;
    thresholds(&world, "Low", "Low").await;

    let mut browser = device(&stack, "Pat refused by the risk policy");
    let sign_in = TenantPasswordSignIn {
        email: pat.email().to_owned(),
        password: pat.password().to_owned(),
        fingerprint_hash: None,
    };
    refuse_risky_sign_in(&world, &browser, &sign_in).await;
    thresholds(&world, "Critical", "Critical").await;
    accept_same_password(&world, &pat, &mut browser, &sign_in).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Denial blocks all account access and records risk as the reason for the failed sign-in.
async fn refuse_risky_sign_in(world: &World<'_>, browser: &Client, sign_in: &TenantPasswordSignIn) {
    sessions::sign_in(world.tenant(), sign_in)
        .send(browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    people::me(world.tenant())
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let failed = audit::tenant_log(world.tenant(), "authentication.login_failed")
        .send(world.admin().client())
        .await
        .ok();
    assert!(
        failed
            .items
            .iter()
            .any(|entry| entry.details.to_string().contains("risk_too_high")),
        "the failed sign-in's record names the risk"
    );
}

/// Raising the denial threshold lets the unchanged password open a fully authenticated session.
async fn accept_same_password(
    world: &World<'_>,
    pat: &Person,
    browser: &mut Client,
    sign_in: &TenantPasswordSignIn,
) {
    let answer = sessions::sign_in(world.tenant(), sign_in)
        .send(browser)
        .await
        .ok();
    let TenantSignedIn::Session(session) = answer else {
        panic!("Pat chose her own password, so none must change");
    };
    assert_eq!(
        session.owed(),
        Owed::Nothing,
        "with the threshold raised the password alone signs Pat in"
    );
    browser.authorize(&session.refresh_token);
    let own = people::me(world.tenant()).send(browser).await.ok();
    assert_eq!(own.id, pat.id(), "the sign-in reads Pat's record");
}

/// The session the password of `email` opens through `browser`, with
/// whatever it still owes left unanswered, so the step reads what the
/// tenant's rules asked for.
///
/// # Panics
///
/// When the sign-in is refused, or the password must change first.
async fn signed_in_from(
    world: &World<'_>,
    browser: &Client,
    email: &str,
    password: &str,
) -> TenantSession {
    let sign_in = TenantPasswordSignIn {
        email: email.to_owned(),
        password: password.to_owned(),
        fingerprint_hash: None,
    };
    let answer = sessions::sign_in(world.tenant(), &sign_in)
        .send(browser)
        .await
        .ok();
    let TenantSignedIn::Session(session) = answer else {
        panic!("{email} chose their own password, so none must change");
    };
    session
}

/// Sets the tenant's risk thresholds, `challenge` for asking more and
/// `deny` for refusing, with its new-device and new-country rules off, as
/// Ann with her password typed again.
async fn thresholds(world: &World<'_>, challenge: &str, deny: &str) {
    let mut settings = tenants::sign_in_settings(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    let Some(step_up) = settings.rest.get_mut("step_up") else {
        panic!("the tenant's sign-in settings hold a step-up policy");
    };
    step_up["require_mfa_new_device"] = json!(false);
    step_up["require_mfa_new_country"] = json!(false);
    step_up["mfa_risk_threshold"] = json!(challenge);
    step_up["deny_risk_threshold"] = json!(deny);
    replaced(world, settings).await;
}

/// Sets the tenant's baseline assurance and its floor for sensitive steps
/// both to `required`, as Ann with her password typed again.
async fn assurance_required(world: &World<'_>, required: &str) {
    let mut settings = tenants::sign_in_settings(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    let Some(step_up) = settings.rest.get_mut("step_up") else {
        panic!("the tenant's sign-in settings hold a step-up policy");
    };
    step_up["baseline_aal"] = json!(required);
    step_up["sensitive_aal"] = json!(required);
    replaced(world, settings).await;
}

/// Replaces the tenant's sign-in settings with `settings`, as Ann with
/// her password typed again.
async fn replaced(world: &World<'_>, settings: SignInSettings) {
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
