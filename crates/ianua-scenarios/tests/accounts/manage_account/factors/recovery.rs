//! Pat, who lost her phone, in a tenant that requires a factor: a
//! recovery code proves her but lets her in nowhere until she has set up
//! a new phone, which then answers her next sign-in.

use std::time::Duration;

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{factors, people, sessions, tenants};
use ianua_scenarios::authenticators::TotpApp;
use ianua_scenarios::clock::Clock;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::factors::{ConfirmFactor, FactorSetup, SessionCode};
use ianua_scenarios::wire::sign_in::Owed;
use ianua_scenarios::wire::tenant_sign_in::{TenantPasswordSignIn, TenantSignedIn};
use ianua_scenarios::wire::tenants::{MfaPolicy, PasswordAgain, ReplaceSignInSettings};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::support::{SignedDevice, device, invited_and_signed_in};

/// One period of the authenticator app, so the new phone's next code is
/// not the one that confirmed it.
const CODE_PERIOD: Duration = Duration::from_secs(30);

/// The browser waiting for recovery and the password request reused on its next sign-in.
struct RecoverySession {
    /// The current pending session and browser.
    device: SignedDevice,
    /// Pat's unchanged password request.
    sign_in: TenantPasswordSignIn,
}

/// Pat, with her authenticator set up, loses her phone after Ann makes a
/// factor required. On a new browser her sign-in owes the code and cannot
/// start a replacement authenticator with her password alone. Her recovery
/// code is accepted, yet she still reads nothing; now she sets up a new phone,
/// confirms it for that sign-in and is in. Her next sign-in owes the
/// code again and the new phone answers it; her old session is out.
#[tokio::test]
async fn a_recovery_code_lets_pat_replace_her_lost_phone_before_she_is_in() {
    let clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited_and_signed_in(&world, "pat").await;
    pat.set_up_authenticator().await;
    let Some(printout) = pat.recovery_codes() else {
        panic!("setting up the authenticator printed recovery codes");
    };
    let code = printout.all()[0].clone();
    factor_required(&world).await;
    let mut recovering = begin_recovery(&world, &pat).await;
    prove_recovery_code(&world, &recovering, code).await;
    let mut phone = replace_phone(&world, &pat, &recovering, &clock).await;
    sign_in_with_replacement(&world, &pat, &mut recovering, &mut phone).await;
    people::me(world.tenant())
        .send(pat.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    stack.stop().await.expect("the stack stops cleanly");
}

/// The password opens a pending session but cannot authorize replacement enrollment.
async fn begin_recovery(world: &World<'_>, pat: &Person) -> RecoverySession {
    let browser = device(world.stack(), "Pat recovering the required factor");
    let sign_in = TenantPasswordSignIn {
        email: pat.email().to_owned(),
        password: pat.password().to_owned(),
        fingerprint_hash: None,
    };
    let device = pending_recovery(world, browser, &sign_in).await;
    RecoverySession { device, sign_in }
}

/// Pat's password leaves the browser owing a factor and unable to enroll its replacement.
async fn pending_recovery(
    world: &World<'_>,
    mut browser: Client,
    sign_in: &TenantPasswordSignIn,
) -> SignedDevice {
    let answer = sessions::sign_in(world.tenant(), sign_in)
        .send(&browser)
        .await
        .ok();
    let TenantSignedIn::Session(waiting) = answer else {
        panic!("Pat chose her own password, so none must change");
    };
    assert_eq!(
        waiting.owed(),
        Owed::FactorCode,
        "a new browser owes the code"
    );
    browser.authorize(&waiting.refresh_token);
    factors::enroll_totp(world.tenant(), &FactorSetup::default())
        .send(&browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    SignedDevice {
        client: browser,
        session: waiting,
    }
}

/// A recovery code authorizes recovery while leaving ordinary account reads unavailable.
async fn prove_recovery_code(world: &World<'_>, recovering: &RecoverySession, code: String) {
    let recovery = SessionCode {
        session_id: recovering.device.session.session_id.clone(),
        code,
    };
    factors::redeem_recovery_code(world.tenant(), &recovery)
        .send(&recovering.device.client)
        .await
        .ok();
    people::me(world.tenant())
        .send(&recovering.device.client)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// Enrolling and confirming a replacement phone completes the recovery session as Pat.
async fn replace_phone(
    world: &World<'_>,
    pat: &Person,
    recovering: &RecoverySession,
    clock: &Clock,
) -> TotpApp {
    let begun = factors::enroll_totp(world.tenant(), &FactorSetup::default())
        .send(&recovering.device.client)
        .await
        .ok();
    let mut phone = TotpApp::scanning(&begun.otpauth_uri);
    clock.advance(CODE_PERIOD);
    let confirm = ConfirmFactor {
        code: phone.code().await,
        session_id: Some(recovering.device.session.session_id.clone()),
    };
    factors::confirm_totp(world.tenant(), &confirm)
        .send(&recovering.device.client)
        .await
        .ok();
    let own = people::me(world.tenant())
        .send(&recovering.device.client)
        .await
        .ok();
    assert_eq!(own.id, pat.id(), "the new phone lets Pat in as herself");
    phone
}

/// The next password sign-in again owes a factor and is completed by the replacement phone.
async fn sign_in_with_replacement(
    world: &World<'_>,
    pat: &Person,
    recovering: &mut RecoverySession,
    phone: &mut TotpApp,
) {
    let answer = sessions::sign_in(world.tenant(), &recovering.sign_in)
        .send(&recovering.device.client)
        .await
        .ok();
    let TenantSignedIn::Session(next) = answer else {
        panic!("Pat chose her own password, so none must change");
    };
    assert_eq!(
        next.owed(),
        Owed::FactorCode,
        "the next sign-in owes the code again"
    );
    recovering.device.client.authorize(&next.refresh_token);
    let from_new_phone = SessionCode {
        session_id: next.session_id,
        code: phone.code().await,
    };
    factors::verify(world.tenant(), &from_new_phone)
        .send(&recovering.device.client)
        .await
        .ok();
    let own = people::me(world.tenant())
        .send(&recovering.device.client)
        .await
        .ok();
    assert_eq!(own.id, pat.id(), "the new phone answers the next sign-in");
}

/// Makes a second factor required in the tenant, with a baseline of a
/// second factor, as Ann with her password typed again.
async fn factor_required(world: &World<'_>) {
    let mut settings = tenants::sign_in_settings(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    settings.mfa_policy = MfaPolicy::Required;
    let Some(step_up) = settings.rest.get_mut("step_up") else {
        panic!("the tenant's sign-in settings hold a step-up policy");
    };
    step_up["baseline_aal"] = json!("Aal2");
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
