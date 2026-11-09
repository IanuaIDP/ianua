//! Pat's authenticator half set up when the platform restarts and when
//! an audit write fails: the setup is neither lost nor switched on until
//! the same code confirms it once, after which the new phone answers her
//! next sign-in.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{factors, people};
use ianua_scenarios::authenticators::TotpApp;
use ianua_scenarios::clock::Clock;
use ianua_scenarios::stack::{AuditWrites, Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::factors::{ConfirmFactor, FactorSetup, Proof};
use ianua_scenarios::world::World;

use crate::support::{invited_and_signed_in, tenant_records};

/// Pat scans her new authenticator, and the API and worker restart: the
/// factor is not on. She confirms it while audit writes fail: the
/// confirmation fails as a server error, the factor is still not on, and
/// nothing is recorded. With audit writes back, the same code confirms it:
/// recovery codes are shown, the factor is on, her session goes on, and
/// her next sign-in is answered by the new phone. One setup is recorded.
#[tokio::test]
async fn a_half_set_up_authenticator_survives_a_restart_and_a_failed_audit() {
    let _clock = Clock::controlled();
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited_and_signed_in(&world, "pat").await;
    let mut phone = scan_before_restart(&world, &pat).await;
    let confirm = ConfirmFactor {
        code: phone.code().await,
        session_id: None,
    };
    fail_confirmation(&world, &pat, &confirm).await;
    retry_confirmation(&world, &pat, &confirm).await;
    pat.find_phone(phone);
    pat.sign_in(&stack).await;
    let own = people::me(world.tenant()).send(pat.client()).await.ok();
    assert_eq!(own.id, pat.id(), "the new phone answers the next sign-in");
    assert_eq!(
        tenant_records(&world, "authentication.mfa_enrolled", &[]).await,
        1,
        "the setup is recorded once"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Scanning before a restart preserves the pending setup without enabling the factor.
async fn scan_before_restart(world: &World<'_>, pat: &Person) -> TotpApp {
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
    let phone = TotpApp::scanning(&begun.otpauth_uri);
    world
        .stack()
        .restart()
        .await
        .expect("the API and worker restart");
    let status = factors::status(world.tenant())
        .send(pat.client())
        .await
        .ok();
    assert!(!status.enabled, "a factor not yet confirmed is not on");
    phone
}

/// A failed audit write rolls back confirmation and records no enrollment.
async fn fail_confirmation(world: &World<'_>, pat: &Person, confirm: &ConfirmFactor) {
    world.stack().audit_writes(AuditWrites::Refuse).await;
    let failed = factors::confirm_totp(world.tenant(), confirm)
        .send(pat.client())
        .await;
    assert_eq!(
        failed.status(),
        Status::INTERNAL_SERVER_ERROR,
        "a confirmation whose record cannot be written fails: {}",
        failed.summary()
    );
    world.stack().audit_writes(AuditWrites::Allow).await;
    let status = factors::status(world.tenant())
        .send(pat.client())
        .await
        .ok();
    assert!(!status.enabled, "a failed confirmation turns nothing on");
    assert_eq!(
        tenant_records(world, "authentication.mfa_enrolled", &[]).await,
        0,
        "a failed confirmation records no setup"
    );
}

/// Retrying the same code enables the factor, returns recovery codes and keeps Pat's session.
async fn retry_confirmation(world: &World<'_>, pat: &Person, confirm: &ConfirmFactor) {
    let shown = factors::confirm_totp(world.tenant(), confirm)
        .send(pat.client())
        .await
        .ok();
    assert!(
        !shown.recovery_codes.is_empty(),
        "the confirmed factor comes with recovery codes"
    );
    let status = factors::status(world.tenant())
        .send(pat.client())
        .await
        .ok();
    assert!(status.enabled, "the same code confirms the factor");
    let own = people::me(world.tenant()).send(pat.client()).await.ok();
    assert_eq!(own.id, pat.id(), "Pat's session goes on");
}
