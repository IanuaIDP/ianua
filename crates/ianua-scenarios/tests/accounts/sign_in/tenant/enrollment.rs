//! A setup Pat gives up: an authenticator she began and never confirmed
//! goes away only on her own proof, its secret confirms nothing afterwards,
//! and the next setup starts from a new secret. Uma, Mallory's stand-in
//! here, has nothing of Pat's to give up.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::factors;
use ianua_scenarios::authenticators::TotpApp;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::factors::{ConfirmFactor, FactorSetup, Proof};
use ianua_scenarios::world::World;

use crate::tenant::support::person;

/// A wrong guess at Pat's password.
const WRONG_PASSWORD: &str = "Scenario wrong orchard guess 3312";

/// `password` as the proof for starting or giving up a setup.
fn proved_by(password: &str) -> FactorSetup {
    FactorSetup {
        proof: Some(Proof::Password {
            password: password.to_owned(),
            code: None,
        }),
    }
}

/// Pat begins an authenticator and leaves it pending. A wrong password
/// gives nothing up, Uma has no setup of hers to give up, and nobody
/// signed in is refused outright. On her own password the setup is gone:
/// a code from the old secret confirms nothing and a second try finds
/// nothing to give up. Her next setup starts from a new secret and
/// confirms, and only that one is in force.
#[tokio::test]
async fn pat_gives_up_a_setup_and_the_next_one_starts_from_a_new_secret() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let uma = person(&world, "uma").await;
    let right = proved_by(pat.password());

    let begun = factors::enroll_totp(world.tenant(), &right)
        .send(pat.client())
        .await
        .ok();
    let mut old_phone = TotpApp::scanning(&begun.otpauth_uri);

    factors::abandon_totp(world.tenant(), &proved_by(WRONG_PASSWORD))
        .send(pat.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    factors::abandon_totp(world.tenant(), &proved_by(uma.password()))
        .send(uma.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    factors::abandon_totp(world.tenant(), &right)
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    still_pending(&world, &pat).await;

    factors::abandon_totp(world.tenant(), &right)
        .send(pat.client())
        .await
        .ok();
    let confirm = ConfirmFactor {
        code: old_phone.code().await,
        session_id: None,
    };
    factors::confirm_totp(world.tenant(), &confirm)
        .send(pat.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    factors::abandon_totp(world.tenant(), &right)
        .send(pat.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");

    let again = factors::enroll_totp(world.tenant(), &right)
        .send(pat.client())
        .await
        .ok();
    assert_ne!(
        again.otpauth_uri, begun.otpauth_uri,
        "the next setup starts from a new secret"
    );
    let mut new_phone = TotpApp::scanning(&again.otpauth_uri);
    let confirm = ConfirmFactor {
        code: new_phone.code().await,
        session_id: None,
    };
    factors::confirm_totp(world.tenant(), &confirm)
        .send(pat.client())
        .await
        .ok();
    let status = factors::status(world.tenant())
        .send(pat.client())
        .await
        .ok();
    assert!(status.enabled, "the new setup is in force");

    stack.stop().await.expect("the stack stops cleanly");
}

/// `pat`'s factor still reads as pending.
async fn still_pending(world: &World<'_>, pat: &Person) {
    let options = factors::options(world.tenant(), None)
        .send(pat.client())
        .await
        .ok();
    assert_eq!(options.held.state, "pending", "the setup is still pending");
}
