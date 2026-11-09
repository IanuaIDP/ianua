//! Max reads whether his account has a second factor: none before he
//! sets one up, his authenticator app after. It is his to read: nobody
//! else's session tells it, and nobody signed in reads anything.

use ianua_scenarios::api::member_factors;
use ianua_scenarios::authenticators::TotpApp;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::factors::ConfirmFactor;
use ianua_scenarios::wire::sign_in::{MemberFactorSetup, MemberProof};
use ianua_scenarios::world::World;

/// Max starts with no second factor. He sets up an authenticator app and
/// reads it enabled, naming its method; Ann's own status is as it was.
/// Nobody signed in reads a status, and Sam reads nothing of Ann's
/// company.
#[tokio::test]
async fn max_reads_his_second_factor_status_before_and_after_setting_one_up() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let before = member_factors::status(world.org())
        .send(world.member().client())
        .await
        .ok();
    assert!(!before.enabled, "Max has no second factor yet");
    assert!(before.method.is_none(), "so no method is named");

    enroll_authenticator(&world).await;

    let after = member_factors::status(world.org())
        .send(world.member().client())
        .await
        .ok();
    assert!(after.enabled, "Max's second factor is on");
    assert_eq!(
        after.method.as_deref(),
        Some("Totp"),
        "his authenticator is named"
    );
    let ann = member_factors::status(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert!(!ann.enabled, "Ann's status is still her own");
    member_factors::status(world.org())
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    member_factors::status(world.org())
        .send(world.stranger().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Max sets up an authenticator app, proving who he is with his
/// password, and confirms it with its first code.
async fn enroll_authenticator(world: &World<'_>) {
    let max = world.member();
    let setup = MemberFactorSetup {
        proof: MemberProof {
            password: max.password().to_owned(),
            code: None,
        },
    };
    let begun = member_factors::begin_totp(world.org(), &setup)
        .send(max.client())
        .await
        .ok();
    let mut phone = TotpApp::scanning(&begun.otpauth_uri);
    let confirm = ConfirmFactor {
        code: phone.code().await,
        session_id: None,
    };
    member_factors::confirm_totp(world.org(), &confirm)
        .send(max.client())
        .await
        .ok();
}
