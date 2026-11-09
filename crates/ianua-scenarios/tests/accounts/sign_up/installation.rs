//! A self-hosted installation and the one-time proof its installer prints
//! for Ann, its owner: used once and only to confirm her, with mail and
//! without, and worth nothing after its day.

use std::time::Duration;

use ianua_scenarios::actors::Founder;
use ianua_scenarios::api::{OrgPath, member_factors, members, onboarding};
use ianua_scenarios::authenticators::TotpApp;
use ianua_scenarios::clock::Clock;
use ianua_scenarios::stack::{Installed, Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::factors::ConfirmFactor;
use ianua_scenarios::wire::onboarding::{ConfirmInstaller, ConfirmSignup, Founded};
use ianua_scenarios::wire::sign_in::{Owed, Session};

use crate::support::{QUIET, installation_of, installed, owner_signed_in, ready_tenant};

/// One second more than the day an installer's proof is kept.
const PAST_A_DAY: Duration = Duration::from_secs(86_401);

/// Rerunning Ann's installer reports an existing installation without a
/// second proof. A guessed proof, using the proof as a sign-up link and
/// reusing it after confirmation all return not found. The valid proof
/// confirms Ann once; she reads her verified account and her tenant is ready.
#[tokio::test]
async fn installing_twice_changes_nothing_and_the_proof_works_once() {
    let stack = Stack::start(Profile::standard().with("DEPLOYMENT", "self_hosted"))
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let install = installation_of(&ann);
    let installation = installed(&stack, &install).await;

    let again = stack
        .installed(&install)
        .await
        .expect("the second run succeeds");
    assert!(
        matches!(again, Installed::AlreadyThere),
        "a second run leaves the installation as it is"
    );

    assert_installer_proof_scope(&ann, &installation.setup_token).await;

    let proof = ConfirmInstaller {
        token: installation.setup_token.clone(),
    };
    onboarding::confirm_installer(&proof)
        .send(ann.client())
        .await
        .ok();
    onboarding::confirm_installer(&proof)
        .send(ann.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");

    owner_signed_in(&stack, &mut ann, &installation.founded).await;
    ready_tenant(&ann, &installation.founded).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Neither a guessed proof nor a valid proof used for public signup is accepted.
async fn assert_installer_proof_scope(ann: &Founder, setup_token: &str) {
    onboarding::confirm_installer(&ConfirmInstaller {
        token: "nobody-issued-this-proof".to_owned(),
    })
    .send(ann.client())
    .await
    .refused(Status::NOT_FOUND, "not_found");
    onboarding::confirm(&ConfirmSignup {
        token: setup_token.to_owned(),
    })
    .send(ann.client())
    .await
    .refused(Status::NOT_FOUND, "not_found");
}

/// With no mail server, the installer's proof stands in for Ann's
/// mailbox. Her password sign-in owes an authenticator app; until she
/// sets one up and confirms it, the session reads nothing. Then she reads
/// her verified account, her first tenant is ready, and nothing was
/// mailed.
#[tokio::test]
async fn an_installed_owner_without_mail_is_in_once_the_authenticator_is_set_up() {
    let stack = Stack::start(Profile::without_mail().with("DEPLOYMENT", "self_hosted"))
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let installation = installed(&stack, &installation_of(&ann)).await;
    onboarding::confirm_installer(&ConfirmInstaller {
        token: installation.setup_token,
    })
    .send(ann.client())
    .await
    .ok();

    let session = ann.password_sign_in().await;
    assert_eq!(
        session.owed(),
        Owed::FactorEnrolment,
        "without mail, an owner's first sign-in owes an authenticator"
    );
    ann.client_mut().authorize(&session.refresh_token);
    let org = OrgPath::new(&installation.founded.org_slug);
    members::me(&org)
        .send(ann.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    enroll_installed_owner(&ann, &org, session).await;

    assert_installed_owner(&ann, &org, &installation.founded).await;
    ready_tenant(&ann, &installation.founded).await;
    stack.mailbox().nothing_for(ann.email(), QUIET).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// The completed session belongs to the installed owner whose proof verified the mailbox.
async fn assert_installed_owner(ann: &Founder, org: &OrgPath, founded: &Founded) {
    let owner = members::me(org).send(ann.client()).await.ok();
    assert_eq!(
        owner.id, founded.admin_user_id,
        "Ann is the owner installed"
    );
    assert!(
        owner.email_verified,
        "the installer's proof verified her address"
    );
}

/// The installed owner satisfies the waiting session's required authenticator setup.
async fn enroll_installed_owner(ann: &Founder, org: &OrgPath, session: Session) {
    let begun = member_factors::begin_required_totp(org)
        .send(ann.client())
        .await
        .ok();
    let mut phone = TotpApp::scanning(&begun.otpauth_uri);
    member_factors::confirm_totp(
        org,
        &ConfirmFactor {
            code: phone.code().await,
            session_id: Some(session.session_id),
        },
    )
    .send(ann.client())
    .await
    .ok();
}

/// Ann's unused installer proof expires after a day and cannot confirm her.
/// Her unauthenticated account read is refused, and rerunning the installer
/// reports an existing installation without another proof.
#[tokio::test]
async fn an_expired_installation_proof_cannot_verify_the_owner() {
    let clock = Clock::controlled();
    let stack = Stack::start(Profile::without_mail().with("DEPLOYMENT", "self_hosted"))
        .await
        .expect("the stack starts");
    let ann = Founder::named(&stack, "Ann");
    let install = installation_of(&ann);
    let installation = installed(&stack, &install).await;

    clock.advance(PAST_A_DAY);
    onboarding::confirm_installer(&ConfirmInstaller {
        token: installation.setup_token,
    })
    .send(ann.client())
    .await
    .refused(Status::GONE, "link_expired");
    members::me(&OrgPath::new(&installation.founded.org_slug))
        .send(ann.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    let again = stack.installed(&install).await.expect("the rerun succeeds");
    assert!(
        matches!(again, Installed::AlreadyThere),
        "the rerun prints no second proof"
    );

    stack.stop().await.expect("the stack stops cleanly");
}
