//! Founding through trouble: audit storage refusing writes, the cache,
//! bus, database or mail server cut, and the API and worker restarted
//! while Ann's link waits. Each time her link founds once, her tenant is
//! ready, and the founding is recorded once.

use ianua_scenarios::actors::{FOUNDER_PASSWORD, Founder};
use ianua_scenarios::api::{onboarding, sessions};
use ianua_scenarios::expect::no_secret_leaked;
use ianua_scenarios::mail::Mail;
use ianua_scenarios::stack::{AuditWrites, Part, Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::sign_in::PasswordSignIn;

use crate::support::{
    QUIET, founding_recorded_once, owner_signed_in, ready_again, ready_tenant, requested,
};

/// Refusing audit writes makes Ann's confirmation fail, and her password
/// cannot sign in afterward. Once audit writes resume, the same link founds
/// the company, Ann reads her verified account, the tenant becomes ready
/// and each founding event is recorded once.
#[tokio::test]
async fn an_audit_failure_rolls_back_founding_and_preserves_the_proof() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let mail = requested(&stack, &ann, "Acme").await;

    stack.audit_writes(AuditWrites::Refuse).await;
    let failed = ann.confirmed_sign_up(&mail).await;
    assert_eq!(
        failed.status(),
        Status::INTERNAL_SERVER_ERROR,
        "a founding nobody can record fails: {}",
        failed.summary()
    );
    stack.audit_writes(AuditWrites::Allow).await;
    sessions::member_sign_in(&PasswordSignIn::of(ann.email(), FOUNDER_PASSWORD))
        .send(ann.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");

    let founded = ann.confirmed_sign_up(&mail).await.ok();
    owner_signed_in(&stack, &mut ann, &founded).await;
    ready_tenant(&ann, &founded).await;
    founding_recorded_once(&ann, &founded, &mail.token_in("/signup/confirm")).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// With the shared cache cut, Ann's first form mails a link and her second
/// mails nothing. After the cache returns, her password is still refused
/// until confirmation. The original link founds the company, its tenant
/// becomes ready and each founding event is recorded once.
#[tokio::test]
async fn a_shared_cache_outage_preserves_local_throttling_and_mailbox_proof() {
    let stack = Stack::start(Profile::standard().with_cuttable_parts())
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");

    stack.cut(Part::Cache);
    let mail = assert_signup_throttling(&stack, &ann).await;

    stack.mend(Part::Cache);
    ready_again(&stack).await;
    sessions::member_sign_in(&PasswordSignIn::of(ann.email(), FOUNDER_PASSWORD))
        .send(ann.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");

    let founded = ann.confirmed_sign_up(&mail).await.ok();
    owner_signed_in(&stack, &mut ann, &founded).await;
    ready_tenant(&ann, &founded).await;
    founding_recorded_once(&ann, &founded, &mail.token_in("/signup/confirm")).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// With the shared cache cut, the first form mails a proof and its repeat mails nothing.
async fn assert_signup_throttling(stack: &Stack, ann: &Founder) -> Mail {
    let accepted = onboarding::sign_up(&ann.sign_up_of("Acme", FOUNDER_PASSWORD))
        .send(ann.client())
        .await;
    assert_eq!(
        accepted.status(),
        Status::ACCEPTED,
        "the form is taken with the cache cut: {}",
        accepted.summary()
    );
    accepted.ok();
    let mail = stack.mailbox().next_for(ann.email()).await;
    onboarding::sign_up(&ann.sign_up_of("Acme", FOUNDER_PASSWORD))
        .send(ann.client())
        .await
        .ok();
    stack.mailbox().nothing_for(ann.email(), QUIET).await;
    mail
}

/// The bus is cut when Ann opens her link. The founding is kept in the
/// database and the setup queued there, whatever the bus delivers. Once
/// the bus is back she uses her company, its founding recorded once, and
/// the link cannot be opened again.
#[tokio::test]
async fn a_bus_outage_does_not_lose_signup_or_duplicate_its_audit() {
    let stack = Stack::start(Profile::standard().with_cuttable_parts())
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let mail = requested(&stack, &ann, "Acme").await;

    stack.cut(Part::Bus);
    let founded = ann.confirmed_sign_up(&mail).await.ok();
    stack.mend(Part::Bus);

    owner_signed_in(&stack, &mut ann, &founded).await;
    ready_tenant(&ann, &founded).await;
    founding_recorded_once(&ann, &founded, &mail.token_in("/signup/confirm")).await;
    ann.confirmed_sign_up(&mail)
        .await
        .refused(Status::NOT_FOUND, "not_found");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann gets her link, and the API and worker restart before she opens
/// it. The link still founds her company; the setup finishes across
/// another restart; she reads her account, her tenant is ready, the
/// founding is recorded once, and the link cannot be opened again.
#[tokio::test]
async fn signup_resumes_after_control_plane_restarts() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let mail = requested(&stack, &ann, "Acme").await;

    stack
        .restart()
        .await
        .expect("the API and worker restart with the link pending");
    let founded = ann.confirmed_sign_up(&mail).await.ok();
    stack
        .restart()
        .await
        .expect("the API and worker restart with the setup running");

    owner_signed_in(&stack, &mut ann, &founded).await;
    ready_tenant(&ann, &founded).await;
    founding_recorded_once(&ann, &founded, &mail.token_in("/signup/confirm")).await;
    ann.confirmed_sign_up(&mail)
        .await
        .refused(Status::NOT_FOUND, "not_found");

    stack.stop().await.expect("the stack stops cleanly");
}

/// A database outage makes Ann's confirmation fail without exposing its
/// token. After recovery, the same link founds the company, Ann reads her
/// verified account, the tenant becomes ready and each founding event is
/// recorded once.
#[tokio::test]
async fn a_database_outage_preserves_the_signup_proof_for_retry() {
    let stack = Stack::start(Profile::standard().with_cuttable_parts())
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let mail = requested(&stack, &ann, "Acme").await;

    stack.cut(Part::Database);
    let refused = ann.confirmed_sign_up(&mail).await;
    assert!(
        refused.status().is_server_error(),
        "a founding with no database fails: {}",
        refused.summary()
    );
    no_secret_leaked(
        refused.exchange().response_body(),
        &[&mail.token_in("/signup/confirm")],
    );

    stack.mend(Part::Database);
    ready_again(&stack).await;
    let founded = ann.confirmed_sign_up(&mail).await.ok();
    owner_signed_in(&stack, &mut ann, &founded).await;
    ready_tenant(&ann, &founded).await;
    founding_recorded_once(&ann, &founded, &mail.token_in("/signup/confirm")).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// The mail server is down when Ann sends her form. The form is taken,
/// her password opens nothing, and no mail comes. Once the server is back
/// the queued link reaches her, with short retries configured; it founds
/// the company once, and no second link follows.
#[tokio::test]
async fn a_mail_outage_retries_delivery_without_creating_an_unproven_owner() {
    let stack = Stack::start(
        Profile::standard()
            .with_cuttable_parts()
            .with("EMAIL_SEND_TIMEOUT_SECONDS", "1")
            .with("JOB_RETRY_BACKOFF_SECONDS", "1,2,3"),
    )
    .await
    .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");

    stack.cut(Part::Mail);
    onboarding::sign_up(&ann.sign_up_of("Acme", FOUNDER_PASSWORD))
        .send(ann.client())
        .await
        .ok();
    sessions::member_sign_in(&PasswordSignIn::of(ann.email(), FOUNDER_PASSWORD))
        .send(ann.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    stack.mailbox().nothing_for(ann.email(), QUIET).await;

    stack.mend(Part::Mail);
    let mail = stack.mailbox().next_for(ann.email()).await;
    let founded = ann.confirmed_sign_up(&mail).await.ok();
    owner_signed_in(&stack, &mut ann, &founded).await;
    ready_tenant(&ann, &founded).await;
    founding_recorded_once(&ann, &founded, &mail.token_in("/signup/confirm")).await;
    stack.mailbox().nothing_for(ann.email(), QUIET).await;

    stack.stop().await.expect("the stack stops cleanly");
}
