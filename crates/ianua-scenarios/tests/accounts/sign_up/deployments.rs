//! Deployments that take no public sign-up: a self-hosted installation,
//! which says so, and a hosted one with no mail server, which says it is
//! open but can prove no mailbox. Ann's form is refused at both, mails
//! nothing, and her password opens nothing.

use ianua_scenarios::actors::{FOUNDER_PASSWORD, Founder};
use ianua_scenarios::api::{onboarding, sessions};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::sign_in::PasswordSignIn;

use crate::support::QUIET;

/// A self-hosted installation advertises closed sign-up and refuses Ann's
/// public founding form. Nothing is mailed and her password cannot sign in.
#[tokio::test]
async fn a_self_hosted_installation_says_sign_up_is_closed_and_takes_none() {
    let stack = Stack::start(Profile::standard().with("DEPLOYMENT", "self_hosted"))
        .await
        .expect("the stack starts");

    assert!(
        !advertised_open(&stack).await,
        "a self-hosted installation says sign-up is closed"
    );
    anns_form_is_refused(&stack).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// A hosted deployment without mail advertises open sign-up but refuses
/// Ann's form. Nothing is mailed and her password cannot sign in.
#[tokio::test]
async fn a_deployment_without_mail_takes_no_sign_up() {
    let stack = Stack::start(Profile::without_mail())
        .await
        .expect("the stack starts");

    assert!(
        advertised_open(&stack).await,
        "a hosted deployment says sign-up is open, mail or no mail"
    );
    anns_form_is_refused(&stack).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Whether the deployment says it takes sign-ups, as anyone may ask.
async fn advertised_open(stack: &Stack) -> bool {
    let reader = Founder::named(stack, "Reader");
    onboarding::availability()
        .send(reader.client())
        .await
        .ok()
        .open
}

/// Ann's form for Acme is refused as forbidden, nothing reaches her
/// mailbox, and her password opens nothing.
async fn anns_form_is_refused(stack: &Stack) {
    let ann = Founder::named(stack, "Ann");
    onboarding::sign_up(&ann.sign_up_of("Acme", FOUNDER_PASSWORD))
        .send(ann.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    sessions::member_sign_in(&PasswordSignIn::of(ann.email(), FOUNDER_PASSWORD))
        .send(ann.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    stack.mailbox().nothing_for(ann.email(), QUIET).await;
}
