//! Sign-up as an attacker tries it: a link replayed or made up, someone
//! else's address, a sign-up never confirmed, a weak or breached password,
//! a header or a script smuggled into a name, fields the form never had,
//! and a mailbox flooded with links.

use ianua_scenarios::actors::{FOUNDER_PASSWORD, Founder};
use ianua_scenarios::api::{onboarding, sessions};
use ianua_scenarios::expect::assert_clean_refusal;
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::stack::{BREACHED_PASSWORDS, Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::onboarding::{ConfirmSignup, Signup};
use ianua_scenarios::wire::sign_in::PasswordSignIn;
use serde::de::IgnoredAny;
use serde_json::json;

use crate::support::{QUIET, requested};

/// How many times Mallory asks for a link to Ann's address in the flood.
const FLOOD: usize = 5;

/// Ann founds her company from its link. Mallory, who saw the link, opens
/// it again: it works once, so nothing more is founded and nothing
/// changes hands.
#[tokio::test]
async fn a_sign_up_link_works_once() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let ann = Founder::named(&stack, "Ann");
    let link = requested(&stack, &ann, "Acme").await;
    ann.confirmed_sign_up(&link).await.ok();

    let mallory = Founder::named(&stack, "Mallory");
    let replayed = mallory.confirmed_sign_up(&link).await;
    assert_clean_refusal("the sign-up link opened a second time", &replayed);

    ann.signed_in(&stack).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Mallory makes up sign-up links: an empty token, a random one, and
/// Ann's real one with one character changed. Each is refused, and Ann's
/// own link still works after them.
#[tokio::test]
async fn a_made_up_or_spoiled_sign_up_link_is_refused() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let ann = Founder::named(&stack, "Ann");
    let link = requested(&stack, &ann, "Acme").await;
    let real = link.token_in("/signup/confirm");

    let mallory = Client::new(&stack, "Mallory, making up links").expect("a client");
    for (what, token) in [
        ("an empty token", String::new()),
        ("a random token", uuid::Uuid::new_v4().simple().to_string()),
        ("Ann's token with one character changed", spoiled(&real)),
    ] {
        let answer = onboarding::confirm(&ConfirmSignup { token })
            .send(&mallory)
            .await;
        assert_clean_refusal(what, &answer);
    }

    ann.confirmed_sign_up(&link).await.ok();
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann has an account. Mallory signs up with Ann's address and her own
/// password: the answer is exactly the one a new address gets, so it says
/// nothing of Ann; whatever reaches Ann carries no link that would found
/// anything (the notice that someone tried is held back when Ann was
/// mailed a moment ago, so it may not come at all); and Mallory's
/// password opens nothing.
#[tokio::test]
async fn signing_up_with_someone_elses_address_learns_and_takes_nothing() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let ann = Founder::named(&stack, "Ann");
    ann.founded(&stack, "Acme").await;

    let mallory = Founder::named(&stack, "Mallory");
    let fresh = Founder::named(&stack, "Nobody");
    let mallorys_password = "Mallory owns this account now 7319";
    let as_ann = Signup {
        admin_email: ann.email().to_owned(),
        ..mallory.sign_up_of("Mallory Inc", mallorys_password)
    };
    let taken = onboarding::sign_up(&as_ann).send(mallory.client()).await;
    let new = onboarding::sign_up(&fresh.sign_up_of("Fresh Co", FOUNDER_PASSWORD))
        .send(fresh.client())
        .await;
    assert_eq!(taken.status(), new.status(), "the same status either way");
    assert_eq!(
        taken.ok().status,
        new.ok().status,
        "the same answer either way"
    );
    assert_no_founding_link(&stack, &ann).await;
    sessions::member_sign_in(&PasswordSignIn::of(ann.email(), mallorys_password))
        .send(mallory.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Any notice about the occupied address carries no proof that can found a company.
async fn assert_no_founding_link(stack: &Stack, ann: &Founder) {
    if let Some(notice) = stack.mailbox().within(ann.email(), QUIET).await {
        assert!(
            notice
                .links()
                .iter()
                .all(|link| !link.path().starts_with("/signup/confirm")),
            "the notice to Ann carries no link that founds anything"
        );
    }
}

/// Mallory signs up with Victor's address, which she does not own, and
/// never confirms: the password she chose opens nothing, and the answer
/// to it is the one an address nobody holds gets.
#[tokio::test]
async fn an_unconfirmed_sign_up_grants_nothing() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let victor = Founder::named(&stack, "Victor");
    onboarding::sign_up(&victor.sign_up_of("Victor Ltd", FOUNDER_PASSWORD))
        .send(victor.client())
        .await
        .ok();

    let unconfirmed =
        sessions::member_sign_in(&PasswordSignIn::of(victor.email(), FOUNDER_PASSWORD))
            .send(victor.client())
            .await
            .refused(Status::NOT_FOUND, "not_found");
    let nobody = format!("nobody@{}", stack.base_domain());
    let unknown = sessions::member_sign_in(&PasswordSignIn::of(&nobody, FOUNDER_PASSWORD))
        .send(victor.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    assert_eq!(
        unconfirmed.message(),
        unknown.message(),
        "an unconfirmed sign-up reads as an address nobody holds"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// A sign-up with a password from a breach, or one far too short, is
/// refused before anything is kept, so no link is mailed.
#[tokio::test]
async fn a_weak_or_breached_password_is_refused_before_any_mail() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let ann = Founder::named(&stack, "Ann");

    for (what, password) in [
        ("a breached password", BREACHED_PASSWORDS[0]),
        ("a password of three letters", "abc"),
    ] {
        let answer = onboarding::sign_up(&ann.sign_up_of("Acme", password))
            .send(ann.client())
            .await;
        assert_clean_refusal(what, &answer);
    }
    stack.mailbox().nothing_for(ann.email(), QUIET).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Mallory hides a mail header in her name, hoping for a copy of the
/// link at Eve's address, and a script in her company's name, hoping it
/// runs where the name is shown. A name holding a line break is refused
/// before anything is kept, so the header reaches no one and nothing is
/// mailed at all.
#[tokio::test]
async fn a_header_or_a_script_in_a_name_is_inert() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mallory = Founder::named(&stack, "Mallory");
    let eve = format!("eve@{}", stack.base_domain());
    let smuggling = Signup {
        admin_display_name: format!("Mallory\r\nBcc: {eve}"),
        company_name: "<script>alert(1)</script> Inc".to_owned(),
        ..mallory.sign_up_of("unused", FOUNDER_PASSWORD)
    };

    onboarding::sign_up(&smuggling)
        .send(mallory.client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    stack.mailbox().nothing_for(&eve, QUIET).await;
    stack.mailbox().nothing_for(mallory.email(), QUIET).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Mallory adds what the form never asks for, hoping the platform takes
/// it: a plan, an operator's role, an address already verified, another
/// organization's id. None of it counts: the form is taken as if they
/// were not there, she ends up the owner of a new organization and
/// nothing more, with no reach into the platform's own staff pages.
#[tokio::test]
async fn fields_the_form_never_had_grant_nothing() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut mallory = Founder::named(&stack, "Mallory");
    let mut body = serde_json::to_value(mallory.sign_up_of("Mallory Inc", FOUNDER_PASSWORD))
        .expect("a sign-up serializes");
    for (field, value) in [
        ("plan", json!("business")),
        ("role", json!("operator")),
        ("is_operator", json!(true)),
        ("email_verified", json!(true)),
        ("organization_id", json!(uuid::Uuid::new_v4())),
    ] {
        body[field] = value;
    }

    mallory
        .client()
        .send::<IgnoredAny>(Call::post("/api/v1/signup").json(&body))
        .await
        .ok();
    let link = stack.mailbox().next_for(mallory.email()).await;
    mallory.confirmed_sign_up(&link).await.ok();
    let session = mallory.signed_in(&stack).await;
    mallory.client_mut().authorize(&session.refresh_token);

    let staff = mallory
        .client()
        .send::<IgnoredAny>(Call::get("/api/v1/operators"))
        .await;
    assert_clean_refusal("an owner reading the platform's operators", &staff);

    stack.stop().await.expect("the stack stops cleanly");
}

/// Mallory asks for sign-ups to Ann's address again and again to flood
/// her mailbox: every request gets the same answer, but Ann gets one link,
/// not one per request.
#[tokio::test]
async fn a_flood_of_sign_ups_mails_one_link() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let ann = Founder::named(&stack, "Ann");
    let mallory = Client::new(&stack, "Mallory, flooding").expect("a client");
    let flood = ann.sign_up_of("Acme", FOUNDER_PASSWORD);

    for _ in 0..FLOOD {
        let answer = onboarding::sign_up(&flood).send(&mallory).await.ok();
        assert_eq!(
            answer.status, "check_inbox",
            "every request is answered alike"
        );
    }
    stack.mailbox().next_for(ann.email()).await;
    stack.mailbox().nothing_for(ann.email(), QUIET).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// `token` with its last character changed.
fn spoiled(token: &str) -> String {
    let mut spoiled: Vec<char> = token.chars().collect();
    let Some(last) = spoiled.last_mut() else {
        return "x".to_owned();
    };
    *last = if *last == 'a' { 'b' } else { 'a' };
    spoiled.into_iter().collect()
}
