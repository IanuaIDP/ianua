//! Two people after one company: Ann's one link opened in two browsers
//! at once, Ann and Bob asking for the same name before either confirms,
//! and Bob spelling Acme's name differently, who founds Globex instead.
//! Each time one company is founded, once, with its one owner.

use ianua_scenarios::actors::{FOUNDER_PASSWORD, Founder};
use ianua_scenarios::api::{OrgPath, members, onboarding, sessions};
use ianua_scenarios::expect::{Matrix, Trail};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::onboarding::{ConfirmSignup, Founded};
use ianua_scenarios::wire::sign_in::PasswordSignIn;
use ianua_scenarios::wire::{Answer, Status};

/// The events a founding records once: the company and its owner.
const FOUNDED_ONCE: [&str; 2] = ["organization.created", "organization.org_user_created"];

/// Ann opens her link in two browsers at once; the second is Mallory's,
/// who saw the link. One click founds the company and the other is
/// refused, and neither signs anyone in. Ann signs in afterwards and reads
/// her account; the company and her account were each created once.
#[tokio::test]
async fn one_link_opened_twice_at_once_founds_one_company() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let mallory = Founder::named(&stack, "Mallory");
    onboarding::sign_up(&ann.sign_up_of("Acme", FOUNDER_PASSWORD))
        .send(ann.client())
        .await
        .ok();
    let mail = stack.mailbox().next_for(ann.email()).await;
    let confirm = ConfirmSignup {
        token: mail.token_in("/signup/confirm"),
    };

    let (first, second) = tokio::join!(
        onboarding::confirm(&confirm).send(ann.client()),
        onboarding::confirm(&confirm).send(mallory.client())
    );
    let founded = assert_one_founding([first, second]);
    assert_clicks_leave_signed_out(&ann, &mallory, &founded).await;

    let session = ann.signed_in(&stack).await;
    ann.client_mut().authorize(&session.refresh_token);
    let owner = members::me(&OrgPath::new(&founded.org_slug))
        .send(ann.client())
        .await
        .ok();
    assert_eq!(owner.email, ann.email(), "Ann is the owner");
    assert_founded_once(&ann, &founded).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Concurrent confirmations produce one company and one missing-token refusal.
fn assert_one_founding(mut answers: [Answer<Founded>; 2]) -> Founded {
    answers.sort_by_key(Answer::status);
    let [accepted, refused] = answers;
    assert_eq!(
        accepted.status(),
        Status::CREATED,
        "one click founds the company: {}",
        accepted.summary()
    );
    let founded = accepted.ok();
    refused.refused(Status::NOT_FOUND, "not_found");
    founded
}

/// Neither browser acquires a session merely by confirming the signup link.
async fn assert_clicks_leave_signed_out(ann: &Founder, mallory: &Founder, founded: &Founded) {
    let org = OrgPath::new(&founded.org_slug);
    Matrix::new(
        "reading the owner's record after a click",
        members::me(&org).call(),
    )
    .refused(ann.client(), Status::UNAUTHORIZED, "unauthenticated")
    .refused(mallory.client(), Status::UNAUTHORIZED, "unauthenticated")
    .run()
    .await;
}

/// The company and owner each have one creation record in the founder's trail.
async fn assert_founded_once(ann: &Founder, founded: &Founded) {
    let trail = Trail::of_organization(ann.client(), &founded.org_slug);
    for event in FOUNDED_ONCE {
        trail.recorded(event).await;
        assert_eq!(trail.count(event).await, 1, "one {event}");
    }
}

/// Ann and Bob both ask for Acme before either confirms. Ann confirms
/// first. Bob's link, still in date, is refused with the name taken, and
/// his password opens nothing. Ann reads her account and Bob is refused
/// it; her trail holds one founding.
#[tokio::test]
async fn a_company_name_claimed_before_confirmation_preserves_its_owner() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let bob = Founder::named(&stack, "Bob");
    for founder in [&ann, &bob] {
        onboarding::sign_up(&founder.sign_up_of("Acme", FOUNDER_PASSWORD))
            .send(founder.client())
            .await
            .ok();
    }
    let anns = stack.mailbox().next_for(ann.email()).await;
    let bobs = stack.mailbox().next_for(bob.email()).await;

    let founded = ann.confirmed_sign_up(&anns).await.ok();
    let problem = bob
        .confirmed_sign_up(&bobs)
        .await
        .refused(Status::CONFLICT, "conflict");
    assert_eq!(problem.message(), "Company name already taken");
    sessions::member_sign_in(&PasswordSignIn::of(bob.email(), FOUNDER_PASSWORD))
        .send(bob.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");

    let session = ann.signed_in(&stack).await;
    ann.client_mut().authorize(&session.refresh_token);
    assert_claimed_company(&ann, &bob, &founded).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// The successful founder alone reads the company, whose founding appears once.
async fn assert_claimed_company(ann: &Founder, bob: &Founder, founded: &Founded) {
    let org = OrgPath::new(&founded.org_slug);
    Matrix::new(
        "reading the owner's record of the company Ann founded",
        members::me(&org).call(),
    )
    .allowed(ann.client())
    .refused(bob.client(), Status::UNAUTHORIZED, "unauthenticated")
    .run()
    .await;
    assert_founded_once(ann, founded).await;
}

/// Ann owns Acme Corp. Bob asks for ACME---CORP, which makes the same
/// slug: refused as taken. He founds Globex instead; each founder reads
/// only their own company, and each company was founded once.
#[tokio::test]
async fn a_duplicate_name_can_be_corrected_without_affecting_the_existing_company() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let mut bob = Founder::named(&stack, "Bob");
    let acme = ann.founded(&stack, "Acme Corp").await;

    let problem = onboarding::sign_up(&bob.sign_up_of("ACME---CORP", FOUNDER_PASSWORD))
        .send(bob.client())
        .await
        .refused(Status::CONFLICT, "conflict");
    assert_eq!(problem.message(), "Company name already taken");

    let globex = bob.founded(&stack, "Globex").await;
    let anns = ann.signed_in(&stack).await;
    let bobs = bob.signed_in(&stack).await;
    ann.client_mut().authorize(&anns.refresh_token);
    bob.client_mut().authorize(&bobs.refresh_token);
    for (company, owner, stranger) in [(&acme, &ann, &bob), (&globex, &bob, &ann)] {
        assert_independent_company(company, owner, stranger).await;
    }

    stack.stop().await.expect("the stack stops cleanly");
}

/// The corrected name leaves both companies isolated and founded exactly once.
async fn assert_independent_company(company: &Founded, owner: &Founder, stranger: &Founder) {
    let org = OrgPath::new(&company.org_slug);
    Matrix::new(
        "reading the owner's record of each company",
        members::me(&org).call(),
    )
    .allowed(owner.client())
    .refused(stranger.client(), Status::FORBIDDEN, "forbidden")
    .run()
    .await;
    let trail = Trail::of_organization(owner.client(), &company.org_slug);
    trail.recorded("organization.created").await;
    assert_eq!(
        trail.count("organization.created").await,
        1,
        "{} was founded once",
        company.org_slug
    );
}
