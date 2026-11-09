//! Pat's consent in her tenant: given and withdrawn purpose by purpose,
//! each decision kept in order; given and read by Pat alone, not by Tess
//! for her nor by Uma; and each version of the terms a decision of its
//! own, with no withdrawal of what was never given.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::account;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::account::Consent;
use ianua_scenarios::world::World;

use crate::support::{invited_and_signed_in, still_signed_in, tenant_records};

/// Every purpose the platform asks consent for.
const PURPOSES: [&str; 6] = [
    "DataProcessing",
    "Marketing",
    "TermsOfService",
    "PrivacyPolicy",
    "HealthDataSharing",
    "Cookies",
];

/// Pat grants every purpose, then withdraws marketing: her history holds
/// seven decisions, the withdrawal first and every grant after it. She
/// withdraws the rest one by one: six grants and six withdrawals are
/// recorded, and her session goes on.
#[tokio::test]
async fn pat_grants_every_purpose_and_withdraws_them_one_by_one() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = invited_and_signed_in(&world, "pat").await;
    grant_every_purpose(&world, &pat).await;
    withdraw_marketing(&world, &pat).await;
    withdraw_remaining_purposes(&world, &pat).await;
    assert_eq!(
        tenant_records(&world, "identity.consent_granted", &[]).await,
        6,
        "each grant is recorded"
    );
    assert_eq!(
        tenant_records(&world, "identity.consent_revoked", &[]).await,
        6,
        "each withdrawal is recorded"
    );
    still_signed_in(&world, &pat).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat grants each supported purpose under the same version of the terms.
async fn grant_every_purpose(world: &World<'_>, pat: &Person) {
    for purpose in PURPOSES {
        account::consent(
            world.tenant(),
            pat.id(),
            &decision(purpose, "terms-v1", true),
        )
        .send(pat.client())
        .await
        .ok();
    }
}

/// The first withdrawal appears ahead of all six earlier grants in Pat's history.
async fn withdraw_marketing(world: &World<'_>, pat: &Person) {
    account::consent(
        world.tenant(),
        pat.id(),
        &decision("Marketing", "terms-v1", false),
    )
    .send(pat.client())
    .await
    .ok();
    let decisions = account::consents(world.tenant(), pat.id())
        .send(pat.client())
        .await
        .ok();
    assert_eq!(decisions.len(), 7, "six grants and one withdrawal");
    let Some(newest) = decisions.first() else {
        panic!("seven decisions have a first");
    };
    assert_eq!(
        newest.consent_type, "Marketing",
        "the withdrawal, made last, comes first"
    );
    assert!(!newest.granted, "the newest decision is the withdrawal");
    assert!(
        decisions.iter().skip(1).all(|decision| decision.granted),
        "every earlier decision is a grant"
    );
}

/// Pat withdraws each remaining purpose individually after withdrawing marketing.
async fn withdraw_remaining_purposes(world: &World<'_>, pat: &Person) {
    for purpose in PURPOSES.iter().filter(|purpose| **purpose != "Marketing") {
        account::consent(
            world.tenant(),
            pat.id(),
            &decision(purpose, "terms-v1", false),
        )
        .send(pat.client())
        .await
        .ok();
    }
}

/// Tess and anonymous callers cannot grant Pat's marketing consent, and
/// Uma cannot read Pat's decisions. Each is refused, Pat's history is
/// empty, and when Pat grants it herself her history holds that one
/// decision.
#[tokio::test]
async fn nobody_but_pat_gives_or_reads_her_consent() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = invited_and_signed_in(&world, "pat").await;
    let uma = invited_and_signed_in(&world, "uma").await;
    let grant = decision("Marketing", "terms-v1", true);
    refuse_consent_callers(&world, &pat, &uma, &grant).await;
    let before = account::consents(world.tenant(), pat.id())
        .send(pat.client())
        .await
        .ok();
    assert!(before.is_empty(), "a refused grant leaves no decision");
    account::consent(world.tenant(), pat.id(), &grant)
        .send(pat.client())
        .await
        .ok();
    let after = account::consents(world.tenant(), pat.id())
        .send(pat.client())
        .await
        .ok();
    assert_eq!(after.len(), 1, "Pat's own grant is her one decision");
    still_signed_in(&world, &pat).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Administrative authority, anonymity and another user's session do not confer Pat's consent rights.
async fn refuse_consent_callers(world: &World<'_>, pat: &Person, uma: &Person, grant: &Consent) {
    account::consent(world.tenant(), pat.id(), grant)
        .send(world.admin().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    account::consent(world.tenant(), pat.id(), grant)
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    account::consents(world.tenant(), pat.id())
        .send(uma.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// Pat cannot withdraw marketing consent she never gave. She
/// grants it under two versions of the terms: her history holds both,
/// newest first. Her session reads no decisions in the twin tenant.
#[tokio::test]
async fn each_version_of_the_terms_is_its_own_decision() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = invited_and_signed_in(&world, "pat").await;

    account::consent(
        world.tenant(),
        pat.id(),
        &decision("Marketing", "v1", false),
    )
    .send(pat.client())
    .await
    .refused(Status::NOT_FOUND, "not_found");
    grant_two_versions(&world, &pat).await;
    account::consents(world.twin(), pat.id())
        .send(pat.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    still_signed_in(&world, &pat).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Each granted version remains in history with the newer decision first.
async fn grant_two_versions(world: &World<'_>, pat: &Person) {
    for version in ["v1", "v2"] {
        account::consent(
            world.tenant(),
            pat.id(),
            &decision("Marketing", version, true),
        )
        .send(pat.client())
        .await
        .ok();
    }
    let decisions = account::consents(world.tenant(), pat.id())
        .send(pat.client())
        .await
        .ok();
    let versions: Vec<&str> = decisions
        .iter()
        .map(|decision| decision.version.as_str())
        .collect();
    assert_eq!(
        versions,
        ["v2", "v1"],
        "both versions are kept, newest first"
    );
}

/// Pat's decision on `purpose` under the terms `version`: a grant when
/// `granted`, a withdrawal otherwise.
fn decision(purpose: &str, version: &str, granted: bool) -> Consent {
    Consent {
        consent_type: purpose.to_owned(),
        version: version.to_owned(),
        granted,
    }
}
