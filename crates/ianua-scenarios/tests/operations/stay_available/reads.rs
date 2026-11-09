//! Ann reading the same thing over and over leaves nothing behind in the
//! platform's memory: the token check, the caches and the rate limiter on
//! a request's way through settle after the first reads and grow no more.

use ianua_scenarios::actors::Founder;
use ianua_scenarios::api::{OrgPath, members};
use ianua_scenarios::memory::Steady;
use ianua_scenarios::stack::{Profile, Stack};

/// Ann reads her organization's members a hundred and fifty times, after
/// twenty reads to warm up, within the rate the plan allows her. What each
/// read leaves held stays within a few kilobytes.
#[tokio::test]
async fn reading_the_members_leaves_nothing_behind() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let mut ann = Founder::named(&stack, "Ann");
    let founded = ann.founded(&stack, "Acme").await;
    let session = ann.signed_in(&stack).await;
    ann.client_mut().authorize(&session.refresh_token);
    let org = OrgPath::new(&founded.org_slug);

    let steady = Steady {
        warm_up: 20,
        rounds: 150,
        per_round: 4 * 1024,
    };
    let (ann, org) = (&ann, &org);
    let per_round = steady
        .holds("reading the members", move || async move {
            members::list(org, None).send(ann.client()).await.ok();
        })
        .await;
    tracing::info!(per_round, "reading the members holds this much per read");

    stack.stop().await.expect("the stack stops cleanly");
}
