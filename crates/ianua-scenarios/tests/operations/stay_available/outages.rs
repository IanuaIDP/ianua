//! A part the platform depends on goes down while Ann and Bea use it, and
//! comes back. The internal listener says the platform is not ready, and
//! tells nobody which part failed. Without the cache Ann's session is
//! still checked against the database and Mallory still gets nothing;
//! without the database every answer is a plain refusal; without the bus
//! work goes on and is still recorded, once. Each part mended, the
//! platform is ready again with no restart.

use ianua_scenarios::api::{OrgPath, members};
use ianua_scenarios::expect::eventually;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Part, Profile, Stack};
use ianua_scenarios::wire::organization::OrgRole;
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;

/// Words that would tell a caller what failed behind an answer.
const GIVEAWAYS: [&str; 8] = [
    "panicked",
    "sqlx",
    "postgres",
    "redis",
    "nats",
    "connection refused",
    "broken pipe",
    ".rs:",
];

/// The record a member's sign-in leaves.
const SIGNED_IN: &str = "organization.org_login_succeeded";

/// Ann reads her members, so her session is in the cache. The cache goes
/// down. Ann still reads them, her session checked against the database;
/// Mallory, with no session, still reads nothing; and the platform says
/// it is not ready. The cache mended, it is ready again and Ann is served,
/// with no restart.
#[tokio::test]
async fn a_cache_outage_preserves_authoritative_access_and_changes_readiness() {
    let stack = Stack::start(Profile::standard().with_cuttable_parts())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let ann = world.owner().client();
    members::list(world.org(), None).send(ann).await.ok();

    stack.cut(Part::Cache);

    members::list(world.org(), None).send(ann).await.ok();
    let mallory = Client::new(&stack, "Mallory, while the cache is down").expect("a client");
    members::list(world.org(), None)
        .send(&mallory)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    eventually("the platform says it is not ready", || not_ready(&stack)).await;

    stack.mend(Part::Cache);

    eventually("the platform is ready again", || ready(&stack)).await;
    eventually("Ann is served again", || served(ann, world.org())).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann reads her members, so her session is in the cache. The database
/// goes down. Her read is refused plainly, from no cache and with no word
/// of what failed, and the platform says it is not ready. The database
/// mended, it is ready again and the same session reads again.
#[tokio::test]
async fn while_the_database_is_down_every_answer_is_plain() {
    let stack = Stack::start(Profile::standard().with_cuttable_parts())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let ann = world.owner().client();
    members::list(world.org(), None).send(ann).await.ok();

    stack.cut(Part::Database);

    let read = members::list(world.org(), None).send(ann).await;
    refused_plainly("Ann's read while the database is down", &read);
    eventually("the platform says it is not ready", || not_ready(&stack)).await;

    stack.mend(Part::Database);

    eventually("the platform is ready again", || ready(&stack)).await;
    eventually("Ann is served again", || served(ann, world.org())).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// The bus goes down. Bea joins Ann's company and signs in: her session
/// works, and exactly one sign-in of hers is recorded. The platform says
/// it is not ready. The bus mended, it is ready again, Bea still reads,
/// and no second sign-in of hers is recorded by the recovery.
#[tokio::test]
async fn while_the_bus_is_down_work_goes_on_and_is_still_recorded() {
    let stack = Stack::start(Profile::standard().with_cuttable_parts())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let trail = world.trail();
    let before = trail.count(SIGNED_IN).await;

    stack.cut(Part::Bus);

    let mut bea = world.colleague("bea", "Bea Busdown", OrgRole::Admin).await;
    bea.land_in(world.tenant().slug());
    bea.sign_in(&stack).await;
    members::list(world.org(), None)
        .send(bea.client())
        .await
        .ok();
    let after = trail.count(SIGNED_IN).await;
    assert_eq!(after, before + 1, "Bea's sign-in was recorded once");
    eventually("the platform says it is not ready", || not_ready(&stack)).await;

    stack.mend(Part::Bus);

    eventually("the platform is ready again", || ready(&stack)).await;
    members::list(world.org(), None)
        .send(bea.client())
        .await
        .ok();
    assert_eq!(
        trail.count(SIGNED_IN).await,
        after,
        "recovery does not record another sign-in"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Asserts `answer`, to `what`, is the plain refusal a database outage
/// gets: unavailable, in the platform's own words, with no word of what
/// failed.
fn refused_plainly<T>(what: &str, answer: &Answer<T>) {
    assert_eq!(
        answer.status(),
        Status::SERVICE_UNAVAILABLE,
        "{what}: {}",
        answer.summary()
    );
    let body = answer.exchange().response_body().to_ascii_lowercase();
    assert_eq!(
        body, "authentication temporarily unavailable",
        "{what} is refused in the platform's own words"
    );
    for word in GIVEAWAYS {
        assert!(!body.contains(word), "{what} says {word:?}: {body}");
    }
}

/// `Some` once the internal listener says the platform is not ready.
async fn not_ready(stack: &Stack) -> Option<()> {
    (readiness(stack).await == Some(Status::SERVICE_UNAVAILABLE)).then_some(())
}

/// `Some` once the internal listener says the platform is ready.
async fn ready(stack: &Stack) -> Option<()> {
    (readiness(stack).await == Some(Status::OK)).then_some(())
}

/// The readiness status, checked to disclose no dependency in its body.
async fn readiness(stack: &Stack) -> Option<Status> {
    let probe = format!("http://{}/health/ready", stack.internal_api());
    let answer = reqwest::get(probe).await.ok()?;
    let status = answer.status();
    assert!(
        answer.bytes().await.ok()?.is_empty(),
        "readiness has no body"
    );
    Some(status)
}

/// `Some` once `client` reads the members of `org`.
async fn served(client: &Client, org: &OrgPath) -> Option<()> {
    let answer = members::list(org, None).send(client).await;
    (answer.status() == Status::OK).then_some(())
}
