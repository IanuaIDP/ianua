//! A connection that follows the metadata Acme's provider publishes at an
//! address, and takes the provider's next key from it without Tess.

use std::time::Duration;

use ianua_scenarios::actors::Person;
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::{Waiting, eventually_paced};
use ianua_scenarios::providers::metadata_host::MetadataHost;
use ianua_scenarios::providers::saml::{Claim, Provider};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::world::World;
use serde_json::json;
use tokio::sync::Mutex;

use crate::support::{Outcome, SamlAnswer, begun, connected_by, owned_domain, pat, signed_in};

/// Past the six hours between two refreshes of followed metadata.
const PAST_A_REFRESH: Duration = Duration::from_secs(6 * 3600 + 60);

/// How long the worker is given to read the metadata again, asking once a
/// second as a person would.
const UNTIL_REFRESHED: Waiting = Waiting {
    patience: Duration::from_secs(60),
    every: Duration::from_secs(1),
};

/// Tess links the tenant to Acme's provider by the address its metadata
/// is published at, and Pat signs in with the key it names. The provider
/// publishes its next key beside the current one; once the platform reads
/// the metadata again, an answer signed by the next key signs Pat in. The
/// provider then publishes only the next key; once read again, the old key
/// signs nobody in, and the new one still does. Tess changes nothing.
#[tokio::test]
async fn a_followed_metadata_address_hands_the_connection_its_next_key() {
    let clock = Clock::controlled();
    let host = MetadataHost::start().await;
    let stack = Stack::start(
        Profile::standard()
            .with("SAML_METADATA_CA_FILE", host.authority_file())
            .with("WORKER_SWEEP_TICK_SECONDS", "1"),
    )
    .await
    .expect("the stack starts");
    let world = World::new(&stack).await;
    let domain = owned_domain(&world).await;
    let old = Provider::new();
    let new = Provider::new();
    host.publish(old.metadata(None));
    let address = host.listed(&stack);
    let connection = connected_by(&world, &domain, json!({"SamlMetadata": {"url": address}})).await;
    let pat = Mutex::new(pat(&world, &domain).await);
    assert_current_key(&world, &pat, &old, &connection).await;
    assert_unlisted_key(&world, &pat, &new, &connection).await;
    host.publish(old.metadata(Some(&new)));
    clock.advance(PAST_A_REFRESH);
    await_next_key(&world, &pat, &new, &connection).await;
    host.publish(new.metadata(None));
    clock.advance(PAST_A_REFRESH);
    await_old_key_removal(&world, &pat, &old, &connection).await;
    assert!(
        signs_in(&world, &pat, &new, &connection).await,
        "the new key still signs Pat in"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// The currently published key signs Pat in before any refresh.
async fn assert_current_key(
    world: &World<'_>,
    pat: &Mutex<Person>,
    old: &Provider,
    connection: &str,
) {
    assert!(
        signs_in(world, pat, old, connection).await,
        "the key the metadata names signs Pat in"
    );
}

/// A replacement key cannot sign Pat in before the metadata names it.
async fn assert_unlisted_key(
    world: &World<'_>,
    pat: &Mutex<Person>,
    new: &Provider,
    connection: &str,
) {
    assert!(
        !signs_in(world, pat, new, connection).await,
        "a key the metadata does not name yet signs nobody in"
    );
}

/// The next refresh eventually admits answers from the added signing key.
async fn await_next_key(world: &World<'_>, pat: &Mutex<Person>, new: &Provider, connection: &str) {
    eventually_paced(
        "the next key to be read from the metadata",
        UNTIL_REFRESHED,
        || async { signs_in(world, pat, new, connection).await.then_some(()) },
    )
    .await;
}

/// The next refresh eventually refuses answers from the removed signing key.
async fn await_old_key_removal(
    world: &World<'_>,
    pat: &Mutex<Person>,
    old: &Provider,
    connection: &str,
) {
    eventually_paced(
        "the old key to be dropped from the metadata",
        UNTIL_REFRESHED,
        || async { (!signs_in(world, pat, old, connection).await).then_some(()) },
    )
    .await;
}

/// Whether an answer `provider` signs for Pat signs her in through the
/// connection.
async fn signs_in(
    world: &World<'_>,
    pat: &Mutex<Person>,
    provider: &Provider,
    connection: &str,
) -> bool {
    let mut pat = pat.lock().await;
    let redirect = begun(world, &pat, connection).await;
    let answer = SamlAnswer {
        provider,
        redirect,
        claim: Claim::Correct,
    };
    matches!(signed_in(world, &mut pat, answer).await, Outcome::SignedIn)
}
