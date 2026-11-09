//! Reporter with no standing key: it proves where it runs with its
//! workload's SPIFFE SVID, bound to the platform's single-use challenge
//! and to the key it made, and only then is that key enrolled. Another
//! workload, another authority, a proof for another key and a spent
//! challenge each enrol nothing.

use ianua_scenarios::agent::external::attest::{SPIFFE, TrustDomain, Workload};
use ianua_scenarios::agent::external::{BootstrapAgent, ExternalAgent};
use ianua_scenarios::agent::keys::AgentKey;
use ianua_scenarios::api::agents::credentials;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::agents::authority::{Capabilities, Grant, Limits};
use ianua_scenarios::wire::agents::token::TokenAsk;
use ianua_scenarios::world::World;

use crate::support::{Witness, granted_by_owner, hidden_from_the_rest, profile};

/// The trust domain the scenario's workloads run in.
const TRUST_DOMAIN: &str = "workloads.scenarios.test";

/// How long Ann's grant lasts, in seconds: a task's worth.
const GRANT_SECONDS: u32 = 600;

/// How long the token Reporter asks for lasts, in seconds: less than the
/// grant, as a token must.
const TOKEN_SECONDS: u32 = 300;

/// `profile` trusting SPIFFE SVIDs of `domain`, its bundle written to
/// `bundle_path`.
fn trusting(profile: Profile, domain: &TrustDomain, bundle_path: &str) -> Profile {
    profile
        .with("AGENT_ATTESTATION_ALLOWLIST", SPIFFE)
        .with("AGENT_SPIFFE_TRUST_DOMAIN", domain.name())
        .with("AGENT_SPIFFE_TRUST_BUNDLE_PATH", bundle_path)
}

/// Reporter bootstraps from its workload's SVID: its key is enrolled as a
/// credential naming the SPIFFE ID, which Ann and Tess may read and nobody
/// else, and it signs Reporter in for a token. Then the missteps: another
/// workload of the same domain, an SVID from another authority, a proof
/// made for another key, and the challenge that proof spent used again
/// with a true one are each refused, and none enrols anything.
#[tokio::test]
async fn an_agent_attests_and_every_false_attestation_is_refused() {
    let domain = TrustDomain::new(TRUST_DOMAIN).expect("a trust domain");
    let bundle = tempfile::NamedTempFile::new().expect("a file for the bundle");
    std::fs::write(bundle.path(), domain.bundle_pem()).expect("the bundle is written");
    let path = bundle.path().display().to_string();
    let stack = Stack::start(trusting(profile(), &domain, &path))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut witness = Witness::of(&world).await;
    let workload = domain.workload("agents/reporter").expect("an SVID");

    let mut reporter = ExternalAgent::bootstrapped(
        &stack,
        world.tenant(),
        world.owner().client(),
        BootstrapAgent {
            name: "Reporter",
            workload: &workload,
        },
    )
    .await;
    witness.recorded("agents.agent_bootstrapped").await;
    assert_attested_key(&world, &reporter, &workload).await;
    grant_and_take_token(&world, &mut witness, &mut reporter).await;
    refuse_false_attestations(&domain, &workload, &reporter).await;
    witness.nothing_new("agents.agent_bootstrapped").await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// The enrolled key names its SPIFFE identity and is visible only to Ann and Tess.
async fn assert_attested_key(world: &World<'_>, reporter: &ExternalAgent, workload: &Workload) {
    let keys = credentials::list(world.tenant(), reporter.id())
        .send(world.owner().client())
        .await
        .ok();
    let attested = keys
        .iter()
        .find(|key| key.kid == reporter.key_id())
        .and_then(|key| key.attestation.as_ref());
    assert_eq!(
        attested.map(|by| (by.method.as_str(), by.subject.as_str())),
        Some((SPIFFE, workload.spiffe_id())),
        "Reporter's key names the SPIFFE ID it was attested by"
    );
    let call = credentials::list(world.tenant(), reporter.id()).call();
    let matrix = Matrix::new("listing Reporter's attested keys", call)
        .allowed(world.owner().client())
        .allowed(world.admin().client());
    hidden_from_the_rest(matrix, world, &[reporter]).run().await;
}

/// Ann grants a read permission and the attested key obtains a token on record.
async fn grant_and_take_token(
    world: &World<'_>,
    witness: &mut Witness<'_>,
    reporter: &mut ExternalAgent,
) {
    let grant = Grant {
        granted: Capabilities::http(&["users:view"]),
        limits: Limits {
            ttl_seconds: GRANT_SECONDS,
            ..Limits::default()
        },
        name: None,
    };
    granted_by_owner(world, reporter, &grant).await;
    reporter
        .take_token(&TokenAsk::bearer(
            Capabilities::http(&["users:view"]),
            TOKEN_SECONDS,
        ))
        .await;
    witness.recorded("agents.token_issued").await;
}

/// Other identities, another authority, the wrong key and a spent challenge cannot bootstrap.
async fn refuse_false_attestations(
    domain: &TrustDomain,
    workload: &Workload,
    reporter: &ExternalAgent,
) {
    let intruder = domain.workload("agents/intruder").expect("an SVID");
    reporter
        .attest(&intruder)
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    let impostor = TrustDomain::new(TRUST_DOMAIN).expect("another authority");
    let forged = impostor.workload("agents/reporter").expect("an SVID");
    reporter
        .attest(&forged)
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    let nonce = reporter.challenge().await.ok().nonce;
    let other_key = AgentKey::generate();
    reporter
        .bootstrap(workload.attestation(&nonce, &other_key))
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    reporter
        .bootstrap(workload.attestation(&nonce, reporter.key()))
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}
