//! Ann connects a cluster of her own: she begins the connection, hands
//! over its service account and proves it. The platform calls only the
//! clouds a deployment set up, so a credential for a cloud nobody here
//! reaches never leaves the stack. An address that cannot be reached is
//! Ann's to correct: she gets the reason and the connection waits. Tess,
//! Max, Sam and nobody signed in change nothing, and every credential
//! stays out of what is read back and out of the trail.

use ianua_scenarios::api::cloud;
use ianua_scenarios::expect::{Matrix, no_secret_leaked};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::cloud::CloudGrant;
use ianua_scenarios::wire::organization::OrgRole;
use ianua_scenarios::world::World;

use crate::support::colleague_signed_in;

/// The cluster Ann connects.
const KUBERNETES: &str = "kubernetes";

/// A cloud this deployment is not set up to drive: it holds no AWS keys.
const AWS: &str = "aws";

/// A cloud Ann did not begin connecting.
const DIGITALOCEAN: &str = "digitalocean";

/// A cluster no name server resolves, so the platform cannot reach it.
const NOBODYS_CLUSTER: &str = "https://cluster.orchard.example:6443";

/// The cluster's service account token, a sentence so nothing takes it
/// for a real token.
const CLUSTER_TOKEN: &str = "a made up service account token for the scenarios";

/// The record of a connection begun.
const STARTED: &str = "organization.cloud_connection_started";

/// The record of a credential handed over.
const ATTACHED: &str = "organization.cloud_credential_attached";

/// The record of a connection proved or refused.
const VERIFIED: &str = "organization.cloud_account_verified";

/// The record of a connection forgotten.
const DISCONNECTED: &str = "organization.cloud_account_disconnected";

/// Kubernetes' service account credential for a cluster nobody reaches,
/// the stack's own certificate standing in for its CA.
fn cluster_grant(world: &World<'_>) -> CloudGrant {
    CloudGrant::KubernetesServiceAccount {
        server: NOBODYS_CLUSTER.to_owned(),
        ca_certificate: world.stack().root_certificate_pem().to_owned(),
        token: CLUSTER_TOKEN.to_owned(),
    }
}

/// Ann begins connecting a cluster and is told the steps, with no
/// external id since a cluster uses none. It lists as waiting for a
/// credential. Asking again answers the same and records the start once.
#[tokio::test]
async fn ann_begins_connecting_a_cluster_and_asking_again_changes_nothing() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;

    let first = cloud::begin(world.org(), KUBERNETES)
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        first.provider, KUBERNETES,
        "the connection is to the cluster"
    );
    assert!(first.external_id.is_none(), "a cluster uses no external id");
    assert!(!first.steps.is_empty(), "Ann is told what to do next");
    let again = cloud::begin(world.org(), KUBERNETES)
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(again.steps, first.steps, "beginning again answers the same");

    let listed = cloud::list(world.org())
        .send(world.owner().client())
        .await
        .ok();
    let [connection] = listed.as_slice() else {
        panic!("one connection is listed, not {}", listed.len());
    };
    assert_eq!(connection.state, "awaiting_credential", "it waits for one");
    assert!(!connection.usable, "it cannot be used yet");
    assert_eq!(
        world.trail().count(STARTED).await,
        1,
        "the start is recorded once"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann hands over a service account for a cluster nobody can reach.
/// The platform stores the grant, tries it, and tells her why it could
/// not; the connection waits to be proved again, unusable, with no failure
/// written down as hers. Trying again gives the same answer. Her token is
/// nowhere in what is read back or recorded.
#[tokio::test]
async fn a_cluster_nobody_can_reach_waits_with_the_reason_for_ann_to_correct() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    cloud::begin(world.org(), KUBERNETES)
        .send(world.owner().client())
        .await
        .ok();

    let refused = cloud::submit(world.org(), KUBERNETES, &cluster_grant(&world))
        .send(world.owner().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    assert!(
        refused.message().contains("reach"),
        "the reason is one Ann can act on: {}",
        refused.message()
    );

    let listed = cloud::list(world.org())
        .send(world.owner().client())
        .await
        .ok();
    let [connection] = listed.as_slice() else {
        panic!("one connection is listed, not {}", listed.len());
    };
    assert_eq!(
        connection.state, "awaiting_verification",
        "the grant waits to be proved"
    );
    assert!(!connection.usable, "it is not usable");
    assert!(connection.account.is_none(), "no account answered");
    assert!(connection.failure_reason.is_none(), "no failure is hers");
    assert!(connection.revocable_by_you, "she can withdraw this grant");
    no_secret_leaked(&format!("{listed:?}"), &[CLUSTER_TOKEN]);

    check_nobody_proved(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Proving again refuses the same way, nothing is verified, and the
/// attached credential's record holds no token.
async fn check_nobody_proved(world: &World<'_>) {
    cloud::verify(world.org(), KUBERNETES)
        .send(world.owner().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    assert_eq!(
        world.trail().count(VERIFIED).await,
        0,
        "nothing was proved or failed"
    );
    let records = world.trail().entries(ATTACHED).await;
    let [record] = records.as_slice() else {
        panic!("one {ATTACHED} is recorded, not {}", records.len());
    };
    no_secret_leaked(&record.details.to_string(), &[CLUSTER_TOKEN]);
}

/// Networks are the customer's infrastructure, so only a proved
/// connection reads them. A connection never proved is refused, as is a
/// request naming no region or one that does not exist; a connection
/// never begun is not found.
#[tokio::test]
async fn networks_are_only_read_through_a_proved_connection() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    cloud::begin(world.org(), KUBERNETES)
        .send(world.owner().client())
        .await
        .ok();

    cloud::networks(world.org(), KUBERNETES, Some("eu-central-1"))
        .send(world.owner().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    cloud::networks(world.org(), KUBERNETES, None)
        .send(world.owner().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    cloud::networks(world.org(), KUBERNETES, Some("moon-north-1"))
        .send(world.owner().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    cloud::networks(world.org(), DIGITALOCEAN, Some("eu-central-1"))
        .send(world.owner().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");

    stack.stop().await.expect("the stack stops cleanly");
}

/// A credential for another cloud than the connection's is refused, as
/// is one handed over before the connection was begun. Proving a
/// connection with no credential yet is a conflict; proving one never
/// begun is not found. A cloud this deployment does not drive cannot be
/// begun, nor can a name that is no cloud at all. None of it is recorded.
#[tokio::test]
async fn a_credential_for_the_wrong_cloud_or_a_cloud_never_begun_is_refused() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    cloud::begin(world.org(), KUBERNETES)
        .send(world.owner().client())
        .await
        .ok();
    refuse_mismatched_credentials(&world).await;
    refuse_clouds_never_connected(&world).await;

    assert_eq!(
        world.trail().count(ATTACHED).await,
        0,
        "no credential was attached"
    );
    assert_eq!(
        world.trail().count(STARTED).await,
        1,
        "only the connection to the cluster began"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Wrong-cloud bodies and proofs of an empty connection are refused.
async fn refuse_mismatched_credentials(world: &World<'_>) {
    let token_only = CloudGrant::DigitalOceanToken {
        token: "a made up cloud token for the scenarios".to_owned(),
    };
    cloud::submit(world.org(), KUBERNETES, &token_only)
        .send(world.owner().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    cloud::submit(world.org(), DIGITALOCEAN, &token_only)
        .send(world.owner().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    cloud::verify(world.org(), KUBERNETES)
        .send(world.owner().client())
        .await
        .refused(Status::CONFLICT, "conflict");
    cloud::verify(world.org(), DIGITALOCEAN)
        .send(world.owner().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
}

/// AWS, whose keys this deployment does not hold, and a made-up cloud
/// cannot be begun.
async fn refuse_clouds_never_connected(world: &World<'_>) {
    for provider in [AWS, "made-up-cloud"] {
        cloud::begin(world.org(), provider)
            .send(world.owner().client())
            .await
            .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    }
}

/// Ann disconnects the cluster she began connecting: the list has
/// nothing, proving it again finds nothing, and the disconnection is
/// recorded once. Sam's company never had a connection to lose.
#[tokio::test]
async fn ann_disconnects_a_cluster_and_it_is_forgotten() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    cloud::begin(world.org(), KUBERNETES)
        .send(world.owner().client())
        .await
        .ok();

    cloud::disconnect(world.org(), KUBERNETES)
        .send(world.owner().client())
        .await
        .ok();

    let listed = cloud::list(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert!(listed.is_empty(), "nothing is connected any more");
    cloud::verify(world.org(), KUBERNETES)
        .send(world.owner().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    assert_eq!(
        world.trail().count(DISCONNECTED).await,
        1,
        "the disconnection is recorded once"
    );
    let sams = cloud::list(world.stranger().org())
        .send(world.stranger().client())
        .await
        .ok();
    assert!(sams.is_empty(), "Sam's company has no connection");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess and Max, plain members, read the list but change nothing; Uma, an
/// administrator, begins a connection for the company; Sam and nobody
/// signed in reach none of it.
#[tokio::test]
async fn only_someone_who_may_change_the_company_touches_its_cloud_connections() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let uma = colleague_signed_in(&world, "uma", OrgRole::Admin).await;
    cloud::begin(world.org(), KUBERNETES)
        .send(uma.client())
        .await
        .ok();

    Matrix::new("reading the connections", cloud::list(world.org()).call())
        .allowed(world.admin().client())
        .allowed(world.member().client())
        .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
        .refused(
            world.anonymous().client(),
            Status::UNAUTHORIZED,
            "unauthenticated",
        )
        .run()
        .await;
    for call in [
        cloud::begin(world.org(), DIGITALOCEAN).call(),
        cloud::submit(world.org(), KUBERNETES, &cluster_grant(&world)).call(),
        cloud::verify(world.org(), KUBERNETES).call(),
        cloud::networks(world.org(), KUBERNETES, Some("eu-central-1")).call(),
        cloud::disconnect(world.org(), KUBERNETES).call(),
    ] {
        Matrix::new("changing a cloud connection", call)
            .refused(world.admin().client(), Status::FORBIDDEN, "forbidden")
            .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
            .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
            .refused(
                world.anonymous().client(),
                Status::UNAUTHORIZED,
                "unauthenticated",
            )
            .run()
            .await;
    }
    assert_eq!(
        world.trail().count(DISCONNECTED).await,
        0,
        "no refused change is recorded"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Anyone may read the role template before running it in their own AWS
/// account: nobody signs in, and it is YAML saying what it grants.
#[tokio::test]
async fn the_aws_role_template_is_there_for_anyone_to_read() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;

    let answer = cloud::aws_template()
        .send_text(world.anonymous().client())
        .await;
    let content_type = answer
        .header("content-type")
        .expect("a content type")
        .to_owned();
    let template = answer.ok();

    assert!(content_type.contains("yaml"), "it reads as YAML");
    assert!(
        template.starts_with("AWSTemplateFormatVersion"),
        "it is a CloudFormation template"
    );
    assert!(
        template.contains("ExternalId"),
        "it asks for the external id"
    );

    stack.stop().await.expect("the stack stops cleanly");
}
