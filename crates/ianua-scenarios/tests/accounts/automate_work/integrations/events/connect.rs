//! What the scenarios of services' sign-ins and events share: Tess
//! connecting an account by signing in at a stand-in for the service, a
//! delivery signed the way a service signs, the runs a delivery started,
//! and a workflow that only delivers to the outside service, which counts
//! them.

use hmac::{Hmac, Mac};
use ianua_scenarios::api::workflows;
use ianua_scenarios::expect::eventually;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::workflows::{
    ExecutionSummary, FinishConnection, NewConnection, Trigger, Workflow,
};
use ianua_scenarios::world::World;
use sha2::Sha256;

use crate::service::Service;
use crate::support::{connected_account, delivery_graph, drafted, published};

/// The code every stand-in sends the browser back with.
pub(super) const CODE: &str = "the code the service sent back";

/// Where a service signs Tess in, and the app it should name.
pub(in crate::integrations) struct SignIn<'a> {
    /// The integration, such as `slack`.
    pub(in crate::integrations) integration: &'a str,
    /// Where the browser must be sent.
    pub(in crate::integrations) authorize: &'a str,
    /// The deployment's app the address must name.
    pub(in crate::integrations) client_id: &'a str,
    /// The space at the service Tess names, for a sign-in that asks for
    /// one, such as the Jira site.
    pub(in crate::integrations) place: Option<&'a str>,
}

/// Tess connects an account at `sign_in`'s service by signing in there,
/// shared with the tenant: the browser is sent there with the app and a
/// challenge, never the verifier; the service's code comes back to the
/// callback, which sends the browser on with a one-time code that Sam
/// cannot finish and Tess does. The account's id.
pub(in crate::integrations) async fn signed_in(world: &World<'_>, sign_in: &SignIn<'_>) -> String {
    let connection = NewConnection {
        integration: sign_in.integration.to_owned(),
        name: format!("Team {}", sign_in.integration),
        sharing: "tenant".to_owned(),
        place: sign_in.place.map(str::to_owned),
    };
    let begun = workflows::begin_connection(world.tenant(), &connection)
        .send(world.admin().client())
        .await
        .ok();
    assert!(
        begun.address.starts_with(sign_in.authorize),
        "{}",
        begun.address
    );
    let sent_to = url::Url::parse(&begun.address).expect("the sign-in address");
    let query: Vec<(String, String)> = sent_to.query_pairs().into_owned().collect();
    let value = |name: &str| pair(&query, name);
    assert_eq!(value("client_id").as_deref(), Some(sign_in.client_id));
    assert_eq!(value("code_challenge_method").as_deref(), Some("S256"));
    assert!(value("code_verifier").is_none(), "the verifier stays home");
    let state = value("state").expect("the sign-in carries a state");

    let code = answered(world, &state).await;
    finish(world, &begun.connection_id, code).await
}

/// The one-time code the callback sends the browser on with, once the
/// service answered `state` with [`CODE`].
async fn answered(world: &World<'_>, state: &str) -> String {
    let answered = workflows::answer_connection(state, CODE)
        .send_text(world.admin().client())
        .await;
    assert_eq!(answered.status(), Status::FOUND);
    let landing = answered
        .header("location")
        .expect("the browser is sent on")
        .to_owned();
    let (_, fragment) = landing
        .split_once('#')
        .expect("the code travels in the fragment");
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(fragment.as_bytes())
        .into_owned()
        .collect();
    pair(&pairs, "code").expect("a one-time code")
}

/// Sam cannot finish the connection with Tess's code; Tess does. The
/// account's id.
async fn finish(world: &World<'_>, connection_id: &str, code: String) -> String {
    workflows::finish_connection(
        world.tenant(),
        connection_id,
        &FinishConnection { code: code.clone() },
    )
    .send(world.member().client())
    .await
    .refused(Status::FORBIDDEN, "forbidden");
    workflows::finish_connection(world.tenant(), connection_id, &FinishConnection { code })
        .send(world.admin().client())
        .await
        .ok()
        .id
}

/// The value of `name` in `pairs`.
fn pair(pairs: &[(String, String)], name: &str) -> Option<String> {
    pairs
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.clone())
}

/// The HMAC-SHA256 of `parts`, joined, under `secret`, in hexadecimal, as
/// GitHub and Slack sign what they deliver.
pub(super) fn signed(secret: &str, parts: &[&[u8]]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("any key is taken");
    for part in parts {
        mac.update(part);
    }
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The path of `address`, the platform's address for a registration,
/// which a stand-in was handed.
pub(super) fn path_of(address: &str) -> String {
    url::Url::parse(address)
        .expect("the registration's address")
        .path()
        .to_owned()
}

/// The path and query of `address`, the platform's address for a
/// registration with its secret in it, as a service was given it.
pub(super) fn path_and_query(address: &str) -> String {
    let address = url::Url::parse(address).expect("the registration's address");
    match address.query() {
        Some(query) => format!("{}?{query}", address.path()),
        None => address.path().to_owned(),
    }
}

/// The runs of `workflow_id` once a delivery started at least one.
pub(super) async fn runs_started(world: &World<'_>, workflow_id: &str) -> Vec<ExecutionSummary> {
    eventually("the delivery to start a run", || async {
        let runs = runs_now(world, workflow_id).await;
        (!runs.is_empty()).then_some(runs)
    })
    .await
}

/// The runs of `workflow_id` as they stand.
pub(super) async fn runs_now(world: &World<'_>, workflow_id: &str) -> Vec<ExecutionSummary> {
    workflows::executions(world.tenant(), workflow_id)
        .send(world.owner().client())
        .await
        .ok()
        .items
}

/// Ann's workflow started by `trigger`, which delivers to `service`
/// through the account Tess connected for it, published, so the service
/// counts the runs a delivery started.
pub(super) async fn delivering_on(
    world: &World<'_>,
    service: &Service,
    trigger: Trigger,
) -> Workflow {
    let account = connected_account(world, service).await;
    let draft = drafted(world, trigger, delivery_graph(service, &account)).await;
    published(world, &draft).await
}
