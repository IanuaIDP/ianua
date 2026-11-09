//! Agents calling a tenant's apps through the gateway with their task
//! tokens, bound to their keys: Ann's reporting agent, and Pat's, each
//! reach the reports app, which sees an assertion naming the agent and
//! whom it acts for; with the token and no proof of the key, nothing gets
//! through, in the agent's own client or in Mallory's.

use ianua_scenarios::agent::external::dpop::ProvenRequest;
use ianua_scenarios::agent::external::{ExternalAgent, IssuedToken};
use ianua_scenarios::api::agents::delegation;
use ianua_scenarios::api::roles;
use ianua_scenarios::expect::{Matrix, Records};
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::routes::{Placement, RouteSpec};
use ianua_scenarios::stack::Stack;
use ianua_scenarios::upstreams::{AssertionCheck, Echo};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::agents::authority::{Capabilities, Grant, Limits};
use ianua_scenarios::wire::roles::{AssignRole, NewRole, SystemPermission};
use ianua_scenarios::wire::routing::RoutePolicy;
use ianua_scenarios::world::World;

use crate::support::{app_host, customer, probe, profile, word};

/// The permission Ann hands her agent, which she holds as the owner.
const VIEW_USERS: &str = "idp:users:view";

/// How long the grants last, in seconds: long enough for the scenario,
/// short enough to be a task's.
const GRANT_SECONDS: u32 = 600;

/// `call` to `url` as `agent` sends it: its task token under the `DPoP`
/// scheme with a fresh proof of its key, or the token alone when `proof`
/// says it leaves the proof out.
fn sent_by(agent: &ExternalAgent, url: &str, proof: Proof) -> Call {
    let Some(issued) = agent.token() else {
        panic!("{} holds a token", agent.name());
    };
    let call = Call::get(url).header("authorization", &format!("DPoP {}", issued.token()));
    match proof {
        Proof::Made => call.header(
            "dpop",
            &agent.dpop_proof(ProvenRequest { method: "GET", url }),
        ),
        Proof::LeftOut => call,
    }
}

/// Whether a request carries its key's proof.
#[derive(Clone, Copy)]
enum Proof {
    /// A fresh proof by the agent's own key.
    Made,
    /// None at all, as a thief holding only the token sends it.
    LeftOut,
}

/// The grant handing an agent the right to view users and the reports
/// app `service_id`, its tokens bound to its key.
fn reports_grant(service_id: &str, name: &str) -> Grant {
    Grant {
        granted: Capabilities::http(&[VIEW_USERS]),
        limits: Limits {
            ttl_seconds: GRANT_SECONDS,
            sender_constrained: true,
            apps: vec![service_id.to_owned()],
            ..Limits::default()
        },
        name: Some(name.to_owned()),
    }
}

/// Ann, who owns Acme's organization, hands her reporting agent the right
/// to view users and the reports app, its tokens bound to its key. With
/// its task token and a proof of its key it reads a report through the
/// gateway; the app sees an assertion naming the agent, acting for Ann,
/// and none of the agent's credentials. The same token without the proof,
/// in the agent's own client and in Mallory's, is refused before the app
/// sees anything. The gateway records the agent's request as allowed.
#[tokio::test]
async fn an_agent_acting_for_a_member_reaches_an_app_with_its_key() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let host = app_host(&world).await;
    let reports = Echo::start(&stack, &host)
        .await
        .expect("the reports app starts");
    let word = word();
    let applied = RouteSpec::public(&format!("reports-{word}"), "/reports/*")
        .asking(RoutePolicy::Authenticated)
        .pinned(&format!("reports-{word}"))
        .applied(
            world.admin().client(),
            &probe(&stack),
            Placement {
                tenant: world.tenant(),
                upstream: &reports.url(),
                host: &host,
            },
        )
        .await;
    let mut reporter =
        ExternalAgent::enrolled(&stack, world.tenant(), world.owner().client(), "Reporter").await;
    let grant = reports_grant(&applied.service_id, "Read the reports");
    let granted = delegation::grant(world.tenant(), reporter.id(), &grant)
        .send(world.owner().client())
        .await
        .ok();
    reporter.hold(IssuedToken::of(granted));
    reports.forget();

    let url = format!("https://{host}/reports/weekly");
    Matrix::new(
        "reading a report with the task token and the key's proof",
        sent_by(&reporter, &url, Proof::Made),
    )
    .allowed(reporter.client())
    .run()
    .await;
    let arrived = reports.arrivals();
    let Some(last) = arrived.last() else {
        panic!("Reporter's request reached the reports app");
    };
    let AssertionCheck::Verified { caller } = &last.assertion else {
        panic!("the app could not check the gateway's assertion: {last:?}");
    };
    assert_eq!(caller.kind, "agent", "the assertion names an agent");
    assert_eq!(
        caller.act.as_deref(),
        Some(reporter.id()),
        "the assertion names Reporter as the one acting"
    );
    assert!(
        caller
            .obo
            .as_deref()
            .is_some_and(|obo| obo.contains(world.owner().id())),
        "the assertion names Ann as whom Reporter acts for: {caller:?}"
    );
    for credential in ["authorization", "dpop"] {
        assert!(
            !last.has_header(credential),
            "Reporter's {credential} reached the app"
        );
    }

    let mallory = Client::new(&stack, "Mallory, with Reporter's token").expect("a client");
    Matrix::new(
        "reading a report with the token and no proof of the key",
        sent_by(&reporter, &url, Proof::LeftOut),
    )
    .refused(reporter.client(), Status::UNAUTHORIZED, "unauthenticated")
    .refused(&mallory, Status::UNAUTHORIZED, "unauthenticated")
    .run()
    .await;
    assert_eq!(
        reports.arrivals().len(),
        1,
        "only the proven request reached the app"
    );

    let record = Records::of_tenant(world.admin().client(), world.tenant())
        .recorded_where("/reports/weekly", "Reporter's allowed", |record| {
            record.decision == "allowed" && record.subject.kind == "agent"
        })
        .await;
    assert_eq!(
        record.subject.id.as_deref(),
        Some(reporter.id()),
        "the record names Reporter as the sender"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat, a user of Acme's tenant whom Tess gave a role that lets her view
/// users and make and empower agents, makes a reporting agent and hands
/// it that right and the reports app herself. Its task token and a proof
/// of its key reach the app, which sees an assertion naming the agent
/// acting for Pat.
#[tokio::test]
async fn an_agent_acting_for_a_tenant_user_reaches_an_app_with_its_key() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let host = app_host(&world).await;
    let reports = Echo::start(&stack, &host)
        .await
        .expect("the reports app starts");
    let word = word();
    let applied = RouteSpec::public(&format!("reports-{word}"), "/reports/*")
        .asking(RoutePolicy::Authenticated)
        .pinned(&format!("reports-{word}"))
        .applied(
            world.admin().client(),
            &probe(&stack),
            Placement {
                tenant: world.tenant(),
                upstream: &reports.url(),
                host: &host,
            },
        )
        .await;
    let mut pat = customer(&world, "pat", "Pat Reader").await;
    let readers = roles::create(
        world.tenant(),
        &NewRole {
            name: format!("Readers {word}"),
            system_permissions: vec![
                SystemPermission::new("Users", "View"),
                SystemPermission::new("Agents", "Create"),
                SystemPermission::new("Agents", "Delegate"),
            ],
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    roles::assign(
        world.tenant(),
        &readers.id,
        &AssignRole {
            user_id: pat.id().to_owned(),
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    pat.sign_in(&stack).await;

    let mut reporter =
        ExternalAgent::enrolled(&stack, world.tenant(), pat.client(), "Pat's reporter").await;
    let grant = reports_grant(&applied.service_id, "Read the reports for Pat");
    let granted = delegation::grant(world.tenant(), reporter.id(), &grant)
        .send(pat.client())
        .await
        .ok();
    reporter.hold(IssuedToken::of(granted));
    reports.forget();

    let url = format!("https://{host}/reports/daily");
    Matrix::new(
        "reading a report for Pat with the task token and the key's proof",
        sent_by(&reporter, &url, Proof::Made),
    )
    .allowed(reporter.client())
    .run()
    .await;
    let arrived = reports.arrivals();
    let Some(last) = arrived.last() else {
        panic!("the reporter's request reached the reports app");
    };
    let AssertionCheck::Verified { caller } = &last.assertion else {
        panic!("the app could not check the gateway's assertion: {last:?}");
    };
    assert_eq!(caller.kind, "agent", "the assertion names an agent");
    assert!(
        caller
            .obo
            .as_deref()
            .is_some_and(|obo| obo.contains(pat.id())),
        "the assertion names Pat as whom the reporter acts for: {caller:?}"
    );
    stack.stop().await.expect("the stack stops cleanly");
}
