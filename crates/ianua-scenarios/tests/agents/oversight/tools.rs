//! Reporter calling outside tools over MCP, through the gateway in front
//! of the tenant's tool server. Every MCP call is the same `POST` to the
//! same path, so the gateway reads the JSON-RPC envelope and holds each
//! tool it names to the tools Ann granted, by name: a granted tool reaches
//! the server, every other one, a longer name starting with a granted one,
//! and a batch hiding one ungranted call among granted ones do not. Ann
//! may grant only tools the tenant registered.

use ianua_scenarios::agent::external::{ExternalAgent, IssuedToken};
use ianua_scenarios::api::agents::{delegation, tools};
use ianua_scenarios::expect::Records;
use ianua_scenarios::net::Call;
use ianua_scenarios::stack::Stack;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::agents::authority::Capabilities;
use ianua_scenarios::wire::agents::tools::RegisterTool;
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;
use serde_json::{Value, json};

use super::{App, VIEW_USERS, bound_grant, granted_agent, opened, proven};
use crate::support::{Witness, profile};

/// The one path the tool server answers MCP on.
const MCP_PATH: &str = "/mcp";

/// The tool Ann grants: listing a repository's issues.
const LIST_ISSUES: &str = "list_issues";

/// A tool whose name starts with the granted one, which a literal grant
/// must not cover.
const LIST_ISSUES_ALL: &str = "list_issues_all";

/// The tool nobody granted: deleting a repository.
const DELETE_REPO: &str = "delete_repo";

/// The tool server behind the gateway, with the gateway's MCP check in its
/// pipeline, and `names` registered as the tenant's tools over its route
/// by Ann.
async fn tool_server(stack: &Stack, world: &World<'_>, names: &[&str]) -> App {
    let server = opened(stack, world, MCP_PATH, vec![json!("Mcp")]).await;
    for name in names {
        let tool = RegisterTool {
            name: (*name).to_owned(),
            description: format!("{name} on the code host"),
            schema: json!({"type": "object", "properties": {"repo": {"type": "string"}}}),
            method: "POST".to_owned(),
            path: MCP_PATH.to_owned(),
            route_id: server.route.route_id.clone(),
        };
        tools::register(world.tenant(), &tool)
            .send(world.owner().client())
            .await
            .ok();
    }
    server
}

/// A JSON-RPC call of `method` with `params`.
fn envelope(method: &str, params: &Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
}

/// A `tools/call` of the tool `name`.
fn calling(name: &str) -> Value {
    envelope(
        "tools/call",
        &json!({"name": name, "arguments": {"repo": "acme/web"}}),
    )
}

/// `body` posted to the tool server as `agent` sends it, proven by its
/// key.
fn posted(agent: &ExternalAgent, server: &App, body: &Value) -> Call {
    let url = server.url(MCP_PATH);
    proven(agent, Call::post(url.as_str()).json(body), "POST", &url)
}

/// Ann registers three tools and grants Reporter one of them by name.
/// Reporter lists the server's tools and calls `list_issues`: both reach
/// the server, and the call is on record as an action Reporter took.
/// `delete_repo`, `list_issues_all`, whose name only starts with the
/// granted one, and a batch burying `delete_repo` after `list_issues` are
/// each refused at the gateway, which records the MCP check as what
/// refused them; the server sees none of them.
#[tokio::test]
async fn reporter_calls_the_tool_ann_granted_and_no_other() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let registered = [LIST_ISSUES, LIST_ISSUES_ALL, DELETE_REPO];
    let server = tool_server(&stack, &world, &registered).await;
    let granted = Capabilities::http(&[VIEW_USERS]).with_tools(&[LIST_ISSUES]);
    let reporter = granted_agent(
        &stack,
        &world,
        "Reporter",
        &bound_grant(server.service_id(), "Read the issues", granted),
    )
    .await;
    let mut witness = Witness::of(&world).await;

    let listing = envelope("tools/list", &json!({}));
    reporter
        .client()
        .send::<IgnoredAny>(posted(&reporter, &server, &listing))
        .await
        .ok();
    reporter
        .client()
        .send::<IgnoredAny>(posted(&reporter, &server, &calling(LIST_ISSUES)))
        .await
        .ok();
    assert_eq!(
        server.echo.arrivals().len(),
        2,
        "the listing and the granted call reached the server"
    );
    let authorized = witness.recorded("agents.action_authorized").await;
    assert!(
        super::names(&authorized, reporter.id()),
        "the record names Reporter: {authorized:?}"
    );

    let batch = json!([calling(LIST_ISSUES), calling(DELETE_REPO)]);
    for refused in [calling(DELETE_REPO), calling(LIST_ISSUES_ALL), batch] {
        reporter
            .client()
            .send::<IgnoredAny>(posted(&reporter, &server, &refused))
            .await
            .refused(Status::FORBIDDEN, "forbidden");
    }
    assert_eq!(
        server.echo.arrivals().len(),
        2,
        "no refused call reached the server"
    );
    let record = Records::of_tenant(world.admin().client(), world.tenant())
        .recorded_where(MCP_PATH, "Reporter's refused tool call", |record| {
            record.decision == "refused" && record.subject.id.as_deref() == Some(reporter.id())
        })
        .await;
    let refused_by = record.decided_by.map(|by| (by.kind, by.name));
    assert_eq!(
        refused_by,
        Some(("stage".to_owned(), "mcp".to_owned())),
        "the gateway's MCP check refused the call"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Helper holds a grant naming no tool: it may list the server's tools and
/// call none of them. Reporter calls its granted tool until Ann revokes
/// its delegation; from the next call on it is not known as anyone, and
/// the server sees nothing more. The revocation is on record.
#[tokio::test]
async fn a_grant_naming_no_tool_calls_none_and_a_revoked_one_calls_nothing_more() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let server = tool_server(&stack, &world, &[LIST_ISSUES]).await;
    let helper = granted_agent(
        &stack,
        &world,
        "Helper",
        &bound_grant(
            server.service_id(),
            "View people",
            Capabilities::http(&[VIEW_USERS]),
        ),
    )
    .await;
    let granted = Capabilities::http(&[VIEW_USERS]).with_tools(&[LIST_ISSUES]);
    let reporter = granted_agent(
        &stack,
        &world,
        "Reporter",
        &bound_grant(server.service_id(), "Read the issues", granted),
    )
    .await;
    let mut witness = Witness::of(&world).await;

    let listing = envelope("tools/list", &json!({}));
    helper
        .client()
        .send::<IgnoredAny>(posted(&helper, &server, &listing))
        .await
        .ok();
    helper
        .client()
        .send::<IgnoredAny>(posted(&helper, &server, &calling(LIST_ISSUES)))
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    reporter
        .client()
        .send::<IgnoredAny>(posted(&reporter, &server, &calling(LIST_ISSUES)))
        .await
        .ok();
    let Some(token) = reporter.token() else {
        panic!("Reporter holds Ann's token");
    };
    delegation::revoke(world.tenant(), reporter.id(), token.delegation_id())
        .send(world.owner().client())
        .await
        .ok();
    witness.recorded("agents.delegation_revoked").await;
    reporter
        .client()
        .send::<IgnoredAny>(posted(&reporter, &server, &calling(LIST_ISSUES)))
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    assert_eq!(
        server.echo.arrivals().len(),
        2,
        "Helper's listing and Reporter's one call before the revocation reached the server"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann may grant only tools the tenant registered: `create_charge`, which
/// nobody registered, and `stripe_*`, a prefix no registered tool falls
/// under, are both refused and nothing is granted. `list_*` covers the
/// registered `list_issues`, so that grant stands, and Reporter calls the
/// tool with it.
#[tokio::test]
async fn ann_grants_only_tools_the_tenant_registered() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let server = tool_server(&stack, &world, &[LIST_ISSUES]).await;
    let ann = world.owner().client();
    let mut reporter = ExternalAgent::enrolled(&stack, world.tenant(), ann, "Reporter").await;
    let mut witness = Witness::of(&world).await;
    witness.caught_up().await;

    for unregistered in ["create_charge", "stripe_*"] {
        let grant = bound_grant(
            server.service_id(),
            "Charge customers",
            Capabilities::http(&[VIEW_USERS]).with_tools(&[unregistered]),
        );
        delegation::grant(world.tenant(), reporter.id(), &grant)
            .send(ann)
            .await
            .refused(Status::FORBIDDEN, "forbidden");
    }
    witness.nothing_new("agents.delegation_granted").await;
    let held = delegation::list(world.tenant(), reporter.id())
        .send(ann)
        .await
        .ok();
    assert!(held.is_empty(), "Reporter was granted {held:?}");

    let prefix = bound_grant(
        server.service_id(),
        "Read whatever lists",
        Capabilities::http(&[VIEW_USERS]).with_tools(&["list_*"]),
    );
    let granted = delegation::grant(world.tenant(), reporter.id(), &prefix)
        .send(ann)
        .await
        .ok();
    witness.recorded("agents.delegation_granted").await;
    assert_eq!(granted.granted.tools, ["list_*"]);
    reporter.hold(IssuedToken::of(granted));
    reporter
        .client()
        .send::<IgnoredAny>(posted(&reporter, &server, &calling(LIST_ISSUES)))
        .await
        .ok();
    assert_eq!(server.echo.arrivals().len(), 1);
    stack.stop().await.expect("the stack stops cleanly");
}
