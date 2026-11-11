//! Rules on the other guarded changes: someone put into a group, an app
//! opened to workflows, and the audit trail exported. Each rule is handed
//! what the change would do, and every rule on a change must allow it: one
//! refusing rule stops it, however many allow.

use ianua_scenarios::api::{Request, audit, policies, routing};
use ianua_scenarios::net::Client;
use ianua_scenarios::routes::{AppliedRoute, Placement, RouteSpec};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::Echo;
use ianua_scenarios::wire::audit::ExportAsked;
use ianua_scenarios::wire::policies::NewGroupMember;
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;

use super::{group, only_run, refused_by_the_rule, rule_on};
use crate::support::pat;

/// The change of someone being put into a group.
const ACCESS_GIVEN: &str = "access_given";

/// The change of an app being opened to workflows.
const APP_OPENED: &str = "app_opened_to_workflows";

/// The change of the audit trail being exported.
const AUDIT_EXPORTED: &str = "audit_exported";

/// The record of an app opened to workflows.
const OPENED_RECORD: &str = "routing.route_opened_to_workflows";

/// Ann publishes a rule allowing access. Tess puts Pat into "Helpdesk":
/// Pat is in it, and the rule was handed the group and Pat. Ann then
/// publishes a second rule refusing access. Tess puts Pat into "Billing":
/// refused with the rule's 403, and Pat is not in it.
#[tokio::test]
async fn every_rule_on_access_must_allow_before_pat_joins_a_group() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = pat(&world).await;
    let helpdesk = group(&world, "Helpdesk").await;
    let billing = group(&world, "Billing").await;
    let allowing = rule_on(&world, ACCESS_GIVEN, "allow").await;

    joining(&world, &helpdesk, pat.id())
        .send(world.admin().client())
        .await
        .ok();
    let run = only_run(&world, &allowing, "succeeded").await;
    rule_on(&world, ACCESS_GIVEN, "refuse").await;
    refused_by_the_rule(&world, joining(&world, &billing, pat.id())).await;

    assert_eq!(run.cause, "before");
    assert_eq!(run.input["group"], helpdesk.as_str(), "{}", run.input);
    assert!(
        run.input["member"]
            .as_str()
            .is_some_and(|member| member.contains(pat.id())),
        "the rule saw Pat: {}",
        run.input
    );
    assert_eq!(members(&world, &helpdesk).await, 1, "Pat is in Helpdesk");
    assert_eq!(members(&world, &billing).await, 0, "Pat is not in Billing");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann publishes a rule allowing apps to be opened to workflows. Tess
/// opens the orders app: the rule was handed the app and its name, and the
/// opening is recorded. Tess closes it again, which no rule is asked
/// about. Ann then publishes a rule refusing it, and Tess's second opening
/// is refused: the trail still records one opening.
#[tokio::test]
async fn a_rule_refusing_apps_opened_to_workflows_keeps_the_app_closed() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let app = orders_app(&world).await;
    let allowing = rule_on(&world, APP_OPENED, "allow").await;

    opening(&world, &app.route)
        .send(world.admin().client())
        .await
        .ok();
    let run = only_run(&world, &allowing, "succeeded").await;
    routing::close_route_to_workflows(world.tenant(), &app.route.route_id)
        .send(world.admin().client())
        .await
        .ok();
    rule_on(&world, APP_OPENED, "refuse").await;
    refused_by_the_rule(&world, opening(&world, &app.route)).await;

    assert_eq!(
        run.input["app"],
        app.route.route_id.as_str(),
        "{}",
        run.input
    );
    assert_eq!(run.input["app_name"], "orders-app");
    assert_eq!(
        openings(&world).await,
        1,
        "only the allowed opening happened"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann publishes a rule allowing audit exports. Tess asks for a CSV
/// export: it is accepted, and the rule was handed the format and Tess as
/// the one who asked. Ann then publishes a rule refusing exports, and
/// Tess's JSON export is refused with the rule's 403.
#[tokio::test]
async fn a_rule_refusing_audit_exports_stops_the_export() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let allowing = rule_on(&world, AUDIT_EXPORTED, "allow").await;

    audit::request_tenant_export(world.tenant(), &exported("csv"))
        .send(world.admin().client())
        .await
        .ok();
    let run = only_run(&world, &allowing, "succeeded").await;
    rule_on(&world, AUDIT_EXPORTED, "refuse").await;
    let refused = audit::request_tenant_export(world.tenant(), &exported("json"));
    refused_by_the_rule(&world, refused).await;

    assert_eq!(run.input["format"], "csv", "{}", run.input);
    assert!(
        run.input["asked_by"]
            .as_str()
            .is_some_and(|asked_by| !asked_by.is_empty()),
        "the rule saw who asked: {}",
        run.input
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Putting the user `user_id` into the group `group_id`.
fn joining(world: &World<'_>, group_id: &str, user_id: &str) -> Request<IgnoredAny> {
    let member = NewGroupMember {
        kind: "user".to_owned(),
        id: user_id.to_owned(),
    };
    policies::add_member(world.tenant(), group_id, &member)
}

/// How many members the group `group_id` has.
async fn members(world: &World<'_>, group_id: &str) -> usize {
    policies::members(world.tenant(), group_id)
        .send(world.admin().client())
        .await
        .ok()
        .items
        .len()
}

/// Opening `route` to workflows.
fn opening(world: &World<'_>, route: &AppliedRoute) -> Request<()> {
    routing::open_route_to_workflows(world.tenant(), &route.route_id)
}

/// How many openings of an app to workflows the tenant's trail records.
async fn openings(world: &World<'_>) -> usize {
    audit::tenant_log(world.tenant(), OPENED_RECORD)
        .send(world.admin().client())
        .await
        .ok()
        .items
        .len()
}

/// An audit export in `format`, of every record.
fn exported(format: &str) -> ExportAsked {
    ExportAsked {
        format: format.to_owned(),
        event_type: None,
    }
}

/// Acme's orders app behind the gateway, and the app itself.
struct OrdersApp {
    route: AppliedRoute,
    _upstream: Echo,
}

/// Tess puts the orders app behind the gateway, closed to workflows.
async fn orders_app(world: &World<'_>) -> OrdersApp {
    let names = routing::hostnames(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    let host = names.slug_subdomain.unwrap_or(names.uuid_subdomain);
    let upstream = Echo::start(world.stack(), &host)
        .await
        .expect("the orders app starts");
    let probe = Client::new(world.stack(), "a visitor of the orders app").expect("a client");
    let route = RouteSpec::public("orders-app", "/orders/*")
        .applied(
            world.admin().client(),
            &probe,
            Placement {
                tenant: world.tenant(),
                upstream: &upstream.url(),
                host: &host,
            },
        )
        .await;
    OrdersApp {
        route,
        _upstream: upstream,
    }
}
