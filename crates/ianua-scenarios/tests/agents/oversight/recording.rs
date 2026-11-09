//! An agent nobody can watch is an agent the gateway does not let act:
//! every action it admits for an agent is recorded before it goes on, and
//! one that cannot be recorded is refused, never forwarded unseen.

use ianua_scenarios::stack::{AuditWrites, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::agents::authority::Capabilities;
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;

use super::{VIEW_USERS, bound_grant, granted_agent, names, proven_get, reports_app};
use crate::support::{Witness, profile};

/// While the gateway cannot add to the inbox its records of agents'
/// actions reach the trail through, Reporter's read of a report is refused
/// as unavailable and never reaches the app, and nothing is recorded of
/// it. Once the gateway may write again, the same read goes through and
/// is on record exactly once, naming Reporter.
#[tokio::test]
async fn an_agent_is_refused_while_its_action_cannot_be_recorded() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let app = reports_app(&stack, &world).await;
    let grant = bound_grant(
        app.service_id(),
        "Read reports",
        Capabilities::http(&[VIEW_USERS]),
    );
    let reporter = granted_agent(&stack, &world, "Reporter", &grant).await;
    let mut witness = Witness::of(&world).await;
    let url = app.url("/reports/weekly");

    stack.gateway_event_writes(AuditWrites::Refuse).await;
    reporter
        .client()
        .send::<IgnoredAny>(proven_get(&reporter, &url))
        .await
        .refused(Status::SERVICE_UNAVAILABLE, "unavailable");
    assert!(
        app.echo.arrivals().is_empty(),
        "an unrecorded action reached the app"
    );

    stack.gateway_event_writes(AuditWrites::Allow).await;
    reporter
        .client()
        .send::<IgnoredAny>(proven_get(&reporter, &url))
        .await
        .ok();
    assert_eq!(app.echo.arrivals().len(), 1);
    let recorded = witness.recorded("agents.action_authorized").await;
    assert!(
        names(&recorded, reporter.id()),
        "the record names Reporter: {recorded:?}"
    );
    let more = witness.fresh("agents.action_authorized").await;
    assert!(
        more.is_empty(),
        "the read was recorded more than once: {more:?}"
    );
    stack.stop().await.expect("the stack stops cleanly");
}
