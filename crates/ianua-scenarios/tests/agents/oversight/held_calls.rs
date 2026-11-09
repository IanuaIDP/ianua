//! A delegation whose every call waits for a person, enforced at the
//! gateway: Reporter's request is held there, and the API opens a request
//! naming Reporter as who asked. Tess, who stands behind neither Reporter
//! nor its grant, approves exactly that call, and it goes through once and
//! only once; another call is another request; a call she denies never
//! goes through.

use ianua_scenarios::agent::external::ExternalAgent;
use ianua_scenarios::api::agents::approvals;
use ianua_scenarios::expect::{Matrix, Records};
use ianua_scenarios::stack::Stack;
use ianua_scenarios::wire::agents::PrincipalKind;
use ianua_scenarios::wire::agents::approvals::Approval;
use ianua_scenarios::wire::agents::authority::Capabilities;
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;

use super::{App, VIEW_USERS, bound_grant, granted_agent, proven_get, reports_app};
use crate::support::{Witness, profile, refused_to_the_rest};

/// The call Tess approves.
const WEEKLY: &str = "/reports/weekly";

/// The call Tess denies.
const MONTHLY: &str = "/reports/monthly";

/// What Reporter is told when it reads `path` on `app`.
async fn reads(reporter: &ExternalAgent, app: &App, path: &str) -> Answer<IgnoredAny> {
    reporter
        .client()
        .send::<IgnoredAny>(proven_get(reporter, &app.url(path)))
        .await
}

/// The request waiting on a person for Reporter's call to `path`, as Tess
/// reads Reporter's pending requests.
async fn waiting_for(world: &World<'_>, reporter: &ExternalAgent, path: &str) -> Approval {
    let pending = approvals::list(world.tenant(), reporter.id(), Some("pending"))
        .send(world.admin().client())
        .await
        .ok();
    let mut held: Vec<Approval> = pending
        .into_iter()
        .filter(|approval| approval.action.contains(path))
        .collect();
    assert_eq!(held.len(), 1, "one request waits for the call to {path}");
    held.remove(0)
}

/// Ann's grant makes every call of Reporter's wait for a person. Its read
/// of the weekly report is held at the gateway and never reaches the app;
/// asking again opens no second request. Tess reads the request: Reporter
/// asked it, one person must decide, and the facts name Ann as whom
/// Reporter acts for. Ann, who stands behind Reporter, may not approve it,
/// nor may Max, Sam or anyone not signed in. Tess approves it: the next
/// read goes through once, the approval is spent, and the read after is
/// held again. A read of the monthly report is a request of its own,
/// which Tess denies; it never goes through. The gateway records the held
/// reads, and the trail each step.
#[tokio::test]
async fn an_approved_call_goes_through_once_and_a_denied_one_never() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let app = reports_app(&stack, &world).await;
    let mut grant = bound_grant(
        app.service_id(),
        "Read reports, asking each time",
        Capabilities::http(&[VIEW_USERS]),
    );
    grant.limits.requires_approval = true;
    let reporter = granted_agent(&stack, &world, "Reporter", &grant).await;
    let mut witness = Witness::of(&world).await;

    reads(&reporter, &app, WEEKLY)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    witness.recorded("agents.approval_requested").await;
    reads(&reporter, &app, WEEKLY)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    witness.nothing_new("agents.approval_requested").await;
    assert!(
        app.echo.arrivals().is_empty(),
        "a held call reached the app"
    );
    let held = Records::of_tenant(world.admin().client(), world.tenant())
        .recorded_where(WEEKLY, "Reporter's held", |record| {
            record.reason.as_deref() == Some("agent_approval_pending")
        })
        .await;
    assert_ne!(held.decision, "allowed", "a held call is not let through");
    assert_eq!(held.subject.id.as_deref(), Some(reporter.id()));

    let weekly = waiting_for(&world, &reporter, WEEKLY).await;
    read_by_tess(&world, &reporter, &weekly).await;
    approved_by_tess(&world, &reporter, &weekly).await;
    witness.recorded("agents.approval_granted").await;
    reads(&reporter, &app, WEEKLY).await.ok();
    assert_eq!(
        app.echo.arrivals().len(),
        1,
        "the approved call went through"
    );
    let spent = approvals::list(world.tenant(), reporter.id(), None)
        .send(world.admin().client())
        .await
        .ok();
    let status = spent
        .iter()
        .find(|approval| approval.id == weekly.id)
        .map(|approval| approval.status.as_str());
    assert_eq!(status, Some("consumed"), "going through spent the approval");
    reads(&reporter, &app, WEEKLY)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    witness.recorded("agents.approval_requested").await;

    reads(&reporter, &app, MONTHLY)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let monthly = waiting_for(&world, &reporter, MONTHLY).await;
    approvals::deny(world.tenant(), reporter.id(), &monthly.id)
        .send(world.admin().client())
        .await
        .ok();
    witness.recorded("agents.approval_denied").await;
    reads(&reporter, &app, MONTHLY)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    assert_eq!(
        app.echo.arrivals().len(),
        1,
        "neither the second weekly read nor the denied monthly one went through"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess reads the held call before deciding: Reporter asked it, one
/// person must decide it, and the platform's facts name Ann as whom
/// Reporter acts for.
async fn read_by_tess(world: &World<'_>, reporter: &ExternalAgent, weekly: &Approval) {
    assert_eq!(
        (weekly.requested_by.kind, weekly.requested_by.id.as_str()),
        (PrincipalKind::Agent, reporter.id()),
        "Reporter asked"
    );
    assert_eq!(weekly.approvers_needed, 1, "one person decides a read");
    let facts = approvals::facts(world.tenant(), reporter.id(), &weekly.id)
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(facts.approval.id, weekly.id);
    let behind: Vec<(PrincipalKind, &str)> = facts
        .on_behalf_of
        .iter()
        .map(|principal| (principal.kind, principal.id.as_str()))
        .collect();
    assert_eq!(
        behind,
        [(PrincipalKind::OrgUser, world.owner().id())],
        "Reporter acts for Ann"
    );
}

/// Ann, who stands behind Reporter, and the rest of the cast are refused;
/// Tess approves.
async fn approved_by_tess(world: &World<'_>, reporter: &ExternalAgent, weekly: &Approval) {
    let approving = approvals::approve(world.tenant(), reporter.id(), &weekly.id);
    let matrix = Matrix::new("approving Reporter's held read", approving.call()).refused(
        world.owner().client(),
        Status::FORBIDDEN,
        "forbidden",
    );
    refused_to_the_rest(matrix, world, &[reporter]).run().await;
    approving.send(world.admin().client()).await.ok();
}
