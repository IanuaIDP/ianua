//! Whose authority an agent acts on, followed back to the person at its
//! root: Ann grants Reporter, Reporter hands part on to Helper, and every
//! witness tells the same chain. The API names each link, the reports app
//! reads Helper acting for Reporter in the gateway's assertion, the
//! gateway's record names both, and revoking Ann's grant ends Helper's
//! part with it. A person hands on only what their own role holds.

use ianua_scenarios::agent::external::{ExternalAgent, IssuedToken};
use ianua_scenarios::api::agents::delegation;
use ianua_scenarios::expect::Records;
use ianua_scenarios::stack::Stack;
use ianua_scenarios::upstreams::AssertionCheck;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::agents::authority::{Capabilities, Delegation, Granted};
use ianua_scenarios::wire::agents::{Principal, PrincipalKind};
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;

use super::{VIEW_USERS, bound_grant, handed_on, names, proven_get, reports_app, steward};
use crate::support::{Witness, profile};

/// The report Helper reads.
const DAILY: &str = "/reports/daily";

/// A permission none of the cast's roles here hands on: deactivating
/// people.
const DEACTIVATE_USERS: &str = "idp:users:deactivate";

/// Each principal in `chain` as its kind and id.
fn links(chain: &[Principal]) -> Vec<(PrincipalKind, &str)> {
    chain
        .iter()
        .map(|principal| (principal.kind, principal.id.as_str()))
        .collect()
}

/// The one delegation `agent` holds, as Ann reads it.
async fn held_by(world: &World<'_>, agent: &ExternalAgent) -> Delegation {
    let mut held = delegation::list(world.tenant(), agent.id())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(held.len(), 1, "{} holds one delegation", agent.name());
    held.remove(0)
}

/// Ann grants Reporter reading reports, to be handed on once; the API
/// answers that it acts for Ann. Reporter hands part of it on to Helper,
/// whose part acts for Reporter and, above it, for Ann. Ann reads both:
/// Reporter's sits at the root, granted by Ann; Helper's one hop down, cut
/// from Reporter's and granted by Reporter. Helper reads a report: the app
/// reads in the gateway's assertion that Helper acts, for Reporter, and the
/// gateway's record names both. Each grant is on record. Ann revokes her
/// grant, and Helper's part ends with it.
#[tokio::test]
async fn authority_runs_from_ann_through_reporter_to_helper() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let app = reports_app(&stack, &world).await;
    let ann = world.owner();
    let mut witness = Witness::of(&world).await;
    let mut reporter =
        ExternalAgent::enrolled(&stack, world.tenant(), ann.client(), "Reporter").await;
    let mut grant = bound_grant(
        app.service_id(),
        "Read reports, and hand reading on",
        Capabilities::http(&[VIEW_USERS]),
    );
    grant.limits.max_depth = 1;
    let granted: Granted = delegation::grant(world.tenant(), reporter.id(), &grant)
        .send(ann.client())
        .await
        .ok();
    assert_eq!(
        links(&granted.on_behalf_of),
        [(PrincipalKind::OrgUser, ann.id())],
        "Ann's grant acts for Ann, a member of her organization"
    );
    let root_id = granted.delegation_id.clone();
    reporter.hold(IssuedToken::of(granted));
    witness.recorded("agents.delegation_granted").await;

    let handed = handed_on(&stack, &world, &reporter, &app).await;
    let helper = handed.helper;
    assert_eq!(
        links(&handed.on_behalf_of),
        [
            (PrincipalKind::Agent, reporter.id()),
            (PrincipalKind::OrgUser, ann.id())
        ],
        "Helper's part acts for Reporter, nearest, then Ann at the root"
    );
    let passed = witness.recorded("agents.delegation_granted").await;
    assert!(
        names(&passed, helper.id()),
        "the hand-on names Helper: {passed:?}"
    );

    let root = held_by(&world, &reporter).await;
    assert_eq!(
        (root.depth, root.parent.as_deref(), root.delegator.kind),
        (0, None, PrincipalKind::OrgUser)
    );
    assert_eq!(root.delegator.id, ann.id());
    let part = held_by(&world, &helper).await;
    assert_eq!(
        (part.depth, part.parent.as_deref(), part.delegator.kind),
        (1, Some(root_id.as_str()), PrincipalKind::Agent)
    );
    assert_eq!(part.delegator.id, reporter.id());

    helper
        .client()
        .send::<IgnoredAny>(proven_get(&helper, &app.url(DAILY)))
        .await
        .ok();
    let arrived = app.echo.arrivals();
    let Some(last) = arrived.last() else {
        panic!("Helper's read reached the app");
    };
    let AssertionCheck::Verified { caller } = &last.assertion else {
        panic!("the app could not check the gateway's assertion: {last:?}");
    };
    assert_eq!(caller.kind, "agent");
    assert_eq!(caller.act.as_deref(), Some(helper.id()), "Helper acts");
    assert!(
        caller
            .obo
            .as_deref()
            .is_some_and(|obo| obo.contains(reporter.id())),
        "the app reads that Helper acts for Reporter: {caller:?}"
    );
    let record = Records::of_tenant(world.admin().client(), world.tenant())
        .recorded_where(DAILY, "Helper's allowed", |record| {
            record.decision == "allowed"
        })
        .await;
    assert_eq!(record.subject.id.as_deref(), Some(helper.id()));
    assert!(
        record
            .subject
            .on_behalf_of
            .as_deref()
            .is_some_and(|behalf| behalf.contains(reporter.id())),
        "the gateway records whom Helper acted for: {record:?}"
    );

    delegation::revoke(world.tenant(), reporter.id(), &root_id)
        .send(ann.client())
        .await
        .ok();
    helper
        .client()
        .send::<IgnoredAny>(proven_get(&helper, &app.url(DAILY)))
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    assert_eq!(
        app.echo.arrivals().len(),
        1,
        "Helper's part ended with Ann's grant"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat's role lets her view people and empower agents, nothing more. She
/// tries to hand her reporter the right to deactivate people: refused, and
/// nothing is granted. Viewing people she may hand on, and that grant acts
/// for Pat, as a member of the organization, not as anyone she is not.
#[tokio::test]
async fn a_person_hands_on_only_what_their_role_holds() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let app = reports_app(&stack, &world).await;
    let pat = steward(&stack, &world).await;
    let reporter =
        ExternalAgent::enrolled(&stack, world.tenant(), pat.client(), "Pat's reporter").await;
    let mut witness = Witness::of(&world).await;
    witness.caught_up().await;

    let wider = bound_grant(
        app.service_id(),
        "Deactivate people",
        Capabilities::http(&[DEACTIVATE_USERS]),
    );
    delegation::grant(world.tenant(), reporter.id(), &wider)
        .send(pat.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    witness.nothing_new("agents.delegation_granted").await;

    let viewing = bound_grant(
        app.service_id(),
        "View people",
        Capabilities::http(&[VIEW_USERS]),
    );
    let granted = delegation::grant(world.tenant(), reporter.id(), &viewing)
        .send(pat.client())
        .await
        .ok();
    assert_eq!(
        links(&granted.on_behalf_of),
        [(PrincipalKind::OrgUser, pat.id())],
        "the grant acts for Pat"
    );
    let recorded = witness.recorded("agents.delegation_granted").await;
    assert!(
        names(&recorded, reporter.id()),
        "the grant names Pat's reporter: {recorded:?}"
    );
    stack.stop().await.expect("the stack stops cleanly");
}
