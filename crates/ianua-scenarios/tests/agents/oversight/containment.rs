//! Fencing in an agent that misbehaves, as the reports app sees it: Ann
//! suspends Reporter and resumes it; Tess stops every agent at once when
//! nobody knows which one went wrong; Ann pulls the kill switch, which
//! stops Reporter and everything it handed on for good; Pat, whose
//! authority her agent acts on, is deactivated; and Mallory, holding a copy
//! of Reporter's token, gets nowhere without its key.

use std::time::{SystemTime, UNIX_EPOCH};

use ianua_scenarios::agent::external::dpop::{self, ProvenRequest};
use ianua_scenarios::agent::external::{ExternalAgent, IssuedToken};
use ianua_scenarios::agent::keys::AgentKey;
use ianua_scenarios::api::agents::{delegation, lifecycle};
use ianua_scenarios::api::members;
use ianua_scenarios::expect::{Matrix, Records};
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::stack::Stack;
use ianua_scenarios::wire::agents::authority::{Capabilities, Grant};
use ianua_scenarios::wire::agents::token::TokenAsk;
use ianua_scenarios::wire::organization::ChangeMemberStatus;
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;

use super::{
    App, GRANT_SECONDS, VIEW_USERS, bare, bound_grant, granted_agent, handed_on, names, proven_get,
    reports_app, steward,
};
use crate::support::{Witness, hidden_from_the_rest, profile};

/// The report every agent here reads.
const WEEKLY: &str = "/reports/weekly";

/// The grant of reading reports Ann makes `name`, on the reports app.
fn reading(app: &App, name: &str) -> Grant {
    bound_grant(app.service_id(), name, Capabilities::http(&[VIEW_USERS]))
}

/// What `agent` is told when it reads the weekly report.
async fn reads(agent: &ExternalAgent, app: &App) -> Answer<IgnoredAny> {
    agent
        .client()
        .send::<IgnoredAny>(proven_get(agent, &app.url(WEEKLY)))
        .await
}

/// Ann suspends Reporter; Max, who may not act on it, is told it does not
/// exist. From Reporter's next request on, its live token is not known as
/// anyone, and the app sees nothing. Ann resumes it and the same token
/// reads the report again. Both changes are on record.
#[tokio::test]
async fn a_suspended_agent_is_refused_until_ann_resumes_it() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let app = reports_app(&stack, &world).await;
    let reporter = granted_agent(&stack, &world, "Reporter", &reading(&app, "Read reports")).await;
    let mut witness = Witness::of(&world).await;
    reads(&reporter, &app).await.ok();

    let suspend = lifecycle::suspend(world.tenant(), reporter.id());
    hidden_from_the_rest(
        Matrix::new("suspending Reporter", suspend.call()),
        &world,
        &[&reporter],
    )
    .run()
    .await;
    suspend.send(world.owner().client()).await.ok();
    witness.recorded("agents.agent_suspended").await;
    reads(&reporter, &app)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    assert_eq!(
        app.echo.arrivals().len(),
        1,
        "the suspended agent reached nothing"
    );

    lifecycle::resume(world.tenant(), reporter.id())
        .send(world.owner().client())
        .await
        .ok();
    witness.recorded("agents.agent_resumed").await;
    reads(&reporter, &app).await.ok();
    assert_eq!(app.echo.arrivals().len(), 2);
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann pulls the kill switch on Reporter, which handed part of her grant
/// on to Helper. Both delegations fall in one pass, and neither agent's
/// token reaches the app again. It is terminal: Reporter cannot be
/// resumed, Ann cannot grant it anything new, and its key mints nothing.
/// Pulling the switch again tears nothing more down. The containment is
/// on record, naming Reporter.
#[tokio::test]
async fn the_kill_switch_stops_an_agent_and_what_it_handed_on_for_good() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let app = reports_app(&stack, &world).await;
    let mut grant = reading(&app, "Read reports, and hand reading on");
    grant.limits.max_depth = 1;
    let reporter = granted_agent(&stack, &world, "Reporter", &grant).await;
    let helper = handed_on(&stack, &world, &reporter, &app).await.helper;
    reads(&helper, &app).await.ok();
    let mut witness = Witness::of(&world).await;

    let contained = lifecycle::contain(world.tenant(), reporter.id())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        contained.revoked_count, 2,
        "Ann's grant and Helper's part fell"
    );
    let record = witness.recorded("agents.agent_contained").await;
    assert!(
        names(&record, reporter.id()),
        "the record names Reporter: {record:?}"
    );
    for agent in [&reporter, &helper] {
        reads(agent, &app)
            .await
            .refused(Status::UNAUTHORIZED, "unauthenticated");
    }
    assert_eq!(
        app.echo.arrivals().len(),
        1,
        "only Helper's read before the switch arrived"
    );

    lifecycle::resume(world.tenant(), reporter.id())
        .send(world.owner().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    delegation::grant(world.tenant(), reporter.id(), &reading(&app, "Read again"))
        .send(world.owner().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let again = TokenAsk::bearer(Capabilities::http(&[VIEW_USERS]), GRANT_SECONDS);
    reporter
        .ask_token(&again)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    witness.nothing_new("agents.delegation_granted").await;
    witness.nothing_new("agents.token_issued").await;

    let twice = lifecycle::contain(world.tenant(), reporter.id())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(twice.revoked_count, 0, "nothing was left to tear down");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Nobody knows which agent went wrong, so Tess stops every one at once;
/// Max may not. Reporter's and Helper's tokens are both refused at the
/// app. Ann resumes Reporter once it is known to be safe: it reads again,
/// and Helper, not yet resumed, stays stopped. Stopping all is on record.
#[tokio::test]
async fn stopping_every_agent_holds_each_until_it_is_resumed_by_hand() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let app = reports_app(&stack, &world).await;
    let reporter = granted_agent(&stack, &world, "Reporter", &reading(&app, "Read reports")).await;
    let helper = granted_agent(&stack, &world, "Helper", &reading(&app, "Read reports too")).await;
    let mut witness = Witness::of(&world).await;

    lifecycle::suspend_all(world.tenant())
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let stopped = lifecycle::suspend_all(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(stopped.suspended_count, 2, "both agents were stopped");
    witness.recorded("agents.all_agents_suspended").await;
    for agent in [&reporter, &helper] {
        reads(agent, &app)
            .await
            .refused(Status::UNAUTHORIZED, "unauthenticated");
    }

    lifecycle::resume(world.tenant(), reporter.id())
        .send(world.owner().client())
        .await
        .ok();
    reads(&reporter, &app).await.ok();
    reads(&helper, &app)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    assert_eq!(
        app.echo.arrivals().len(),
        1,
        "only the resumed Reporter reached the app"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat, a member Ann gave a role that lets her view people and make and
/// empower agents, hands her reporter reading reports. Ann deactivates
/// Pat: deactivating her withdraws every delegation she granted, so from
/// the next request on her reporter's live token proves nobody and is
/// refused as unauthenticated, and the gateway records the credential as
/// revoked by its identity check. Ann's own Reporter, acting for Ann,
/// reads on.
#[tokio::test]
async fn an_agent_stops_when_the_person_it_acts_for_is_deactivated() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let app = reports_app(&stack, &world).await;
    let pat = steward(&stack, &world).await;
    let mut pats =
        ExternalAgent::enrolled(&stack, world.tenant(), pat.client(), "Pat's reporter").await;
    let for_pat = reading(&app, "Read reports for Pat");
    let granted = delegation::grant(world.tenant(), pats.id(), &for_pat)
        .send(pat.client())
        .await
        .ok();
    pats.hold(IssuedToken::of(granted));
    let anns = granted_agent(&stack, &world, "Reporter", &reading(&app, "Read reports")).await;
    reads(&pats, &app).await.ok();

    members::change_status(
        world.org(),
        pat.id(),
        &ChangeMemberStatus {
            status: "Deactivated".to_owned(),
        },
    )
    .send(world.owner().client())
    .await
    .ok();
    reads(&pats, &app)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    reads(&anns, &app).await.ok();
    assert_eq!(
        app.echo.arrivals().len(),
        2,
        "Pat's reporter reached the app only before"
    );

    let record = Records::of_tenant(world.admin().client(), world.tenant())
        .recorded_where(WEEKLY, "Pat's reporter's refused", |record| {
            record.decision == "refused"
        })
        .await;
    assert_eq!(
        record.reason.as_deref(),
        Some("credential_revoked"),
        "the gateway records that what stood behind the token was withdrawn: {record:?}"
    );
    let refused_by = record.decided_by.map(|by| (by.kind, by.name));
    assert_eq!(
        refused_by,
        Some(("stage".to_owned(), "identity".to_owned())),
        "the gateway's identity check refused the token"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Mallory copies Reporter's request off the wire, its token and its
/// proof, and sends it again: the proof is spent, so she is not known as
/// anyone, and a proof that merely fails records nothing. She sends the
/// token bare, then beside a proof made with a key of her own: both are
/// refused, and the trail records the stolen token as an attack on
/// Reporter. Only Reporter's own request reached the app, and Reporter
/// reads on.
#[tokio::test]
async fn a_stolen_token_is_worth_nothing_without_its_key() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let app = reports_app(&stack, &world).await;
    let reporter = granted_agent(&stack, &world, "Reporter", &reading(&app, "Read reports")).await;
    let mallory = Client::new(&stack, "Mallory, with Reporter's token").expect("a client");
    let mut witness = Witness::of(&world).await;
    let url = app.url(WEEKLY);

    let captured = proven_get(&reporter, &url);
    reporter
        .client()
        .send::<IgnoredAny>(captured.clone())
        .await
        .ok();
    mallory
        .send::<IgnoredAny>(captured)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    witness.nothing_new("agents.token_attack_refused").await;

    mallory
        .send::<IgnoredAny>(bare(&reporter, Call::get(url.as_str())))
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let attack = witness.recorded("agents.token_attack_refused").await;
    assert!(
        names(&attack, reporter.id()),
        "the attack names Reporter: {attack:?}"
    );
    mallory
        .send::<IgnoredAny>(proven_by_mallory(&reporter, &url))
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    assert_eq!(
        app.echo.arrivals().len(),
        1,
        "only Reporter's own request arrived"
    );
    reads(&reporter, &app).await.ok();
    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann asks Reporter to prove itself again. Its status stays `Active`, and
/// she can still see that it may not act until it has.
#[tokio::test]
async fn ann_sees_that_reporter_must_prove_itself_again() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let app = reports_app(&stack, &world).await;
    let reporter = granted_agent(&stack, &world, "Reporter", &reading(&app, "Read reports")).await;
    let before = lifecycle::get(world.tenant(), reporter.id())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(before.standing, "Active");

    lifecycle::require_reattestation(world.tenant(), reporter.id())
        .send(world.owner().client())
        .await
        .ok();

    let after = lifecycle::get(world.tenant(), reporter.id())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(after.status, "Active");
    assert_eq!(after.standing, "MustReattest");
    stack.stop().await.expect("the stack stops cleanly");
}

/// A `GET` of `url` carrying Reporter's token beside a proof Mallory made
/// with a key of her own.
fn proven_by_mallory(reporter: &ExternalAgent, url: &str) -> Call {
    let hers = AgentKey::generate();
    let issued_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        });
    let token = reporter.token().map(IssuedToken::token);
    let proof = dpop::proof(
        &hers,
        ProvenRequest { method: "GET", url },
        token,
        issued_at,
    );
    bare(reporter, Call::get(url)).header("dpop", &proof)
}
