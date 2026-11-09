//! Watcher, an agent Tess owns, set by her to watch Ann's Reporter: it
//! reads Reporter's evidence at its review desk, signed in by an assertion
//! its own key signed and spent on use, and gives a verdict resting on
//! records it read. It acts on nothing and may be granted nothing. A
//! watcher answering to the same person, or holding authority, is
//! refused; Reporter cannot read its watcher's desk; once Tess ends the
//! watch, the desk is closed.

use ianua_scenarios::agent::external::ExternalAgent;
use ianua_scenarios::api::agents::delegation;
use ianua_scenarios::api::agents::reviews::{self, Desk};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::Stack;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::agents::PrincipalKind;
use ianua_scenarios::wire::agents::authority::{Capabilities, Grant, Limits};
use ianua_scenarios::wire::agents::reviews::{AssignReviewer, Verdict};
use ianua_scenarios::wire::agents::token::TokenAsk;
use ianua_scenarios::world::World;

use super::{GRANT_SECONDS, VIEW_USERS};
use crate::support::{Witness, granted_by_owner, hidden_from_the_rest, profile};

/// Viewing people, for an hour at most: what Ann hands Reporter.
fn viewing() -> Grant {
    Grant {
        granted: Capabilities::http(&[VIEW_USERS]),
        limits: Limits {
            ttl_seconds: GRANT_SECONDS,
            ..Limits::default()
        },
        name: Some("View people".to_owned()),
    }
}

/// The assignment of `watcher` to watch another agent.
fn watching(watcher: &ExternalAgent) -> AssignReviewer {
    AssignReviewer {
        reviewer_agent_id: watcher.id().to_owned(),
    }
}

/// A concern resting on the records `cited`.
fn concern(cited: Vec<i64>) -> Verdict {
    Verdict {
        kind: "concern".to_owned(),
        note: "Reporter asked for tokens it never used.".to_owned(),
        cited_seqs: cited,
    }
}

/// Ann's Reporter, holding her grant and having taken a token under it,
/// so its evidence holds what it did.
async fn busy_reporter(stack: &Stack, world: &World<'_>) -> ExternalAgent {
    let reporter =
        ExternalAgent::enrolled(stack, world.tenant(), world.owner().client(), "Reporter").await;
    granted_by_owner(world, &reporter, &viewing()).await;
    let ask = TokenAsk::bearer(Capabilities::http(&[VIEW_USERS]), GRANT_SECONDS);
    reporter.ask_token(&ask).await.ok();
    reporter
}

/// Tess sets Watcher, her own agent holding nothing, to watch Ann's
/// Reporter; Max, Sam, nobody signed in and the agents themselves may not.
/// Ann reads who watches Reporter. At its desk Watcher reads Reporter's
/// evidence and gives a concern resting on the first record, which is on
/// record as Watcher's verdict. A verdict citing one of Watcher's own
/// records is refused, as is an assertion used twice. Reporter cannot read
/// its watcher's desk, and Tess, who owns Watcher, cannot grant it
/// anything. Tess ends the watch, and the desk is closed to Watcher from
/// then on.
#[tokio::test]
async fn a_watcher_reads_an_agents_evidence_and_rests_its_verdict_on_it() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let reporter = busy_reporter(&stack, &world).await;
    let watcher =
        ExternalAgent::enrolled(&stack, world.tenant(), world.admin().client(), "Watcher").await;
    let mut witness = Witness::of(&world).await;

    let assigning = reviews::assign(world.tenant(), reporter.id(), &watching(&watcher));
    hidden_from_the_rest(
        Matrix::new("setting Watcher on Reporter", assigning.call()),
        &world,
        &[&reporter, &watcher],
    )
    .run()
    .await;
    let assignment = assigning.send(world.admin().client()).await.ok();
    witness.recorded("agents.reviewer_assigned").await;
    let listed = reviews::list(world.tenant(), reporter.id())
        .send(world.owner().client())
        .await
        .ok();
    let who: Vec<(&str, PrincipalKind, &str)> = listed
        .iter()
        .map(|watch| {
            (
                watch.reviewer_agent_id.as_str(),
                watch.assigned_by.kind,
                watch.assigned_by.id.as_str(),
            )
        })
        .collect();
    assert_eq!(
        who,
        [(watcher.id(), PrincipalKind::OrgUser, world.admin().id())],
        "Ann reads that Tess set Watcher on Reporter"
    );

    let first = read_at_desk(&world, &watcher, &reporter).await;
    reviews::desk_verdict(
        world.tenant(),
        reporter.id(),
        desk_of(&watcher, &watcher.assertion()),
        &concern(vec![first]),
    )
    .send(watcher.client())
    .await
    .ok();
    witness.recorded("agents.review_verdict").await;
    refused_at_desk(&world, &watcher, &reporter).await;
    witness.nothing_new("agents.review_verdict").await;

    delegation::grant(world.tenant(), watcher.id(), &viewing())
        .send(world.admin().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    reviews::end(world.tenant(), reporter.id(), &assignment.id)
        .send(world.admin().client())
        .await
        .ok();
    witness.recorded("agents.review_ended").await;
    reviews::desk_evidence(
        world.tenant(),
        reporter.id(),
        desk_of(&watcher, &watcher.assertion()),
    )
    .send(watcher.client())
    .await
    .refused(Status::FORBIDDEN, "forbidden");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Watcher's sign-in at the desk with `assertion`.
fn desk_of<'a>(watcher: &'a ExternalAgent, assertion: &'a str) -> Desk<'a> {
    Desk {
        reviewer_id: watcher.id(),
        assertion,
    }
}

/// Watcher reads Reporter's evidence at its desk, and the place of the
/// first record in the chain.
async fn read_at_desk(world: &World<'_>, watcher: &ExternalAgent, reporter: &ExternalAgent) -> i64 {
    let page = reviews::desk_evidence(
        world.tenant(),
        reporter.id(),
        desk_of(watcher, &watcher.assertion()),
    )
    .send(watcher.client())
    .await
    .ok();
    let Some(first) = page.records.first() else {
        panic!("Reporter's evidence holds what it did");
    };
    assert!(
        page.records
            .iter()
            .any(|record| record.event_type == "agents.token_issued"),
        "the token Reporter took is evidence: {page:?}"
    );
    first.seq
}

/// What the desk refuses: a verdict citing a record of Watcher's own, an
/// assertion used twice, and Reporter reading its watcher's desk.
async fn refused_at_desk(world: &World<'_>, watcher: &ExternalAgent, reporter: &ExternalAgent) {
    let own = reviews::evidence(world.tenant(), watcher.id())
        .send(world.admin().client())
        .await
        .ok();
    let Some(not_reporters) = own.records.first() else {
        panic!("Watcher's own evidence holds its making");
    };
    reviews::desk_verdict(
        world.tenant(),
        reporter.id(),
        desk_of(watcher, &watcher.assertion()),
        &concern(vec![not_reporters.seq]),
    )
    .send(watcher.client())
    .await
    .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    let spent = watcher.assertion();
    reviews::desk_evidence(world.tenant(), reporter.id(), desk_of(watcher, &spent))
        .send(watcher.client())
        .await
        .ok();
    reviews::desk_evidence(world.tenant(), reporter.id(), desk_of(watcher, &spent))
        .send(watcher.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    let turned_round = Desk {
        reviewer_id: reporter.id(),
        assertion: &reporter.assertion(),
    };
    reviews::desk_evidence(world.tenant(), watcher.id(), turned_round)
        .send(reporter.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// Tess tries to set Shadow, Ann's own second agent, to watch Ann's
/// Reporter: one person would watch herself, so it is refused. She then
/// tries Watcher, her own agent, after granting it viewing people: a
/// watcher holding authority could act to cover what it saw, so that is
/// refused too. Nothing is assigned.
#[tokio::test]
async fn a_watcher_must_answer_to_someone_else_and_hold_nothing() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let ann = world.owner().client();
    let tess = world.admin().client();
    let reporter = ExternalAgent::enrolled(&stack, world.tenant(), ann, "Reporter").await;
    let shadow = ExternalAgent::enrolled(&stack, world.tenant(), ann, "Shadow").await;
    let watcher = ExternalAgent::enrolled(&stack, world.tenant(), tess, "Watcher").await;
    delegation::grant(world.tenant(), watcher.id(), &viewing())
        .send(tess)
        .await
        .ok();
    let mut witness = Witness::of(&world).await;
    witness.caught_up().await;

    reviews::assign(world.tenant(), reporter.id(), &watching(&shadow))
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    reviews::assign(world.tenant(), reporter.id(), &watching(&watcher))
        .send(tess)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    witness.nothing_new("agents.reviewer_assigned").await;
    let listed = reviews::list(world.tenant(), reporter.id())
        .send(ann)
        .await
        .ok();
    assert!(listed.is_empty(), "nobody watches Reporter: {listed:?}");
    stack.stop().await.expect("the stack stops cleanly");
}
