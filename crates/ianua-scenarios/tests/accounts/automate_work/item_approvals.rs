//! One approval for every item of a loop: Tess's loop delivers each issue
//! to the outside service, and its first step asks Ann once for the whole
//! list instead of once per pass. The service shows when passes really
//! ran. Nothing is delivered while the approval waits; Ann's yes counts
//! only once she opened every page of the items, then each pass delivers
//! exactly once. Max may not approve, and Ann's no fails the loop before
//! any pass runs.

use ianua_scenarios::api::Request;
use ianua_scenarios::api::workflows::{self, ItemsAsked};
use ianua_scenarios::expect::eventually;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::workflows::{
    ApproveItems, Edge, ExecutionDecided, ItemsPage, Node, PassRun, Step, Trigger,
};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::service::Service;
use crate::support::{
    APPROVAL_STEP, DELIVERY_STEP, LOOP_STEP, connected_account, delivery_graph, drafted,
    each_issue, ended, published, started_with,
};

/// The three issues Tess's loop goes over.
const ISSUES: [&str; 3] = ["login fails", "slow search", "typo on pricing"];

/// The most items one page shows: two, so three issues take two pages.
const PAGE: u32 = 2;

/// The approval step asking once for every item, the loop's first step.
fn whole_loop_approval() -> Node {
    Node {
        key: APPROVAL_STEP.to_owned(),
        name: "Approve every delivery".to_owned(),
        step: Step::WholeLoopApproval {
            summary: "Deliver each of these issues".to_owned(),
            action_class: "read".to_owned(),
            window_seconds: 300,
            covers: "whole_loop".to_owned(),
        },
    }
}

/// Tess drafts and Ann publishes a loop over the issues, two at a time,
/// that asks one approval for every issue before delivering each; Tess
/// starts it with the three issues and the run's id.
async fn started_loop(world: &World<'_>, service: &Service) -> String {
    let account = connected_account(world, service).await;
    let mut body = delivery_graph(service, &account);
    body.nodes.insert(0, whole_loop_approval());
    body.edges.push(Edge {
        from: APPROVAL_STEP.to_owned(),
        to: DELIVERY_STEP.to_owned(),
    });
    let draft = drafted(world, Trigger::Manual, each_issue(body, 2)).await;
    let workflow = published(world, &draft).await;
    started_with(world, &workflow, json!({ "issues": ISSUES }))
        .await
        .execution_id
}

/// The page after `after`, or the first, of the items the loop of
/// `execution_id` asks about, as asked for.
fn page_of<'a>(execution_id: &'a str, after: Option<&'a str>) -> ItemsAsked<'a> {
    ItemsAsked {
        execution_id,
        step: LOOP_STEP,
        after,
        limit: PAGE,
    }
}

/// Ann opens the first page of items once the loop asks for its
/// approval.
async fn first_page(world: &World<'_>, execution_id: &str) -> ItemsPage {
    eventually("the loop to ask for its approval", || async {
        let answer = workflows::approval_items(world.tenant(), &page_of(execution_id, None))
            .send(world.owner().client())
            .await;
        (answer.status() == Status::OK).then(|| answer.ok())
    })
    .await
}

/// The passes the loop of `execution_id` started so far.
async fn passes(world: &World<'_>, execution_id: &str) -> Vec<PassRun> {
    workflows::passes(world.tenant(), execution_id)
        .send(world.admin().client())
        .await
        .ok()
        .items
}

/// Tess's loop asks Ann once for all three issues. While it waits, no pass
/// has started and nothing reached the service. Ann opens the first page,
/// showing two of three issues, and approves: refused, since she has not
/// seen the third. Max, who may not approve steps, is refused too. Ann
/// opens the second page, now shown all three, and approves: the run
/// succeeds, each issue is delivered exactly once, three passes ran, and
/// the trail records her one approval.
#[tokio::test]
async fn one_approval_after_every_page_releases_each_pass_once() {
    let service = Service::start().await;
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let execution_id = started_loop(&world, &service).await;

    let first = first_page(&world, &execution_id).await;
    assert!(
        passes(&world, &execution_id).await.is_empty(),
        "no pass yet"
    );
    assert_eq!(service.calls(), 0, "nothing is delivered while it waits");
    refused_before_every_page(&world, &execution_id).await;
    let cursor = first.next_cursor.clone().expect("a second page");
    let last = workflows::approval_items(world.tenant(), &page_of(&execution_id, Some(&cursor)))
        .send(world.owner().client())
        .await
        .ok();
    yes_to_every_item(&world, &execution_id)
        .send(world.owner().client())
        .await
        .ok();

    ended(&world, &execution_id, "succeeded").await;
    check_pages(&first, &last);
    assert_eq!(service.delivered(), 3, "each issue was delivered once");
    assert_eq!(service.calls(), 3, "and nothing more reached the service");
    assert_eq!(passes(&world, &execution_id).await.len(), 3);
    assert_eq!(world.trail().count("workflows.approval_granted").await, 1);
    stack.stop().await.expect("the stack stops cleanly");
}

/// A yes to every item of the loop of `execution_id`, whoever sends it.
fn yes_to_every_item(world: &World<'_>, execution_id: &str) -> Request<ExecutionDecided> {
    workflows::approve_items(
        world.tenant(),
        execution_id,
        LOOP_STEP,
        &ApproveItems { mfa_code: None },
    )
}

/// Ann's yes before she saw the third issue is refused as a conflict,
/// and Max's yes is forbidden.
async fn refused_before_every_page(world: &World<'_>, execution_id: &str) {
    yes_to_every_item(world, execution_id)
        .send(world.owner().client())
        .await
        .refused(Status::CONFLICT, "conflict");
    yes_to_every_item(world, execution_id)
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// The two pages show the three issues in order, counting what Ann was
/// shown, and the second is the last.
fn check_pages(first: &ItemsPage, last: &ItemsPage) {
    let shown: Vec<_> = first
        .items
        .iter()
        .chain(&last.items)
        .map(|item| (item.position, item.item.clone()))
        .collect();
    assert_eq!(
        shown,
        [
            (0, json!(ISSUES[0])),
            (1, json!(ISSUES[1])),
            (2, json!(ISSUES[2]))
        ]
    );
    assert_eq!((first.total, first.shown), (3, 2));
    assert_eq!((last.total, last.shown), (3, 3));
    assert!(last.next_cursor.is_none(), "the second page is the last");
}

/// Tess's loop asks Ann once for all three issues. Ann opens the items and
/// denies the approval: the loop and the run fail, no pass ever started,
/// and nothing reached the service.
#[tokio::test]
async fn a_denied_loop_approval_fails_the_loop_with_no_pass_run() {
    let service = Service::start().await;
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let execution_id = started_loop(&world, &service).await;
    first_page(&world, &execution_id).await;

    workflows::deny(world.tenant(), &execution_id, LOOP_STEP)
        .send(world.owner().client())
        .await
        .ok();

    let execution = ended(&world, &execution_id, "failed").await;
    let loop_phase = execution
        .steps
        .iter()
        .find(|step| step.key == LOOP_STEP)
        .map(|step| step.phase.clone());
    assert_eq!(loop_phase.as_deref(), Some("failed"), "the loop failed");
    assert!(
        passes(&world, &execution_id).await.is_empty(),
        "no pass ran"
    );
    assert_eq!(service.calls(), 0, "nothing reached the service");
    stack.stop().await.expect("the stack stops cleanly");
}
