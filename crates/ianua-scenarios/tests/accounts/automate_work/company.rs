//! Company steps: Pat's workflow acts on Acme itself, as Pat. A step signs
//! Lee out everywhere through the same action Pat could take by hand, the
//! audit trail names Pat and the run, and a step Pat could not take by hand
//! fails without changing anything. Another puts a notice in Lee's inbox.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::agents::{delegation, lifecycle};
use ianua_scenarios::api::{audit, notifications, people, policies, workflows};
use ianua_scenarios::expect::eventually;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::agents::authority::{Capabilities, Grant, Limits};
use ianua_scenarios::wire::agents::identity::NewAgent;
use ianua_scenarios::wire::policies::{AskForGroup, AskedGroup, NewGroup, NewGroupMember};
use ianua_scenarios::wire::workflows::{
    Edge, Execution, Graph, MappedField, Node, StartExecution, Step, Trigger,
};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::support::{
    ApprovalStep, Approver, drafted, ended, invited, published, run, started_with, written,
};

/// The key of the step that signs Lee out.
const SIGN_OUT_STEP: &str = "sign-out";

/// What Pat may do by hand: run workflows and manage people.
const MANAGES_PEOPLE: &[(&str, &str)] = &[
    ("Workflows", "View"),
    ("Workflows", "Run"),
    ("Users", "Manage"),
];

/// What Pat may do when only allowed to run workflows.
const RUNS_ONLY: &[(&str, &str)] = &[("Workflows", "View"), ("Workflows", "Run")];

/// What Pat may do to change groups by hand: run workflows, find people,
/// and read and assign roles.
const MANAGES_GROUPS: &[(&str, &str)] = &[
    ("Workflows", "View"),
    ("Workflows", "Run"),
    ("Users", "View"),
    ("Roles", "View"),
    ("Roles", "Assign"),
];

/// The key of the approval before a step changing who can do what.
const YES_STEP: &str = "yes";

/// The key of the step taking Lee out of every group.
const UNGROUP_STEP: &str = "ungroup";

/// A graph taking the person at `address` out of every group, once someone
/// says yes: the step changes who can do what.
fn ungrouping(address: &str) -> Graph {
    Graph {
        nodes: vec![
            ungrouping_approval(),
            Node {
                key: UNGROUP_STEP.to_owned(),
                name: "Take Lee out of every group".to_owned(),
                step: Step::Action {
                    integration: "ianua".to_owned(),
                    operation: "remove-groups".to_owned(),
                    account_id: None,
                    effect: "admin".to_owned(),
                    ceiling: "internal".to_owned(),
                    inputs: vec![MappedField {
                        field: "person".to_owned(),
                        source: written(address),
                    }],
                },
            },
        ],
        edges: vec![Edge {
            from: YES_STEP.to_owned(),
            to: UNGROUP_STEP.to_owned(),
        }],
    }
}

/// Removing every group membership requires an approval for an administrative change.
fn ungrouping_approval() -> Node {
    Node {
        key: YES_STEP.to_owned(),
        name: "Approve taking Lee out of every group".to_owned(),
        step: Step::Approval {
            summary: "Take Lee out of every group".to_owned(),
            action_class: "admin".to_owned(),
            window_seconds: 120,
        },
    }
}

/// A graph of one company step signing out the person reached at `address`.
fn signing_out(address: &str) -> Graph {
    Graph {
        nodes: vec![Node {
            key: SIGN_OUT_STEP.to_owned(),
            name: "Sign Lee out everywhere".to_owned(),
            step: Step::Action {
                integration: "ianua".to_owned(),
                operation: "sign-out".to_owned(),
                account_id: None,
                effect: "write".to_owned(),
                ceiling: "internal".to_owned(),
                inputs: vec![MappedField {
                    field: "person".to_owned(),
                    source: written(address),
                }],
            },
        }],
        edges: vec![],
    }
}

/// Pat runs the workflow signing Lee out, and it ends as `expected` says.
async fn sign_out_lee(
    world: &World<'_>,
    pat: &mut Person,
    lee: &Person,
    expected: &str,
) -> Execution {
    let execution_id = start_graph(world, pat, signing_out(lee.email())).await;
    ended(world, &execution_id, expected).await
}

/// Tess drafts the graph, Ann publishes it, and the named person starts its manual run.
async fn start_graph(world: &World<'_>, person: &mut Person, graph: Graph) -> String {
    let draft = drafted(world, Trigger::Manual, graph).await;
    let workflow = published(world, &draft).await;
    let start = StartExecution {
        input: json!({}),
        exposure: "internal".to_owned(),
    };
    let started = person
        .send(workflows::start(world.tenant(), &workflow.id, &start))
        .await
        .ok();
    started.execution_id
}

/// Whether Lee's session still lets Lee in.
async fn lee_signed_in(world: &World<'_>, lee: &Person) -> Status {
    people::me(world.tenant()).send(lee.client()).await.status()
}

/// Pat may manage people and runs a workflow signing Lee out. Lee's
/// session ends at once, and the audit trail says the session was ended by
/// Pat, through that run.
#[tokio::test]
async fn pat_s_run_signs_lee_out_as_pat() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited(&world, ("pat", "Pat Runner"), MANAGES_PEOPLE).await;
    let lee = invited(&world, ("lee", "Lee Lost"), &[("Workflows", "View")]).await;
    assert_eq!(lee_signed_in(&world, &lee).await, Status::OK);

    let run = sign_out_lee(&world, &mut pat, &lee, "succeeded").await;

    let step = run
        .steps
        .iter()
        .find(|step| step.key == SIGN_OUT_STEP)
        .expect("the run has its sign-out step");
    let ended = step
        .output
        .as_ref()
        .and_then(|output| output["sessions_ended"].as_f64());
    assert!(ended.is_some_and(|count| count >= 1.0), "{:?}", step.output);
    assert_eq!(lee_signed_in(&world, &lee).await, Status::UNAUTHORIZED);
    check_sign_out_audit(&world, &run.id, pat.email()).await;
}

/// The session revocation audit record identifies the workflow run and Pat as its actor.
async fn check_sign_out_audit(world: &World<'_>, execution_id: &str, email: &str) {
    let log = audit::tenant_log(world.tenant(), "authentication.session_revoked")
        .send(world.admin().client())
        .await
        .ok();
    let through_run = log.items.iter().find(|entry| {
        entry.acted_through.as_ref().is_some_and(|through| {
            through.kind == "workflow_run" && through.execution_id.as_deref() == Some(execution_id)
        })
    });
    let entry = through_run.expect("the session's end names the run it came through");
    assert!(entry.actor.contains(email), "{}", entry.actor);
}

/// Pat may run workflows but cannot manage people. A run that tries to
/// sign Lee out fails, and Lee's session still reads their account.
#[tokio::test]
async fn a_step_pat_could_not_take_by_hand_fails_and_changes_nothing() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited(&world, ("pat", "Pat Runner"), RUNS_ONLY).await;
    let lee = invited(&world, ("lee", "Lee Lost"), &[("Workflows", "View")]).await;

    sign_out_lee(&world, &mut pat, &lee, "failed").await;

    assert_eq!(lee_signed_in(&world, &lee).await, Status::OK);
}

/// Lee is in Support. Pat's workflow takes Lee out of every group, an
/// admin change, so it waits for two people to say yes, each with their
/// authenticator's code: before Bea and after Bea alone, Lee stays in
/// Support. Once Cal says yes too, Lee is in no group, taken out as Pat,
/// through the run.
#[tokio::test]
async fn pat_s_run_takes_lee_out_of_every_group_once_two_people_say_yes() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited(&world, ("pat", "Pat Runner"), MANAGES_GROUPS).await;
    let lee = invited(&world, ("lee", "Lee Lost"), &[("Workflows", "View")]).await;
    let lee_id = people::me(world.tenant()).send(lee.client()).await.ok().id;
    let support_id = add_to_support(&world, &lee_id).await;
    let execution_id = start_graph(&world, &mut pat, ungrouping(lee.email())).await;
    wait_for_ungrouping(&world, &execution_id).await;
    assert!(
        in_support(&world, &support_id, &lee_id).await,
        "nothing changes before the yes"
    );
    approve_ungrouping(&world, &execution_id, &support_id, &lee_id).await;
}

/// Tess creates Support with Lee as its first member.
async fn add_to_support(world: &World<'_>, lee_id: &str) -> String {
    let support = policies::create_group(
        world.tenant(),
        &NewGroup {
            name: "Support".to_owned(),
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    policies::add_member(
        world.tenant(),
        &support.id,
        &NewGroupMember {
            kind: "user".to_owned(),
            id: lee_id.to_owned(),
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    support.id
}

/// The administrative run reaches its approval and stays running until decisions arrive.
async fn wait_for_ungrouping(world: &World<'_>, execution_id: &str) {
    let held = eventually("the run to wait for a yes, or end", || async {
        let execution = run(world, execution_id).await;
        let waiting = execution
            .steps
            .iter()
            .any(|step| step.key == YES_STEP && step.phase == "running");
        (waiting || execution.status != "running").then_some(execution)
    })
    .await;
    assert_eq!(held.status, "running", "the run waits for a yes: {held:?}");
}

/// Bea alone changes nothing; Cal's second approval lets the run remove Lee's one membership.
async fn approve_ungrouping(world: &World<'_>, execution_id: &str, support_id: &str, lee_id: &str) {
    let shown = workflows::approval(world.tenant(), execution_id, YES_STEP)
        .send(world.owner().client())
        .await
        .ok();
    let mut bea = Approver::joined(world, "bea", "Bea Approver").await;
    let mut cal = Approver::joined(world, "cal", "Cal Approver").await;
    let target = ApprovalStep {
        execution_id,
        step: YES_STEP,
    };
    bea.approve(world, target, &shown.shown).await;
    assert!(
        in_support(world, support_id, lee_id).await,
        "one yes is not enough for a change to who can do what"
    );
    cal.approve(world, target, &shown.shown).await;
    let finished = ended(world, execution_id, "succeeded").await;
    check_groups_left(&finished);
    assert!(!in_support(world, support_id, lee_id).await);
}

/// The remove-groups step reports that it removed Lee's one membership.
fn check_groups_left(finished: &Execution) {
    let step = finished
        .steps
        .iter()
        .find(|step| step.key == UNGROUP_STEP)
        .expect("the run has its step");
    let left = step
        .output
        .as_ref()
        .and_then(|output| output["groups_left"].as_f64());
    assert_eq!(left, Some(1.0));
}

/// Whether the person `user_id` is in the group `group_id`, as Tess reads
/// its members.
async fn in_support(world: &World<'_>, group_id: &str, user_id: &str) -> bool {
    let members = policies::members(world.tenant(), group_id)
        .send(world.admin().client())
        .await
        .ok();
    members
        .items
        .iter()
        .any(|member| member.kind == "user" && member.id == user_id)
}

/// The key of the step telling Lee.
const NOTIFY_STEP: &str = "tell-lee";

/// What Pat's workflow tells Lee.
const NOTICE_TITLE: &str = "You were signed out";

/// A graph of one company step telling the person reached at `address`.
fn telling(address: &str) -> Graph {
    Graph {
        nodes: vec![Node {
            key: NOTIFY_STEP.to_owned(),
            name: "Tell Lee".to_owned(),
            step: Step::Action {
                integration: "ianua".to_owned(),
                operation: "notify".to_owned(),
                account_id: None,
                effect: "communicate".to_owned(),
                ceiling: "internal".to_owned(),
                inputs: vec![
                    MappedField {
                        field: "person".to_owned(),
                        source: written(address),
                    },
                    MappedField {
                        field: "title".to_owned(),
                        source: written(NOTICE_TITLE),
                    },
                    MappedField {
                        field: "message".to_owned(),
                        source: written("Sign in again and check your devices."),
                    },
                ],
            },
        }],
        edges: vec![],
    }
}

/// Pat's workflow tells Lee they were signed out. Lee, who may see almost
/// nothing, finds the notice in their inbox, unread, and the audit trail
/// says Pat sent it, through the run.
#[tokio::test]
async fn pat_s_run_puts_a_notice_in_lee_s_inbox() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited(&world, ("pat", "Pat Runner"), MANAGES_PEOPLE).await;
    let lee = invited(&world, ("lee", "Lee Lost"), &[("Workflows", "View")]).await;
    let execution_id = start_graph(&world, &mut pat, telling(lee.email())).await;
    let run = ended(&world, &execution_id, "succeeded").await;
    check_notice(&world, &lee).await;
    check_notice_author(&world, &run.id, pat.email()).await;
}

/// Lee's inbox contains the unread notice and its expected message.
async fn check_notice(world: &World<'_>, lee: &Person) {
    let inbox = notifications::inbox(world.tenant())
        .send(lee.client())
        .await
        .ok();
    let notice = inbox
        .items
        .iter()
        .find(|notice| notice.title == NOTICE_TITLE)
        .expect("the notice is in Lee's inbox");
    assert!(!notice.read);
    assert_eq!(
        notice.body.as_deref(),
        Some("Sign in again and check your devices.")
    );
}

/// The notice audit record names Pat and the run she started.
async fn check_notice_author(world: &World<'_>, execution_id: &str, email: &str) {
    let log = audit::tenant_log(world.tenant(), "notifications.notice_sent")
        .send(world.admin().client())
        .await
        .ok();
    let entry = log
        .items
        .iter()
        .find(|entry| {
            entry
                .acted_through
                .as_ref()
                .is_some_and(|through| through.execution_id.as_deref() == Some(execution_id))
        })
        .expect("the notice names the run it came through");
    assert!(entry.actor.contains(email), "{}", entry.actor);
}

/// A graph of one company step offering the person at `address` to ask to
/// join `group_id`.
fn offering_support(address: &str, group_id: &str) -> Graph {
    Graph {
        nodes: vec![Node {
            key: "offer".to_owned(),
            name: "Offer Lee Support".to_owned(),
            step: Step::Action {
                integration: "ianua".to_owned(),
                operation: "offer-access".to_owned(),
                account_id: None,
                effect: "communicate".to_owned(),
                ceiling: "internal".to_owned(),
                inputs: vec![
                    MappedField {
                        field: "person".to_owned(),
                        source: written(address),
                    },
                    MappedField {
                        field: "group".to_owned(),
                        source: written(group_id),
                    },
                    MappedField {
                        field: "title".to_owned(),
                        source: written("You may ask to join Support"),
                    },
                ],
            },
        }],
        edges: vec![],
    }
}

/// Pat's workflow offers Lee to ask to join Support. Lee's notice names
/// the group, so Lee's dashboard can offer the request, Lee is not in
/// Support yet, and the trail records the offer.
#[tokio::test]
async fn pat_s_run_offers_lee_to_ask_to_join_support() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited(&world, ("pat", "Pat Runner"), MANAGES_PEOPLE).await;
    let lee = invited(&world, ("lee", "Lee Lost"), &[("Workflows", "View")]).await;
    let support = policies::create_group(
        world.tenant(),
        &NewGroup {
            name: "Support".to_owned(),
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    let execution_id =
        start_graph(&world, &mut pat, offering_support(lee.email(), &support.id)).await;
    ended(&world, &execution_id, "succeeded").await;
    check_access_offer(&world, &lee, &support.id).await;
}

/// Lee's offer names Support, and the tenant trail contains one access-offered record.
async fn check_access_offer(world: &World<'_>, lee: &Person, support_id: &str) {
    let inbox = notifications::inbox(world.tenant())
        .send(lee.client())
        .await
        .ok();
    let offer = inbox
        .items
        .iter()
        .find(|notice| notice.title == "You may ask to join Support")
        .expect("the offer is in Lee's inbox");
    assert_eq!(offer.resource_id.as_deref(), Some(support_id));
    let log = audit::tenant_log(world.tenant(), "notifications.access_offered")
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(log.items.len(), 1, "the offer is on the trail");
}

/// A graph of one company step taking back every task `agent_id` holds.
fn revoking_tasks(agent_id: &str) -> Graph {
    Graph {
        nodes: vec![Node {
            key: "revoke".to_owned(),
            name: "Take back Triage's tasks".to_owned(),
            step: Step::Action {
                integration: "ianua".to_owned(),
                operation: "revoke-agent-tasks".to_owned(),
                account_id: None,
                effect: "write".to_owned(),
                ceiling: "internal".to_owned(),
                inputs: vec![MappedField {
                    field: "agent".to_owned(),
                    source: written(agent_id),
                }],
            },
        }],
        edges: vec![],
    }
}

/// Ann gave Triage a task. Tess's workflow takes back every task Triage
/// holds: it runs at once, as it only narrows, and the task is revoked.
#[tokio::test]
async fn a_run_takes_back_every_task_an_agent_holds() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let triage = grant_triage_task(&world).await;
    let draft = drafted(&world, Trigger::Manual, revoking_tasks(&triage)).await;
    let workflow = published(&world, &draft).await;

    let started = started_with(&world, &workflow, json!({})).await;
    let run = ended(&world, &started.execution_id, "succeeded").await;

    let revoked = run.steps[0]
        .output
        .as_ref()
        .and_then(|output| output["tasks_revoked"].as_f64());
    assert_eq!(revoked, Some(1.0), "{:?}", run.steps[0].output);
    let held = delegation::list(world.tenant(), &triage)
        .send(world.owner().client())
        .await
        .ok();
    assert!(
        held.iter().all(|task| task.revoked),
        "every task Triage held is revoked"
    );
}

/// Ann creates Triage and grants it a one-hour task to read people.
async fn grant_triage_task(world: &World<'_>) -> String {
    let ann = world.owner().client();
    let made = NewAgent {
        name: "Triage".to_owned(),
        description: Some("Reads support tickets.".to_owned()),
        ..NewAgent::default()
    };
    let triage = lifecycle::create(world.tenant(), &made)
        .send(ann)
        .await
        .ok()
        .id;
    let grant = Grant {
        granted: Capabilities::http(&["users:view"]),
        limits: Limits {
            ttl_seconds: 3600,
            ..Limits::default()
        },
        name: Some("Read people".to_owned()),
    };
    delegation::grant(world.tenant(), &triage, &grant)
        .send(ann)
        .await
        .ok();
    triage
}

/// What reminding Tess says.
const REMINDER_TITLE: &str = "Lee is waiting to join Support";

/// A graph of one company step reminding the person at `address` every
/// hour until `request_id` is decided.
fn reminding(address: &str, request_id: &str) -> Graph {
    let field = |name: &str, value: &str| MappedField {
        field: name.to_owned(),
        source: written(value),
    };
    Graph {
        nodes: vec![Node {
            key: "remind".to_owned(),
            name: "Remind Tess".to_owned(),
            step: Step::Action {
                integration: "ianua".to_owned(),
                operation: "remind-until-decided".to_owned(),
                account_id: None,
                effect: "communicate".to_owned(),
                ceiling: "internal".to_owned(),
                inputs: vec![
                    field("person", address),
                    field("request", request_id),
                    field("title", REMINDER_TITLE),
                    field("every", "1"),
                ],
            },
        }],
        edges: vec![],
    }
}

/// Lee asks to join Support, as a request someone must approve.
async fn lee_asks_for_support(world: &World<'_>, lee: &mut Person) -> String {
    let support = policies::create_group(
        world.tenant(),
        &NewGroup {
            name: "Support".to_owned(),
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    let asked = AskForGroup {
        asked: AskedGroup {
            kind: "group",
            id: support.id,
        },
        reason: "I cover the help desk next week".to_owned(),
        length_seconds: 7 * 24 * 3600,
    };
    lee.send(policies::ask_for_group(world.tenant(), &asked))
        .await
        .ok()
        .id
}

/// Pat's workflow reminds Tess of Lee's open request. Tess finds the
/// reminder in her inbox, and the step waits for its next round, an hour
/// on, with the run still going.
#[tokio::test]
async fn pat_s_run_reminds_tess_while_lee_s_request_is_open() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited(&world, ("pat", "Pat Runner"), MANAGES_GROUPS).await;
    let mut lee = invited(&world, ("lee", "Lee Lost"), &[("Workflows", "View")]).await;
    let bea = invited(&world, ("bea", "Bea Approver"), &[("Workflows", "View")]).await;
    let request_id = lee_asks_for_support(&world, &mut lee).await;
    let execution_id = start_graph(&world, &mut pat, reminding(bea.email(), &request_id)).await;
    wait_for_reminder(&world, &bea, &execution_id).await;
}

/// Bea receives a reminder while its execution waits for the next round.
async fn wait_for_reminder(world: &World<'_>, bea: &Person, execution_id: &str) {
    eventually("Bea to be reminded", || async {
        let inbox = notifications::inbox(world.tenant())
            .send(bea.client())
            .await
            .ok();
        inbox
            .items
            .iter()
            .any(|notice| notice.title == REMINDER_TITLE)
            .then_some(())
    })
    .await;
    let waiting = eventually("the reminder's next round to wait", || async {
        let execution = run(world, execution_id).await;
        (execution.steps[0].phase == "ready").then_some(execution)
    })
    .await;

    assert_eq!(waiting.status, "running");
}

/// Tess approved Lee's request before the workflow ran. The reminder step
/// sends nothing and ends at once, saying the request was approved.
#[tokio::test]
async fn a_reminder_for_a_decided_request_ends_at_once() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited(&world, ("pat", "Pat Runner"), MANAGES_GROUPS).await;
    let mut lee = invited(&world, ("lee", "Lee Lost"), &[("Workflows", "View")]).await;
    let bea = invited(&world, ("bea", "Bea Approver"), &[("Workflows", "View")]).await;
    let request_id = lee_asks_for_support(&world, &mut lee).await;
    policies::approve_request(world.tenant(), &request_id)
        .send(world.admin().client())
        .await
        .ok();
    let execution_id = start_graph(&world, &mut pat, reminding(bea.email(), &request_id)).await;
    let finished = ended(&world, &execution_id, "succeeded").await;
    check_reminder_finished(&world, &bea, &finished).await;
}

/// An already approved request ends the reminder step without adding a reminder to Bea's inbox.
async fn check_reminder_finished(world: &World<'_>, bea: &Person, finished: &Execution) {
    let ended_as = finished.steps[0]
        .output
        .as_ref()
        .and_then(|output| output["ended"].as_str().map(str::to_owned));
    assert_eq!(ended_as.as_deref(), Some("approved"));
    let inbox = notifications::inbox(world.tenant())
        .send(bea.client())
        .await
        .ok();
    assert!(
        !inbox
            .items
            .iter()
            .any(|notice| notice.title == REMINDER_TITLE),
        "nobody was reminded"
    );
}
