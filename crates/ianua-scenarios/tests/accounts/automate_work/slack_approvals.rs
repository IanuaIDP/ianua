//! Approvals that also ask in Slack: Ann's approval step posts its
//! question to the finance channel through the team's Slack account, with
//! Approve and Deny buttons that only open the approval in the dashboard.
//! Slack carries the question, never the answer: deciding in the platform
//! decides it, and a stand-in for Slack shows each question asked once.
//! A loop asks Slack again for each pass's own approval, and once, before
//! any pass, for one approval of every item.

use ianua_scenarios::api::workflows;
use ianua_scenarios::expect::eventually;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, CannedApp, Received};
use ianua_scenarios::wire::workflows::{
    Approve, Edge, Graph, Node, PassRun, SlackAsk, Step, Trigger,
};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::service::Service;
use crate::support::{
    APPROVAL_STEP, DELIVERY_STEP, LOOP_STEP, account_at, connected_account, delivery_graph,
    drafted, ended, published, run, started, started_with,
};

/// The bot token the team's Slack account holds: a sentence, so no
/// scanner takes it for a key.
const TOKEN: &str = "acme slack bot token for approvals";

/// Where Slack takes a new message.
const POST_MESSAGE: &str = "/chat.postMessage";

/// Where Slack says whether a token is live.
const AUTH_TEST: &str = "/auth.test";

/// The channel the questions are asked in.
const CHANNEL: &str = "C0FINANCE";

/// What the approval asks.
const SUMMARY: &str = "Approve this external delivery";

/// How long an approval may wait: two minutes, longer than any scenario
/// takes to decide it.
const WINDOW_SECONDS: u32 = 120;

/// The accounts a workflow here acts through: the outside service's and
/// the team's Slack account.
struct Accounts {
    service: String,
    slack: String,
}

/// A Slack stand-in taking the bot's token and every post.
async fn slack() -> CannedApp {
    CannedApp::start([
        (AUTH_TEST, Canned::json(&json!({ "ok": true }))),
        (
            POST_MESSAGE,
            Canned::json(&json!({ "ok": true, "ts": "1700000000.2" })),
        ),
    ])
    .await
    .expect("the Slack stand-in starts")
}

/// Tess connects the outside service and the team's Slack account.
async fn accounts(world: &World<'_>, service: &Service) -> Accounts {
    Accounts {
        service: connected_account(world, service).await,
        slack: account_at(world, "slack", TOKEN).await,
    }
}

/// The approval step keyed [`APPROVAL_STEP`], also asking in the finance
/// channel through `slack_account`; `covers` says whether it asks once for
/// a whole loop.
fn asking_in_slack(slack_account: &str, covers: Option<&str>) -> Node {
    Node {
        key: APPROVAL_STEP.to_owned(),
        name: "Approve delivery".to_owned(),
        step: Step::SlackApproval {
            summary: SUMMARY.to_owned(),
            action_class: "read".to_owned(),
            window_seconds: WINDOW_SECONDS,
            slack: SlackAsk {
                account_id: slack_account.to_owned(),
                channel: CHANNEL.to_owned(),
            },
            covers: covers.map(str::to_owned),
        },
    }
}

/// The delivery, held until the approval that also asks in Slack is
/// given; `covers` as [`asking_in_slack`] takes it.
fn approved_in_slack(service: &Service, accounts: &Accounts, covers: Option<&str>) -> Graph {
    let mut nodes = vec![asking_in_slack(&accounts.slack, covers)];
    nodes.extend(delivery_graph(service, &accounts.service).nodes);
    Graph {
        nodes,
        edges: vec![Edge {
            from: APPROVAL_STEP.to_owned(),
            to: DELIVERY_STEP.to_owned(),
        }],
    }
}

/// A loop over the trigger's issues, one at a time, running `body` for
/// each.
fn each_issue(body: Graph) -> Graph {
    Graph {
        nodes: vec![Node {
            key: LOOP_STEP.to_owned(),
            name: "Each issue".to_owned(),
            step: Step::Loop {
                over: "trigger.issues".to_owned(),
                steps: body,
                most_items: 10,
                at_once: 2,
            },
        }],
        edges: vec![],
    }
}

/// The questions Slack received, once `count` of them arrived.
async fn questions(slack: &CannedApp, count: usize) -> Vec<Received> {
    eventually("Slack to be asked", || async {
        let asked: Vec<_> = slack
            .received()
            .into_iter()
            .filter(|call| call.path == POST_MESSAGE)
            .collect();
        (asked.len() >= count).then_some(asked)
    })
    .await
}

/// The question names the channel and the summary, comes with the bot's
/// token, and its buttons open the approval of `execution_id`'s step in
/// the dashboard, one to approve and one to deny.
fn check_question(question: &Received, execution_id: &str) {
    let body = question.json();
    assert_eq!(body["channel"], CHANNEL);
    assert_eq!(body["text"], format!("Approval asked: {SUMMARY}"));
    assert_eq!(
        question.header("authorization"),
        Some(format!("Bearer {TOKEN}").as_str())
    );
    let page = format!("/workflows/runs/{execution_id}/approvals/{APPROVAL_STEP}");
    let buttons = body["blocks"].to_string();
    assert!(
        buttons.contains(&format!("{page}?decision=approve")),
        "{buttons}"
    );
    assert!(
        buttons.contains(&format!("{page}?decision=deny")),
        "{buttons}"
    );
}

/// Ann approves exactly what the approval of `execution_id` shows her, in
/// the platform.
async fn ann_approves(world: &World<'_>, execution_id: &str) {
    let shown = workflows::approval(world.tenant(), execution_id, APPROVAL_STEP)
        .send(world.owner().client())
        .await
        .ok();
    let approval = Approve {
        shown: shown.shown,
        mfa_code: None,
    };
    workflows::approve(world.tenant(), execution_id, APPROVAL_STEP, &approval)
        .send(world.owner().client())
        .await
        .ok();
}

/// Ann's delivery waits for an approval that also asks in the finance
/// channel. Tess starts it: Slack is asked once, with the bot's token,
/// the summary and buttons opening this run's approval, and nothing is
/// delivered. Ann approves in the platform: the run succeeds, the service
/// is called once, and Slack was asked nothing more.
#[tokio::test]
async fn an_approval_asks_in_slack_once_and_is_decided_in_the_platform() {
    let slack = slack().await;
    let service = Service::start().await;
    let stack = Stack::start(Profile::standard().with("SLACK_API_URL", &slack.url()))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let accounts = accounts(&world, &service).await;
    let graph = approved_in_slack(&service, &accounts, None);
    let workflow = published(&world, &drafted(&world, Trigger::Manual, graph).await).await;

    let execution_id = started(&world, &workflow).await.execution_id;
    let asked = questions(&slack, 1).await;
    assert_eq!(service.calls(), 0, "nothing is delivered before the yes");
    ann_approves(&world, &execution_id).await;
    ended(&world, &execution_id, "succeeded").await;

    check_question(&asked[0], &execution_id);
    assert_eq!(service.delivered(), 1, "the yes released one delivery");
    assert_eq!(slack.asked_for(POST_MESSAGE), 1, "Slack was asked once");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess loops over two refunds, each pass waiting for an approval that
/// also asks in Slack. Each pass asks Slack its own question, naming its
/// own run. Ann approves each pass in the platform: both refunds are
/// delivered, the loop succeeds, and Slack was asked exactly twice.
#[tokio::test]
async fn each_pass_of_a_loop_asks_slack_its_own_question() {
    let slack = slack().await;
    let service = Service::start().await;
    let stack = Stack::start(Profile::standard().with("SLACK_API_URL", &slack.url()))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let accounts = accounts(&world, &service).await;
    let graph = each_issue(approved_in_slack(&service, &accounts, None));
    let workflow = published(&world, &drafted(&world, Trigger::Manual, graph).await).await;
    let input = json!({"issues": ["refund order 1", "refund order 2"]});

    let execution_id = started_with(&world, &workflow, input).await.execution_id;
    let held = passes_held(&world, &execution_id).await;
    let asked = questions(&slack, 2).await;
    for pass in &held {
        ann_approves(&world, &pass.id).await;
    }
    ended(&world, &execution_id, "succeeded").await;

    check_each_pass_asked(&asked, &held);
    assert_eq!(service.delivered(), 2, "each approved pass delivered once");
    assert_eq!(slack.asked_for(POST_MESSAGE), 2, "one question per pass");
    stack.stop().await.expect("the stack stops cleanly");
}

/// The two passes of the run `execution_id`, once both wait at their
/// approval.
async fn passes_held(world: &World<'_>, execution_id: &str) -> Vec<PassRun> {
    eventually("both passes to wait for their approval", || async {
        let passes = workflows::passes(world.tenant(), execution_id)
            .send(world.admin().client())
            .await
            .ok()
            .items;
        if passes.len() != 2 {
            return None;
        }
        for pass in &passes {
            let waiting = run(world, &pass.id)
                .await
                .steps
                .iter()
                .any(|step| step.key == APPROVAL_STEP && step.phase == "running");
            if !waiting {
                return None;
            }
        }
        Some(passes)
    })
    .await
}

/// Every pass in `held` was asked about in one of `asked`, under its own
/// run.
fn check_each_pass_asked(asked: &[Received], held: &[PassRun]) {
    for pass in held {
        let question = asked
            .iter()
            .find(|question| question.body.contains(&pass.id))
            .expect("Slack was asked about every pass");
        check_question(question, &pass.id);
    }
}

/// Tess loops over three refunds, its first step asking one approval for
/// every item, also in Slack. Slack is asked once, about the loop itself,
/// and no pass starts. Ann denies it in the platform: the run fails,
/// nothing is delivered, and Slack was asked nothing more.
#[tokio::test]
async fn one_approval_of_every_item_asks_slack_once_before_any_pass() {
    let slack = slack().await;
    let service = Service::start().await;
    let stack = Stack::start(Profile::standard().with("SLACK_API_URL", &slack.url()))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let accounts = accounts(&world, &service).await;
    let graph = each_issue(approved_in_slack(&service, &accounts, Some("whole_loop")));
    let workflow = published(&world, &drafted(&world, Trigger::Manual, graph).await).await;
    let input = json!({"issues": ["refund 1", "refund 2", "refund 3"]});

    let execution_id = started_with(&world, &workflow, input).await.execution_id;
    let asked = questions(&slack, 1).await;
    let passes = workflows::passes(world.tenant(), &execution_id)
        .send(world.admin().client())
        .await
        .ok();
    workflows::deny(world.tenant(), &execution_id, LOOP_STEP)
        .send(world.owner().client())
        .await
        .ok();
    ended(&world, &execution_id, "failed").await;

    assert!(passes.items.is_empty(), "no pass starts before the yes");
    check_loop_question(&asked[0], &execution_id);
    assert_eq!(service.calls(), 0, "nothing was delivered");
    assert_eq!(slack.asked_for(POST_MESSAGE), 1, "Slack was asked once");
    stack.stop().await.expect("the stack stops cleanly");
}

/// The loop's question names the summary and opens the approval of the
/// loop step of `execution_id`.
fn check_loop_question(question: &Received, execution_id: &str) {
    let body = question.json();
    assert_eq!(body["channel"], CHANNEL);
    assert_eq!(body["text"], format!("Approval asked: {SUMMARY}"));
    let page = format!("/workflows/runs/{execution_id}/approvals/{LOOP_STEP}?decision=approve");
    assert!(body["blocks"].to_string().contains(&page), "{body}");
}
