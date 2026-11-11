//! Watching workflows live, over the WebSocket the builder opens. A run's
//! stream lights each step up as it is approved, starts and succeeds, then
//! says how the run ended, naming steps and never what they handled. A
//! draft's stream tells whoever has it open that someone changed it. Only
//! someone who may view workflows opens either.

use std::time::Duration;

use ianua_scenarios::api::workflows;
use ianua_scenarios::expect::eventually;
use ianua_scenarios::net::{Frame, Socket};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::workflows::{Approve, DraftEdit, Trigger};
use ianua_scenarios::world::World;
use serde_json::Value;

use crate::service::{CREDENTIAL, Service};
use crate::support::{
    APPROVAL_STEP, DELIVERY_STEP, approved_delivery_graph, connected_account, delivery_graph,
    drafted, published, run, started,
};

/// How long a live frame is waited for: the worker records the moment
/// first.
const PATIENCE: Duration = Duration::from_secs(45);

/// Tess's run waits for Ann's approval, and Tess opens its live stream;
/// Max cannot open it. Ann approves: from then on Tess's stream shows the
/// approval given and its step done, the delivery starting and
/// succeeding, then the run ending in success, in that order, and no frame
/// carries the service's credential.
#[tokio::test]
async fn tess_watches_her_run_light_up_step_by_step_and_max_may_not() {
    let service = Service::start().await;
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = connected_account(&world, &service).await;
    let graph = approved_delivery_graph(&service, &account);
    let workflow = published(&world, &drafted(&world, Trigger::Manual, graph).await).await;
    let execution_id = started(&world, &workflow).await.execution_id;
    held_at_the_approval(&world, &execution_id).await;
    let path = workflows::run_stream(world.tenant(), &execution_id);
    let mut stream = world.admin().client().open_socket(&path).await.open();
    world
        .member()
        .client()
        .open_socket(&path)
        .await
        .refusal()
        .refused(Status::FORBIDDEN, "forbidden");

    let shown = workflows::approval(world.tenant(), &execution_id, APPROVAL_STEP)
        .send(world.owner().client())
        .await
        .ok()
        .shown;
    let approval = Approve {
        shown,
        mfa_code: None,
    };
    workflows::approve(world.tenant(), &execution_id, APPROVAL_STEP, &approval)
        .send(world.owner().client())
        .await
        .ok();
    let (moments, texts) = moments_until_ended(&mut stream).await;
    stream.close().await;

    let approved = format!("step_approved {APPROVAL_STEP}");
    let from_approval = moments
        .iter()
        .position(|moment| *moment == approved)
        .map(|at| &moments[at..]);
    assert_eq!(
        from_approval,
        Some(
            &[
                approved.clone(),
                format!("step_succeeded {APPROVAL_STEP}"),
                format!("step_started {DELIVERY_STEP}"),
                format!("step_succeeded {DELIVERY_STEP}"),
                "ended succeeded".to_owned(),
            ][..]
        ),
        "{moments:?}"
    );
    assert!(
        texts.iter().all(|text| !text.contains(CREDENTIAL)),
        "no frame carries the credential"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess opens the live stream of her draft; Max cannot open it. She
/// replaces its steps, and her stream says the draft's steps were
/// replaced, naming the workflow.
#[tokio::test]
async fn whoever_has_a_draft_open_hears_that_its_steps_changed() {
    let service = Service::start().await;
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let account = connected_account(&world, &service).await;
    let draft = drafted(&world, Trigger::Manual, delivery_graph(&service, &account)).await;
    let path = workflows::draft_stream(world.tenant(), &draft.id);
    let mut stream = world.admin().client().open_socket(&path).await.open();
    world
        .member()
        .client()
        .open_socket(&path)
        .await
        .refusal()
        .refused(Status::FORBIDDEN, "forbidden");

    let edit = DraftEdit::ReplaceSteps {
        graph: approved_delivery_graph(&service, &account),
    };
    workflows::edit_draft(world.tenant(), &draft.id, &edit)
        .send(world.admin().client())
        .await
        .ok();
    let change = next_of(&mut stream, "draft_changed").await;
    stream.close().await;

    assert_eq!(change["workflow_id"], draft.id.as_str());
    assert_eq!(change["event_type"], "workflows.draft_steps_replaced");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Waits until the run `execution_id` is held at its approval step.
async fn held_at_the_approval(world: &World<'_>, execution_id: &str) {
    eventually("the run to wait for its approval", || async {
        let execution = run(world, execution_id).await;
        let held = execution
            .steps
            .iter()
            .any(|step| step.key == APPROVAL_STEP && step.phase == "running");
        (execution.status == "running" && held).then_some(())
    })
    .await;
}

/// The run moments `stream` gives until the run ends, each as what
/// happened and its step or end, with every text the stream sent.
async fn moments_until_ended(stream: &mut Socket) -> (Vec<String>, Vec<String>) {
    let mut moments = Vec::new();
    let mut texts = Vec::new();
    loop {
        let (moment, text) = next_text_of(stream, "run_moment").await;
        texts.push(text);
        let happened = moment["happened"].as_str().unwrap_or_default().to_owned();
        let about = moment["step"].as_str().or(moment["end"].as_str());
        moments.push(format!("{happened} {}", about.unwrap_or_default()));
        if happened == "ended" {
            return (moments, texts);
        }
    }
}

/// The body of the next frame of `kind` on `stream`, passing over others.
async fn next_of(stream: &mut Socket, kind: &str) -> Value {
    next_text_of(stream, kind).await.0
}

/// The body of the next frame of `kind` on `stream`, with its text.
///
/// # Panics
///
/// When the stream closes or stays quiet past [`PATIENCE`] first.
async fn next_text_of(stream: &mut Socket, kind: &str) -> (Value, String) {
    loop {
        let Some(Frame::Text(text)) = stream.next_within(PATIENCE).await else {
            panic!("the stream gave no {kind} frame");
        };
        let frame: Value = serde_json::from_str(&text).expect("a frame is JSON");
        if frame["msg_type"] == kind {
            return (frame["notification"].clone(), text);
        }
    }
}
