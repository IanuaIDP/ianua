//! An event written while it cannot go out: the bus is down when Ann's
//! change records it, and the worker relaying it is killed before the bus
//! comes back. The event waits in the outbox, nothing acts on it meanwhile,
//! and once the bus is back it is delivered from there; what it starts is
//! done once, and nothing is recorded that did not happen or recorded
//! twice, even when the platform restarts after it. An event the bus hands
//! out again after its job ended starts nothing more.

use std::time::Duration;

use ianua_scenarios::api::{people, workflows};
use ianua_scenarios::automation::{connected_account, delivery_graph, drafted, ended, published};
use ianua_scenarios::expect::{Trail, eventually};
use ianua_scenarios::stack::{Part, Profile, Stack};
use ianua_scenarios::upstreams::OutsideService;
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::wire::workflows::{ExecutionSummary, Trigger, Workflow};
use ianua_scenarios::world::{MEMBER_ROLE, World};

use crate::support::{
    STAGING, TENANT_CREATED, ann_in_staging, assert_made_once, assert_recorded_once, once_set_up,
    recorded_for, room_for_another_tenant, staging_made, still_provisioning, watched_for,
};

/// How long the platform is watched for work that must not start, on the
/// real clock: several of the relay's one-second passes.
const QUIET: Duration = Duration::from_secs(3);

/// The record that announces a new tenant, whose delivery starts its setup.
const PROVISIONED: &str = "tenant.provisioned";

/// The bus goes down and Ann makes `staging`: its creation is recorded
/// once, and its announcement waits. For a few seconds nothing sets it up.
/// The control plane is killed with the announcement still undelivered,
/// and starts again with the bus back. The announcement goes out from the
/// outbox and `staging` is set up: Ann signs in to it and finds its two
/// starting roles once each and one signing key. After another restart
/// the trail still holds one creation, one announcement, two seeded roles,
/// one key and one move into use, none written by the recovery itself.
#[tokio::test]
async fn an_event_held_while_the_bus_is_down_and_the_relay_killed_is_delivered_once() {
    let stack = Stack::start(Profile::standard().with_cuttable_parts())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    room_for_another_tenant(&world).await;
    let before = world.trail().count(TENANT_CREATED).await;

    stack.cut(Part::Bus);
    let staging = staging_made(&world).await;
    assert_eq!(
        world.trail().count(TENANT_CREATED).await,
        before + 1,
        "staging's creation is recorded while the bus is down"
    );
    watched_for(QUIET).await;
    still_provisioning(
        &world,
        &staging,
        "nothing set staging up while its announcement could not go out",
    )
    .await;

    stack
        .crash()
        .await
        .expect("the platform crashes and starts again");
    once_set_up(&world, &staging).await;
    stack.restart().await.expect("the platform restarts");
    watched_for(QUIET).await;

    let ann = ann_in_staging(&world).await;
    assert_made_once(&world.org().tenant(STAGING), &ann).await;
    assert_recorded_once(&world, ann.client(), &staging).await;
    assert_eq!(
        recorded_for(&world, ann.client(), &staging, PROVISIONED).await,
        1,
        "staging was announced once"
    );
    assert_eq!(
        Trail::of_organization(ann.client(), world.org().slug())
            .count(TENANT_CREATED)
            .await,
        before + 1,
        "one creation of staging is recorded"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// The record an invitation into the tenant leaves, which Ann's workflow
/// starts on.
const USER_INVITED: &str = "identity.user_invited";

/// The record a run started leaves.
const EXECUTION_STARTED: &str = "workflows.execution_started";

/// Ann's workflow starts on an invitation. Tess invites Uma: one run
/// starts, reaches the outside service once and ends. The bus hands the
/// same event out again, with its own seal, as it does past its duplicate
/// window or when an acknowledgement was lost. For seconds afterwards no
/// second run starts, the service is not called again and no second start
/// is recorded.
#[tokio::test]
async fn an_event_delivered_again_after_its_job_ended_starts_nothing_more() {
    let service = OutsideService::start().await;
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let workflow = on_invitation(&world, &service).await;

    invite_uma(&world).await;
    let run = first_run(&world, &workflow).await;
    ended(&world, world.admin().client(), &run.id, "succeeded").await;
    assert_eq!(service.delivered(), 1, "the run called the service once");

    assert_eq!(
        stack.deliver_again(USER_INVITED).await,
        1,
        "Uma's invitation went out again, the only one on the bus"
    );
    watched_for(QUIET).await;

    assert_eq!(
        runs_of(&world, &workflow).await.len(),
        1,
        "an event delivered again starts no second run"
    );
    assert_eq!(service.delivered(), 1, "the service was not called again");
    assert_eq!(
        world.trail().count(EXECUTION_STARTED).await,
        1,
        "one start is recorded"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess drafts a workflow delivering to `service`, started on an
/// invitation into the tenant, and Ann publishes it.
async fn on_invitation(world: &World<'_>, service: &OutsideService) -> Workflow {
    let account = connected_account(world, service).await;
    let trigger = Trigger::Event {
        event: USER_INVITED.to_owned(),
    };
    let draft = drafted(world, trigger, delivery_graph(service, &account)).await;
    published(world, &draft).await
}

/// Tess invites Uma into the tenant with its `Member` role.
async fn invite_uma(world: &World<'_>) {
    let invitation = InviteUser {
        email: world.address("uma"),
        display_name: "Uma Invited".to_owned(),
        role_id: world.role_id(MEMBER_ROLE).await,
    };
    people::invite(world.tenant(), &invitation)
        .send(world.admin().client())
        .await
        .ok();
}

/// The runs of `workflow`, as Tess reads them.
async fn runs_of(world: &World<'_>, workflow: &Workflow) -> Vec<ExecutionSummary> {
    workflows::executions(world.tenant(), &workflow.id)
        .send(world.admin().client())
        .await
        .ok()
        .items
}

/// The first run of `workflow`, once the event started one.
async fn first_run(world: &World<'_>, workflow: &Workflow) -> ExecutionSummary {
    eventually("the invitation to start a run", || async {
        runs_of(world, workflow).await.into_iter().next()
    })
    .await
}
