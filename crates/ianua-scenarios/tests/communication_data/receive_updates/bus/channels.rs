//! Two agents' only way to pass data: a channel a person opens. Ann's
//! agents Reporter and Helper may share Reporter's tasks once Tess opens a
//! channel between them. She closes it and it stays closed. A channel
//! that names one agent twice, or topics outside the sender's own area,
//! is refused, and nobody without a say over the sender opens or closes
//! one.

use ianua_scenarios::agent::external::ExternalAgent;
use ianua_scenarios::api::messaging;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::agents::messaging::area_topic;
use ianua_scenarios::wire::messaging::NewChannel;
use ianua_scenarios::world::World;

use crate::bus::refused_to_the_cast;
use crate::support::person;

/// How long the channels here stay open, in seconds: an hour.
const AN_HOUR: u32 = 3600;

/// The record an opened channel leaves.
const OPENED: &str = "messaging.channel_opened";

/// The record a closed channel leaves.
const CLOSED: &str = "messaging.channel_closed";

/// Ann's two agents, made with their own keys.
struct Agents {
    reporter: ExternalAgent,
    helper: ExternalAgent,
}

/// Ann makes Reporter and Helper.
async fn agents(stack: &Stack, world: &World<'_>) -> Agents {
    let owner = world.owner().client();
    Agents {
        reporter: ExternalAgent::enrolled(stack, world.tenant(), owner, "Reporter").await,
        helper: ExternalAgent::enrolled(stack, world.tenant(), owner, "Helper").await,
    }
}

/// A channel letting Helper read Reporter's tasks for an hour.
fn tasks_channel(agents: &Agents) -> NewChannel {
    NewChannel {
        sender_agent_id: agents.reporter.id().to_owned(),
        receiver_agent_id: agents.helper.id().to_owned(),
        topics: Some(area_topic(agents.reporter.id(), "tasks")),
        resource: None,
        max_class: "Internal".to_owned(),
        lifetime_seconds: AN_HOUR,
    }
}

/// Tess opens a channel letting Helper read Reporter's tasks, on record,
/// and finds it open in the tenant's list. She closes it, on record: the
/// list shows it closed, with when, and it cannot be closed twice.
#[tokio::test]
async fn tess_opens_a_channel_between_two_agents_and_closes_it() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let agents = agents(&stack, &world).await;
    let seen = world.trail().ids().await;

    let channel = messaging::open_channel(world.tenant(), &tasks_channel(&agents))
        .send(tess)
        .await
        .ok();
    assert_eq!(channel.sender_agent_id, agents.reporter.id());
    assert_eq!(channel.receiver_agent_id, agents.helper.id());
    assert_eq!(channel.scope_kind, "topics");
    assert_eq!(channel.scope, area_topic(agents.reporter.id(), "tasks"));
    assert!(channel.open, "a new channel carries messages");
    world.trail().recorded_after(&seen, OPENED).await;
    let listed = messaging::channels(world.tenant()).send(tess).await.ok();
    assert!(
        listed
            .items
            .iter()
            .any(|one| one.id == channel.id && one.open),
        "the tenant's list shows it open"
    );

    messaging::close_channel(world.tenant(), &channel.id)
        .send(tess)
        .await
        .ok();
    world.trail().recorded_after(&seen, CLOSED).await;
    let listed = messaging::channels(world.tenant()).send(tess).await.ok();
    let closed = listed
        .items
        .iter()
        .find(|one| one.id == channel.id)
        .expect("a closed channel stays on record");
    assert!(!closed.open, "a closed channel carries nothing");
    assert!(closed.closed_at.is_some(), "the list says when it closed");
    messaging::close_channel(world.tenant(), &channel.id)
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    stack.stop().await.expect("the stack stops cleanly");
}

/// A channel is between two different agents, over the sender's own area,
/// for a real while. Tess is refused a channel from Reporter to Reporter,
/// one over Helper's tasks, one naming both topics and a resource, one
/// naming neither, one for thirty seconds, and one from an agent that does
/// not exist. Nothing is opened.
#[tokio::test]
async fn a_channel_must_join_two_agents_over_the_senders_own_area() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let agents = agents(&stack, &world).await;
    let seen = world.trail().ids().await;

    let to_itself = NewChannel {
        receiver_agent_id: agents.reporter.id().to_owned(),
        ..tasks_channel(&agents)
    };
    let outside_its_area = NewChannel {
        topics: Some(area_topic(agents.helper.id(), "tasks")),
        ..tasks_channel(&agents)
    };
    let both_kinds = NewChannel {
        resource: Some("doc:42".to_owned()),
        ..tasks_channel(&agents)
    };
    let neither_kind = NewChannel {
        topics: None,
        ..tasks_channel(&agents)
    };
    let too_short = NewChannel {
        lifetime_seconds: 30,
        ..tasks_channel(&agents)
    };
    for refused in [
        to_itself,
        outside_its_area,
        both_kinds,
        neither_kind,
        too_short,
    ] {
        messaging::open_channel(world.tenant(), &refused)
            .send(tess)
            .await
            .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    }

    let no_such_agent = NewChannel {
        sender_agent_id: uuid::Uuid::now_v7().to_string(),
        ..tasks_channel(&agents)
    };
    messaging::open_channel(world.tenant(), &no_such_agent)
        .send(tess)
        .await
        .refused(Status::NOT_FOUND, "not_found");

    world.trail().nothing_after(&seen, OPENED).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Uma, an ordinary user of the tenant, and Max, a member with no
/// administrator's rights, have no say over Reporter: to them the sender
/// and its channel do not exist. Sam, from the other company, and nobody
/// signed in are refused outright. None of them lists the channels, and
/// the channel stays open, nothing further on record.
#[tokio::test]
async fn nobody_without_a_say_over_the_sender_touches_its_channels() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let uma = person(&world, "uma").await;
    let agents = agents(&stack, &world).await;
    let channel = messaging::open_channel(world.tenant(), &tasks_channel(&agents))
        .send(tess)
        .await
        .ok();
    let seen = world.trail().ids().await;

    for call in [
        messaging::open_channel(world.tenant(), &tasks_channel(&agents)).call(),
        messaging::close_channel(world.tenant(), &channel.id).call(),
    ] {
        Matrix::new("changing a channel of Reporter's", call)
            .refused(uma.client(), Status::NOT_FOUND, "not_found")
            .refused(world.member().client(), Status::NOT_FOUND, "not_found")
            .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
            .refused(
                world.anonymous().client(),
                Status::UNAUTHORIZED,
                "unauthenticated",
            )
            .run()
            .await;
    }
    refused_to_the_cast(
        &world,
        &uma,
        "listing the channels",
        messaging::channels(world.tenant()).call(),
    )
    .await;

    let listed = messaging::channels(world.tenant()).send(tess).await.ok();
    assert!(
        listed
            .items
            .iter()
            .any(|one| one.id == channel.id && one.open),
        "the channel stays open"
    );
    world.trail().nothing_after(&seen, CLOSED).await;

    stack.stop().await.expect("the stack stops cleanly");
}
