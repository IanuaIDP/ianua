//! A stream starting with nobody, told about the people added to it, by
//! its receiver or a person of the tenant.

use ianua_scenarios::api::signals;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::signals::{OpaqueSubject, PollAsk, StreamSubject};
use ianua_scenarios::world::World;

use crate::support::{
    EventSource, TOKEN_CLAIMS_CHANGE, awaited, checked, give_role, person, prove_endpoint,
    published, reading_role, register, stream,
};

/// A stream starting with nobody, its endpoint proved. Tess gives Uma a
/// role, then the receiver adds Pat by its key and Tess gives Pat a role:
/// the receiver hears about Pat and nothing about Uma, whom it never
/// asked about. Uma is added as a person of the tenant, and the next role
/// given to her is heard. The receiver takes Pat out; the trail notes
/// each subject added and removed, and subjects that do not exist or are
/// not named as opaque ids are refused.
#[tokio::test]
async fn a_stream_starting_with_nobody_hears_only_of_those_added() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let tenant = world.tenant();
    let (_, keys) = published(&world).await;
    let pat = person(&world, "pat").await;
    let uma = person(&world, "uma").await;
    let receiver = register(&world, &stream("Poll", "NONE"), "Acme's receiver").await;
    prove_endpoint(&world, &receiver, &keys).await;
    let id = receiver.id.as_str();
    let trail_before = world.trail().ids().await;
    let first_role = reading_role(&world, "Signalled First").await;
    let second_role = reading_role(&world, "Signalled Second").await;

    give_role(&world, &uma, &first_role).await;
    signals::add_subject(tenant, id, &StreamSubject::user(pat.id()))
        .send(&receiver.client)
        .await
        .ok();
    give_role(&world, &pat, &second_role).await;
    let pat_id = pat.id().to_owned();
    let about_pat = |event: &serde_json::Value| event["subject"]["id"] == pat_id.as_str();
    let source = EventSource {
        tenant,
        receiver: &receiver,
        keys: &keys,
    };
    let (jti, _, _) = awaited(&source, TOKEN_CLAIMS_CHANGE, about_pat).await;

    let polled = signals::poll(tenant, id, &PollAsk::default())
        .send(&receiver.client)
        .await
        .ok();
    let uma_id = uma.id();
    let heard_of_uma = polled.sets.values().any(|token| {
        checked(&keys, token)["events"][TOKEN_CLAIMS_CHANGE]["subject"]["id"] == uma_id
    });
    assert!(
        !heard_of_uma,
        "the stream hears nothing of Uma, whom it never asked about"
    );
    signals::poll(
        tenant,
        id,
        &PollAsk {
            ack: vec![jti],
            max_events: None,
        },
    )
    .send(&receiver.client)
    .await
    .ok();

    signals::add_subject(tenant, id, &StreamSubject::user(uma.id()))
        .send(tess)
        .await
        .ok();
    give_role(&world, &uma, &second_role).await;
    let uma_id = uma.id().to_owned();
    let about_uma = |event: &serde_json::Value| event["subject"]["id"] == uma_id.as_str();
    awaited(&source, TOKEN_CLAIMS_CHANGE, about_uma).await;

    signals::remove_subject(tenant, id, &StreamSubject::user(pat.id()))
        .send(&receiver.client)
        .await
        .ok();

    let unknown = StreamSubject::user("00000000-0000-4000-8000-000000000001");
    signals::add_subject(tenant, id, &unknown)
        .send(&receiver.client)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    let mut not_opaque = StreamSubject::user(pat.id());
    not_opaque.subject = OpaqueSubject {
        format: "email".to_owned(),
        id: pat.id().to_owned(),
    };
    signals::add_subject(tenant, id, &not_opaque)
        .send(&receiver.client)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    let trail = world.trail();
    trail
        .recorded_after(&trail_before, "signals.subject_added")
        .await;
    trail
        .recorded_after(&trail_before, "signals.subject_removed")
        .await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// A person of another company cannot name someone in this tenant as a
/// subject of its stream: Sam, holding his own tenant, is forbidden; and
/// nobody signed in is asked to sign in.
#[tokio::test]
async fn nobody_outside_the_tenant_changes_a_stream_s_subjects() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tenant = world.tenant();
    let (_, keys) = published(&world).await;
    let pat = person(&world, "pat").await;
    let receiver = register(&world, &stream("Poll", "NONE"), "Acme's receiver").await;
    prove_endpoint(&world, &receiver, &keys).await;

    Matrix::new(
        "adding Pat as a subject",
        signals::add_subject(tenant, &receiver.id, &StreamSubject::user(pat.id())).call(),
    )
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;

    stack.stop().await.expect("the stack stops cleanly");
}
