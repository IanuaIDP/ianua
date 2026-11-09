//! What keeps a stream to whoever it belongs to: nobody without the right
//! reads or changes it, Mallory's keys and made-up challenges are refused,
//! and an endpoint inside the deployment cannot be registered.

use ianua_scenarios::api::signals;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::signals::{
    AskVerification, ConfirmEndpoint, NewStream, PollAsk, StreamChange, StreamSubject,
};
use ianua_scenarios::world::World;

use crate::support::{ENDPOINT, holding_key, published, register, stream};

/// Max, an ordinary user of the tenant, Sam, from the other company, and
/// nobody signed in cannot read or change a stream or its history; for a
/// receiver's own calls, Max and Sam are refused and the anonymous visitor
/// asked to sign in. Nothing changed: the stream still runs.
#[tokio::test]
async fn nobody_without_the_right_reads_or_changes_a_stream() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let tenant = world.tenant();
    let receiver = register(&world, &stream("Poll", "ALL"), "Acme's receiver").await;
    let id = receiver.id.as_str();
    let trail_before = world.trail().ids().await;
    let moved = StreamChange {
        endpoint: Some(ENDPOINT.to_owned()),
    };
    let asked = AskVerification {
        state: "maloryprobe".to_owned(),
    };
    let subject = StreamSubject::user("00000000-0000-4000-8000-000000000002");
    let poll = PollAsk::default();

    for (what, call) in [
        ("listing streams", signals::list(tenant).call()),
        ("reading a stream", signals::get(tenant, id).call()),
        ("reading its status", signals::status(tenant, id).call()),
        (
            "reading its history",
            signals::deliveries(tenant, id).call(),
        ),
        (
            "registering a stream",
            signals::register(tenant, &stream("Poll", "ALL")).call(),
        ),
        (
            "changing a stream",
            signals::change(tenant, id, &moved).call(),
        ),
        ("pausing a stream", signals::pause(tenant, id).call()),
        ("resuming a stream", signals::resume(tenant, id).call()),
        ("disabling a stream", signals::disable(tenant, id).call()),
        ("deleting a stream", signals::delete(tenant, id).call()),
        ("polling a stream", signals::poll(tenant, id, &poll).call()),
        (
            "asking for verification",
            signals::verify(tenant, id, &asked).call(),
        ),
        (
            "adding a subject",
            signals::add_subject(tenant, id, &subject).call(),
        ),
        (
            "removing a subject",
            signals::remove_subject(tenant, id, &subject).call(),
        ),
    ] {
        Matrix::new(what, call)
            .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
            .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
            .refused(
                world.anonymous().client(),
                Status::UNAUTHORIZED,
                "unauthenticated",
            )
            .run()
            .await;
    }

    let shown = signals::get(tenant, id).send(tess).await.ok();
    assert_eq!(shown.status, "Active", "the stream still runs");
    world
        .trail()
        .nothing_after(&trail_before, "signals.stream_paused")
        .await;
    world
        .trail()
        .nothing_after(&trail_before, "signals.stream_deleted")
        .await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Mallory presents a key she made up, and another stream's real key, and
/// is refused with no event handed over, each told only that it does not
/// count. A challenge she made up does not prove the
/// endpoint, and on a stream that does not exist it reads as if she were
/// never known. A push stream is polled by nobody. The transmitter's
/// configuration is public; the deliveries are not.
#[tokio::test]
async fn mallorys_keys_and_guesses_are_refused() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let tenant = world.tenant();
    let receiver = register(&world, &stream("Poll", "ALL"), "Acme's receiver").await;
    let id = receiver.id.as_str();
    let other = register(&world, &stream("Poll", "ALL"), "Mallory's own stream").await;
    let poll = PollAsk::default();

    let made_up = holding_key(&world, "Mallory", "not any stream's key at all");
    signals::poll(tenant, id, &poll)
        .send(&made_up)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    signals::poll(tenant, id, &poll)
        .send(&other.client)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    let anonymous = world.anonymous().client();
    let guess = ConfirmEndpoint {
        challenge: uuid::Uuid::new_v4().simple().to_string(),
    };
    signals::confirm(tenant, id, &guess)
        .send(anonymous)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let shown = signals::get(tenant, id).send(tess).await.ok();
    assert_eq!(
        shown.verification, "Pending",
        "a made-up challenge proves nothing"
    );
    signals::confirm(tenant, "00000000-0000-4000-8000-000000000003", &guess)
        .send(anonymous)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    let pushed = register(&world, &stream("Push", "ALL"), "Acme's pushed receiver").await;
    signals::poll(tenant, &pushed.id, &poll)
        .send(&pushed.client)
        .await
        .refused(Status::CONFLICT, "conflict");

    let (configuration, _) = published(&world).await;
    assert!(
        !configuration.jwks_uri.is_empty(),
        "anyone may read the transmitter's configuration"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Mallory, an administrator who should know better, registers a receiver
/// on the deployment's loopback, an internal range, the cloud metadata
/// address, plain HTTP or a name only an inside resolver answers, and
/// moves a stream to one of them: each is refused and the stream keeps
/// its address. A stream without any signal type is refused too.
#[tokio::test]
async fn an_endpoint_inside_the_deployment_is_refused() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let tenant = world.tenant();
    let existing = register(&world, &stream("Poll", "ALL"), "Acme's receiver").await;
    let trail_before = world.trail().ids().await;
    let inside = [
        "https://127.0.0.1/events",
        "https://localhost/events",
        "https://10.1.2.3/events",
        "https://169.254.169.254/latest/meta-data/",
        "http://signals.acme.invalid/events",
        "https://signals",
        "https://signals.acme.internal/events",
    ];

    for address in inside {
        let mut to_register: NewStream = stream("Poll", "ALL");
        to_register.endpoint = address.to_owned();
        signals::register(tenant, &to_register)
            .send(tess)
            .await
            .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
        let moved = StreamChange {
            endpoint: Some(address.to_owned()),
        };
        signals::change(tenant, &existing.id, &moved)
            .send(tess)
            .await
            .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    }
    let mut nothing_to_hear = stream("Poll", "ALL");
    nothing_to_hear.signal_types.clear();
    signals::register(tenant, &nothing_to_hear)
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    let shown = signals::get(tenant, &existing.id).send(tess).await.ok();
    assert_eq!(shown.endpoint, ENDPOINT, "the stream kept its endpoint");
    assert_eq!(shown.verification, "Pending", "and did not start over");
    world
        .trail()
        .nothing_after(&trail_before, "signals.stream_registered")
        .await;

    stack.stop().await.expect("the stack stops cleanly");
}
