//! Tess streaming the tenant's audit records to the collector Acme runs:
//! every change proved by her own password typed again, the collector's
//! credential sealed the moment it is typed and never read back, and a
//! collector that stops answering noted against the stream. Most scenarios
//! name a host nothing answers, under the reserved `.invalid` domain; one
//! reaches a stand-in for the real collector, to read what it gets.

use ianua_scenarios::api::{audit_streams, roles};
use ianua_scenarios::expect::{Matrix, eventually, no_secret_leaked};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, OutsideReceiver};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::audit_streams::{
    AuditStream, AuditStreamCreated, AuditStreamSetup, StreamProof,
};
use ianua_scenarios::wire::roles::{NewRole, SystemPermission};
use ianua_scenarios::world::World;
use serde_json::{Value, json};

/// The collector's address: public-looking, and answered by nothing.
const COLLECTOR: &str = "https://collector.acme.invalid/events";

/// What the collector's own token reads as: a plain sentence, so nothing
/// takes it for a real key, made fresh for each scenario.
fn credential() -> String {
    format!("acme collector words {}", uuid::Uuid::new_v4().simple())
}

/// A stream of every record to `destination`, proved by `password`.
fn setup(destination: Value, password: &str) -> AuditStreamSetup {
    AuditStreamSetup {
        name: "Acme's collector".to_owned(),
        destination,
        events: None,
        proof: StreamProof {
            password: password.to_owned(),
        },
    }
}

/// The HTTPS destination `endpoint`, carrying `credential` in its
/// `authorization` header.
fn http_destination(endpoint: &str, credential: &str) -> Value {
    json!({
        "kind": "http",
        "endpoint": endpoint,
        "header": {"name": "authorization", "value": credential},
    })
}

/// The stream Tess adds to Acme's collector, proved with her password.
async fn added(world: &World<'_>, credential: &str) -> AuditStreamCreated {
    audit_streams::create(
        world.tenant(),
        &setup(
            http_destination(COLLECTOR, credential),
            world.admin().password(),
        ),
    )
    .send(world.admin().client())
    .await
    .ok()
}

/// The stream `id` as Tess reads it among the tenant's streams, once it
/// is there.
fn stream_named(streams: Vec<AuditStream>, id: &str) -> Option<AuditStream> {
    streams.into_iter().find(|stream| stream.id == id)
}

/// Tess adds a stream to the collector, narrowed to role events, with
/// the collector's credential. Reading it back shows the kind of
/// destination, the address and the header's name, and never its value;
/// the record of the change does not name it either. She changes it to a
/// Splunk collector and then Datadog, and neither token is ever shown.
/// She pauses it, which it can only be once, resumes it, which it also can
/// only be once, removes it, and it is gone. Every step is on the trail.
#[tokio::test]
async fn tess_sets_up_a_stream_without_ever_reading_its_credential_back() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let tenant = world.tenant();
    let password = world.admin().password();
    let header_value = credential();
    let trail_before = world.trail().ids().await;

    let mut narrowed = setup(http_destination(COLLECTOR, &header_value), password);
    narrowed.events = Some(vec!["authorization.role_created".to_owned()]);
    let created = audit_streams::create(tenant, &narrowed)
        .send(tess)
        .await
        .ok();

    let listed = tess
        .send_text(audit_streams::list(tenant).call())
        .await
        .ok();
    no_secret_leaked(&listed, &[&header_value]);
    let streams = audit_streams::list(tenant).send(tess).await.ok();
    let stream = stream_named(streams, &created.id).expect("the stream is listed");
    assert_eq!(stream.name, "Acme's collector", "its name is read back");
    assert_eq!(stream.destination.kind, "http", "where it goes, by kind");
    assert_eq!(
        stream.destination.endpoint.as_deref(),
        Some(COLLECTOR),
        "the collector's address is read back"
    );
    assert_eq!(
        stream.destination.header_name.as_deref(),
        Some("authorization"),
        "the header goes by its name only"
    );
    assert_eq!(
        stream.events,
        Some(vec!["authorization.role_created".to_owned()]),
        "narrowed to role events"
    );
    assert_eq!(stream.state, "active", "a new stream is active");
    let record = world
        .trail()
        .recorded_after(&trail_before, "tenant.audit_stream_created")
        .await;
    no_secret_leaked(&record.details.to_string(), &[&header_value]);

    let token = credential();
    let to_splunk = setup(
        json!({"kind": "splunk", "endpoint": COLLECTOR, "token": token, "index": "acme_audit"}),
        password,
    );
    audit_streams::reconfigure(tenant, &created.id, &to_splunk)
        .send(tess)
        .await
        .ok();
    let streams = audit_streams::list(tenant).send(tess).await.ok();
    let splunk = stream_named(streams, &created.id).expect("the stream is listed");
    assert_eq!(splunk.destination.kind, "splunk", "the destination changed");
    assert_eq!(
        splunk.destination.index.as_deref(),
        Some("acme_audit"),
        "its index is read back"
    );
    let read = tess
        .send_text(audit_streams::list(tenant).call())
        .await
        .ok();
    no_secret_leaked(&read, &[&token]);

    let api_key = credential();
    let to_datadog = setup(
        json!({"kind": "datadog", "site": "eu1", "api_key": api_key}),
        password,
    );
    audit_streams::reconfigure(tenant, &created.id, &to_datadog)
        .send(tess)
        .await
        .ok();
    let streams = audit_streams::list(tenant).send(tess).await.ok();
    let datadog = stream_named(streams, &created.id).expect("the stream is listed");
    assert_eq!(
        datadog.destination.kind, "datadog",
        "the destination changed"
    );
    assert_eq!(datadog.destination.site.as_deref(), Some("eu1"));
    let read = tess
        .send_text(audit_streams::list(tenant).call())
        .await
        .ok();
    no_secret_leaked(&read, &[&api_key]);

    audit_streams::pause(tenant, &created.id)
        .send(tess)
        .await
        .ok();
    let streams = audit_streams::list(tenant).send(tess).await.ok();
    let paused = stream_named(streams, &created.id).expect("the stream is listed");
    assert_eq!(paused.state, "paused", "the stream is paused");
    assert_eq!(
        paused.paused_reason.as_deref(),
        Some("by_administrator"),
        "stopped by a person, not its failures"
    );
    audit_streams::pause(tenant, &created.id)
        .send(tess)
        .await
        .refused(Status::CONFLICT, "conflict");
    audit_streams::resume(tenant, &created.id)
        .send(tess)
        .await
        .ok();
    audit_streams::resume(tenant, &created.id)
        .send(tess)
        .await
        .refused(Status::CONFLICT, "conflict");
    audit_streams::remove(tenant, &created.id)
        .send(tess)
        .await
        .ok();
    let streams = audit_streams::list(tenant).send(tess).await.ok();
    assert!(
        stream_named(streams, &created.id).is_none(),
        "the stream is gone"
    );

    let trail = world.trail();
    let secrets = [header_value.as_str(), token.as_str(), api_key.as_str()];
    for event in [
        "tenant.audit_stream_changed",
        "tenant.audit_stream_paused",
        "tenant.audit_stream_resumed",
        "tenant.audit_stream_removed",
    ] {
        let record = trail.recorded_after(&trail_before, event).await;
        no_secret_leaked(&record.details.to_string(), &secrets);
    }

    stack.stop().await.expect("the stack stops cleanly");
}

/// Mallory, an administrator who should know better, tries to send the
/// records somewhere inside the deployment: to the machine's loopback, an
/// internal range, the cloud metadata address, plain HTTP, or a syslog
/// host on an internal name. Each is refused, and so are a site Datadog
/// does not have and an event type that does not exist. Nothing was
/// added.
#[tokio::test]
async fn a_stream_cannot_send_inside_the_deployment() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let tenant = world.tenant();
    let password = world.admin().password();
    let trail_before = world.trail().ids().await;
    let word = credential();
    let refused_destinations = [
        http_destination("https://127.0.0.1/events", &word),
        http_destination("https://10.0.0.7/events", &word),
        http_destination("https://169.254.169.254/latest/meta-data/", &word),
        http_destination("http://collector.acme.invalid/events", &word),
        json!({"kind": "splunk", "endpoint": "https://localhost/events", "token": word}),
        json!({"kind": "syslog", "host": "10.0.0.7"}),
        json!({"kind": "syslog", "host": "collector.internal"}),
        json!({"kind": "datadog", "site": "mars1", "api_key": word}),
    ];

    for destination in refused_destinations {
        audit_streams::create(tenant, &setup(destination, password))
            .send(tess)
            .await
            .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    }
    let mut unknown_event = setup(http_destination(COLLECTOR, &word), password);
    unknown_event.events = Some(vec!["nothing.of_the_kind".to_owned()]);
    audit_streams::create(tenant, &unknown_event)
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    let streams = audit_streams::list(tenant).send(tess).await.ok();
    assert!(streams.is_empty(), "nothing was added: {streams:?}");
    world
        .trail()
        .nothing_after(&trail_before, "tenant.audit_stream_created")
        .await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess adds a stream for every record and makes a role. The worker tries
/// to send the record to the collector, which answers nothing, so the
/// stream is noted as failing, the failed sends counted, while the record
/// itself stays in the tenant's trail and Tess's role stands.
#[tokio::test]
async fn a_silent_collector_marks_the_stream_failing() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let tenant = world.tenant();
    let created = added(&world, &credential()).await;
    let trail_before = world.trail().ids().await;

    roles::create(
        tenant,
        &NewRole {
            name: "Collected Role".to_owned(),
            system_permissions: vec![SystemPermission::new("Users", "View")],
        },
    )
    .send(tess)
    .await
    .ok();
    world
        .trail()
        .recorded_after(&trail_before, "authorization.role_created")
        .await;

    let id = created.id.as_str();
    let stream = eventually("the stream is noted as failing", || async move {
        let streams = audit_streams::list(tenant).send(tess).await.ok();
        stream_named(streams, id).filter(|stream| stream.state == "failing")
    })
    .await;
    assert!(
        stream.failures.is_some_and(|failures| failures >= 1),
        "its failed sends are counted: {stream:?}"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// A stream copies every record out of the tenant, so setting one up is
/// closed to all but a signed-in person who may change compliance, and
/// proves who they are again. Max, an ordinary user, cannot list the
/// streams nor add one even with his own password; Sam, from the other
/// company, and nobody signed in get nowhere; and Tess herself, her
/// password mistyped, is refused as if she held no right. No stream
/// appears.
#[tokio::test]
async fn nobody_without_the_right_streams_the_records_out() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let tenant = world.tenant();
    let word = credential();
    let destination = http_destination(COLLECTOR, &word);
    let owned_by_tess = added(&world, &credential()).await;
    let trail_before = world.trail().ids().await;
    let change_of = setup(destination.clone(), world.admin().password());

    for (what, call) in [
        ("listing the streams", audit_streams::list(tenant).call()),
        (
            "changing a stream",
            audit_streams::reconfigure(tenant, &owned_by_tess.id, &change_of).call(),
        ),
        (
            "pausing a stream",
            audit_streams::pause(tenant, &owned_by_tess.id).call(),
        ),
        (
            "resuming a stream",
            audit_streams::resume(tenant, &owned_by_tess.id).call(),
        ),
        (
            "removing a stream",
            audit_streams::remove(tenant, &owned_by_tess.id).call(),
        ),
        (
            "adding a stream",
            audit_streams::create(tenant, &change_of).call(),
        ),
    ] {
        Matrix::new(what, call)
            .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
            .refused(
                world.anonymous().client(),
                Status::UNAUTHORIZED,
                "unauthenticated",
            )
            .run()
            .await;
    }
    audit_streams::list(tenant)
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    audit_streams::create(tenant, &setup(destination, world.member().password()))
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    let wrong = setup(
        http_destination(COLLECTOR, &word),
        "Not Tess's own words 9 1!",
    );
    audit_streams::reconfigure(tenant, &owned_by_tess.id, &wrong)
        .send(tess)
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    let streams = audit_streams::list(tenant).send(tess).await.ok();
    assert_eq!(streams.len(), 1, "only Tess's stream stands: {streams:?}");
    assert_eq!(streams[0].state, "active", "and it was not paused");
    world
        .trail()
        .nothing_after(&trail_before, "tenant.audit_stream_changed")
        .await;
    world
        .trail()
        .nothing_after(&trail_before, "tenant.audit_stream_removed")
        .await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// The path Acme's collector takes records at.
const COLLECTED: &str = "/audit";

/// Tess adds a stream for every record to Acme's real collector, with its
/// credential, and makes a role. The collector receives that record as
/// JSON: the event, who did it, the tenant, and the role by name, with
/// the credential it asked for in the header. Nothing the collector was
/// sent, in any post, carries the credential in a body, nor Tess's
/// password, and the stream stays active.
#[tokio::test]
async fn acmes_collector_receives_the_record_and_no_secret() {
    let collector = OutsideReceiver::start(
        "collector.acme.example",
        [(COLLECTED, Canned::json(&json!({ "accepted": true })))],
    )
    .await;
    let stack = Stack::start(
        Profile::standard().with("OUTBOUND_DELIVERY_CA_FILE", collector.authority_file()),
    )
    .await
    .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let tenant = world.tenant();
    let password = world.admin().password();
    let header_value = credential();
    let address = collector.url_on(&stack, COLLECTED);
    let created = audit_streams::create(
        tenant,
        &setup(http_destination(&address, &header_value), password),
    )
    .send(tess)
    .await
    .ok();

    roles::create(
        tenant,
        &NewRole {
            name: "Collected Role".to_owned(),
            system_permissions: vec![SystemPermission::new("Users", "View")],
        },
    )
    .send(tess)
    .await
    .ok();

    let acme = &collector;
    let record = eventually("the collector received the role's record", || async move {
        acme.received_at("POST", COLLECTED)
            .into_iter()
            .find(|post| post.json()["event_type"] == "authorization.role_created")
    })
    .await;
    assert_eq!(record.header("content-type"), Some("application/json"));
    assert_eq!(
        record.header("authorization"),
        Some(header_value.as_str()),
        "the collector's credential is the one header it asked for"
    );
    let body = record.json();
    assert_eq!(
        body["actor"],
        format!("org_user:{}", world.admin().id()),
        "the record names Tess: {body}"
    );
    assert!(
        body["tenant_id"].as_str().is_some_and(|id| !id.is_empty()),
        "the record names the tenant: {body}"
    );
    assert!(
        record.body.contains("Collected Role"),
        "the record names the role: {body}"
    );
    for post in collector.received_at("POST", COLLECTED) {
        no_secret_leaked(&post.body, &[header_value.as_str(), password]);
    }

    let streams = audit_streams::list(tenant).send(tess).await.ok();
    let stream = stream_named(streams, &created.id).expect("the stream is listed");
    assert_eq!(stream.state, "active", "the stream stays active");

    stack.stop().await.expect("the stack stops cleanly");
}
