//! Tess subscribing a server of Acme's to the tenant's events: the signing
//! secret she is shown once and never again, addresses inside the
//! deployment refused however they are written, how each delivery attempt
//! ended, and pausing, rotating the secret and deleting. Most scenarios
//! name a host that resolves nowhere, under the reserved `.invalid`
//! domain, so their attempts end `Unreachable`; where what Acme's server
//! really receives matters, the deployment trusts a stand-in for it
//! (`OUTBOUND_DELIVERY_CA_FILE`) and the post arrives there, signed.

use ianua_scenarios::api::{roles, webhooks};
use ianua_scenarios::expect::{Matrix, eventually, no_secret_leaked, standard_webhook_signed_by};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, OutsideReceiver, Received};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::roles::{NewRole, SystemPermission};
use ianua_scenarios::wire::webhooks::{
    NewWebhook, RotateWebhookSecret, WebhookChange, WebhookCreated, WebhookTestEvent,
};
use ianua_scenarios::world::World;
use serde_json::{Value, json};

use crate::support::{give_role, person};

/// The endpoint on Acme's server: a public-looking address nothing
/// answers, in the reserved `.invalid` domain.
const ENDPOINT: &str = "https://hooks.acme.invalid/events";

/// A second address on Acme's server.
const OTHER_ENDPOINT: &str = "https://hooks.acme.invalid/other";

/// The event a webhook is subscribed to in these scenarios: Tess making a
/// role is one she may see.
fn role_created() -> Value {
    json!({"Authorization": "RoleCreated"})
}

/// A subscription to Tess's making of a role, retried as `retry` says.
fn subscription(retry: Option<&str>) -> NewWebhook {
    NewWebhook {
        url: ENDPOINT.to_owned(),
        event_types: vec![role_created()],
        description: Some("Tells Acme's server of new roles".to_owned()),
        retry: retry.map(str::to_owned),
    }
}

/// The subscription Tess makes for the role events, as `retry` says.
async fn subscribed(world: &World<'_>, retry: Option<&str>) -> WebhookCreated {
    webhooks::create(world.tenant(), &subscription(retry))
        .send(world.admin().client())
        .await
        .ok()
}

/// The path Acme's own server takes webhook posts at.
const EVENTS: &str = "/events";

/// Acme's own server, answering every post with success.
async fn acmes_server() -> OutsideReceiver {
    OutsideReceiver::start(
        "hooks.acme.example",
        [(EVENTS, Canned::json(&json!({ "received": true })))],
    )
    .await
}

/// The standard deployment, trusting `server`'s authority for deliveries.
fn reaching(server: &OutsideReceiver) -> Profile {
    Profile::standard().with("OUTBOUND_DELIVERY_CA_FILE", server.authority_file())
}

/// The subscription Tess makes to Acme's server, as `retry` says.
async fn subscribed_to(
    world: &World<'_>,
    server: &OutsideReceiver,
    retry: Option<&str>,
) -> WebhookCreated {
    let mut to_make = subscription(retry);
    to_make.url = server.url_on(world.stack(), EVENTS);
    webhooks::create(world.tenant(), &to_make)
        .send(world.admin().client())
        .await
        .ok()
}

/// Sends Tess's test event to `webhook` and hands back the one post that
/// reached `server` for it, with the attempt the platform noted.
async fn test_post(
    world: &World<'_>,
    server: &OutsideReceiver,
    webhook: &str,
) -> (Received, ianua_scenarios::wire::webhooks::WebhookDelivery) {
    let before = server.received_at("POST", EVENTS).len();
    let sample = WebhookTestEvent {
        event_type: role_created(),
    };
    let attempt = webhooks::send_test(world.tenant(), webhook, &sample)
        .send(world.admin().client())
        .await
        .ok();
    let mut posts = server.received_at("POST", EVENTS);
    assert_eq!(
        posts.len(),
        before + 1,
        "one test post reached Acme's server"
    );
    (posts.remove(before), attempt)
}

/// Tess reads which events she may subscribe to, the role event among
/// them, and subscribes Acme's server. She is shown its signing secret
/// once. Reading the subscription back shows its address and status,
/// and never the secret, either when she lists her webhooks or asks for
/// this one, and the audit record of it does not name the secret.
#[tokio::test]
async fn tess_subscribes_a_webhook_and_sees_its_secret_only_once() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let tenant = world.tenant();
    let trail_before = world.trail().ids().await;

    let catalog = webhooks::event_types(tenant).send(tess).await.ok();
    let listed = catalog
        .iter()
        .find(|entry| entry.name == "authorization.role_created")
        .expect("the role event can be subscribed to");
    assert_eq!(
        listed.event_type,
        role_created(),
        "a webhook lists the event in this shape"
    );

    let created = subscribed(&world, None).await;
    assert!(!created.signing_secret.is_empty(), "a secret is shown");

    let listed = tess.send_text(webhooks::list(tenant).call()).await.ok();
    assert!(listed.contains(&created.id), "the webhook is listed");
    no_secret_leaked(&listed, &[&created.signing_secret]);
    let read = tess
        .send_text(webhooks::get(tenant, &created.id).call())
        .await
        .ok();
    no_secret_leaked(&read, &[&created.signing_secret]);
    let webhook = webhooks::get(tenant, &created.id).send(tess).await.ok();
    assert_eq!(webhook.url, ENDPOINT, "the address is read back");
    assert_eq!(webhook.status, "Active", "a new webhook is active");
    assert_eq!(webhook.retry, "Standard", "the standard policy by default");

    let record = world
        .trail()
        .recorded_after(&trail_before, "webhooks.subscription_created")
        .await;
    assert_eq!(
        record.details["subscription"]["id"],
        created.id.as_str(),
        "the record names the webhook"
    );
    no_secret_leaked(&record.details.to_string(), &[&created.signing_secret]);

    stack.stop().await.expect("the stack stops cleanly");
}

/// Mallory, an administrator who should know better, tries to point a
/// webhook at the deployment's own network: the machine's loopback, an
/// internal range, the cloud metadata address, plain HTTP, or a name only
/// an inside resolver answers. Every one is refused, when subscribing and
/// when changing an existing webhook, and the existing webhook keeps its
/// address.
#[tokio::test]
async fn a_webhook_cannot_point_inside_the_deployment() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let tenant = world.tenant();
    let existing = subscribed(&world, None).await;
    let trail_before = world.trail().ids().await;
    let inside = [
        "https://127.0.0.1/hook",
        "https://localhost/hook",
        "https://10.1.2.3/hook",
        "https://192.168.0.5/hook",
        "https://169.254.169.254/latest/meta-data/",
        "https://[::1]/hook",
        "http://hooks.acme.invalid/events",
        "https://billing/hook",
        "https://hooks.acme.internal/events",
        "https://hooks.acme.cluster.local/events",
    ];

    for address in inside {
        let mut to_make = subscription(None);
        to_make.url = address.to_owned();
        webhooks::create(tenant, &to_make)
            .send(tess)
            .await
            .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
        let change = WebhookChange {
            url: Some(address.to_owned()),
            description: None,
        };
        webhooks::change(tenant, &existing.id, &change)
            .send(tess)
            .await
            .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    }

    let webhook = webhooks::get(tenant, &existing.id).send(tess).await.ok();
    assert_eq!(
        webhook.url, ENDPOINT,
        "the existing webhook kept its address"
    );
    world
        .trail()
        .nothing_after(&trail_before, "webhooks.subscription_created")
        .await;
    world
        .trail()
        .nothing_after(&trail_before, "webhooks.subscription_updated")
        .await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess sends the webhook a test event. Nothing answers, so the try ends
/// `Unreachable`, shown in its delivery history without counting against
/// the webhook. She sends the same message again: the new attempt carries
/// the same message id, so a receiver that already handled it would drop
/// it, and it is counted as a failure. Each attempt is recorded in the
/// audit trail.
#[tokio::test]
async fn a_test_event_to_a_silent_endpoint_is_recorded_and_can_be_resent() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let tenant = world.tenant();
    let created = subscribed(&world, None).await;
    let trail_before = world.trail().ids().await;
    let sample = WebhookTestEvent {
        event_type: role_created(),
    };

    let test = webhooks::send_test(tenant, &created.id, &sample)
        .send(tess)
        .await
        .ok();
    assert_eq!(test.status, "Unreachable", "nothing answered: {test:?}");
    assert_eq!(test.response_status, None, "no code came back");
    assert_eq!(test.attempt_number, 0, "the first try");
    assert_eq!(test.subscription_id, created.id, "for this webhook");

    let shown = webhooks::get(tenant, &created.id).send(tess).await.ok();
    assert_eq!(
        shown.consecutive_failures, 0,
        "a test send does not count against the webhook"
    );
    let history = webhooks::deliveries(tenant, &created.id)
        .send(tess)
        .await
        .ok();
    assert!(
        history.items.iter().any(|attempt| attempt.id == test.id),
        "the test attempt is in the history: {history:?}"
    );

    let again = webhooks::resend(tenant, &created.id, &test.id)
        .send(tess)
        .await
        .ok();
    assert_eq!(
        again.message_id, test.message_id,
        "a resend carries the same message id"
    );
    assert_ne!(again.id, test.id, "as an attempt of its own");
    assert_eq!(
        again.status, "Unreachable",
        "nothing answered this time either"
    );
    let shown = webhooks::get(tenant, &created.id).send(tess).await.ok();
    assert_eq!(shown.consecutive_failures, 1, "a resend is counted");
    world
        .trail()
        .recorded_after(&trail_before, "webhooks.delivery_attempted")
        .await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess subscribes Acme's server with the aggressive retry policy, then
/// makes a role. The worker sends the event and, nothing answering, tries
/// it again: every attempt carries the same message id, in order, and
/// the webhook's failure count climbs. Tess's role was made all the same.
#[tokio::test]
async fn a_failing_delivery_is_retried_under_the_same_message_id() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let tenant = world.tenant();
    let created = subscribed(&world, Some("Aggressive")).await;

    roles::create(
        tenant,
        &NewRole {
            name: "Webhook Delivery Role".to_owned(),
            system_permissions: vec![SystemPermission::new("Users", "View")],
        },
    )
    .send(tess)
    .await
    .ok();

    let id = created.id.as_str();

    let tries = eventually(
        "the worker has tried the event three times",
        || async move {
            let history = webhooks::deliveries(tenant, id).send(tess).await.ok();
            (history.items.len() >= 3).then_some(history.items)
        },
    )
    .await;
    assert!(
        tries
            .iter()
            .all(|attempt| attempt.status == "Unreachable" && attempt.response_status.is_none()),
        "every try ended with nothing answering: {tries:?}"
    );
    assert!(
        tries
            .iter()
            .all(|attempt| attempt.message_id == tries[0].message_id),
        "the same message each time: {tries:?}"
    );
    let mut numbers: Vec<u8> = tries.iter().map(|attempt| attempt.attempt_number).collect();
    numbers.sort_unstable();
    assert_eq!(numbers[..3], [0, 1, 2], "the tries are numbered in order");
    let webhook = webhooks::get(tenant, id).send(tess).await.ok();
    assert!(
        webhook.consecutive_failures >= 1,
        "the failures counted: {webhook:?}"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess pauses the webhook and cannot pause it twice, resumes it and
/// cannot resume it twice. She changes its address and rotates its secret
/// twice, once at once and once with an overlap; a second rotation gives
/// a different secret and a bad overlap is refused. She cannot delete it
/// while it is active; paused, she deletes it, it is gone, and each step
/// is in the trail.
#[tokio::test]
async fn tess_pauses_rotates_and_deletes_a_webhook() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let tenant = world.tenant();
    let created = subscribed(&world, None).await;
    let trail_before = world.trail().ids().await;

    webhooks::pause(tenant, &created.id).send(tess).await.ok();
    let paused = webhooks::get(tenant, &created.id).send(tess).await.ok();
    assert_eq!(paused.status, "Paused", "the webhook is paused");
    webhooks::pause(tenant, &created.id)
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    webhooks::resume(tenant, &created.id).send(tess).await.ok();
    let resumed = webhooks::get(tenant, &created.id).send(tess).await.ok();
    assert_eq!(resumed.status, "Active", "the webhook is active again");
    webhooks::resume(tenant, &created.id)
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    let change = WebhookChange {
        url: Some(OTHER_ENDPOINT.to_owned()),
        description: Some("Tells Acme's other server".to_owned()),
    };
    let changed = webhooks::change(tenant, &created.id, &change)
        .send(tess)
        .await
        .ok();
    assert_eq!(changed.url, OTHER_ENDPOINT, "the address changed");

    let first = webhooks::rotate_secret(tenant, &created.id, None)
        .send(tess)
        .await
        .ok();
    assert_ne!(
        first.signing_secret, created.signing_secret,
        "a rotation issues a new secret"
    );
    let overlap = RotateWebhookSecret {
        overlap_seconds: 3600,
    };
    let second = webhooks::rotate_secret(tenant, &created.id, Some(overlap))
        .send(tess)
        .await
        .ok();
    assert_ne!(
        second.signing_secret, first.signing_secret,
        "each rotation issues its own"
    );
    let too_long = RotateWebhookSecret {
        overlap_seconds: 8 * 24 * 3600,
    };
    webhooks::rotate_secret(tenant, &created.id, Some(too_long))
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    webhooks::delete(tenant, &created.id)
        .send(tess)
        .await
        .refused(Status::CONFLICT, "conflict");
    webhooks::pause(tenant, &created.id).send(tess).await.ok();
    webhooks::delete(tenant, &created.id).send(tess).await.ok();
    webhooks::get(tenant, &created.id)
        .send(tess)
        .await
        .refused(Status::NOT_FOUND, "not_found");

    let trail = world.trail();
    let secrets = [
        created.signing_secret.as_str(),
        first.signing_secret.as_str(),
        second.signing_secret.as_str(),
    ];
    for event in [
        "webhooks.subscription_paused",
        "webhooks.subscription_resumed",
        "webhooks.subscription_updated",
        "webhooks.secret_rotated",
        "webhooks.subscription_deleted",
    ] {
        let record = trail.recorded_after(&trail_before, event).await;
        no_secret_leaked(&record.details.to_string(), &secrets);
    }

    stack.stop().await.expect("the stack stops cleanly");
}

/// Max, an ordinary user of the tenant, Sam, from the other company, and
/// nobody signed in get nowhere: not the webhooks, their history, the
/// event list or any change. A role that only lets Pat read webhooks
/// shows them to her and refuses every change. Given the right to change
/// webhooks too, but none to see user events, she cannot subscribe to
/// those, and nobody may subscribe to the delivery event itself, since
/// each delivery would raise another.
#[tokio::test]
async fn nobody_without_the_right_reads_or_changes_a_webhook() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let tenant = world.tenant();
    let created = subscribed(&world, None).await;
    let trail_before = world.trail().ids().await;
    let delivery = "00000000-0000-4000-8000-000000000001";
    let sample = WebhookTestEvent {
        event_type: role_created(),
    };
    let change = WebhookChange {
        url: Some(OTHER_ENDPOINT.to_owned()),
        description: None,
    };
    let calls = [
        ("listing webhooks", webhooks::list(tenant).call()),
        (
            "reading a webhook",
            webhooks::get(tenant, &created.id).call(),
        ),
        (
            "reading its history",
            webhooks::deliveries(tenant, &created.id).call(),
        ),
        ("listing the events", webhooks::event_types(tenant).call()),
        (
            "making a webhook",
            webhooks::create(tenant, &subscription(None)).call(),
        ),
        (
            "changing a webhook",
            webhooks::change(tenant, &created.id, &change).call(),
        ),
        (
            "pausing a webhook",
            webhooks::pause(tenant, &created.id).call(),
        ),
        (
            "resuming a webhook",
            webhooks::resume(tenant, &created.id).call(),
        ),
        (
            "rotating its secret",
            webhooks::rotate_secret(tenant, &created.id, None).call(),
        ),
        (
            "sending a test event",
            webhooks::send_test(tenant, &created.id, &sample).call(),
        ),
        (
            "sending a delivery again",
            webhooks::resend(tenant, &created.id, delivery).call(),
        ),
        (
            "deleting a webhook",
            webhooks::delete(tenant, &created.id).call(),
        ),
    ];
    for (what, call) in calls {
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
    let held = webhooks::get(tenant, &created.id).send(tess).await.ok();
    assert_eq!(held.status, "Active", "none of them paused the webhook");
    assert_eq!(held.url, ENDPOINT, "or changed its address");

    let pat = person(&world, "pat").await;
    let readers = roles::create(
        tenant,
        &NewRole {
            name: "Webhook Readers".to_owned(),
            system_permissions: vec![SystemPermission::new("Webhooks", "View")],
        },
    )
    .send(tess)
    .await
    .ok();
    give_role(&world, &pat, &readers.id).await;
    let id = created.id.as_str();
    let pat_client = pat.client();
    eventually("Pat's reading right reaches her session", || async move {
        let read = webhooks::get(tenant, id).send(pat_client).await;
        read.status().is_success().then_some(())
    })
    .await;
    webhooks::pause(tenant, id)
        .send(pat_client)
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    let makers = roles::create(
        tenant,
        &NewRole {
            name: "Webhook Makers".to_owned(),
            system_permissions: vec![SystemPermission::new("Webhooks", "Update")],
        },
    )
    .send(tess)
    .await
    .ok();
    give_role(&world, &pat, &makers.id).await;
    let noted = WebhookChange {
        url: None,
        description: Some("Noted by Pat".to_owned()),
    };
    let noted = &noted;
    eventually("Pat's making right reaches her session", || async move {
        let changed = webhooks::change(tenant, id, noted).send(pat_client).await;
        changed.status().is_success().then_some(())
    })
    .await;
    let mut user_events = subscription(None);
    user_events.event_types = vec![json!({"Identity": "UserRegistered"})];
    webhooks::create(tenant, &user_events)
        .send(pat_client)
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    let mut own_deliveries = subscription(None);
    own_deliveries.event_types = vec![json!({"Webhooks": "DeliveryAttempted"})];
    webhooks::create(tenant, &own_deliveries)
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    world
        .trail()
        .nothing_after(&trail_before, "webhooks.subscription_paused")
        .await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess sends a test event to Acme's real server. It answers, and the
/// attempt is noted as a success with that answer. The post that arrived
/// carries the exact sample body and a signature Acme's server verifies
/// with the secret Tess was shown once, over the id and the time it was
/// sent, and the id is the attempt's own message id.
#[tokio::test]
async fn a_test_event_reaches_acmes_server_signed_with_the_secret_shown() {
    let server = acmes_server().await;
    let stack = Stack::start(reaching(&server))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let created = subscribed_to(&world, &server, None).await;

    let (post, attempt) = test_post(&world, &server, &created.id).await;

    assert_eq!(
        attempt.status, "Success",
        "Acme's server answered: {attempt:?}"
    );
    assert_eq!(attempt.response_status, Some(200));
    assert_eq!(post.header("content-type"), Some("application/json"));
    assert_eq!(
        post.json(),
        json!({
            "type": "authorization.role_created",
            "test": true,
            "data": { "description": "A new role was created." },
        }),
        "the post is the sample, and nothing else"
    );
    assert!(
        standard_webhook_signed_by(&post, &created.signing_secret),
        "Acme's server verifies the signature: {:?}",
        post.header("webhook-signature")
    );
    assert_eq!(
        post.header("webhook-id"),
        Some(attempt.message_id.as_str()),
        "the header names the attempt's message"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Acme's server answers `503` twice, then takes the delivery. Tess makes a
/// role under the aggressive policy: the worker tries it three times, and
/// Acme's server sees one body under one message id, each try signed with
/// the secret Tess was shown. The body names the event, the tenant and
/// Tess's role, and the last try is on record as having succeeded.
#[tokio::test]
async fn a_retried_delivery_carries_one_message_id_and_stays_signed() {
    let server = acmes_server().await;
    server.answer_next([Canned::refusing(503), Canned::refusing(503)]);
    let stack = Stack::start(reaching(&server))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let tenant = world.tenant();
    let created = subscribed_to(&world, &server, Some("Aggressive")).await;

    let role = roles::create(
        tenant,
        &NewRole {
            name: "Webhook Delivery Role".to_owned(),
            system_permissions: vec![SystemPermission::new("Users", "View")],
        },
    )
    .send(tess)
    .await
    .ok();

    let acme = &server;
    let tries = eventually("three tries reached Acme's server", || async move {
        let posts = acme.received_at("POST", EVENTS);
        (posts.len() >= 3).then_some(posts)
    })
    .await;
    let id = tries[0].header("webhook-id").expect("a message id");
    assert!(
        tries
            .iter()
            .all(|attempt| attempt.header("webhook-id") == Some(id)
                && attempt.body == tries[0].body
                && standard_webhook_signed_by(attempt, &created.signing_secret)),
        "every try is the same message, signed: {tries:?}"
    );
    let body = tries[0].json();
    assert_eq!(body["type"], "authorization.role_created");
    assert_eq!(body["data"]["role"]["id"], role.id, "it names Tess's role");
    assert_eq!(body["data"]["role"]["label"], "Webhook Delivery Role");
    assert!(
        body["tenant_id"].as_str().is_some_and(|id| !id.is_empty()),
        "it names the tenant: {body}"
    );

    let webhook = created.id.as_str();
    let success = eventually("the last try is on record", || async move {
        let history = webhooks::deliveries(tenant, webhook).send(tess).await.ok();
        history
            .items
            .into_iter()
            .find(|attempt| attempt.response_status == Some(200))
    })
    .await;
    assert_eq!(success.message_id, id, "the record names the same message");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess rotates the webhook's secret twice while Acme's server keeps
/// verifying her test posts. With an hour's overlap a post is signed by
/// both secrets, so Acme can switch over; rotated at once, the first
/// secret stops: a new post verifies with the newest secret alone.
#[tokio::test]
async fn the_old_secret_stops_signing_once_a_rotation_takes_effect() {
    let server = acmes_server().await;
    let stack = Stack::start(reaching(&server))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let tenant = world.tenant();
    let created = subscribed_to(&world, &server, None).await;
    let (first, _) = test_post(&world, &server, &created.id).await;
    assert!(standard_webhook_signed_by(&first, &created.signing_secret));

    let overlap = RotateWebhookSecret {
        overlap_seconds: 3600,
    };
    let rotated = webhooks::rotate_secret(tenant, &created.id, Some(overlap))
        .send(tess)
        .await
        .ok();
    let (overlapping, _) = test_post(&world, &server, &created.id).await;
    assert!(
        standard_webhook_signed_by(&overlapping, &created.signing_secret),
        "within the overlap the old secret still signs"
    );
    assert!(
        standard_webhook_signed_by(&overlapping, &rotated.signing_secret),
        "and the new one signs too"
    );

    let immediate = webhooks::rotate_secret(tenant, &created.id, None)
        .send(tess)
        .await
        .ok();
    let (after, _) = test_post(&world, &server, &created.id).await;
    assert!(
        standard_webhook_signed_by(&after, &immediate.signing_secret),
        "the newest secret signs"
    );
    assert!(
        !standard_webhook_signed_by(&after, &created.signing_secret),
        "the first secret signs nothing now"
    );
    assert!(
        !standard_webhook_signed_by(&after, &rotated.signing_secret),
        "nor the one rotated away at once"
    );

    stack.stop().await.expect("the stack stops cleanly");
}
