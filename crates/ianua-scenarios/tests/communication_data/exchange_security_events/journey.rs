//! A receiver of Acme's hearing from the tenant end to end: Tess registers
//! it, it proves its endpoint by echoing the challenge it was sent in a
//! signed event, and it is then told of a role Tess gives, in a token it
//! checks against what the tenant publishes.

use ianua_scenarios::api::signals;
use ianua_scenarios::expect::{eventually, no_secret_leaked, verified_rs256};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{Canned, OutsideReceiver, Received};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::signals::{AskVerification, ConfirmEndpoint, NewStream, PollAsk};
use ianua_scenarios::world::World;
use serde_json::Value;

use crate::support::{
    ENDPOINT, EventSource, TOKEN_CLAIMS_CHANGE, VERIFICATION, awaited, checked, give_role, person,
    prove_endpoint, published, reading_role, register, stream, tampered,
};

/// The URN of a transmitter delivering by push.
const PUSH: &str = "urn:ietf:rfc:8935";

/// The URN of a transmitter delivering by poll.
const POLL: &str = "urn:ietf:rfc:8936";

/// The transmitter publishes where its receivers register and which keys
/// sign its tokens. Tess registers Acme's receiver as a poll stream
/// hearing about everyone. Read back, the stream waits for its endpoint to
/// prove itself and never shows its key. The receiver polls and gets the
/// verification event: signed by the tenant's published key, its issuer
/// the tenant's, its audience the endpoint, about the stream, carrying a
/// challenge; the same token changed by Mallory fails the check. The
/// receiver echoes the challenge, with no credential but that, and the
/// stream is verified. Tess gives Pat a role: the receiver reads a token
/// about Pat naming her permissions, signed and unaltered. Its delivery
/// history shows the token as queued, and once the receiver acknowledges
/// it the token is not offered again. The trail records the registration
/// without the key, and no token names Pat's address.
#[tokio::test]
async fn a_poll_receiver_proves_its_endpoint_and_hears_of_a_role_change() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let tenant = world.tenant();
    let (configuration, keys) = published(&world).await;
    assert!(
        configuration
            .delivery_methods_supported
            .iter()
            .any(|method| method == PUSH),
        "the transmitter offers push"
    );
    assert!(
        configuration
            .delivery_methods_supported
            .iter()
            .any(|method| method == POLL),
        "the transmitter offers poll"
    );
    assert!(
        configuration.configuration_endpoint.ends_with("/streams"),
        "streams are registered at {}",
        configuration.configuration_endpoint
    );
    assert!(
        configuration
            .verification_endpoint
            .contains("/streams/{stream_id}/verify"),
        "the verification endpoint names the stream: {}",
        configuration.verification_endpoint
    );
    let pat = person(&world, "pat").await;
    let role = reading_role(&world, "Signalled Readers").await;
    let trail_before = world.trail().ids().await;

    let receiver = register(&world, &stream("Poll", "ALL"), "Acme's receiver").await;
    let id = receiver.id.as_str();
    let shown = signals::get(tenant, id).send(tess).await.ok();
    assert_eq!(shown.endpoint, ENDPOINT, "the endpoint is read back");
    assert_eq!(
        shown.verification, "Pending",
        "its endpoint must prove itself"
    );
    assert_eq!(shown.status, "Active", "a new stream is active");
    assert!(!shown.sends_authorization, "this stream pushes no header");
    let listed = tess.send_text(signals::list(tenant).call()).await.ok();
    no_secret_leaked(&listed, &[&receiver.key]);
    let read = tess.send_text(signals::get(tenant, id).call()).await.ok();
    no_secret_leaked(&read, &[&receiver.key]);

    let source = EventSource {
        tenant,
        receiver: &receiver,
        keys: &keys,
    };
    let (first_jti, verification, token) =
        awaited(&source, VERIFICATION, |event: &serde_json::Value| {
            event["state"].is_string()
        })
        .await;
    assert_eq!(
        verification["iss"], configuration.issuer,
        "issued by the tenant"
    );
    assert_eq!(verification["aud"], ENDPOINT, "addressed to the endpoint");
    let event = &verification["events"][VERIFICATION];
    assert_eq!(event["subject"]["format"], "opaque", "subjects are opaque");
    assert_eq!(event["subject"]["id"], id, "it names the stream");
    assert!(
        verified_rs256(&keys, &tampered(&token), "secevent+jwt").is_err(),
        "a token changed on the way fails the check"
    );

    let challenge = event["state"].as_str().expect("a challenge").to_owned();
    signals::confirm(tenant, id, &ConfirmEndpoint { challenge })
        .send(world.anonymous().client())
        .await
        .ok();
    let confirmed = signals::get(tenant, id).send(tess).await.ok();
    assert_eq!(
        confirmed.verification, "Verified",
        "the endpoint proved itself"
    );
    signals::poll(
        tenant,
        id,
        &PollAsk {
            ack: vec![first_jti],
            max_events: None,
        },
    )
    .send(&receiver.client)
    .await
    .ok();

    give_role(&world, &pat, &role).await;
    let pat_id = pat.id().to_owned();
    let about_pat = |event: &serde_json::Value| event["subject"]["id"] == pat_id.as_str();
    let (jti, claims, token) = awaited(&source, TOKEN_CLAIMS_CHANGE, about_pat).await;
    assert_eq!(claims["iss"], configuration.issuer, "issued by the tenant");
    assert_eq!(claims["aud"], ENDPOINT, "addressed to the endpoint");
    assert!(
        checked(&keys, &token).is_object(),
        "the role change verifies as signed"
    );
    let event = &claims["events"][TOKEN_CLAIMS_CHANGE];
    assert_eq!(event["subject"]["format"], "opaque", "subjects are opaque");
    assert!(
        event["claims"]["permissions"]
            .as_array()
            .is_some_and(|permissions| !permissions.is_empty()),
        "it names what Pat holds now: {event}"
    );
    no_secret_leaked(&claims.to_string(), &[pat.email()]);

    let history = signals::deliveries(tenant, id).send(tess).await.ok();
    let attempt = history
        .items
        .iter()
        .find(|attempt| attempt.signal_id == jti)
        .expect("the delivery of the token is shown");
    assert_eq!(attempt.status, "Queued", "a poll stream holds tokens");
    assert_eq!(attempt.signal_type, "PermissionsChanged");

    let acknowledged = PollAsk {
        ack: vec![jti.clone()],
        max_events: None,
    };
    let next = signals::poll(tenant, id, &acknowledged)
        .send(&receiver.client)
        .await
        .ok();
    assert!(
        !next.sets.contains_key(&jti),
        "an acknowledged token is not offered again"
    );

    let record = world
        .trail()
        .recorded_after(&trail_before, "signals.stream_registered")
        .await;
    assert_eq!(
        record.details["stream"]["id"], id,
        "the record names the stream"
    );
    no_secret_leaked(&record.details.to_string(), &[&receiver.key]);

    stack.stop().await.expect("the stack stops cleanly");
}

/// Acme's receiver, its endpoint proved, asks for a verification event
/// carrying a state of its own and finds it in its next poll, signed; the
/// request is recorded. Asked again right away it is told to wait a
/// moment.
#[tokio::test]
async fn a_receiver_asks_for_a_verification_event_carrying_its_own_state() {
    let stack = Stack::start(Profile::standard().with("SIGNAL_VERIFICATIONS_PER_WINDOW", "1"))
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tenant = world.tenant();
    let (_, keys) = published(&world).await;
    let receiver = register(&world, &stream("Poll", "ALL"), "Acme's receiver").await;
    prove_endpoint(&world, &receiver, &keys).await;
    let trail_before = world.trail().ids().await;

    let asked = AskVerification {
        state: "acmecheck1".to_owned(),
    };
    signals::verify(tenant, &receiver.id, &asked)
        .send(&receiver.client)
        .await
        .ok();
    let source = EventSource {
        tenant,
        receiver: &receiver,
        keys: &keys,
    };
    let (_, claims, _) = awaited(&source, VERIFICATION, |event: &serde_json::Value| {
        event["state"] == "acmecheck1"
    })
    .await;
    assert_eq!(
        claims["events"][VERIFICATION]["state"], "acmecheck1",
        "the event carries the receiver's state"
    );
    world
        .trail()
        .recorded_after(&trail_before, "signals.verification_requested")
        .await;
    signals::verify(tenant, &receiver.id, &asked)
        .send(&receiver.client)
        .await
        .refused(Status::TOO_MANY_REQUESTS, "rate_limit_exceeded");

    stack.stop().await.expect("the stack stops cleanly");
}

/// The path Acme's server takes pushed tokens at.
const SIGNALS: &str = "/signals";

/// What Acme's server asked to be sent with each push: a sentence, so no
/// scanner takes it for a key.
const RECEIVER_HEADER: &str = "acme signal receiver words";

/// The token in the first post to `server` about `urn` for which
/// `matches` holds, once it has arrived, with its claims as `keys` verify
/// them.
async fn pushed_token(
    server: &OutsideReceiver,
    keys: &ianua_scenarios::wire::oauth::Keys,
    urn: &str,
    matches: impl Fn(&Value) -> bool,
) -> (Received, Value) {
    let matches = &matches;
    let what = format!("a push about {urn}");
    eventually(&what, || async move {
        server
            .received_at("POST", SIGNALS)
            .into_iter()
            .find_map(|post| {
                let claims = checked(keys, &post.body);
                let about = claims["events"].get(urn)?;
                matches(about).then(|| (post.clone(), claims.clone()))
            })
    })
    .await
}

/// Tess registers Acme's real server as a push receiver with a header of
/// its own. The verification token reaches it as a Security Event Token,
/// addressed to the endpoint, signed by the tenant's published key, with
/// the header it asked for, and it proves its endpoint by echoing the
/// challenge. Tess gives Pat a role: the token about it reaches Acme's
/// server, verifies, changes on the way would be caught, and names her
/// permissions without her address. Its delivery history shows the push
/// succeeded.
#[tokio::test]
async fn a_push_receiver_hears_of_a_role_in_a_token_it_verifies() {
    let server = OutsideReceiver::start(
        "signals.acme.example",
        [(SIGNALS, Canned::json(&serde_json::json!({})))],
    )
    .await;
    let stack = Stack::start(
        Profile::standard().with("OUTBOUND_DELIVERY_CA_FILE", server.authority_file()),
    )
    .await
    .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let tenant = world.tenant();
    let (configuration, keys) = published(&world).await;
    let endpoint = server.url_on(&stack, SIGNALS);
    let pat = person(&world, "pat").await;
    let role = reading_role(&world, "Pushed Readers").await;

    let receiver = register(
        &world,
        &NewStream {
            endpoint: endpoint.clone(),
            delivery_method: "Push".to_owned(),
            signal_types: vec!["PermissionsChanged".to_owned()],
            authorization_header: Some(RECEIVER_HEADER.to_owned()),
            default_subjects: "ALL".to_owned(),
        },
        "Acme's pushed receiver",
    )
    .await;
    let id = receiver.id.as_str();

    let (verification, claims) = pushed_token(&server, &keys, VERIFICATION, |_| true).await;
    assert_eq!(
        verification.header("content-type"),
        Some("application/secevent+jwt")
    );
    assert_eq!(verification.header("authorization"), Some(RECEIVER_HEADER));
    assert_eq!(claims["iss"], configuration.issuer, "issued by the tenant");
    assert_eq!(claims["aud"], endpoint, "addressed to the endpoint");
    let challenge = claims["events"][VERIFICATION]["state"]
        .as_str()
        .expect("a challenge")
        .to_owned();
    signals::confirm(tenant, id, &ConfirmEndpoint { challenge })
        .send(world.anonymous().client())
        .await
        .ok();

    give_role(&world, &pat, &role).await;
    let pat_id = pat.id().to_owned();
    let about_pat = |event: &Value| event["subject"]["id"] == pat_id.as_str();
    let (post, told) = pushed_token(&server, &keys, TOKEN_CLAIMS_CHANGE, about_pat).await;
    assert_eq!(post.header("authorization"), Some(RECEIVER_HEADER));
    assert!(
        verified_rs256(&keys, &tampered(&post.body), "secevent+jwt").is_err(),
        "a token changed on the way fails the check"
    );
    assert!(
        told["events"][TOKEN_CLAIMS_CHANGE]["claims"]["permissions"]
            .as_array()
            .is_some_and(|permissions| !permissions.is_empty()),
        "it names what Pat holds now: {told}"
    );
    no_secret_leaked(&told.to_string(), &[pat.email()]);

    let jti = told["jti"].as_str().expect("a jti");
    let attempt = eventually("the push is on record", || async move {
        let history = signals::deliveries(tenant, id).send(tess).await.ok();
        history
            .items
            .into_iter()
            .find(|attempt| attempt.signal_id == jti)
    })
    .await;
    assert_eq!(attempt.status, "Success", "the push was taken: {attempt:?}");

    stack.stop().await.expect("the stack stops cleanly");
}
