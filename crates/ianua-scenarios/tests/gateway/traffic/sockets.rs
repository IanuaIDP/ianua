//! A WebSocket through the gateway: the handshake is an ordinary request,
//! decided like any other, and what follows runs both ways without the
//! gateway reading it.

use std::time::Duration;

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{consumers, people, policies};
use ianua_scenarios::expect::{Records, eventually};
use ianua_scenarios::net::{Call, Client, Frame, Opened, Socket};
use ianua_scenarios::routes::{Placement, RouteSpec};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::{AssertionCheck, SocketApp};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::consumers::NewConsumer;
use ianua_scenarios::wire::policies::{BlankDraft, NewGroup, NewGroupMember, NewRule};
use ianua_scenarios::wire::routing::RoutePolicy;
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;
use serde_json::json;

use crate::support::{HostedApp, app_host, customer, profile, signed_in_on};

/// The longest an answer through the socket may take.
const ANSWER_WITHIN: Duration = Duration::from_secs(10);

/// The path of the live feed.
const FEED_PATH: &str = "/live/feed";

/// How often the gateway checks an open connection's caller in these
/// scenarios.
const RECHECK_SECONDS: u64 = 2;

/// How long a close may take: one recheck interval, and the margin of a
/// change reaching the gateway.
const CLOSES_WITHIN: Duration = Duration::from_secs(RECHECK_SECONDS + 8);

/// A deployment checking open connections every [`RECHECK_SECONDS`].
fn rechecking() -> Profile {
    profile()
        .with(
            "GATEWAY_TUNNEL_RECHECK_SECONDS",
            &RECHECK_SECONDS.to_string(),
        )
        .with("GATEWAY_TUNNEL_RECHECK_TIMEOUT_SECONDS", "1")
}

/// Pat, signed in on the live app, opens a WebSocket through the gateway.
/// The app verifies the assertion naming her at the handshake and sees
/// none of her cookies; two messages go there and back, in order. Nobody
/// signed in is refused the handshake, the app seeing nothing of it. Pat
/// closes the socket and the gateway records her handshake as allowed.
#[tokio::test]
async fn pat_talks_to_an_app_over_a_websocket_and_nobody_else_gets_a_handshake() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let app_server = SocketApp::start(&stack, &app_host(&world).await)
        .await
        .expect("the live app starts");
    let spec = RouteSpec::public("live", "/live/*").asking(RoutePolicy::Authenticated);
    let app = HostedApp::opened(&world, "live", spec, &app_server.url()).await;
    let pat = customer(&world, "pat", "Pat Customer").await;
    signed_in_on(&app.host, &pat).await;
    let address = app.page(FEED_PATH);

    let refused = match world.anonymous().client().open_socket(&address).await {
        Opened::Open(_) => panic!("a visitor's handshake got through"),
        Opened::Refused(answer) => *answer,
    };
    refused.refused(Status::UNAUTHORIZED, "unauthenticated");
    assert!(
        app_server.handshakes().is_empty(),
        "the refused handshake reached nothing"
    );

    let mut socket = pat.client().open_socket(&address).await.open();
    for said in ["good morning", "how are the numbers"] {
        socket.send_text(said).await;
        assert_eq!(
            socket.next_within(ANSWER_WITHIN).await,
            Some(Frame::Text(format!("heard: {said}"))),
            "the app's answer came back through the gateway"
        );
    }
    assert_eq!(
        app_server.heard(),
        vec!["good morning".to_owned(), "how are the numbers".to_owned()],
        "the app heard both messages, in order"
    );
    let handshakes = app_server.handshakes();
    assert_eq!(handshakes.len(), 1, "Pat's handshake reached the app once");
    let handshake = &handshakes[0];
    let AssertionCheck::Verified { caller } = &handshake.assertion else {
        panic!("the app could not check the handshake's assertion: {handshake:?}");
    };
    assert_eq!(caller.sub, pat.id(), "the app knows it is Pat");
    assert_eq!(handshake.path, FEED_PATH, "the handshake kept its path");
    assert!(
        !handshake.has_header("cookie"),
        "Pat's session cookie stayed behind"
    );

    socket.close().await;
    let record = Records::of_tenant(world.admin().client(), world.tenant())
        .recorded_where(FEED_PATH, "Pat's", |record| {
            record.subject.id.as_deref() == Some(pat.id())
        })
        .await;
    assert_eq!(record.decision, "allowed", "Pat's handshake is allowed");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat's and Uma's sockets to the live app are open. Tess suspends Pat:
/// within one recheck the gateway closes her socket, and its record says
/// her access ended. Uma's socket carries on.
#[tokio::test]
async fn suspending_pat_closes_her_open_socket_and_leaves_umas() {
    let stack = Stack::start(rechecking()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let app_server = SocketApp::start(&stack, &app_host(&world).await)
        .await
        .expect("the live app starts");
    let spec = RouteSpec::public("live", "/live/*").asking(RoutePolicy::Authenticated);
    let app = HostedApp::opened(&world, "live", spec, &app_server.url()).await;
    let pat = customer(&world, "pat", "Pat Customer").await;
    let uma = customer(&world, "uma", "Uma Colleague").await;
    signed_in_on(&app.host, &pat).await;
    signed_in_on(&app.host, &uma).await;
    let address = app.page(FEED_PATH);
    let mut pats = pat.client().open_socket(&address).await.open();
    let mut umas = uma.client().open_socket(&address).await.open();

    people::deactivate(world.tenant(), pat.id())
        .send(world.admin().client())
        .await
        .ok();

    assert_closes(&mut pats).await;
    assert_still_talks(&mut umas).await;
    assert_close_recorded(&world, &pat).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// A partner's program holds a socket to the orders feed, opened with its
/// key. Tess disables the partner: within one recheck the gateway closes
/// the socket, and the key opens no other.
#[tokio::test]
async fn disabling_a_partner_closes_its_open_socket() {
    let stack = Stack::start(rechecking()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let partner = consumers::create(
        world.tenant(),
        &NewConsumer {
            name: "Orders partner".to_owned(),
            description: None,
            credential_kind: "api_key".to_owned(),
        },
    )
    .send(tess)
    .await
    .ok();
    let key = partner.api_key.expect("the key is shown once");
    let host = app_host(&world).await;
    let feed = SocketApp::start(&stack, &host)
        .await
        .expect("the orders feed starts");
    let probe = Client::new(&stack, "a probe").expect("a client for the probe");
    RouteSpec::public("partner-feed", "/live/*")
        .asking(RoutePolicy::Authenticated)
        .pinned("partner-feed")
        .applied(
            tess,
            &probe,
            Placement {
                tenant: world.tenant(),
                upstream: &feed.url(),
                host: &host,
            },
        )
        .await;
    let program = Client::new(&stack, "the partner's program").expect("a client for the partner");
    let address = format!("https://{host}{FEED_PATH}");
    let by_key = || Call::get(&address).header("x-api-key", &key);
    let mut socket = eventually("the partner's socket to open", || async {
        match program.open_socket_by(by_key()).await {
            Opened::Open(socket) => Some(socket),
            Opened::Refused(_) => None,
        }
    })
    .await;

    consumers::disable(world.tenant(), &partner.id)
        .send(tess)
        .await
        .ok();

    assert_closes(&mut socket).await;
    eventually("the partner's key to be refused", || async {
        matches!(program.open_socket_by(by_key()).await, Opened::Refused(_)).then_some(())
    })
    .await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Only the Staff group may reach the live app. Pat's and Uma's sockets are
/// open, each through their place in Staff. Tess takes Pat out: within one
/// recheck the gateway closes her socket, and its record says her access
/// ended. Uma, still in Staff, carries on.
#[tokio::test]
async fn taking_pat_out_of_the_routes_group_closes_her_open_socket() {
    let stack = Stack::start(rechecking()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let app_server = SocketApp::start(&stack, &app_host(&world).await)
        .await
        .expect("the live app starts");
    let spec = RouteSpec::public("live", "/live/*").asking(RoutePolicy::Authenticated);
    let app = HostedApp::opened(&world, "live", spec, &app_server.url()).await;
    let pat = customer(&world, "pat", "Pat Customer").await;
    let uma = customer(&world, "uma", "Uma Colleague").await;
    let quinn = customer(&world, "quinn", "Quinn Contractor").await;
    for person in [&pat, &uma, &quinn] {
        signed_in_on(&app.host, person).await;
    }
    let staff = staff_only(&world, &[&pat, &uma]).await;
    let address = app.page(FEED_PATH);
    eventually("the gateway to refuse who is outside Staff", || async {
        let answer = quinn
            .client()
            .send::<IgnoredAny>(Call::get(address.as_str()))
            .await;
        (answer.status() == Status::FORBIDDEN).then_some(())
    })
    .await;
    let mut pats = pat.client().open_socket(&address).await.open();
    let mut umas = uma.client().open_socket(&address).await.open();

    policies::remove_member(world.tenant(), &staff, "user", pat.id())
        .send(world.admin().client())
        .await
        .ok();

    assert_closes(&mut pats).await;
    assert_still_talks(&mut umas).await;
    assert_close_recorded(&world, &pat).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Waits until `socket` is closed by the gateway, within [`CLOSES_WITHIN`].
async fn assert_closes(socket: &mut Socket) {
    let closed = socket.next_within(CLOSES_WITHIN).await;
    assert!(
        matches!(closed, Some(Frame::Closed(_))),
        "the gateway closes the socket within one recheck: {closed:?}"
    );
}

/// `socket` still carries a message there and back.
async fn assert_still_talks(socket: &mut Socket) {
    socket.send_text("still there").await;
    assert_eq!(
        socket.next_within(ANSWER_WITHIN).await,
        Some(Frame::Text("heard: still there".to_owned())),
        "the other person's socket stays open"
    );
}

/// `person`'s handshake record says the gateway closed the socket because
/// their access ended.
async fn assert_close_recorded(world: &World<'_>, person: &Person) {
    let record = Records::of_tenant(world.admin().client(), world.tenant())
        .recorded_where(FEED_PATH, "the closed", |record| {
            record.subject.id.as_deref() == Some(person.id()) && record.closed.is_some()
        })
        .await;
    assert_eq!(record.decision, "allowed", "the handshake stays allowed");
    let closed = record.closed.expect("the record names the close");
    assert_eq!(closed.reason, "access_ended", "the close says access ended");
}

/// Tess makes a Staff group holding `members` and a policy refusing all
/// but Staff; Ann makes it live. Answers the group's id.
async fn staff_only(world: &World<'_>, members: &[&Person]) -> String {
    let tess = world.admin().client();
    let group = policies::create_group(
        world.tenant(),
        &NewGroup {
            name: "Staff".to_owned(),
        },
    )
    .send(tess)
    .await
    .ok()
    .id;
    for member in members {
        policies::add_member(
            world.tenant(),
            &group,
            &NewGroupMember {
                kind: "user".to_owned(),
                id: member.id().to_owned(),
            },
        )
        .send(tess)
        .await
        .ok();
    }
    let blank = BlankDraft {
        from: "blank".to_owned(),
        default_action: json!({ "Deny": { "reason": "Only staff get in" } }),
    };
    policies::start_draft(world.tenant(), &blank)
        .send(tess)
        .await
        .ok();
    let rule = NewRule {
        name: "staff-in".to_owned(),
        conditions: vec![json!({ "GroupIs": group })],
        action: json!("Allow"),
        priority: 10,
    };
    policies::add_rule(world.tenant(), &rule)
        .send(tess)
        .await
        .ok();
    policies::move_on(world.tenant(), "submit_for_review")
        .send(tess)
        .await
        .ok();
    policies::move_on(world.tenant(), "activate")
        .send(world.owner().client())
        .await
        .ok();
    group
}
