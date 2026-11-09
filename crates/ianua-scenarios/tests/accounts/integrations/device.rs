//! Pat signs in a television that cannot show a browser (RFC 8628): the
//! TV asks for codes, shows a short one, and Pat types it in her own
//! session to approve or refuse it. The TV collects tokens that stand for
//! Pat only after she approved, gets nothing after she refused, and keeps
//! waiting while nobody answered. Uma, Sam and nobody signed in approve
//! nothing for it.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{oauth, people};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::oauth::{
    ClientRegistered, DeviceAnswer, DeviceAsk, DeviceCodes, DevicePoll, NewClient,
};
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::world::{MEMBER_ROLE, World};

/// The scopes the TV asks for.
const SCOPE: &str = "openid email";

/// The record a device asking for codes leaves.
const REQUESTED: &str = "oauth.device_authorization_requested";

/// The record a person approving a device leaves.
const APPROVED: &str = "oauth.device_authorization_approved";

/// The record a person refusing a device leaves.
const DENIED: &str = "oauth.device_authorization_denied";

/// The record the device collecting its approval leaves.
const COLLECTED: &str = "oauth.device_authorization_collected";

/// The TV's app, registered by Tess as a public client that may use the
/// device flow and nothing else.
async fn tv_app(world: &World<'_>) -> ClientRegistered {
    let client = NewClient {
        name: "Living room TV".to_owned(),
        redirect_uris: Vec::new(),
        grant_types: vec!["DeviceCode".to_owned()],
        scopes: SCOPE.split(' ').map(str::to_owned).collect(),
        token_endpoint_auth_method: "none".to_owned(),
        post_logout_redirect_uris: Vec::new(),
    };
    oauth::register_client(world.tenant(), &client)
        .send(world.admin().client())
        .await
        .ok()
}

/// Someone at the address `name`, invited into the tenant by Tess with
/// its `Member` role, who accepted from the mailed link and signed in.
async fn person(world: &World<'_>, name: &str) -> Person {
    let mut person = world.newcomer(name, &format!("{name} Viewer"));
    let invitation = people::invite(
        world.tenant(),
        &InviteUser {
            email: person.email().to_owned(),
            display_name: person.account().display_name.clone(),
            role_id: world.role_id(MEMBER_ROLE).await,
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    person.record_invitation(&invitation.id);
    person.accept_invitation(world.stack()).await;
    person.sign_in(world.stack()).await;
    person
}

/// The TV asks for its codes.
async fn codes(world: &World<'_>, tv: &Client, app: &ClientRegistered) -> DeviceCodes {
    let ask = DeviceAsk {
        client_id: app.client_id.clone(),
        scope: SCOPE.to_owned(),
    };
    oauth::device_codes(world.tenant(), &ask)
        .send(tv)
        .await
        .ok()
}

/// The TV's poll with the device code of `codes`.
fn poll(app: &ClientRegistered, codes: &DeviceCodes) -> DevicePoll {
    DevicePoll {
        client_id: app.client_id.clone(),
        device_code: codes.device_code.clone(),
    }
}

/// The short code of `codes`, as Pat types it.
fn typed(codes: &DeviceCodes) -> DeviceAnswer {
    DeviceAnswer {
        user_code: codes.user_code.clone(),
    }
}

/// The TV asks for codes, on record, and shows the short one with the
/// page to type it on. Pat types it in her session and approves, on
/// record. The TV's poll collects tokens, on record, and the access token
/// stands for Pat, with her address.
#[tokio::test]
async fn pat_signs_her_tv_in_by_typing_the_code_it_shows() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let app = tv_app(&world).await;
    let tv = Client::new(&stack, "Pat's TV").expect("a client");
    let seen = world.trail().ids().await;

    let shown = codes(&world, &tv, &app).await;
    assert!(!shown.verification_uri.is_empty(), "the TV shows a page");
    assert!(
        shown.verification_uri_complete.contains(&shown.user_code),
        "the page with the code filled in carries the code"
    );
    assert!(shown.interval >= 1, "the TV is told how long to wait");
    world.trail().recorded_after(&seen, REQUESTED).await;

    oauth::approve_device(world.tenant(), &typed(&shown))
        .send(pat.client())
        .await
        .ok();
    world.trail().recorded_after(&seen, APPROVED).await;

    let tokens = oauth::device_token(world.tenant(), &poll(&app, &shown))
        .send(&tv)
        .await
        .ok();
    world.trail().recorded_after(&seen, COLLECTED).await;
    let who = oauth::user_info(world.tenant(), &tokens.access_token)
        .send(&tv)
        .await
        .ok();
    assert_eq!(who.sub, pat.id(), "the TV is signed in as Pat");
    assert_eq!(who.email.as_deref(), Some(pat.email()));

    stack.stop().await.expect("the stack stops cleanly");
}

/// The TV asks for codes nobody answers: its poll is told to keep
/// waiting. A second request Pat did not start, she refuses, on record:
/// the TV's poll is told she refused, and she cannot approve it after
/// all. A code no device shows is not found.
#[tokio::test]
async fn pat_refuses_a_tv_she_did_not_start_and_an_unanswered_one_waits() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let app = tv_app(&world).await;
    let tv = Client::new(&stack, "a TV in the lobby").expect("a client");
    let seen = world.trail().ids().await;

    let waiting = codes(&world, &tv, &app).await;
    oauth::device_token(world.tenant(), &poll(&app, &waiting))
        .send(&tv)
        .await
        .refused(Status::BAD_REQUEST, "authorization_pending");

    let unasked = codes(&world, &tv, &app).await;
    oauth::deny_device(world.tenant(), &typed(&unasked))
        .send(pat.client())
        .await
        .ok();
    world.trail().recorded_after(&seen, DENIED).await;
    oauth::device_token(world.tenant(), &poll(&app, &unasked))
        .send(&tv)
        .await
        .refused(Status::BAD_REQUEST, "access_denied");
    oauth::approve_device(world.tenant(), &typed(&unasked))
        .send(pat.client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    world.trail().nothing_after(&seen, APPROVED).await;

    let made_up = DeviceAnswer {
        user_code: "ZZZZ-9999".to_owned(),
    };
    oauth::approve_device(world.tenant(), &made_up)
        .send(pat.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");

    stack.stop().await.expect("the stack stops cleanly");
}

/// The TV shows a code. Sam, from the other company, and nobody signed in
/// may not approve or refuse it in Pat's tenant. Nothing is recorded and
/// the TV, polling, is still told to wait.
#[tokio::test]
async fn nobody_outside_the_tenant_answers_for_pat_s_tv() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let app = tv_app(&world).await;
    let tv = Client::new(&stack, "Pat's TV").expect("a client");
    let shown = codes(&world, &tv, &app).await;
    let seen = world.trail().ids().await;

    for request in [
        oauth::approve_device(world.tenant(), &typed(&shown)).call(),
        oauth::deny_device(world.tenant(), &typed(&shown)).call(),
    ] {
        Matrix::new("answering for Pat's TV", request)
            .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
            .refused(
                world.anonymous().client(),
                Status::UNAUTHORIZED,
                "unauthenticated",
            )
            .run()
            .await;
    }

    world.trail().nothing_after(&seen, APPROVED).await;
    world.trail().nothing_after(&seen, DENIED).await;
    oauth::device_token(world.tenant(), &poll(&app, &shown))
        .send(&tv)
        .await
        .refused(Status::BAD_REQUEST, "authorization_pending");

    stack.stop().await.expect("the stack stops cleanly");
}
