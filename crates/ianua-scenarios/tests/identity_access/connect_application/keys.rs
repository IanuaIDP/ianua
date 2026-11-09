//! A program's API key: Tess pauses and resumes it, and the record shows
//! each step and never the key; it reaches only its scopes, and nobody
//! makes a key they could not hold themselves.

use ianua_scenarios::actors::{KeyHolder, KeyRequest};
use ianua_scenarios::api::{api_keys, people};
use ianua_scenarios::expect::{Matrix, no_secret_leaked};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::api_keys::NewApiKey;
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::world::{MEMBER_ROLE, World};

/// The scope the program's key is made with.
const VIEW_PEOPLE: &str = "idp:users:view";

/// A scope reaching what the program's key does not.
const MANAGE_PEOPLE: &str = "idp:users:manage";

/// The records a key's life leaves, in order.
const LIFE: [&str; 3] = [
    "oauth.api_key_created",
    "oauth.api_key_paused",
    "oauth.api_key_resumed",
];

/// A program's key, made by Tess to read people.
async fn program(world: &World<'_>) -> KeyHolder {
    KeyHolder::issued_by(
        world.stack(),
        world.admin(),
        world.tenant(),
        KeyRequest {
            name: "directory reader",
            scopes: &[VIEW_PEOPLE],
        },
    )
    .await
}

/// What the tenant's key list says of `program` is its one scope and that
/// it has not been paused; `paused_at` shows once it is. Max, Sam and
/// nobody signed in cannot pause it and it reads on. Tess pauses it: the
/// next call is refused at once and the key is shown as paused. Tess
/// resumes it and it reads again, shown as working. Each of the three
/// steps is on the record, once, and no record shows the key.
#[tokio::test]
async fn tess_pauses_a_key_and_nothing_gets_through_until_she_resumes_it() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let program = program(&world).await;
    let tess = world.admin().client();

    let shown = api_keys::get(world.tenant(), program.key_id())
        .send(tess)
        .await
        .ok();
    assert_eq!(
        shown.scopes,
        [VIEW_PEOPLE],
        "the key shows what it may reach"
    );
    assert_eq!(shown.paused_at, None, "a new key works");

    Matrix::new(
        "pausing the program's key",
        api_keys::pause(world.tenant(), program.key_id()).call(),
    )
    .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;
    people::list(world.tenant(), None)
        .send(program.client())
        .await
        .ok();

    api_keys::pause(world.tenant(), program.key_id())
        .send(tess)
        .await
        .ok();
    people::list(world.tenant(), None)
        .send(program.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let paused = api_keys::get(world.tenant(), program.key_id())
        .send(tess)
        .await
        .ok();
    assert!(paused.paused_at.is_some(), "the key is shown as paused");

    api_keys::resume(world.tenant(), program.key_id())
        .send(tess)
        .await
        .ok();
    people::list(world.tenant(), None)
        .send(program.client())
        .await
        .ok();
    let resumed = api_keys::get(world.tenant(), program.key_id())
        .send(tess)
        .await
        .ok();
    assert_eq!(resumed.paused_at, None, "the key is shown as working");

    for event in LIFE {
        assert_eq!(
            world.trail().count(event).await,
            1,
            "{event} is on record once"
        );
    }
    for record in world.trail().entries("oauth.api_key_").await {
        no_secret_leaked(&record.details.to_string(), &[program.secret()]);
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// A key that may only read people cannot invite anyone or make another
/// key, however much its maker holds. Max, who holds no right to keys,
/// cannot make one at all. Tess gets a refusal for a key with no scope
/// and for a scope that names nothing, and nothing is made.
#[tokio::test]
async fn a_key_reaches_only_its_scopes_and_nobody_makes_more_than_they_hold() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let program = program(&world).await;

    let invitation = InviteUser {
        email: world.address("newcomer"),
        display_name: "A Newcomer".to_owned(),
        role_id: world.role_id(MEMBER_ROLE).await,
    };
    people::invite(world.tenant(), &invitation)
        .send(program.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    let wanted = |scopes: &[&str]| NewApiKey {
        name: "another key".to_owned(),
        scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
    };
    api_keys::create(world.tenant(), &wanted(&[MANAGE_PEOPLE]))
        .send(program.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    api_keys::create(world.tenant(), &wanted(&[VIEW_PEOPLE]))
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    for (scopes, why) in [
        (wanted(&[]), "no scope at all"),
        (wanted(&["idp:nothing:here"]), "a scope naming nothing"),
    ] {
        let answer = api_keys::create(world.tenant(), &scopes)
            .send(world.admin().client())
            .await;
        assert_eq!(
            answer.status(),
            Status::UNPROCESSABLE_ENTITY,
            "{why}: {}",
            answer.summary()
        );
        answer.refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    }
    let keys = api_keys::list(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    assert!(
        keys.items.iter().all(|key| key.name != "another key"),
        "no refused key exists"
    );
    stack.stop().await.expect("the stack stops cleanly");
}
