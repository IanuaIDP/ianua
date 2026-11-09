//! A program calling the tenant's API with a key Tess made for it: it
//! reads what its scopes allow and nothing in Sam's tenant, loses the read
//! when its scopes narrow and gets it back when they widen, and dies when
//! Tess revokes the key while its replacement goes on. Max, Sam and
//! nobody signed in cannot revoke a key.

use ianua_scenarios::actors::{KeyHolder, KeyRequest};
use ianua_scenarios::api::{api_keys, people};
use ianua_scenarios::expect::{Matrix, no_secret_leaked};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::api_keys::ApiKeyChange;
use ianua_scenarios::world::World;

/// Tess makes a key for a program that reads people and metrics. It
/// reads the tenant's people and not Sam's. Narrowing its scopes to none
/// is refused and changes nothing; narrowed to metrics it reads no
/// people; widened again it does. Tess makes a replacement key and
/// revokes the first: the first reads nothing any more, the replacement
/// reads on, and the revocation's one record shows neither key.
#[tokio::test]
async fn a_programs_key_reads_what_its_scopes_allow_until_it_is_revoked() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let original = KeyHolder::issued_by(
        &stack,
        world.admin(),
        world.tenant(),
        KeyRequest {
            name: "directory reader",
            scopes: &["idp:users:view", "idp:metrics:view"],
        },
    )
    .await;

    check_original_access(&world, &original).await;
    narrow_scopes(&world, &original).await;
    restore_people_scope(&world, &original).await;
    replace_key(&world, &original).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// The original key reads only its tenant, and an empty scope update leaves that access intact.
async fn check_original_access(world: &World<'_>, original: &KeyHolder) {
    people::list(world.tenant(), None)
        .send(original.client())
        .await
        .ok();
    people::list(world.twin(), None)
        .send(original.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    let no_scopes = ApiKeyChange {
        scopes: Some(vec![]),
        ..Default::default()
    };
    api_keys::change(world.tenant(), original.key_id(), &no_scopes)
        .send(world.admin().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    people::list(world.tenant(), None)
        .send(original.client())
        .await
        .ok();
}

/// Removing the people scope takes effect on the key's next request.
async fn narrow_scopes(world: &World<'_>, original: &KeyHolder) {
    let metrics_alone = ApiKeyChange {
        scopes: Some(vec!["idp:metrics:view".to_owned()]),
        ..Default::default()
    };
    api_keys::change(world.tenant(), original.key_id(), &metrics_alone)
        .send(world.admin().client())
        .await
        .ok();
    people::list(world.tenant(), None)
        .send(original.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// Restoring the people scope lets the same key read people again.
async fn restore_people_scope(world: &World<'_>, original: &KeyHolder) {
    let people_again = ApiKeyChange {
        scopes: Some(vec!["idp:users:view".to_owned()]),
        ..Default::default()
    };
    api_keys::change(world.tenant(), original.key_id(), &people_again)
        .send(world.admin().client())
        .await
        .ok();
    people::list(world.tenant(), None)
        .send(original.client())
        .await
        .ok();
}

/// A replacement reads before and after the original key is revoked.
async fn replace_key(world: &World<'_>, original: &KeyHolder) {
    let replacement = KeyHolder::issued_by(
        world.stack(),
        world.admin(),
        world.tenant(),
        KeyRequest {
            name: "replacement directory reader",
            scopes: &["idp:users:view"],
        },
    )
    .await;
    people::list(world.tenant(), None)
        .send(replacement.client())
        .await
        .ok();
    api_keys::revoke(world.tenant(), original.key_id())
        .send(world.admin().client())
        .await
        .ok();
    people::list(world.tenant(), None)
        .send(original.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    people::list(world.tenant(), None)
        .send(replacement.client())
        .await
        .ok();

    check_revocation_record(world, original, &replacement).await;
}

/// The single revocation record contains neither key's secret.
async fn check_revocation_record(world: &World<'_>, original: &KeyHolder, replacement: &KeyHolder) {
    let records = world.trail().entries("oauth.api_key_revoked").await;
    assert_eq!(records.len(), 1, "one revocation is recorded");
    for record in records {
        no_secret_leaked(
            &record.details.to_string(),
            &[original.secret(), replacement.secret()],
        );
    }
}

/// Max, Sam and an anonymous visitor cannot revoke the key Tess made for
/// a program. The program still reads with it, and nothing
/// recorded a revocation.
#[tokio::test]
async fn only_the_tenants_administrator_revokes_a_programs_key() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let program = KeyHolder::issued_by(
        &stack,
        world.admin(),
        world.tenant(),
        KeyRequest {
            name: "directory reader",
            scopes: &["idp:users:view"],
        },
    )
    .await;
    people::list(world.tenant(), None)
        .send(program.client())
        .await
        .ok();

    refuse_other_revokers(&world, &program).await;
    check_key_survived(&world, &program).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Refused revocations leave the key usable and produce no revocation record.
async fn check_key_survived(world: &World<'_>, program: &KeyHolder) {
    people::list(world.tenant(), None)
        .send(program.client())
        .await
        .ok();
    assert_eq!(
        world.trail().count("oauth.api_key_revoked").await,
        0,
        "a refused revocation records nothing"
    );
}

/// Members, outsiders and anonymous visitors cannot revoke the program's key.
async fn refuse_other_revokers(world: &World<'_>, program: &KeyHolder) {
    Matrix::new(
        "revoking the program's key",
        api_keys::revoke(world.tenant(), program.key_id()).call(),
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
}
