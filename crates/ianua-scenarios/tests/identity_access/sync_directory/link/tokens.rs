//! Whose directory a token opens: exactly one tenant's, and every other
//! way in is refused the same, in SCIM's own format, with nothing said
//! about which tenants exist.

use ianua_scenarios::api::{OrgPath, directory};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::directory::DirectoryUser;
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;

use crate::support::{OnRemove, holding, linked_directory, made};

/// The media type every SCIM answer carries.
const SCIM_JSON: &str = "application/scim+json";

/// Fails unless `answer` is SCIM's own refusal of a directory it cannot
/// place.
fn assert_not_let_in<T>(answer: &Answer<T>, who: &str) {
    assert_eq!(
        answer.status(),
        Status::UNAUTHORIZED,
        "{who} is refused: {}",
        answer.summary()
    );
    assert!(
        answer
            .header("content-type")
            .is_some_and(|kind| kind.starts_with(SCIM_JSON)),
        "{who}'s refusal is in SCIM's format"
    );
}

/// Sam's directory, linked to the twin tenant with its own token.
async fn twin_directory(world: &World<'_>) -> Client {
    let token = directory::enable(world.twin())
        .send(world.stranger().client())
        .await
        .ok();
    holding(
        world,
        "the twin's directory",
        token
            .bearer_token
            .as_deref()
            .expect("the first setup shows its token"),
    )
}

/// The first tenant's directory keeps Pat. The twin tenant has no link
/// yet, and the first tenant's token is refused there. Sam links the twin
/// and his directory makes Quinn. Each token still lists its own tenant,
/// and is refused on the other: Sam's directory finds no Pat and the
/// first finds no Quinn. No token, a made-up token, a password scheme and
/// a tenant or company that does not exist are all refused exactly alike,
/// so Mallory learns nothing about which tenants are there.
#[tokio::test]
async fn a_token_opens_only_its_own_tenants_directory() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let linked = linked_directory(&world, OnRemove::Deactivate).await;
    let pat = made(&world, &linked, "pat").await;

    assert_not_let_in(
        &directory::list_users(world.twin()).send(&linked).await,
        "a token on a tenant with no link",
    );

    let twin = twin_directory(&world).await;
    let quinn = world.newcomer("quinn", "Quinn Twin");
    directory::create_user(
        world.twin(),
        &DirectoryUser {
            user_name: quinn.email().to_owned(),
            display_name: quinn.account().display_name.clone(),
            active: true,
            external_id: "external-quinn".to_owned(),
        },
    )
    .send(&twin)
    .await
    .ok();

    directory::list_users(world.tenant())
        .send(&linked)
        .await
        .ok();
    directory::list_users(world.twin()).send(&twin).await.ok();
    assert_not_let_in(
        &directory::list_users(world.tenant()).send(&twin).await,
        "the twin's token on the first tenant",
    );
    assert_not_let_in(
        &directory::list_users(world.twin()).send(&linked).await,
        "the first tenant's token on the twin",
    );
    let finds = |filter: String| directory::find_users(world.tenant(), &filter);
    let no_quinn = finds(format!("userName eq \"{}\"", quinn.email()))
        .send(&linked)
        .await
        .ok();
    assert_eq!(no_quinn.total_results, 0, "Quinn is in the other tenant");
    let no_pat = directory::find_users(world.twin(), &format!("userName eq \"{}\"", pat.email()))
        .send(&twin)
        .await
        .ok();
    assert_eq!(no_pat.total_results, 0, "Pat is in the other tenant");

    let lists = directory::list_users(world.tenant());
    assert_not_let_in(
        &lists.clone().send(world.anonymous().client()).await,
        "no token at all",
    );
    let guesser = holding(&world, "Mallory guessing", "a token nobody ever issued");
    assert_not_let_in(&lists.clone().send(&guesser).await, "a made-up token");
    assert_not_let_in(
        &lists
            .clone()
            .header("authorization", "Basic made-up-credential")
            .send(world.anonymous().client())
            .await,
        "a password scheme",
    );
    let other_tenant = world.org().tenant("no-such-tenant");
    assert_not_let_in(
        &directory::list_users(&other_tenant).send(&linked).await,
        "a tenant that does not exist",
    );
    let other_company = OrgPath::new("no-such-company").tenant("anything");
    assert_not_let_in(
        &directory::list_users(&other_company).send(&guesser).await,
        "a company that does not exist",
    );

    stack.stop().await.expect("the stack stops cleanly");
}
