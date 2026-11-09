//! What the endpoint does with the people its directory makes: which role
//! it may give them, and whether they wait for their mailbox.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{directory, people, roles};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::directory::{DirectoryPatch, DirectoryRecord, DirectorySettings};
use ianua_scenarios::wire::roles::{NewRole, RoleChange, SystemPermission};
use ianua_scenarios::world::World;
use serde_json::Value;

use crate::support::{OnRemove, linked_directory, made, proved_mailbox};

/// The audit record a settings change leaves.
const SETTINGS_UPDATED: &str = "federation.scim_settings_updated";

/// The directory's settings with `default_role_id` given to new accounts,
/// people let in at once and kept when removed.
fn giving(default_role_id: Option<String>) -> DirectorySettings {
    DirectorySettings {
        default_role_id,
        auto_activate: true,
        deactivate_on_remove: true,
    }
}

/// A role called `name` carrying the permission `permission` on `area`,
/// made by Tess.
async fn role(world: &World<'_>, name: &str, area: &str, permission: &str) -> String {
    roles::create(
        world.tenant(),
        &NewRole {
            name: name.to_owned(),
            system_permissions: vec![SystemPermission::new(area, permission)],
        },
    )
    .send(world.admin().client())
    .await
    .ok()
    .id
}

/// The names of the roles Tess reads on `person`.
async fn role_names(world: &World<'_>, person: &Person) -> Vec<String> {
    let found = people::list(world.tenant(), Some(person.email()))
        .send(world.admin().client())
        .await
        .ok();
    let [listed] = found.items.as_slice() else {
        panic!("Tess finds {} alone: {found:?}", person.email());
    };
    listed.roles.iter().map(|role| role.name.clone()).collect()
}

/// The link's `name` setting, as Tess reads it.
async fn setting(world: &World<'_>, name: &str) -> Value {
    directory::status(world.tenant())
        .send(world.admin().client())
        .await
        .ok()
        .rest["settings"][name]
        .clone()
}

/// A record for `person`, as the directory sends one.
fn record_of(person: &Person) -> DirectoryRecord {
    DirectoryRecord {
        user_name: person.email().to_owned(),
        ..DirectoryRecord::default()
    }
}

/// Fails unless the directory's creation of `person` is refused as
/// forbidden and opens no account.
async fn assert_refused_a_place(world: &World<'_>, linked: &Client, person: &Person) {
    directory::create_record(world.tenant(), &record_of(person))
        .send(linked)
        .await
        .refused(Status::FORBIDDEN, "");
    let nobody = directory::find_users(
        world.tenant(),
        &format!("userName eq \"{}\"", person.email()),
    )
    .send(linked)
    .await
    .ok();
    assert_eq!(nobody.total_results, 0, "the refused record opened nothing");
}

/// Tess tries to have the directory give new people a role that reads
/// users: refused, since nobody chooses each person a directory makes,
/// and the setting stays empty with nothing recorded. A role that reads
/// only the metrics overview is accepted, and Pat, made next, holds it.
/// While it is named Tess may not delete it. When Tess herself adds
/// reading users to the role, the directory stops making people, Quinn
/// refused and not made, until Tess takes the role off the link and Uma
/// is made without it.
#[tokio::test]
async fn the_directory_gives_new_people_only_a_role_without_built_in_power() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let linked = linked_directory(&world, OnRemove::Deactivate).await;
    let powerful = role(&world, "People readers", "Users", "View").await;
    let plain = role(&world, "Directory staff", "Metrics", "View").await;
    let updates = world.trail().count(SETTINGS_UPDATED).await;

    directory::replace_settings(world.tenant(), &giving(Some(powerful)))
        .send(world.admin().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    assert!(setting(&world, "default_role_id").await.is_null());
    assert_eq!(
        world.trail().count(SETTINGS_UPDATED).await,
        updates,
        "a refused role records no change"
    );

    directory::replace_settings(world.tenant(), &giving(Some(plain.clone())))
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(setting(&world, "default_role_id").await, plain.as_str());
    assert_eq!(
        world.trail().count(SETTINGS_UPDATED).await,
        updates + 1,
        "the change is recorded once"
    );

    let pat = made(&world, &linked, "pat").await;
    assert!(
        role_names(&world, &pat)
            .await
            .iter()
            .any(|name| name == "Directory staff"),
        "Pat starts with the directory's role"
    );

    let delete_named = roles::remove(world.tenant(), &plain)
        .send(world.admin().client())
        .await;
    assert_eq!(
        delete_named.status(),
        Status::CONFLICT,
        "the role the link names stays: {}",
        delete_named.summary()
    );

    roles::change(
        world.tenant(),
        &plain,
        &RoleChange {
            name: None,
            system_permissions: Some(vec![
                SystemPermission::new("Metrics", "View"),
                SystemPermission::new("Users", "View"),
            ]),
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    let quinn = world.newcomer("quinn", "Quinn Waiting");
    assert_refused_a_place(&world, &linked, &quinn).await;

    directory::replace_settings(world.tenant(), &giving(None))
        .send(world.admin().client())
        .await
        .ok();
    let uma = made(&world, &linked, "uma").await;
    assert!(
        role_names(&world, &uma)
            .await
            .iter()
            .all(|name| name != "Directory staff"),
        "a link naming no role gives none"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess has new people wait for their own mailbox. The directory makes
/// Pat: Tess reads her waiting and the directory reads her switched off.
/// Pat follows the link mailed to her: she is active and her mailbox
/// proved, and the directory reads her switched on. Tess goes back to
/// letting people in at once, but a record that arrives switched off is
/// not let in by that: the directory sends Uma off, and she is deactivated
/// until it lets her in itself, when her link is mailed and she proves her
/// mailbox.
#[tokio::test]
async fn people_wait_for_their_mailbox_only_when_tess_says_so() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let linked = linked_directory(&world, OnRemove::Deactivate).await;
    directory::replace_settings(
        world.tenant(),
        &DirectorySettings {
            default_role_id: None,
            auto_activate: false,
            deactivate_on_remove: true,
        },
    )
    .send(world.admin().client())
    .await
    .ok();

    let pat = made(&world, &linked, "pat").await;
    let waiting = people::get(world.tenant(), pat.id())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(waiting.status, "PendingVerification");
    assert!(
        !directory::get_user(world.tenant(), pat.id())
            .send(&linked)
            .await
            .ok()
            .active,
        "the directory reads Pat as not yet in"
    );

    proved_mailbox(&world, pat.email()).await;
    let proved = people::get(world.tenant(), pat.id())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(proved.status, "Active", "her own mailbox lets Pat in");
    assert!(proved.email_verified);
    assert!(
        directory::get_user(world.tenant(), pat.id())
            .send(&linked)
            .await
            .ok()
            .active
    );

    directory::replace_settings(world.tenant(), &giving(None))
        .send(world.admin().client())
        .await
        .ok();
    let uma = world.newcomer("uma", "Uma Off");
    let off = DirectoryRecord {
        active: Some(false),
        ..record_of(&uma)
    };
    let uma_id = directory::create_record(world.tenant(), &off)
        .send(&linked)
        .await
        .ok()
        .id;
    let stays_out = people::get(world.tenant(), &uma_id)
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(
        stays_out.status, "Deactivated",
        "a record sent off stays off"
    );
    directory::patch_user(world.tenant(), &uma_id, &DirectoryPatch::reactivation())
        .send(&linked)
        .await
        .ok();
    let let_in = people::get(world.tenant(), &uma_id)
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(let_in.status, "Active", "the directory lets her in itself");
    proved_mailbox(&world, uma.email()).await;
    let proved_uma = people::get(world.tenant(), &uma_id)
        .send(world.admin().client())
        .await
        .ok();
    assert!(
        proved_uma.email_verified,
        "the link reached Uma once let in"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Max, Sam and nobody signed in may not change what the directory does
/// with the people it makes. A tenant whose link was never set up has no
/// settings to change: Sam's twin is told so.
#[tokio::test]
async fn only_tess_changes_what_the_directory_does() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    linked_directory(&world, OnRemove::Deactivate).await;

    Matrix::new(
        "changing what the directory does",
        directory::replace_settings(world.tenant(), &giving(None)).call(),
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

    let twin = directory::replace_settings(world.twin(), &giving(None))
        .send(world.stranger().client())
        .await;
    assert_eq!(
        twin.status(),
        Status::NOT_FOUND,
        "a link never set up has no settings: {}",
        twin.summary()
    );

    stack.stop().await.expect("the stack stops cleanly");
}
