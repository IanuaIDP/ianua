//! Uma may manage people's records and roles, but not deactivate anyone,
//! and she wants to. She tries every road from what she holds to more:
//! a new role carrying the right, the same right written into the role she
//! holds, and the tenant's Admin role given to herself. Each is refused,
//! she still cannot deactivate Pat, and a role holding only what she holds
//! is hers to make and give.

use ianua_scenarios::api::{people, roles};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::roles::{AssignRole, NewRole, RoleChange, SystemPermission};
use ianua_scenarios::world::{ADMIN_ROLE, World};

use crate::support::{person, role_with};

/// What Uma holds: people's records and roles, read and changed.
const UMAS_RIGHTS: [(&str, &str); 5] = [
    ("Users", "View"),
    ("Users", "Update"),
    ("Roles", "View"),
    ("Roles", "Create"),
    ("Roles", "Update"),
];

/// Tess gives Uma a role holding people's records and roles. Uma makes a
/// role that may deactivate people, writes that right into her own role,
/// and gives herself the Admin role: each is refused as forbidden, and she
/// still cannot deactivate Pat. Uma then makes a role that may only read
/// people and gives it to Pat, which she may.
#[tokio::test]
async fn uma_cannot_climb_from_what_she_holds_to_what_she_does_not() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let uma = person(&world, "uma").await;
    let pat = person(&world, "pat").await;
    let umas_role = role_with(&world, "Record keepers", &UMAS_RIGHTS).await;
    roles::assign(world.tenant(), &umas_role, &to(uma.id()))
        .send(world.admin().client())
        .await
        .ok();
    let deactivating = vec![SystemPermission::new("Users", "Deactivate")];

    let made = NewRole {
        name: "Cleaners".to_owned(),
        system_permissions: deactivating.clone(),
    };
    roles::create(world.tenant(), &made)
        .send(uma.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let widened = RoleChange {
        name: None,
        system_permissions: Some(
            UMAS_RIGHTS
                .iter()
                .map(|(resource, action)| SystemPermission::new(resource, action))
                .chain(deactivating)
                .collect(),
        ),
    };
    roles::change(world.tenant(), &umas_role, &widened)
        .send(uma.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    roles::assign(
        world.tenant(),
        &world.role_id(ADMIN_ROLE).await,
        &to(uma.id()),
    )
    .send(uma.client())
    .await
    .refused(Status::FORBIDDEN, "forbidden");
    people::deactivate(world.tenant(), pat.id())
        .send(uma.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    let readers = NewRole {
        name: "Readers".to_owned(),
        system_permissions: vec![SystemPermission::new("Users", "View")],
    };
    let readers = roles::create(world.tenant(), &readers)
        .send(uma.client())
        .await
        .ok();
    roles::assign(world.tenant(), &readers.id, &to(pat.id()))
        .send(uma.client())
        .await
        .ok();
    let pat_now = people::get(world.tenant(), pat.id())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(pat_now.status, "Active", "Pat was never deactivated");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Giving a role to the person `user_id`.
fn to(user_id: &str) -> AssignRole {
    AssignRole {
        user_id: user_id.to_owned(),
    }
}
