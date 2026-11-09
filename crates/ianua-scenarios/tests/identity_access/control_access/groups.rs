//! Groups read, renamed, moved and deleted: a group inherits the roles of
//! the group above it, so moving it changes what its members hold, at
//! once; a group with children stays until they move or go. Whoever lacks
//! the right moves and deletes nothing.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::control_access;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::control_access::{GroupPlacement, GroupRename};
use ianua_scenarios::world::World;

use crate::support::{
    add_to_group, comes_to_be_refused, comes_to_read, group, group_with_role, person, reader,
    reads_the_users, refused_the_users,
};

/// Where a group moves under `parent`.
fn under(parent: &str) -> GroupPlacement {
    GroupPlacement {
        parent_id: Some(parent.to_owned()),
    }
}

/// The top of the tree.
fn to_the_top() -> GroupPlacement {
    GroupPlacement { parent_id: None }
}

/// Pat is in Night shift, a group holding nothing, and reads no users.
/// Tess moves it under Readers, a group holding the reader role: Pat reads
/// at once through what the group inherits, and the group shows its new
/// parent. Tess moves it back to the top of the tree: Pat is refused
/// again. Max, Sam and nobody signed in may not move it, a group may not
/// move under itself or its descendant, and a parent nobody knows is
/// refused. The move is recorded.
#[tokio::test]
async fn moving_a_group_changes_what_its_members_inherit_at_once() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let role = reader(&world).await;
    let readers = group_with_role(&world, "Readers", &role).await;
    let night_shift = group(&world, "Night shift").await;
    add_to_group(&world, &night_shift, &pat).await;
    refused_the_users(&world, &pat).await;

    Matrix::new(
        "moving a group",
        control_access::move_group(world.tenant(), &night_shift, &under(&readers)).call(),
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
    refused_the_users(&world, &pat).await;

    control_access::move_group(world.tenant(), &night_shift, &under(&readers))
        .send(world.admin().client())
        .await
        .ok();
    comes_to_read(&world, &pat, "once Night shift is under Readers").await;
    let moved = control_access::get_group(world.tenant(), &night_shift)
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(moved.parent_id.as_deref(), Some(readers.as_str()));
    let access = control_access::principal_access(world.tenant(), "user", pat.id())
        .send(world.admin().client())
        .await
        .ok();
    assert!(
        access
            .through_groups
            .iter()
            .any(|held| held.role.id == role),
        "Pat holds the role through the group above"
    );

    control_access::move_group(world.tenant(), &readers, &under(&night_shift))
        .send(world.admin().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    control_access::move_group(world.tenant(), &night_shift, &under(&night_shift))
        .send(world.admin().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    control_access::move_group(
        world.tenant(),
        &night_shift,
        &under("00000000-0000-4000-8000-000000000000"),
    )
    .send(world.admin().client())
    .await
    .refused(Status::NOT_FOUND, "not_found");

    control_access::move_group(world.tenant(), &night_shift, &to_the_top())
        .send(world.admin().client())
        .await
        .ok();
    comes_to_be_refused(&world, &pat, "once Night shift is at the top").await;
    world.trail().recorded("authorization.group_moved").await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess renames Finance to Accounts, reads it back and lists it; Sam and
/// Max read nothing of it, and a name another group has is refused.
/// Deleting Readers while Accounts sits under it is refused; once Accounts
/// is gone Readers can be deleted, Pat, who sat in Accounts and read the
/// users through it, loses that at once. The groups read back gone, and
/// the rename and both deletions are recorded.
#[tokio::test]
async fn a_group_is_renamed_read_and_deleted_children_first() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let role = reader(&world).await;
    let readers = group_with_role(&world, "Readers", &role).await;
    let finance = group(&world, "Finance").await;
    control_access::move_group(world.tenant(), &finance, &under(&readers))
        .send(world.admin().client())
        .await
        .ok();
    add_to_group(&world, &finance, &pat).await;
    reads_the_users(&world, &pat).await;

    Matrix::new(
        "reading a group",
        control_access::get_group(world.tenant(), &finance).call(),
    )
    .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .run()
    .await;
    rename_finance(&world, &finance, &pat).await;
    delete_children_first(&world, &readers, &finance, &pat).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess renames Finance to Accounts, and may not take Readers' name; Max
/// renames nothing.
async fn rename_finance(world: &World<'_>, finance: &str, pat: &Person) {
    let tess = world.admin().client();
    let rename = GroupRename {
        name: "Accounts".to_owned(),
    };
    control_access::rename_group(world.tenant(), finance, &rename)
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    control_access::rename_group(world.tenant(), finance, &rename)
        .send(tess)
        .await
        .ok();
    let renamed = control_access::get_group(world.tenant(), finance)
        .send(tess)
        .await
        .ok();
    assert_eq!(renamed.name, "Accounts");
    let listed = control_access::list_groups(world.tenant())
        .send(tess)
        .await
        .ok();
    assert!(
        listed.items.iter().any(|group| group.name == "Accounts"),
        "the new name is listed"
    );
    let taken = GroupRename {
        name: "Readers".to_owned(),
    };
    control_access::rename_group(world.tenant(), finance, &taken)
        .send(tess)
        .await
        .refused(Status::CONFLICT, "conflict");
    world.trail().recorded("authorization.group_renamed").await;
    reads_the_users(world, pat).await;
}

/// A group with a child is refused deletion; the child's deletion ends
/// its members' access, and the parent may then go.
async fn delete_children_first(world: &World<'_>, readers: &str, finance: &str, pat: &Person) {
    let tess = world.admin().client();
    control_access::delete_group(world.tenant(), readers)
        .send(tess)
        .await
        .refused(Status::CONFLICT, "conflict");
    control_access::delete_group(world.tenant(), finance)
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    control_access::delete_group(world.tenant(), finance)
        .send(tess)
        .await
        .ok();
    comes_to_be_refused(world, pat, "with her group deleted").await;
    control_access::delete_group(world.tenant(), readers)
        .send(tess)
        .await
        .ok();
    control_access::get_group(world.tenant(), readers)
        .send(tess)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    assert_eq!(
        world.trail().count("authorization.group_deleted").await,
        2,
        "each deletion is recorded"
    );
}
