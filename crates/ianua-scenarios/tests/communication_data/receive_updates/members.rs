//! Ann's inbox as the owner of her company: Tess, who runs a tenant for
//! her, changes what someone may do there, and Ann hears of it in the
//! company's inbox. She reads one notice, then all, each read on record.
//! Max cannot mark Ann's notices, Sam and nobody signed in reach no inbox
//! of hers, and a read they were refused leaves no record.

use ianua_scenarios::api::notifications;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::world::World;

use crate::support::{
    AUTHORIZATION, READ_ALL, READ_ONE, fresh_member_notice, give_role, member_ids, person,
    reader_role,
};

/// Tess gives Pat the reader role in the tenant. Ann finds an unread
/// notice about it in her company inbox and the bell counts it. She marks
/// it read: it leaves her unread list and shows read in her inbox. Then
/// she marks everything read, and none of the notices she had before is
/// unread any more. Both reads are on record; Max's try at marking Ann's
/// notice is refused and adds no record.
#[tokio::test]
async fn ann_hears_of_tess_s_change_in_her_company_inbox_and_reads_it() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let role = reader_role(&world).await;
    let trail_before = world.trail().ids().await;
    let ann = world.owner().client();
    let seen = member_ids(world.org(), ann).await;

    give_role(&world, &pat, &role).await;
    let told = fresh_member_notice(world.org(), ann, &seen, AUTHORIZATION).await;
    let badge = notifications::member_unread_count(world.org())
        .send(ann)
        .await
        .ok();
    assert!(badge.count >= 1, "Ann's bell counts the notice");

    notifications::member_mark_read(world.org(), &told.id)
        .send(ann)
        .await
        .ok();
    let unread = notifications::member_unread(world.org())
        .send(ann)
        .await
        .ok();
    assert!(
        unread.items.iter().all(|notice| notice.id != told.id),
        "a notice Ann read leaves her unread list"
    );
    let inbox = notifications::member_inbox(world.org())
        .send(ann)
        .await
        .ok();
    let held: Vec<String> = inbox.items.iter().map(|notice| notice.id.clone()).collect();
    let shown = inbox.items.iter().find(|notice| notice.id == told.id);
    assert!(
        shown.is_some_and(|notice| notice.read),
        "the notice still shows in Ann's inbox, read"
    );

    notifications::member_mark_all_read(world.org())
        .send(ann)
        .await
        .ok();
    let unread = notifications::member_unread(world.org())
        .send(ann)
        .await
        .ok();
    assert!(
        unread.items.iter().all(|notice| !held.contains(&notice.id)),
        "every notice Ann held is read"
    );
    world.trail().recorded_after(&trail_before, READ_ONE).await;
    world.trail().recorded_after(&trail_before, READ_ALL).await;

    let reads_before = world.trail().count(READ_ONE).await;
    notifications::member_mark_read(world.org(), &told.id)
        .send(world.member().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    assert_eq!(
        world.trail().count(READ_ONE).await,
        reads_before,
        "a refused read adds no record"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ann has an unread notice about Tess's change. Max, a member of the
/// same company, is told it is not found, as it is not in his inbox; Sam,
/// from the other company, is forbidden; nobody signed in is asked to
/// sign in. Ann still finds the notice unread.
#[tokio::test]
async fn nobody_but_ann_marks_ann_s_notices_read() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let role = reader_role(&world).await;
    let ann = world.owner().client();
    let seen = member_ids(world.org(), ann).await;
    give_role(&world, &pat, &role).await;
    let told = fresh_member_notice(world.org(), ann, &seen, AUTHORIZATION).await;

    Matrix::new(
        "marking Ann's notice read",
        notifications::member_mark_read(world.org(), &told.id).call(),
    )
    .refused(world.member().client(), Status::NOT_FOUND, "not_found")
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;
    Matrix::new(
        "reading the company inbox",
        notifications::member_inbox(world.org()).call(),
    )
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;

    let unread = notifications::member_unread(world.org())
        .send(ann)
        .await
        .ok();
    assert!(
        unread.items.iter().any(|notice| notice.id == told.id),
        "Ann's notice is still unread"
    );

    stack.stop().await.expect("the stack stops cleanly");
}
