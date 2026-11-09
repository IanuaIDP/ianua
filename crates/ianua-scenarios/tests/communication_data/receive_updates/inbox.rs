//! Pat's inbox in her tenant: Tess gives her a role and takes it back,
//! and Pat finds each in her inbox, unread, with the bell counting them.
//! She reads one, then all, each read on record. Uma, Sam and nobody
//! signed in cannot mark Pat's notices, Uma is told nothing about Pat's
//! role, and a read they were refused leaves no record.

use ianua_scenarios::api::notifications;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::world::World;

use crate::support::{
    AUTHORIZATION, READ_ALL, READ_ONE, fresh_tenant_notice, give_role, person, reader_role,
    take_role, tenant_ids,
};

/// Tess gives Pat the reader role. Pat finds an unread notice about it in
/// her inbox, and the bell counts at least that one. She marks it read: it
/// leaves her unread list and shows read in her inbox. Tess takes the role
/// back, and a second notice comes. Pat marks everything read: at least
/// that one changed, the bell shows nothing and no unread notice is left.
/// Uma, an ordinary user of the same tenant, was told nothing about Pat's
/// role. Both reads are on record; Uma's try at marking Pat's notice is
/// refused and adds no record.
#[tokio::test]
async fn pat_finds_her_role_changes_in_her_inbox_and_reads_them() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let uma = person(&world, "uma").await;
    let role = reader_role(&world).await;
    let trail_before = world.trail().ids().await;
    let uma_before = tenant_ids(world.tenant(), uma.client()).await;

    let seen = tenant_ids(world.tenant(), pat.client()).await;
    give_role(&world, &pat, &role).await;
    let given = fresh_tenant_notice(world.tenant(), pat.client(), &seen, AUTHORIZATION).await;
    let badge = notifications::unread_count(world.tenant())
        .send(pat.client())
        .await
        .ok();
    assert!(
        badge.count >= 1,
        "the bell counts the notice about the role"
    );

    notifications::mark_read(world.tenant(), &given.id)
        .send(pat.client())
        .await
        .ok();
    let unread = notifications::unread(world.tenant())
        .send(pat.client())
        .await
        .ok();
    assert!(
        unread.items.iter().all(|notice| notice.id != given.id),
        "a notice Pat read leaves her unread list"
    );
    let inbox = notifications::inbox(world.tenant())
        .send(pat.client())
        .await
        .ok();
    let shown = inbox.items.iter().find(|notice| notice.id == given.id);
    assert!(
        shown.is_some_and(|notice| notice.read),
        "the notice still shows in Pat's inbox, read"
    );

    let seen = tenant_ids(world.tenant(), pat.client()).await;
    take_role(&world, &pat, &role).await;
    fresh_tenant_notice(world.tenant(), pat.client(), &seen, AUTHORIZATION).await;
    let marked = notifications::mark_all_read(world.tenant())
        .send(pat.client())
        .await
        .ok();
    assert!(
        marked.marked >= 1,
        "marking all read changed the new notice"
    );
    let badge = notifications::unread_count(world.tenant())
        .send(pat.client())
        .await
        .ok();
    assert_eq!(badge.count, 0, "the bell shows nothing unread");
    let unread = notifications::unread(world.tenant())
        .send(pat.client())
        .await
        .ok();
    assert!(unread.items.is_empty(), "no unread notice is left");

    let uma_inbox = notifications::inbox(world.tenant())
        .send(uma.client())
        .await
        .ok();
    assert!(
        uma_inbox
            .items
            .iter()
            .filter(|notice| !uma_before.contains(&notice.id))
            .all(|notice| notice.category != AUTHORIZATION),
        "Uma is told nothing about Pat's role"
    );
    world.trail().recorded_after(&trail_before, READ_ONE).await;
    world.trail().recorded_after(&trail_before, READ_ALL).await;

    let reads_before = world.trail().count(READ_ONE).await;
    notifications::mark_read(world.tenant(), &given.id)
        .send(uma.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    assert_eq!(
        world.trail().count(READ_ONE).await,
        reads_before,
        "a refused read adds no record"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat has an unread notice about the role Tess gave her. Uma, in the same
/// tenant, is told it is not found, as if it did not exist; Sam, from the
/// other company, is forbidden; nobody signed in is asked to sign in. Pat
/// still finds the notice unread, and the bell still counts it.
#[tokio::test]
async fn nobody_but_pat_marks_pat_s_notices_read() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let uma = person(&world, "uma").await;
    let role = reader_role(&world).await;
    let seen = tenant_ids(world.tenant(), pat.client()).await;
    give_role(&world, &pat, &role).await;
    let given = fresh_tenant_notice(world.tenant(), pat.client(), &seen, AUTHORIZATION).await;

    Matrix::new(
        "marking Pat's notice read",
        notifications::mark_read(world.tenant(), &given.id).call(),
    )
    .refused(uma.client(), Status::NOT_FOUND, "not_found")
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;
    Matrix::new(
        "reading Pat's unread count",
        notifications::unread_count(world.tenant()).call(),
    )
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;

    let unread = notifications::unread(world.tenant())
        .send(pat.client())
        .await
        .ok();
    assert!(
        unread.items.iter().any(|notice| notice.id == given.id),
        "Pat's notice is still unread"
    );
    let badge = notifications::unread_count(world.tenant())
        .send(pat.client())
        .await
        .ok();
    assert!(badge.count >= 1, "the bell still counts it");

    stack.stop().await.expect("the stack stops cleanly");
}
