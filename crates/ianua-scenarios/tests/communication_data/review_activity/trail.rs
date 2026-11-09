//! Reading the tenant's audit log as an administrator reviews it: page by
//! page, newest first, narrowed to one person or a time, and only by
//! someone who may.

use std::collections::HashSet;

use ianua_scenarios::api::audit;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::audit::AuditEntry;
use ianua_scenarios::world::World;

use crate::support::{invited, invitee};

/// The record an invitation leaves.
const INVITED: &str = "identity.user_invited";

/// How many people Tess invites.
const INVITED_COUNT: usize = 5;

/// Tess invites five people. Read two at a time, newest first, the log
/// hands her every invitation once, page after page, and then no further
/// page. Narrowed to what came after Wes's invitation, it holds the last
/// two; narrowed to what came before, the first two. Max, a plain member,
/// may not read it.
#[tokio::test]
async fn tess_reads_the_log_page_by_page_and_narrowed() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut ids = Vec::new();
    for name in ["uma", "vic", "wes", "xia", "yan"] {
        ids.push(invited(&world, name).await.id().to_owned());
    }

    let read = every_invitation(&world).await;
    assert_all_invitations(&read, &ids);
    assert_time_filters(&world, &read, &ids).await;
    audit::tenant_log(world.tenant(), INVITED)
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    stack.stop().await.expect("the stack stops cleanly");
}

/// All invited people appear once, with records ordered newest first.
fn assert_all_invitations(read: &[AuditEntry], ids: &[String]) {
    let invitees: Vec<String> = read.iter().filter_map(invitee).collect();
    let distinct: HashSet<&String> = invitees.iter().collect();
    assert_eq!(
        invitees.len(),
        INVITED_COUNT,
        "each invitation is read once"
    );
    assert_eq!(
        distinct,
        ids.iter().collect::<HashSet<_>>(),
        "every invitation is read"
    );
    assert!(
        read.windows(2)
            .all(|pair| pair[0].occurred_at >= pair[1].occurred_at),
        "newest first"
    );
}

/// Time bounds around Wes's invitation select the two records on each side.
async fn assert_time_filters(world: &World<'_>, read: &[AuditEntry], ids: &[String]) {
    let wes = read
        .iter()
        .find(|entry| invitee(entry).as_deref() == Some(ids[2].as_str()))
        .expect("Wes's invitation is read");
    for (bound, expected, why) in [
        ("since", &ids[3..], "after Wes's come Xia's and Yan's"),
        ("before", &ids[..2], "before Wes's come Uma's and Vic's"),
    ] {
        let narrowed = audit::tenant_log_where(
            world.tenant(),
            &[("event_type", INVITED), (bound, &wes.occurred_at)],
        )
        .send(world.admin().client())
        .await
        .ok();
        let found: HashSet<String> = narrowed.items.iter().filter_map(invitee).collect();
        assert_eq!(
            found,
            expected.iter().cloned().collect::<HashSet<_>>(),
            "{why}"
        );
    }
}

/// Every invitation record, read two at a time by Tess, following each
/// page's cursor, checking no page holds more than two.
async fn every_invitation(world: &World<'_>) -> Vec<AuditEntry> {
    let mut read = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..=INVITED_COUNT {
        let mut filters = vec![("event_type", INVITED), ("limit", "2")];
        if let Some(after) = &cursor {
            filters.push(("after", after));
        }
        let page = audit::tenant_log_where(world.tenant(), &filters)
            .send(world.admin().client())
            .await
            .ok();
        assert!(page.items.len() <= 2, "a page holds at most two");
        read.extend(page.items);
        let Some(next) = page.next_cursor else {
            return read;
        };
        cursor = Some(next);
    }
    panic!("the pages never ended");
}
