//! What a directory changes through SCIM, an LDAP application reads the
//! same way at once.

use ianua_scenarios::api::directory;
use ianua_scenarios::ldap::person_dn;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::directory::{DirectoryGroup, DirectoryMember, DirectoryPatch};
use ianua_scenarios::world::World;
use ldap3_proto::proto::{LdapFilter, LdapResultCode};
use serde_json::{Value, json};

use super::{groups_of, users_of, wiki_account, wiki_bound};
use crate::support::{OnRemove, linked_directory, made};

/// Pat is in the directory's Finance group, and the wiki reads both. The
/// directory renames Pat and renames Finance to Treasury and takes Pat out
/// of it: the wiki's next search finds Treasury empty, no Finance at all,
/// and Pat under her new name in no group.
#[tokio::test]
async fn the_wiki_reads_what_the_directory_changes_at_once() {
    let stack = Stack::start(Profile::standard().with_directory())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let linked = linked_directory(&world, OnRemove::Deactivate).await;
    let pat = made(&world, &linked, "pat").await;
    let finance = directory::create_group(
        world.tenant(),
        &DirectoryGroup {
            display_name: "Finance".to_owned(),
            members: vec![DirectoryMember {
                value: pat.id().to_owned(),
            }],
        },
    )
    .send(&linked)
    .await
    .ok();
    let (users, groups) = (users_of(&world), groups_of(&world));
    let wiki = wiki_account(&world, vec![users.clone(), groups.clone()]).await;
    let mut app = wiki_bound(&world, &wiki.secret).await;
    let by_name = |name: &str| LdapFilter::Equality("cn".to_owned(), name.to_owned());
    let pat_dn = person_dn(world.org().slug(), world.tenant().slug(), pat.email());

    let (found, done) = app.search(&groups, by_name("Finance")).await;
    assert_eq!(done, LdapResultCode::Success);
    assert_eq!(found[0].values("member"), std::slice::from_ref(&pat_dn));

    directory::patch_user(
        world.tenant(),
        pat.id(),
        &DirectoryPatch::one("replace", "displayName", Value::from("Pat Renamed")),
    )
    .send(&linked)
    .await
    .ok();
    directory::patch_group(
        world.tenant(),
        &finance.id,
        &DirectoryPatch::one("replace", "displayName", Value::from("Treasury")),
    )
    .send(&linked)
    .await
    .ok();
    directory::patch_group(
        world.tenant(),
        &finance.id,
        &DirectoryPatch::one("remove", "members", json!([{ "value": pat.id() }])),
    )
    .send(&linked)
    .await
    .ok();

    let (gone, _) = app.search(&groups, by_name("Finance")).await;
    assert!(gone.is_empty(), "no Finance any more: {gone:?}");
    let (treasury, _) = app.search(&groups, by_name("Treasury")).await;
    let [treasury] = treasury.as_slice() else {
        panic!("the wiki finds Treasury alone: {treasury:?}");
    };
    assert!(
        treasury.values("member").is_empty(),
        "Treasury holds nobody: {treasury:?}"
    );
    let (people, _) = app.search(&users, by_name("Pat Renamed")).await;
    let [renamed] = people.as_slice() else {
        panic!("the wiki finds Pat under her new name: {people:?}");
    };
    assert_eq!(
        renamed.dn, pat_dn,
        "the rename leaves her entry where it was"
    );
    assert!(
        renamed.values("memberOf").is_empty(),
        "Pat is in no group now: {renamed:?}"
    );

    stack.stop().await.expect("the stack stops cleanly");
}
