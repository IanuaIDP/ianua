//! The accounts applications bind to the directory as: what each reaches
//! and how Tess ends what it can do.

use ianua_scenarios::api::directory;
use ianua_scenarios::expect::{Matrix, no_secret_leaked};
use ianua_scenarios::ldap::{LdapClient, person_dn, users_dn};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::directory::{DirectoryGroup, DirectoryMember, NewServiceAccount};
use ianua_scenarios::world::World;
use ldap3_proto::proto::{LdapFilter, LdapResultCode};

use super::{groups_of, read_only, users_of, wiki_account, wiki_bound, wiki_dn};
use crate::support::{OnRemove, linked_directory, made};

/// A filter matching every entry.
fn everything() -> LdapFilter {
    LdapFilter::Present("objectClass".to_owned())
}

/// Pat is in the directory's Finance group. Tess gives the wiki a
/// read-only account over the tenant's users. Bound, the wiki says who it
/// is, finds Pat, and is refused the groups and the twin tenant's people.
/// Tess widens its scope to the groups too: bound afresh, the wiki finds
/// Finance with Pat as its member. Tess's plan holds one account, so a
/// second is refused.
#[tokio::test]
async fn the_wiki_reads_only_where_its_account_reaches() {
    let stack = Stack::start(Profile::standard().with_directory())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let linked = linked_directory(&world, OnRemove::Deactivate).await;
    let pat = made(&world, &linked, "pat").await;
    directory::create_group(
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
    let wiki = wiki_account(&world, vec![users.clone()]).await;

    let mut app = wiki_bound(&world, &wiki.secret).await;
    assert_eq!(app.who_am_i().await, wiki_dn(&world));
    let (found, done) = app
        .search(
            &users,
            LdapFilter::Equality("mail".to_owned(), pat.email().to_owned()),
        )
        .await;
    assert_eq!(done, LdapResultCode::Success);
    assert_eq!(found.len(), 1, "the wiki finds Pat: {found:?}");

    let (none, refused) = app.search(&groups, everything()).await;
    assert!(none.is_empty(), "the groups stay out of reach: {none:?}");
    assert_eq!(refused, LdapResultCode::InsufficentAccessRights);
    let twin_users = users_dn(world.twin().organization().slug(), world.twin().slug());
    let (none, refused) = app.search(&twin_users, everything()).await;
    assert!(none.is_empty(), "the twin's people stay out of reach");
    assert_eq!(refused, LdapResultCode::InsufficentAccessRights);

    directory::change_service_scope(
        world.tenant(),
        &wiki.id,
        &read_only(vec![users.clone(), groups.clone()]),
    )
    .send(world.admin().client())
    .await
    .ok();
    let mut widened = wiki_bound(&world, &wiki.secret).await;
    let (found, done) = widened
        .search(
            &groups,
            LdapFilter::Equality("cn".to_owned(), "Finance".to_owned()),
        )
        .await;
    assert_eq!(done, LdapResultCode::Success);
    let [finance] = found.as_slice() else {
        panic!("the wiki finds Finance alone: {found:?}");
    };
    assert_eq!(
        finance.values("member"),
        [person_dn(
            world.org().slug(),
            world.tenant().slug(),
            pat.email()
        )]
    );

    let second = directory::create_service_account(
        world.tenant(),
        &NewServiceAccount {
            name: "second-wiki".to_owned(),
            scope: read_only(vec![users.clone()]),
        },
    )
    .send(world.admin().client())
    .await;
    assert_eq!(
        second.status(),
        Status::FORBIDDEN,
        "the plan holds one account: {}",
        second.summary()
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Max, Sam and nobody signed in may not make, read or rotate the wiki's
/// account. Tess rotates its secret: the connection the wiki had open is
/// told its bind no longer counts, the old secret binds no more and the
/// new one does. Tess disables the account: it binds no more, even on an
/// open connection, and enabled again it binds with the same secret. Tess
/// deletes it: it binds no more and she reads it as gone. No read ever
/// shows a secret.
#[tokio::test]
async fn a_rotated_disabled_or_deleted_account_binds_no_more() {
    let stack = Stack::start(Profile::standard().with_directory())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let users = users_of(&world);
    let wiki = wiki_account(&world, vec![users.clone()]).await;
    let tess = world.admin().client();

    for call in [
        directory::service_accounts(world.tenant()).call(),
        directory::service_account(world.tenant(), &wiki.id).call(),
        directory::rotate_service_secret(world.tenant(), &wiki.id).call(),
        directory::disable_service_account(world.tenant(), &wiki.id).call(),
        directory::delete_service_account(world.tenant(), &wiki.id).call(),
    ] {
        Matrix::new("the wiki's account", call)
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

    let mut open = wiki_bound(&world, &wiki.secret).await;
    let rotated = directory::rotate_service_secret(world.tenant(), &wiki.id)
        .send(tess)
        .await
        .ok();
    let (none, cut_off) = open.search(&users, everything()).await;
    assert!(none.is_empty());
    assert_eq!(
        cut_off,
        LdapResultCode::InvalidCredentials,
        "a rotated secret ends the bind already open"
    );
    let mut fresh = LdapClient::connect(world.stack()).await;
    assert_eq!(
        fresh.bind(&wiki_dn(&world), &wiki.secret).await,
        LdapResultCode::InvalidCredentials,
        "the old secret binds no more"
    );

    let mut current = wiki_bound(&world, &rotated.secret).await;
    directory::disable_service_account(world.tenant(), &wiki.id)
        .send(tess)
        .await
        .ok();
    let (_, switched_off) = current.search(&users, everything()).await;
    assert_eq!(
        switched_off,
        LdapResultCode::InvalidCredentials,
        "a disabled account's open bind ends"
    );
    let disabled = directory::service_account(world.tenant(), &wiki.id)
        .send(tess)
        .await
        .ok();
    assert_eq!(disabled.status, "Disabled");
    let mut refused = LdapClient::connect(world.stack()).await;
    assert_eq!(
        refused.bind(&wiki_dn(&world), &rotated.secret).await,
        LdapResultCode::InvalidCredentials,
        "a disabled account binds no more"
    );
    directory::activate_service_account(world.tenant(), &wiki.id)
        .send(tess)
        .await
        .ok();
    wiki_bound(&world, &rotated.secret).await;

    let listing = directory::service_accounts(world.tenant())
        .send(tess)
        .await
        .ok();
    let everything_read = serde_json::to_string(&listing).expect("the listing writes as JSON");
    no_secret_leaked(&everything_read, &[&wiki.secret, &rotated.secret]);

    directory::delete_service_account(world.tenant(), &wiki.id)
        .send(tess)
        .await
        .ok();
    let gone = directory::service_account(world.tenant(), &wiki.id)
        .send(tess)
        .await;
    assert_eq!(gone.status(), Status::NOT_FOUND, "{}", gone.summary());
    let mut after = LdapClient::connect(world.stack()).await;
    assert_eq!(
        after.bind(&wiki_dn(&world), &rotated.secret).await,
        LdapResultCode::InvalidCredentials,
        "a deleted account binds no more"
    );

    stack.stop().await.expect("the stack stops cleanly");
}
