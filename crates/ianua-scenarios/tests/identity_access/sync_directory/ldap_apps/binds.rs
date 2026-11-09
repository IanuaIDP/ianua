//! The binds that reach nothing: nobody, no password, a wrong secret, an
//! account that is not there, another tenant's name and a name that
//! means nothing, all refused the same way.

use ianua_scenarios::ldap::{LdapClient, service_dn};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::world::World;
use ldap3_proto::proto::{LdapFilter, LdapResultCode};

use super::{users_of, wiki_account, wiki_dn};

/// The directory's refusal of every bind Mallory is not entitled to.
const REFUSED: LdapResultCode = LdapResultCode::InvalidCredentials;

/// Tess makes the wiki's account. A connection that binds as nobody
/// succeeds and says it is nobody, and is refused the tenant's users. With
/// the wiki's own name and no password, a wrong secret, a name the tenant
/// has no account under, the real secret under the twin tenant's name and
/// a name that is no directory name at all, Mallory binds as nobody and
/// each answer is the same refusal, the connection still bound as no one.
#[tokio::test]
async fn binds_mallory_cannot_prove_reach_nothing() {
    let stack = Stack::start(Profile::standard().with_directory())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let users = users_of(&world);
    let wiki = wiki_account(&world, vec![users.clone()]).await;

    let mut anyone = LdapClient::connect(world.stack()).await;
    assert_eq!(anyone.bind("", "").await, LdapResultCode::Success);
    assert_eq!(
        anyone.who_am_i().await,
        "",
        "binding as nobody names nobody"
    );
    let (none, refused) = anyone
        .search(&users, LdapFilter::Present("objectClass".to_owned()))
        .await;
    assert!(none.is_empty(), "nobody reads the people: {none:?}");
    assert_eq!(refused, LdapResultCode::InsufficentAccessRights);

    let (org, tenant) = (world.org().slug(), world.tenant().slug());
    let (twin_org, twin) = (world.twin().organization().slug(), world.twin().slug());
    let attempts = [
        (wiki_dn(&world), String::new()),
        (wiki_dn(&world), "not the wiki's secret".to_owned()),
        (service_dn(org, tenant, "payroll"), wiki.secret.clone()),
        (service_dn(twin_org, twin, "wiki"), wiki.secret.clone()),
        ("this names nobody".to_owned(), wiki.secret.clone()),
    ];
    let mut mallory = LdapClient::connect(world.stack()).await;
    for (dn, secret) in &attempts {
        assert_eq!(mallory.bind(dn, secret).await, REFUSED, "{dn} binds nobody");
        assert_eq!(mallory.who_am_i().await, "", "the connection is nobody's");
    }

    stack.stop().await.expect("the stack stops cleanly");
}
