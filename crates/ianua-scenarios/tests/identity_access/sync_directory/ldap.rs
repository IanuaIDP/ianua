//! The tenant directory over LDAP, for the applications that speak only
//! LDAP: what the company's directory keeps over SCIM is what they find,
//! and who it deactivates no longer binds.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::directory;
use ianua_scenarios::ldap::{ClientCertificate, LdapClient, person_dn, service_dn, users_dn};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::directory::{
    DirectoryGroup, DirectoryMember, DirectoryPatch, NewServiceAccount, ServiceAccountScope,
};
use ianua_scenarios::world::World;
use ldap3_proto::proto::{LdapFilter, LdapResultCode};

use crate::support::{
    OWN_PASSWORD, OnRemove, laptop_certificate, linked_directory, made, settled_in,
};

/// The name the wiki binds under.
const WIKI: &str = "wiki";

/// Keeps the original bind connections open while Pat is deactivated.
struct PasswordClients {
    _without: LdapClient,
    _pat: LdapClient,
    _guesser: LdapClient,
}

/// The directory makes Pat, who settles in, and puts her in Finance. Tess
/// gives the wiki a read-only service account over the tenant's users.
/// The wiki binds as it and finds Pat by her address, with her name and
/// her Finance group. Pat's password alone binds nobody. Her laptop gets
/// a client certificate from the tenant, and over it her password binds
/// her as herself, while a wrong one binds nobody. The directory
/// deactivates Pat, and even her laptop and password bind her no more.
#[tokio::test]
async fn an_ldap_app_finds_what_the_directory_keeps_and_a_deactivated_pat_binds_no_more() {
    let stack = Stack::start(Profile::standard().with_directory())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let linked = linked_directory(&world, OnRemove::Deactivate).await;
    let mut pat = made(&world, &linked, "pat").await;
    settled_in(&world, &mut pat).await;
    add_finance(&world, &linked, &pat).await;
    let (org, tenant) = (world.org().slug(), world.tenant().slug());
    let users = users_dn(org, tenant);
    let secret = create_wiki_account(&world, &users).await;
    let _app = assert_wiki_finds_pat(&world, &pat, &users, &secret).await;
    let pat_dn = person_dn(org, tenant, pat.email());
    let laptop = laptop_certificate(&world, &pat).await;
    let _bindings = assert_password_bindings(&stack, &laptop, &pat_dn).await;
    directory::patch_user(world.tenant(), pat.id(), &DirectoryPatch::deactivation())
        .send(&linked)
        .await
        .ok();
    let mut after = LdapClient::connect_presenting(&stack, &laptop).await;
    assert_eq!(
        after.bind(&pat_dn, OWN_PASSWORD).await,
        LdapResultCode::InvalidCredentials,
        "a deactivated Pat binds no more"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// The directory records Pat as a member of Finance before the LDAP read.
async fn add_finance(world: &World<'_>, linked: &Client, pat: &Person) {
    directory::create_group(
        world.tenant(),
        &DirectoryGroup {
            display_name: "Finance".to_owned(),
            members: vec![DirectoryMember {
                value: pat.id().to_owned(),
            }],
        },
    )
    .send(linked)
    .await
    .ok();
}

/// Tess creates the wiki's read-only account over the tenant's user subtree.
async fn create_wiki_account(world: &World<'_>, users: &str) -> String {
    let wiki = directory::create_service_account(
        world.tenant(),
        &NewServiceAccount {
            name: WIKI.to_owned(),
            scope: ServiceAccountScope {
                access: "ReadOnly".to_owned(),
                base_dns: vec![users.to_owned()],
            },
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    wiki.secret
}

/// The wiki finds only Pat, including her display name and Finance membership.
async fn assert_wiki_finds_pat(
    world: &World<'_>,
    pat: &Person,
    users: &str,
    secret: &str,
) -> LdapClient {
    let (org, tenant) = (world.org().slug(), world.tenant().slug());
    let mut app = LdapClient::connect(world.stack()).await;
    assert_eq!(
        app.bind(&service_dn(org, tenant, WIKI), secret).await,
        LdapResultCode::Success
    );
    let (found, done) = app
        .search(
            users,
            LdapFilter::Equality("mail".to_owned(), pat.email().to_owned()),
        )
        .await;
    assert_eq!(done, LdapResultCode::Success);
    let [entry] = found.as_slice() else {
        panic!("the wiki finds Pat alone: {found:?}");
    };
    assert_eq!(entry.dn, person_dn(org, tenant, pat.email()));
    assert_eq!(entry.values("cn"), [pat.account().display_name.clone()]);
    assert!(
        entry
            .values("memberOf")
            .iter()
            .any(|group| group.to_ascii_lowercase().starts_with("cn=finance,")),
        "the wiki sees Pat's Finance group: {entry:?}"
    );
    app
}

/// Pat binds only with both her laptop certificate and correct password.
async fn assert_password_bindings(
    stack: &Stack,
    laptop: &ClientCertificate,
    pat_dn: &str,
) -> PasswordClients {
    let mut without = LdapClient::connect(stack).await;
    assert_eq!(
        without.bind(pat_dn, OWN_PASSWORD).await,
        LdapResultCode::InvalidCredentials,
        "Pat's password alone binds nobody"
    );
    let mut pats_client = LdapClient::connect_presenting(stack, laptop).await;
    assert_eq!(
        pats_client.bind(pat_dn, OWN_PASSWORD).await,
        LdapResultCode::Success
    );
    assert_eq!(pats_client.who_am_i().await, pat_dn);
    let mut guesser = LdapClient::connect_presenting(stack, laptop).await;
    assert_eq!(
        guesser
            .bind(pat_dn, "Not the right sentence at all 1!")
            .await,
        LdapResultCode::InvalidCredentials,
        "a wrong password binds nobody, even from Pat's laptop"
    );
    PasswordClients {
        _without: without,
        _pat: pats_client,
        _guesser: guesser,
    }
}
