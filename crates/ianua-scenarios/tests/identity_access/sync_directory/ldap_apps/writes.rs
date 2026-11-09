//! The changes a person may make over LDAP: Pat, an administrator bound
//! from her own laptop, keeps the tenant's people and groups within the
//! directory's rules, and nobody else writes anything.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{directory, people, roles};
use ianua_scenarios::ldap::{ClientCertificate, LdapClient, group_dn, person_dn, service_dn};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::directory::{NewServiceAccount, ServiceAccountScope};
use ianua_scenarios::wire::roles::AssignRole;
use ianua_scenarios::world::{ADMIN_ROLE, World};
use ldap3_proto::proto::{LdapFilter, LdapResultCode};

use super::{groups_of, users_of};
use crate::support::{
    OWN_PASSWORD, OnRemove, laptop_certificate, linked_directory, made, settled_in,
};

/// The password Uma is given when Pat adds her: a sentence, so no scanner
/// takes it for a key.
const UMAS_FIRST_PASSWORD: &str = "Quiet lantern meadow sentence 5127!";

/// Someone the directory made, settled in, with a client certificate
/// from the tenant for their laptop.
async fn settled_with_laptop(
    world: &World<'_>,
    linked: &Client,
    name: &str,
) -> (Person, ClientCertificate) {
    let mut person = made(world, linked, name).await;
    settled_in(world, &mut person).await;
    let laptop = laptop_certificate(world, &person).await;
    (person, laptop)
}

/// A connection from `laptop` bound as `person`.
async fn person_bound(
    world: &World<'_>,
    person: &Person,
    laptop: &ClientCertificate,
) -> LdapClient {
    let mut client = LdapClient::connect_presenting(world.stack(), laptop).await;
    let dn = person_dn(world.org().slug(), world.tenant().slug(), person.email());
    assert_eq!(
        client.bind(&dn, OWN_PASSWORD).await,
        LdapResultCode::Success,
        "{} binds from their laptop",
        person.email()
    );
    client
}

/// Tess gives Pat the Admin role, and Pat binds from her laptop. She adds
/// Uma with a first password and an Editors group, renames Uma by her
/// `cn` and adds her to Editors, all recorded and visible to Tess. Over
/// LDAP she may not add a person whose `mail` contradicts the DN, or with
/// no password; an entry outside the people and groups; or change an
/// address, a password or a group's name through a plain Modify. She
/// removes Uma from Editors, deletes Uma and Editors, and Tess reads Uma
/// as gone.
#[tokio::test]
async fn pat_writes_the_directory_over_ldap_within_its_rules() {
    let stack = Stack::start(Profile::standard().with_directory())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let linked = linked_directory(&world, OnRemove::Deactivate).await;
    let (pat, laptop) = settled_with_laptop(&world, &linked, "pat").await;
    let admin = world.role_id(ADMIN_ROLE).await;
    roles::assign(
        world.tenant(),
        &admin,
        &AssignRole {
            user_id: pat.id().to_owned(),
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    let mut client = person_bound(&world, &pat, &laptop).await;
    let (org, tenant) = (world.org().slug(), world.tenant().slug());
    let uma_address = world.address("uma");
    let uma_dn = person_dn(org, tenant, &uma_address);
    let editors_dn = group_dn(org, tenant, "Editors");

    assert_eq!(
        client
            .add(
                &uma_dn,
                &[
                    ("cn", &["Uma Added"]),
                    ("mail", &[uma_address.as_str()]),
                    ("userPassword", &[UMAS_FIRST_PASSWORD]),
                ],
            )
            .await,
        LdapResultCode::Success
    );
    assert_eq!(
        client.add(&editors_dn, &[("cn", &["Editors"])]).await,
        LdapResultCode::Success
    );
    assert_eq!(
        client.replace_values(&uma_dn, "cn", &["Uma Renamed"]).await,
        LdapResultCode::Success
    );
    assert_eq!(
        client.add_values(&editors_dn, "member", &[&uma_dn]).await,
        LdapResultCode::Success
    );

    let found = people::list(world.tenant(), Some(&uma_address))
        .send(world.admin().client())
        .await
        .ok();
    let [uma] = found.items.as_slice() else {
        panic!("Tess finds Uma alone: {found:?}");
    };
    assert_eq!(uma.display_name, "Uma Renamed");
    let uma_id = uma.id.clone();
    let (members, _) = client
        .search(
            &groups_of(&world),
            LdapFilter::Equality("cn".to_owned(), "Editors".to_owned()),
        )
        .await;
    assert_eq!(members[0].values("member"), std::slice::from_ref(&uma_dn));
    world
        .trail()
        .recorded("authorization.group_member_added")
        .await;

    let someone_else = person_dn(org, tenant, &world.address("someone.else"));
    assert_eq!(
        client
            .add(
                &someone_else,
                &[
                    ("cn", &["Someone Else"]),
                    ("mail", &["another@elsewhere.example"]),
                    ("userPassword", &[UMAS_FIRST_PASSWORD]),
                ],
            )
            .await,
        LdapResultCode::ConstraintViolation,
        "a mail that contradicts the entry's name"
    );
    assert_eq!(
        client
            .add(&someone_else, &[("cn", &["Someone Else"])])
            .await,
        LdapResultCode::ConstraintViolation,
        "a person with no password"
    );
    assert_eq!(
        client
            .add(&service_dn(org, tenant, "payroll"), &[("cn", &["payroll"])],)
            .await,
        LdapResultCode::UnwillingToPerform,
        "only people and groups are added"
    );
    assert_eq!(
        client
            .replace_values(&uma_dn, "mail", &["x@elsewhere.example"])
            .await,
        LdapResultCode::NotALlowedOnRDN,
        "an address names the entry"
    );
    assert_eq!(
        client
            .replace_values(&uma_dn, "userPassword", &["A new sentence 9!"])
            .await,
        LdapResultCode::UnwillingToPerform,
        "a password changes through Password-Modify"
    );
    assert_eq!(
        client
            .replace_values(&editors_dn, "member", &[&uma_dn])
            .await,
        LdapResultCode::UnwillingToPerform,
        "members are added and deleted"
    );
    assert_eq!(
        client.replace_values(&editors_dn, "cn", &["Writers"]).await,
        LdapResultCode::NotALlowedOnRDN,
        "a group's name is its entry's name"
    );

    assert_eq!(
        client
            .delete_values(&editors_dn, "member", &[&uma_dn])
            .await,
        LdapResultCode::Success
    );
    assert_eq!(client.delete(&uma_dn).await, LdapResultCode::Success);
    assert_eq!(client.delete(&editors_dn).await, LdapResultCode::Success);
    assert_eq!(
        client.delete(&users_of(&world)).await,
        LdapResultCode::UnwillingToPerform,
        "the tree's own nodes stay"
    );
    let gone = people::get(world.tenant(), &uma_id)
        .send(world.admin().client())
        .await;
    assert_eq!(gone.status(), Status::NOT_FOUND, "{}", gone.summary());

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess cannot give a service account the right to write: the access
/// that would is an unknown value now. The wiki's read-only account and a
/// connection bound as nobody may not add, change or delete anything.
/// Quinn, whom the directory made and who has no role that may, is refused
/// the same way, and Pat stays as she was.
#[tokio::test]
async fn a_service_account_nobody_and_a_plain_person_write_nothing() {
    let stack = Stack::start(Profile::standard().with_directory())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let linked = linked_directory(&world, OnRemove::Deactivate).await;
    let (quinn, laptop) = settled_with_laptop(&world, &linked, "quinn").await;
    let pat = made(&world, &linked, "pat").await;
    let (org, tenant) = (world.org().slug(), world.tenant().slug());
    let users = users_of(&world);
    let pat_dn = person_dn(org, tenant, pat.email());
    let new_dn = person_dn(org, tenant, &world.address("new.hire"));

    let refused = directory::create_service_account(
        world.tenant(),
        &NewServiceAccount {
            name: "writer".to_owned(),
            scope: ServiceAccountScope {
                access: "ReadWrite".to_owned(),
                base_dns: vec![users.clone()],
            },
        },
    )
    .send(world.admin().client())
    .await;
    assert_eq!(
        refused.status(),
        Status::UNPROCESSABLE_ENTITY,
        "no service account writes: {}",
        refused.summary()
    );
    let wiki = directory::create_service_account(
        world.tenant(),
        &NewServiceAccount {
            name: "wiki".to_owned(),
            scope: ServiceAccountScope {
                access: "ReadOnly".to_owned(),
                base_dns: vec![users],
            },
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    let mut service = LdapClient::connect(world.stack()).await;
    assert_eq!(
        service
            .bind(&service_dn(org, tenant, "wiki"), &wiki.secret)
            .await,
        LdapResultCode::Success
    );
    let mut nobody = LdapClient::connect(world.stack()).await;
    let mut plain = person_bound(&world, &quinn, &laptop).await;

    for (who, client) in [
        ("a service account", &mut service),
        ("nobody bound", &mut nobody),
        ("Quinn", &mut plain),
    ] {
        assert_eq!(
            client
                .add(
                    &new_dn,
                    &[
                        ("cn", &["New Hire"]),
                        ("userPassword", &[UMAS_FIRST_PASSWORD]),
                    ],
                )
                .await,
            LdapResultCode::InsufficentAccessRights,
            "{who} may not add a person"
        );
        assert_eq!(
            client
                .replace_values(&pat_dn, "cn", &["Pat Vandalised"])
                .await,
            LdapResultCode::InsufficentAccessRights,
            "{who} may not rename Pat"
        );
        assert_eq!(
            client.delete(&pat_dn).await,
            LdapResultCode::InsufficentAccessRights,
            "{who} may not delete Pat"
        );
    }

    let kept = people::get(world.tenant(), pat.id())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(
        kept.display_name,
        pat.account().display_name,
        "Pat is as she was"
    );

    stack.stop().await.expect("the stack stops cleanly");
}
