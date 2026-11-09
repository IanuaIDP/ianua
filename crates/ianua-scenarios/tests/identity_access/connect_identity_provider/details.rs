//! What Tess keeps about the tenant's link to Acme's provider beyond
//! setting it up: which addresses are sent to it, switching it off and on
//! and deleting it, the provider's groups mapped to roles here, assertions
//! sealed to the platform's own key, and the links of the tenant's users.

use ianua_scenarios::api::{connections, roles};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::net::Call;
use ianua_scenarios::providers::saml::{Claim, Provider};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::account::ProviderLinks;
use ianua_scenarios::wire::connections::{
    DiscoverRealm, EncryptionKey, GroupMapping, GroupRule, MappedGrant,
};
use ianua_scenarios::wire::roles::{NewRole, SystemPermission};
use ianua_scenarios::world::World;
use serde_json::json;

use crate::support::{
    Outcome, SamlAnswer, Settings, begun, connected, owned_domain, pat, signed_in,
};

/// The address of the connection, under the tenant Tess administers.
fn path(connection: &str) -> String {
    format!("/federation/connections/{connection}")
}

/// Tess sends every address at the company's domain straight to Acme's
/// provider. The sign-in page, asked with no session, routes such an
/// address and no other. Tess switches the connection off: the address is
/// no longer routed, and it cannot be switched off twice. She switches it
/// on again, also only once, and it routes again. She cannot delete it
/// while it is on; off, she deletes it and it is gone. Each step is on the
/// trail. Max, Sam and nobody signed in change nothing.
#[tokio::test]
async fn an_address_is_routed_only_while_its_connection_is_on() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let tenant = world.tenant();
    let anonymous = world.anonymous().client();
    let domain = owned_domain(&world).await;
    let provider = Provider::new();
    let connection = connected(
        &world,
        &domain,
        &Settings {
            provider: &provider,
            next: None,
            sign_requests: false,
        },
    )
    .await;
    let hint = Call::patch(tenant.at(&path(&connection))).json(&json!({"domain_hint": domain}));
    tess.send::<()>(hint).await.ok();
    let trail_before = world.trail().ids().await;
    let listed = connections::list(tenant).send(tess).await.ok();
    assert!(
        listed.items.iter().any(|item| item.id == connection),
        "Tess finds the connection in her list"
    );
    let ann_address = DiscoverRealm {
        email: format!("ann@{domain}"),
    };
    let elsewhere = DiscoverRealm {
        email: "ann@elsewhere.example".to_owned(),
    };

    let routed = connections::discover(tenant, &ann_address)
        .send(anonymous)
        .await
        .ok();
    assert!(
        routed.routed,
        "an address at the domain goes to the provider"
    );
    assert_eq!(
        routed.connection_id.as_deref(),
        Some(connection.as_str()),
        "the answer names the connection"
    );
    assert_eq!(routed.provider_name.as_deref(), Some("Acme SAML"));
    assert_eq!(routed.protocol.as_deref(), Some("Saml"));
    let not_routed = connections::discover(tenant, &elsewhere)
        .send(anonymous)
        .await
        .ok();
    assert!(!not_routed.routed, "an address elsewhere signs in here");
    assert_eq!(
        not_routed.connection_id, None,
        "and is told of no connection"
    );

    connections::disable(tenant, &connection)
        .send(tess)
        .await
        .ok();
    let off = connections::get(tenant, &connection).send(tess).await.ok();
    assert_eq!(off.status, "Disabled", "the connection is off");
    connections::disable(tenant, &connection)
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    let unrouted = connections::discover(tenant, &ann_address)
        .send(anonymous)
        .await
        .ok();
    assert!(!unrouted.routed, "a switched-off connection routes nobody");

    connections::activate(tenant, &connection)
        .send(tess)
        .await
        .ok();
    let on = connections::get(tenant, &connection).send(tess).await.ok();
    assert_eq!(on.status, "Active", "the connection is on again");
    connections::activate(tenant, &connection)
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    let routed_again = connections::discover(tenant, &ann_address)
        .send(anonymous)
        .await
        .ok();
    assert!(routed_again.routed, "the address routes again");

    for (what, call) in [
        (
            "activating a connection",
            connections::activate(tenant, &connection).call(),
        ),
        (
            "disabling a connection",
            connections::disable(tenant, &connection).call(),
        ),
        (
            "deleting a connection",
            connections::delete(tenant, &connection).call(),
        ),
    ] {
        Matrix::new(what, call)
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
    connections::delete(tenant, &connection)
        .send(tess)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    connections::disable(tenant, &connection)
        .send(tess)
        .await
        .ok();
    connections::delete(tenant, &connection)
        .send(tess)
        .await
        .ok();
    connections::get(tenant, &connection)
        .send(tess)
        .await
        .refused(Status::NOT_FOUND, "not_found");

    let trail = world.trail();
    for event in [
        "federation.connection_activated",
        "federation.connection_disabled",
        "federation.connection_deleted",
    ] {
        trail.recorded_after(&trail_before, event).await;
    }

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess maps the provider's "Engineers" group to a role that carries no
/// built-in permission: reading the connection back shows the rule. An
/// empty mapping, a role that does not exist and a role carrying a
/// built-in permission, which only a person may give, are refused. She
/// stops the mapping and it is gone. Max, Sam and nobody signed in change
/// nothing.
#[tokio::test]
async fn tess_maps_the_providers_groups_to_roles_here() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let tenant = world.tenant();
    let domain = owned_domain(&world).await;
    let provider = Provider::new();
    let connection = connected(
        &world,
        &domain,
        &Settings {
            provider: &provider,
            next: None,
            sign_requests: false,
        },
    )
    .await;
    let role = roles::create(
        tenant,
        &NewRole {
            name: "Mapped Engineers".to_owned(),
            system_permissions: Vec::new(),
        },
    )
    .send(tess)
    .await
    .ok();
    let powerful = roles::create(
        tenant,
        &NewRole {
            name: "Mapped Administrators".to_owned(),
            system_permissions: vec![SystemPermission::new("Users", "View")],
        },
    )
    .send(tess)
    .await
    .ok();
    let trail_before = world.trail().ids().await;
    let mapping = GroupMapping {
        claim: "groups".to_owned(),
        rules: vec![GroupRule {
            provider_group: "Engineers".to_owned(),
            grant: MappedGrant::Role(role.id.clone()),
        }],
    };
    let calls = [
        (
            "mapping groups",
            connections::map_groups(tenant, &connection, &mapping).call(),
        ),
        (
            "stopping a mapping",
            connections::stop_mapping_groups(tenant, &connection).call(),
        ),
    ];
    for (what, call) in calls {
        Matrix::new(what, call)
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
    let unmapped = connections::get(tenant, &connection).send(tess).await.ok();
    assert!(
        unmapped.group_mapping.is_none(),
        "the refused calls mapped nothing: {unmapped:?}"
    );

    connections::map_groups(tenant, &connection, &mapping)
        .send(tess)
        .await
        .ok();
    let shown = connections::get(tenant, &connection).send(tess).await.ok();
    let shown_mapping = shown.group_mapping.expect("the mapping is on");
    assert_eq!(
        shown_mapping.rules[0].provider_group, "Engineers",
        "the group is read back"
    );

    let nothing = GroupMapping {
        claim: "groups".to_owned(),
        rules: Vec::new(),
    };
    connections::map_groups(tenant, &connection, &nothing)
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    let unknown_role = GroupMapping {
        claim: "groups".to_owned(),
        rules: vec![GroupRule {
            provider_group: "Ghosts".to_owned(),
            grant: MappedGrant::Role("00000000-0000-4000-8000-000000000004".to_owned()),
        }],
    };
    connections::map_groups(tenant, &connection, &unknown_role)
        .send(tess)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    let powerful_role = GroupMapping {
        claim: "groups".to_owned(),
        rules: vec![GroupRule {
            provider_group: "Administrators".to_owned(),
            grant: MappedGrant::Role(powerful.id.clone()),
        }],
    };
    connections::map_groups(tenant, &connection, &powerful_role)
        .send(tess)
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    connections::stop_mapping_groups(tenant, &connection)
        .send(tess)
        .await
        .ok();
    let stopped = connections::get(tenant, &connection).send(tess).await.ok();
    assert!(stopped.group_mapping.is_none(), "the mapping is gone");
    world
        .trail()
        .recorded_after(&trail_before, "federation.connection_updated")
        .await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess requires that Acme's provider seal its assertions. With no key of
/// her own the platform makes one: the certificate comes back to give
/// the provider, and the connection reads as requiring sealed assertions
/// with that certificate. A certificate without its private key, or the
/// other way round, is refused. She stops requiring them and the connection
/// reads as readable. Max, Sam and nobody signed in change nothing.
#[tokio::test]
async fn tess_requires_assertions_sealed_to_the_platforms_key() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let tenant = world.tenant();
    let domain = owned_domain(&world).await;
    let provider = Provider::new();
    let connection = connected(
        &world,
        &domain,
        &Settings {
            provider: &provider,
            next: None,
            sign_requests: false,
        },
    )
    .await;
    for (what, call) in [
        (
            "requiring sealed assertions",
            connections::require_encrypted_assertions(
                tenant,
                &connection,
                &EncryptionKey::default(),
            )
            .call(),
        ),
        (
            "accepting readable assertions",
            connections::accept_readable_assertions(tenant, &connection).call(),
        ),
    ] {
        Matrix::new(what, call)
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

    let sealed =
        connections::require_encrypted_assertions(tenant, &connection, &EncryptionKey::default())
            .send(tess)
            .await
            .ok();
    assert!(
        sealed.certificate.contains("BEGIN CERTIFICATE"),
        "the certificate to give the provider comes back"
    );
    let shown = connections::get(tenant, &connection).send(tess).await.ok();
    let saml = shown.saml.expect("a SAML connection shows its settings");
    assert!(
        saml.requires_encrypted_assertions,
        "assertions must now be sealed"
    );
    assert_eq!(
        saml.encryption_certificate.as_deref(),
        Some(sealed.certificate.as_str()),
        "the connection shows the certificate given"
    );

    let certificate_only = EncryptionKey {
        certificate: Some(sealed.certificate.clone()),
        private_key: None,
    };
    connections::require_encrypted_assertions(tenant, &connection, &certificate_only)
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    connections::accept_readable_assertions(tenant, &connection)
        .send(tess)
        .await
        .ok();
    let readable = connections::get(tenant, &connection).send(tess).await.ok();
    assert!(
        !readable
            .saml
            .expect("a SAML connection shows its settings")
            .requires_encrypted_assertions,
        "assertions no longer need sealing"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat signs in through Acme's provider, which links her account. Tess
/// sees the link on Pat's account and takes it off: Pat is told by the
/// audit trail recording it, the link is gone, and taking it off again
/// finds nothing. Pat, whom her role gives no such right, cannot read
/// anyone's links.
#[tokio::test]
async fn tess_sees_and_removes_a_tenant_users_provider_link() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let tenant = world.tenant();
    let domain = owned_domain(&world).await;
    let provider = Provider::new();
    let connection = connected(
        &world,
        &domain,
        &Settings {
            provider: &provider,
            next: None,
            sign_requests: false,
        },
    )
    .await;
    let mut pat = pat(&world, &domain).await;
    let redirect = begun(&world, &pat, &connection).await;
    let outcome = signed_in(
        &world,
        &mut pat,
        SamlAnswer {
            provider: &provider,
            redirect,
            claim: Claim::Correct,
        },
    )
    .await;
    assert!(
        matches!(outcome, Outcome::SignedIn),
        "Pat signs in through the provider: {outcome:?}"
    );

    let links: ProviderLinks = connections::user_links(tenant, pat.id())
        .send(tess)
        .await
        .ok();
    assert!(
        links
            .links
            .iter()
            .any(|link| link.connection_id == connection),
        "Tess sees Pat's link: {links:?}"
    );
    let someone_else = "00000000-0000-4000-8000-000000000005";
    connections::user_links(tenant, someone_else)
        .send(pat.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    connections::unlink_user(tenant, &connection, someone_else)
        .send(pat.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let trail_before = world.trail().ids().await;

    connections::unlink_user(tenant, &connection, pat.id())
        .send(tess)
        .await
        .ok();
    let after = connections::user_links(tenant, pat.id())
        .send(tess)
        .await
        .ok();
    assert!(after.links.is_empty(), "the link is gone: {after:?}");
    connections::unlink_user(tenant, &connection, pat.id())
        .send(tess)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    let record = world
        .trail()
        .recorded_after(&trail_before, "federation.account_unlinked")
        .await;
    assert!(record.tenant_id.is_some(), "recorded in the tenant");

    stack.stop().await.expect("the stack stops cleanly");
}
