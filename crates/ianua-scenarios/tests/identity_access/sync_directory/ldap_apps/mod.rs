//! Applications and people reaching the tenant's LDAP directory: the
//! service accounts Tess makes and what they reach, the binds that reach
//! nothing, the writes a person may make, and what the directory's SCIM
//! changes look like from an application reading over LDAP.
//!
//! - `service_accounts`: the wiki reads only under what its account's
//!   scope covers until Tess widens it, the plan holds one account, and
//!   rotating, disabling and deleting end its binds, open or new.
//! - `binds`: anonymous binds, missing and wrong secrets, unknown
//!   accounts, another tenant's name and malformed names reach nothing,
//!   and every refusal reads the same.
//! - `writes`: Pat, an administrator, adds, changes and removes people and
//!   groups over LDAP within the directory's rules; a service account,
//!   nobody bound and a person with no right write nothing.
//! - `following`: what SCIM renames and removes, the wiki reads the same
//!   way at once.

mod binds;
mod following;
mod service_accounts;
mod writes;

use ianua_scenarios::api::directory;
use ianua_scenarios::ldap::{LdapClient, groups_dn, service_dn, users_dn};
use ianua_scenarios::wire::directory::{
    NewServiceAccount, ServiceAccountMade, ServiceAccountScope,
};
use ianua_scenarios::world::World;
use ldap3_proto::proto::LdapResultCode;

/// The name the wiki binds under.
const WIKI: &str = "wiki";

/// The DN of the world's tenant's users.
fn users_of(world: &World<'_>) -> String {
    users_dn(world.org().slug(), world.tenant().slug())
}

/// The DN of the world's tenant's groups.
fn groups_of(world: &World<'_>) -> String {
    groups_dn(world.org().slug(), world.tenant().slug())
}

/// The DN the wiki binds as.
fn wiki_dn(world: &World<'_>) -> String {
    service_dn(world.org().slug(), world.tenant().slug(), WIKI)
}

/// A read-only reach under `base_dns`.
fn read_only(base_dns: Vec<String>) -> ServiceAccountScope {
    ServiceAccountScope {
        access: "ReadOnly".to_owned(),
        base_dns,
    }
}

/// The wiki's account, made by Tess, reaching only under `base_dns`.
async fn wiki_account(world: &World<'_>, base_dns: Vec<String>) -> ServiceAccountMade {
    directory::create_service_account(
        world.tenant(),
        &NewServiceAccount {
            name: WIKI.to_owned(),
            scope: read_only(base_dns),
        },
    )
    .send(world.admin().client())
    .await
    .ok()
}

/// A connection bound as the wiki with `secret`.
async fn wiki_bound(world: &World<'_>, secret: &str) -> LdapClient {
    let mut app = LdapClient::connect(world.stack()).await;
    assert_eq!(
        app.bind(&wiki_dn(world), secret).await,
        LdapResultCode::Success,
        "the wiki binds with its secret"
    );
    app
}
