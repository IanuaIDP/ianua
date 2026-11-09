//! A tenant's people: each registered by the owner with the demo password
//! and their team's role, let in at once.

use ianua_app::email::{EmailVerification, LinkScope};
use ianua_app::use_case::Command as _;
use ianua_app::use_cases::identity::users::New;
use ianua_domain::types::{DisplayName, Email, RoleId, UserId};

use crate::demo::DemoError;
use crate::demo::catalog::{self, PersonSeed};
use crate::demo::seeder::{DemoTenant, Seed, Seeder};

/// The person `seed` names, found by their address or registered by the
/// owner holding `role`.
///
/// # Errors
///
/// [`DemoError`] when the person cannot be looked up or registered.
pub(super) async fn person(
    seeder: &Seeder<'_>,
    tenant: &DemoTenant,
    seed: &PersonSeed,
    role: RoleId,
) -> Result<Seed<UserId>, DemoError> {
    let email = Email::new(address(seed))?;
    let users = seeder.adapters.user_store.as_ref();
    if let Some(found) = users.find_by_email(&tenant.scoped(), &email).await? {
        return Ok(Seed::Found(*found.id()));
    }
    let name = format!("{} {}", seed.first, seed.last);
    let request = New {
        email,
        display_name: DisplayName::new(name, &seeder.limits().display_name)?,
        password: Some(catalog::PASSWORD.to_owned()),
        verification: EmailVerification::Automatic,
        roles: vec![role],
        scope: LinkScope::Tenant {
            org: seeder.organization.slug.clone(),
            tenant: tenant.slug.clone(),
        },
    };
    let acting = seeder.in_tenant(tenant).await?;
    let register = seeder.state.identity.users.register.as_ref();
    let registered = seeder
        .kept(
            "a person",
            register.execute(&acting.caller, &acting.auditor, request),
        )
        .await?;
    Ok(Seed::Made(registered.id))
}

/// The address `seed` signs in with: their names in lower case, under the
/// demo's mail domain.
fn address(seed: &PersonSeed) -> String {
    format!(
        "{}.{}@{}",
        seed.first.to_lowercase(),
        seed.last.to_lowercase(),
        catalog::MAIL_DOMAIN
    )
}
