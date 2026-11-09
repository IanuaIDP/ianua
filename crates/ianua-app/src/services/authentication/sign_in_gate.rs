//! The tenant's say on a sign-in, asked by every way of signing in before it
//! looks at a credential.

use ianua_domain::domains::authentication::admission::SignInAdmitted;
use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::tenant::access::sign_in_gate::SignInRefusal;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::message;
use ianua_domain::types::{Fact, IpAddress, UserAgent};

use crate::error::AppError;
use crate::ports::tenant::TenantStore;
use crate::services::lookup::existing_tenant;
use crate::tenancy::ScopedTenant;

/// Where a sign-in request came from.
#[derive(Debug, Clone, Default)]
pub struct ClientOrigin {
    /// The caller's address, or that it could not be told.
    pub ip_address: Fact<IpAddress>,
    /// The caller's browser or client, as it described itself.
    pub user_agent: Option<UserAgent>,
}

/// Loads the tenant and has it admit a sign-in with `method` from
/// `client_ip`, handing back the tenant and the admission every credential
/// check then takes.
///
/// # Errors
///
/// - `AppError::TenantUnavailable` if the workspace is suspended, archived
///   or deleted.
/// - `AppError::Forbidden` if the method is switched off, the address is
///   not allowed or not known to a workspace that lists addresses, or the
///   workspace asks for passkey sign-in only.
/// - `AppError::NotFound` if the tenant does not exist.
/// - `AppError::Internal` if the tenant cannot be read.
pub(crate) async fn admit(
    tenant_store: &dyn TenantStore,
    tenant: &ScopedTenant,
    method: AuthMethod,
    client_ip: Fact<&IpAddress>,
) -> Result<(Tenant, SignInAdmitted), AppError> {
    let loaded = existing_tenant(tenant_store, tenant).await?;
    let admitted = loaded
        .admits_sign_in(method, client_ip)
        .map_err(refusal_error)?;
    Ok((loaded, admitted))
}

/// The error a caller sees for `refusal`.
pub(crate) fn refusal_error(refusal: SignInRefusal) -> AppError {
    match refusal {
        SignInRefusal::Unavailable(status) => AppError::TenantUnavailable(message!(
            "authentication-this-workspace-is-and-cannot-be",
            format!("this workspace is {status} and cannot be signed into")
        )),
        SignInRefusal::MethodOff(method) => AppError::Forbidden(message!(
            "authentication-this-workspace-does-not-accept-sign-2",
            format!(
                "this workspace does not accept {} sign-in",
                method_name(method)
            )
        )),
        SignInRefusal::AddressNotAllowed => AppError::Forbidden(message!(
            "authentication-this-workspace-does-not-accept-sign",
            "this workspace does not accept sign-in from here"
        )),
        SignInRefusal::PasskeyOnly => AppError::Forbidden(message!(
            "authentication-this-workspace-asks-you-to-sign",
            "this workspace asks you to sign in with your passkey"
        )),
    }
}

/// How `method` is named to the person signing in.
fn method_name(method: AuthMethod) -> &'static str {
    match method {
        AuthMethod::Password => "password",
        AuthMethod::MagicLink => "magic-link",
        AuthMethod::Passkey => "passkey",
        AuthMethod::Saml => "SAML",
        AuthMethod::Oidc => "OIDC",
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::tenant::access::auth_config::TenantAuthSettings;
    use ianua_domain::domains::tenant::status::TenantStatus;
    use ianua_domain::types::{CidrRange, TenantId};

    use super::*;
    use crate::test_support::tenant::{
        FakeTenantStore, tenant_store_in_status, tenant_store_signing_in_with,
        tenant_store_without_password_login,
    };
    use crate::test_support::{block_on, test_ctx};

    fn office_only() -> TenantAuthSettings {
        TenantAuthSettings {
            ip_allowlist: vec![CidrRange::new("203.0.113.0/24").unwrap()],
            ..TenantAuthSettings::default()
        }
    }

    fn address(ip: &str) -> IpAddress {
        IpAddress::new(ip).unwrap()
    }

    /// Ann signs in with a password to an open workspace that takes them, and
    /// is admitted for that method.
    #[test]
    fn an_open_workspace_admits_a_method_it_accepts() {
        let store = tenant_store_signing_in_with(TenantAuthSettings::default());

        let (tenant, admitted) = block_on(admit(
            store.as_ref(),
            &test_ctx().tenant(),
            AuthMethod::Password,
            Fact::Unknown,
        ))
        .unwrap();

        assert_eq!(tenant.id(), &test_ctx().tenant_id());
        assert_eq!(admitted.method(), AuthMethod::Password);
    }

    /// A suspended tenant rejects password sign-in with workspace
    /// unavailable.
    #[test]
    fn a_suspended_workspace_admits_nobody() {
        let store = tenant_store_in_status(TenantStatus::Suspended);

        let result = block_on(admit(
            store.as_ref(),
            &test_ctx().tenant(),
            AuthMethod::Password,
            Fact::Unknown,
        ));

        assert!(matches!(result, Err(AppError::TenantUnavailable(_))));
    }

    /// Password sign-in is forbidden when the tenant has disabled that
    /// method.
    #[test]
    fn a_method_switched_off_is_refused() {
        let store = tenant_store_without_password_login();

        let result = block_on(admit(
            store.as_ref(),
            &test_ctx().tenant(),
            AuthMethod::Password,
            Fact::Unknown,
        ));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Ann signs in from the office network her workspace lists, and is
    /// admitted.
    #[test]
    fn a_listed_address_is_admitted() {
        let store = tenant_store_signing_in_with(office_only());
        let office = address("203.0.113.7");

        let result = block_on(admit(
            store.as_ref(),
            &test_ctx().tenant(),
            AuthMethod::Password,
            Fact::Known(&office),
        ));

        assert!(result.is_ok());
    }

    /// An address outside the tenant's office network is forbidden from
    /// starting password sign-in.
    #[test]
    fn an_unlisted_address_is_refused() {
        let store = tenant_store_signing_in_with(office_only());
        let elsewhere = address("198.51.100.9");

        let result = block_on(admit(
            store.as_ref(),
            &test_ctx().tenant(),
            AuthMethod::Password,
            Fact::Known(&elsewhere),
        ));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// An office-only tenant refuses sign-in when the request's address
    /// is unknown.
    #[test]
    fn an_unknown_address_is_refused_where_addresses_are_listed() {
        let store = tenant_store_signing_in_with(office_only());

        let result = block_on(admit(
            store.as_ref(),
            &test_ctx().tenant(),
            AuthMethod::Password,
            Fact::Unknown,
        ));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Admission for an unknown tenant returns not found instead of a
    /// sign-in grant.
    #[test]
    fn an_unknown_workspace_admits_nobody() {
        let result = block_on(admit(
            &FakeTenantStore::empty(),
            &ScopedTenant::for_test(TenantId::new()),
            AuthMethod::Password,
            Fact::Unknown,
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
