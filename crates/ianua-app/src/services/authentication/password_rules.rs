//! The password rules a tenant or an organization has configured.
//!
//! Read in one place because two kinds of caller must agree on them: the
//! status check that tells a signed-out reader what a new password needs, and
//! the submit that enforces it. A form shown one policy and checked against
//! another refuses passwords it just told the reader were fine.

use ianua_domain::message;
use ianua_domain::types::{OrganizationId, PasswordPolicy, TenantId};

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::organization::OrganizationStore;
use crate::ports::tenant::TenantStore;
use crate::services::lookup::existing_tenant;

/// The password policy `tenant_id` has configured.
///
/// Never falls back to the deployment default when the tenant cannot be read:
/// that would quietly accept a password the tenant had decided was too weak,
/// which is the one direction a strength check must never fail in.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant does not exist.
/// - `AppError::Internal` on lookup failure.
pub(crate) async fn for_tenant(
    store: &dyn TenantStore,
    tenant_id: &TenantId,
) -> Result<PasswordPolicy, AppError> {
    let tenant = existing_tenant(store, tenant_id).await?;
    Ok(tenant.auth_config().password_policy().clone())
}

/// The rules a password `tenant_id` is newly given must meet, or `None` when
/// the tenant signs nobody in with a password and so takes no new ones.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant does not exist.
/// - `AppError::Internal` on lookup failure.
pub(crate) async fn for_new_tenant_password(
    store: &dyn TenantStore,
    tenant_id: &TenantId,
) -> Result<Option<PasswordPolicy>, AppError> {
    let tenant = existing_tenant(store, tenant_id).await?;
    Ok(tenant.auth_config().new_password_policy().cloned())
}

/// The password policy `organization_id` has configured for its own users.
///
/// # Errors
///
/// - `AppError::NotFound` if the organization does not exist.
/// - `AppError::Internal` on lookup failure.
pub(crate) async fn for_organization(
    store: &dyn OrganizationStore,
    organization_id: &OrganizationId,
) -> Result<PasswordPolicy, AppError> {
    let organization = store
        .find_by_id(organization_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "authentication-organization-not-found",
            "organization not found"
        ))?;
    Ok(organization.auth_config().password_policy().clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::organization::{
        FakeOrganizationStore, org_store_with_strict_password_policy, strict_password_policy,
    };
    use crate::test_support::tenant::{
        FakeTenantStore, tenant_store_with_password_policy, tenant_store_without_password_login,
    };
    use crate::test_support::{block_on, test_ctx};

    /// Ann's tenant asks for long passwords with a symbol, and those are the
    /// rules read back.
    #[test]
    fn a_tenants_own_rules_are_read() {
        let store = tenant_store_with_password_policy(strict_password_policy());

        let policy = block_on(for_tenant(store.as_ref(), &test_ctx().tenant_id())).unwrap();

        assert_eq!(policy, strict_password_policy());
    }

    /// Looking up an unknown tenant's password policy returns not found
    /// instead of supplying default rules.
    #[test]
    fn an_unknown_tenant_has_no_rules_to_fall_back_on() {
        let result = block_on(for_tenant(&FakeTenantStore::empty(), &TenantId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann's tenant signs people in with a password, so a new password is
    /// held to its rules.
    #[test]
    fn a_password_tenant_holds_new_passwords_to_its_rules() {
        let store = tenant_store_with_password_policy(strict_password_policy());

        let policy = block_on(for_new_tenant_password(
            store.as_ref(),
            &test_ctx().tenant_id(),
        ))
        .unwrap();

        assert_eq!(policy, Some(strict_password_policy()));
    }

    /// A tenant without password sign-in returns no policy for new
    /// passwords, signalling that this path is unavailable.
    #[test]
    fn a_passkey_only_tenant_takes_no_new_passwords() {
        let store = tenant_store_without_password_login();

        let policy = block_on(for_new_tenant_password(
            store.as_ref(),
            &test_ctx().tenant_id(),
        ))
        .unwrap();

        assert_eq!(policy, None);
    }

    /// New-password policy lookup fails with not found for an unknown
    /// tenant.
    #[test]
    fn an_unknown_tenant_takes_no_new_password() {
        let result = block_on(for_new_tenant_password(
            &FakeTenantStore::empty(),
            &TenantId::new(),
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann's organization asks for strict passwords, and those are the rules
    /// read back.
    #[test]
    fn an_organizations_own_rules_are_read() {
        let organization_id = OrganizationId::new();
        let store = org_store_with_strict_password_policy(organization_id);

        let policy = block_on(for_organization(store.as_ref(), &organization_id)).unwrap();

        assert_eq!(policy, strict_password_policy());
    }

    /// An unknown organization has no fallback password policy: its
    /// lookup returns not found.
    #[test]
    fn an_unknown_organization_has_no_rules_to_fall_back_on() {
        let result = block_on(for_organization(
            &FakeOrganizationStore::empty(),
            &OrganizationId::new(),
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
