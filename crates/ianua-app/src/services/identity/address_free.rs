//! Refusing an address another account already signs in with, which every
//! use case that opens an account or moves one onto a new address checks
//! first, whoever asks: an admin, the person, or the tenant's directory.
//!
//! An address is unique within its tenant, or within its organization for
//! the organization's own members. The same person may hold an account in
//! several organizations under one address.

use ianua_domain::message;
use ianua_domain::types::{Email, OrganizationId};

use crate::error::{AppError, OrInternal};
use crate::ports::identity::UserStore;
use crate::ports::organization::OrgUserStore;
use crate::tenancy::ScopedTenant;

/// Refuses `email` when a user of the tenant already has it.
///
/// # Errors
///
/// - `AppError::Conflict` if the address is taken.
/// - `AppError::Internal` on storage failure.
pub(crate) async fn ensure_email_free(
    store: &dyn UserStore,
    tenant: &ScopedTenant,
    email: &Email,
) -> Result<(), AppError> {
    let taken = store.email_exists(tenant, email).await.or_internal()?;
    if taken {
        return Err(AppError::Conflict(message!(
            "identity-email-already-taken",
            "email already taken"
        )));
    }
    Ok(())
}

/// Refuses `email` when a member of `organization_id` already has it. An
/// account on the address in another organization leaves it free here.
///
/// # Errors
///
/// - `AppError::Conflict` if a member of the organization has the address.
/// - `AppError::Internal` on storage failure.
pub(crate) async fn ensure_member_address_free(
    store: &dyn OrgUserStore,
    organization_id: &OrganizationId,
    email: &Email,
) -> Result<(), AppError> {
    let held = store
        .find_by_email(organization_id, email)
        .await
        .or_internal()?;
    if held.is_some() {
        return Err(AppError::Conflict(message!(
            "identity-email-already-registered",
            "email already registered"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::{TenantId, UserId};

    use super::*;
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::organization::{FakeOrgUserStore, org_user_store_with, test_org_user};
    use crate::test_support::{block_on, test_ctx};

    fn free(users: &FakeUserStore, tenant: &ScopedTenant, email: &str) -> Result<(), AppError> {
        block_on(ensure_email_free(
            users,
            tenant,
            &Email::new(email).unwrap(),
        ))
    }

    /// Nobody in Acme signs in with Ada's address yet. It is free.
    #[test]
    fn an_address_nobody_has_is_free() {
        let users = FakeUserStore::empty();

        assert!(free(&users, &test_ctx().tenant(), "ada@acme.com").is_ok());
    }

    /// Grace's address conflicts with another account request in her tenant.
    #[test]
    fn an_address_another_user_has_is_a_conflict() {
        let users = FakeUserStore::empty();
        users.add_active_user(UserId::new(), "grace@acme.com");

        let result = free(&users, &test_ctx().tenant(), "grace@acme.com");

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// Grace signs in to Globex as grace@acme.com. Acme is another tenant,
    /// so the address is still free there.
    #[test]
    fn an_address_held_in_another_tenant_is_free() {
        let users = FakeUserStore::empty();
        users.add_active_user(UserId::new(), "grace@acme.com");
        let globex = ScopedTenant::for_test(TenantId::new());

        assert!(free(&users, &globex, "grace@acme.com").is_ok());
    }

    /// Whether `email` is free among the members of `organization_id`.
    fn member_free(
        members: &FakeOrgUserStore,
        organization_id: &OrganizationId,
        email: &str,
    ) -> Result<(), AppError> {
        block_on(ensure_member_address_free(
            members,
            organization_id,
            &Email::new(email).unwrap(),
        ))
    }

    /// Grace's member address is unavailable for another account in Acme.
    #[test]
    fn an_address_a_member_has_is_taken_in_their_organization() {
        let acme = OrganizationId::new();
        let members = org_user_store_with([test_org_user(acme, "grace@acme.com", OrgRole::Member)]);

        let result = member_free(&members, &acme, "grace@acme.com");

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// Grace is a member of Acme as grace@acme.com. Globex is another
    /// organization, so she may hold an account there on the same address.
    #[test]
    fn an_address_held_in_another_organization_is_free() {
        let acme = OrganizationId::new();
        let members = org_user_store_with([test_org_user(acme, "grace@acme.com", OrgRole::Member)]);

        assert!(member_free(&members, &OrganizationId::new(), "grace@acme.com").is_ok());
    }
}
