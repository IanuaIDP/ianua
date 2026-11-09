//! Lookups that use cases in several folders share.
//!
//! A lookup used by one folder lives in that folder's `lookup.rs`. These are
//! needed across folders, so they live once here instead of once per folder.
//! Each loads one aggregate, or answers `NotFound` or the aggregate's
//! starting state, and decides nothing else.

use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::authentication::sessions::session::Session;
use ianua_domain::domains::authorization::break_glass::BreakGlassPolicy;
use ianua_domain::domains::authorization::role::Role;
use ianua_domain::domains::consumers::consumer::Consumer;
use ianua_domain::domains::crypto::signing_key::SigningKeySet;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::membership::TenantReach;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{
    AgentId, ConsumerId, OrganizationId, RoleId, SessionId, TenantId, UserId,
};

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::agents::AgentStore;
use crate::ports::authentication::BreakGlassStore;
use crate::ports::authorization::RoleStore;
use crate::ports::consumers::ConsumerStore;
use crate::ports::crypto::SigningKeyStore;
use crate::ports::identity::UserStore;
use crate::ports::organization::{OrgTenantGrantStore, OrganizationStore};
use crate::ports::shared::SessionStore;
use crate::ports::tenant::TenantStore;
use crate::tenancy::ScopedTenant;

/// The tenant with `tenant_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if there is no such tenant.
/// - `AppError::Internal` on storage failure.
pub(crate) async fn existing_tenant(
    store: &dyn TenantStore,
    tenant_id: &TenantId,
) -> Result<Tenant, AppError> {
    store
        .find_by_id(tenant_id)
        .await
        .or_internal()?
        .or_not_found(message!("app-tenant-not-found", "tenant not found"))
}

/// The tenant's user with `user_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such user.
/// - `AppError::Internal` on storage failure.
pub(crate) async fn existing_user(
    store: &dyn UserStore,
    tenant: &ScopedTenant,
    user_id: &UserId,
) -> Result<User<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, user_id)
        .await
        .or_internal()?
        .or_not_found(message!("app-user-not-found", "user not found"))
}

/// The tenant's role with `role_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such role.
/// - `AppError::Internal` on storage failure.
pub(crate) async fn existing_role(
    store: &dyn RoleStore,
    tenant: &ScopedTenant,
    role_id: &RoleId,
) -> Result<Role<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, role_id)
        .await
        .or_internal()?
        .or_not_found(message!("app-role-not-found", "role not found"))
}

/// The tenant's agent with `agent_id`, whatever its status.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such agent.
/// - `AppError::Internal` on storage failure.
pub(crate) async fn existing_agent(
    store: &dyn AgentStore,
    tenant: &ScopedTenant,
    agent_id: &AgentId,
) -> Result<AgentIdentity<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, agent_id)
        .await
        .or_internal()?
        .or_not_found(message!("app-agent-not-found", "agent not found"))
}

/// The organization with `id`.
///
/// # Errors
///
/// - `AppError::NotFound` if there is no such organization.
/// - `AppError::Internal` on storage failure.
pub(crate) async fn existing_organization(
    store: &dyn OrganizationStore,
    id: &OrganizationId,
) -> Result<Organization, AppError> {
    store
        .find_by_id(id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "authentication-organization-not-found",
            "organization not found"
        ))
}

/// The tenant's consumer with `consumer_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such consumer.
/// - `AppError::Internal` on storage failure.
pub(crate) async fn existing_consumer(
    store: &dyn ConsumerStore,
    tenant: &ScopedTenant,
    consumer_id: &ConsumerId,
) -> Result<Consumer<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, consumer_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "consumers-consumer-not-found",
            "consumer not found"
        ))
}

/// The tenant's signing key set.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no key set.
/// - `AppError::Internal` on storage failure.
pub(crate) async fn existing_key_set(
    store: &dyn SigningKeyStore,
    tenant: &ScopedTenant,
) -> Result<SigningKeySet<ResolvedTenant>, AppError> {
    store
        .find(tenant)
        .await
        .or_internal()?
        .or_not_found(message!("app-no-signing-key-set", "no signing key set"))
}

/// The tenant's break-glass policy, or one that lets nothing when the
/// tenant never set one.
///
/// # Errors
///
/// - `AppError::Internal` on storage failure.
pub(crate) async fn break_glass_policy(
    store: &dyn BreakGlassStore,
    tenant: &ScopedTenant,
) -> Result<BreakGlassPolicy, AppError> {
    let stored = store.find_policy(tenant).await.or_internal()?;
    Ok(stored.unwrap_or_else(|| BreakGlassPolicy::off(**tenant)))
}

/// The session with `session_id`, which must belong to `user_id`.
///
/// Someone else's session answers the same as a missing one, so its
/// existence is not revealed.
///
/// # Errors
///
/// - `AppError::NotFound` if there is no such session or it is another
///   user's.
/// - `AppError::Internal` on storage failure.
pub(crate) async fn owned_session(
    store: &dyn SessionStore,
    tenant: &ScopedTenant,
    session_id: &SessionId,
    user_id: &UserId,
) -> Result<Session<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, session_id)
        .await
        .or_internal()?
        .filter(|session| session.user_id() == user_id)
        .or_not_found(message!("app-session-not-found", "session not found"))
}

/// The tenants `member` was let into, one by one. Read only for a role
/// that reaches tenants that way: any other's grants count for nothing.
///
/// # Errors
///
/// - `AppError::Internal` on storage failure.
pub(crate) async fn granted_tenants(
    store: &dyn OrgTenantGrantStore,
    member: &OrgUser,
) -> Result<Vec<TenantId>, AppError> {
    match member.role().tenant_reach() {
        TenantReach::Granted => store.list_tenant_ids(member.id()).await.or_internal(),
        TenantReach::Every | TenantReach::Nothing => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::agents::FakeAgentStore;
    use crate::test_support::crypto::FakeSigningKeyStore;
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::tenant::{FakeTenantStore, test_tenant};
    use crate::test_support::{block_on, test_ctx};

    /// Ann's tenant is on file, so looking it up hands it back.
    #[test]
    fn a_stored_tenant_is_found() {
        let tenant = test_tenant("acme", "acme.example.com");
        let tenant_id = *tenant.id();
        let store = FakeTenantStore::holding(tenant);

        let found = block_on(existing_tenant(&store, &tenant_id)).unwrap();

        assert_eq!(found.id(), &tenant_id);
    }

    /// A tenant nobody registered answers not found.
    #[test]
    fn an_unknown_tenant_is_not_found() {
        let result = block_on(existing_tenant(&FakeTenantStore::empty(), &TenantId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann is a user of the tenant, so looking her up hands her back.
    #[test]
    fn a_stored_user_is_found() {
        let ann = UserId::new();
        let store = FakeUserStore::with_user(ann, "ann@example.com");

        let found = block_on(existing_user(&store, &test_ctx().tenant(), &ann)).unwrap();

        assert_eq!(found.id(), &ann);
    }

    /// Looking up Ann through another tenant returns not found.
    #[test]
    fn a_user_of_another_tenant_is_not_found() {
        let ann = UserId::new();
        let store = FakeUserStore::with_user(ann, "ann@example.com");
        let elsewhere = ScopedTenant::for_test(TenantId::new());

        let result = block_on(existing_user(&store, &elsewhere, &ann));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann's agent is on file, so looking it up hands it back.
    #[test]
    fn a_stored_agent_is_found() {
        let agent = AgentId::new();
        let store = FakeAgentStore::with_active(agent);

        let found = block_on(existing_agent(&store, &test_ctx().tenant(), &agent)).unwrap();

        assert_eq!(found.id(), &agent);
    }

    /// An agent nobody registered answers not found.
    #[test]
    fn an_unknown_agent_is_not_found() {
        let result = block_on(existing_agent(
            &FakeAgentStore::empty(),
            &test_ctx().tenant(),
            &AgentId::new(),
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A tenant that never generated signing keys answers not found.
    #[test]
    fn a_tenant_without_signing_keys_is_not_found() {
        let result = block_on(existing_key_set(
            &FakeSigningKeyStore::empty(),
            &test_ctx().tenant(),
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
