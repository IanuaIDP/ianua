//! Get clone: how far a copy of one tenant's setup into another has come.

use std::sync::Arc;

use ianua_domain::domains::tenant::clone::TenantClone;
use ianua_domain::types::TenantCloneId;

use crate::acting::{OperatorAuthorities, OrgActors};
use crate::error::AppError;
use crate::ports::tenant::{TenantCloneStore, TenantStore};
use crate::use_case::Query;
use crate::use_cases::tenant::clones::lookup::existing_clone;
use crate::use_cases::tenant::lifecycle::steward::{Acting, StewardSources, TenantSteward};

/// The ports [`GetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// Tenants, for the one the clone fills.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Where clones are kept.
    pub clone_store: Arc<dyn TenantCloneStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

/// Reads one clone, for following its progress.
pub struct GetUseCase {
    ports: GetPorts,
}

impl GetUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetUseCase {
    type Caller = TenantSteward;
    type Input = TenantCloneId;
    type Output = Result<TenantClone, AppError>;

    /// The clone `id`: what it copies, what it copied so far, and where it
    /// is. A member reads only clones into their own organization's
    /// tenants.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the credential is someone else's, or the
    ///   operator is disabled.
    /// - `AppError::NotFound` when there is no such clone, or it fills a
    ///   tenant of another organization than the member's.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &TenantSteward,
        id: TenantCloneId,
    ) -> Result<TenantClone, AppError> {
        let sources = StewardSources {
            org_actors: self.ports.org_actors.as_ref(),
            operator_authorities: self.ports.operator_authorities.as_ref(),
        };
        let acting = Acting::resolve(sources, caller).await?;
        let clone = existing_clone(self.ports.clone_store.as_ref(), &id).await?;
        acting
            .reached_tenant(self.ports.tenant_store.as_ref(), clone.target())
            .await?;
        Ok(clone)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::tenant::clone::ClonePart;
    use ianua_domain::types::{ActedBy, OrganizationId};

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::tenant::{FakeTenantCloneStore, FakeTenantStore, test_tenant_in};
    use crate::test_support::{block_on, test_ctx, test_org_caller};

    /// A use case holding one clone between two tenants of `organization`,
    /// read by members as `actors` says, with the clone's id.
    fn holding(organization: OrganizationId, actors: FakeOrgActors) -> (GetUseCase, TenantCloneId) {
        let source = test_tenant_in(organization, "prod", "prod.acme.com");
        let target = test_tenant_in(organization, "staging", "staging.acme.com");
        let clone =
            TenantClone::start(vec![ClonePart::Routes], &source, &target, ActedBy::Platform)
                .unwrap();
        let id = *clone.id();
        let clones = Arc::new(FakeTenantCloneStore::empty());
        block_on(clones.save(&clone)).unwrap();
        let uc = GetUseCase::new(GetPorts {
            tenant_store: Arc::new(FakeTenantStore::holding_all([source, target])),
            clone_store: clones,
            org_actors: Arc::new(actors),
            ..GetPorts::fakes()
        });
        (uc, id)
    }

    fn read(uc: &GetUseCase, id: TenantCloneId) -> Result<TenantClone, AppError> {
        block_on(uc.execute(&TenantSteward::Member(test_org_caller()), id))
    }

    /// Ann, an owner of Acme, follows the clone into staging. She sees it
    /// still copying the routes.
    #[test]
    fn a_member_reads_a_clone_of_their_organization() {
        let (uc, id) = holding(
            test_ctx().organization_id(),
            FakeOrgActors::in_role(OrgRole::Owner),
        );

        let clone = read(&uc, id).unwrap();

        assert_eq!(clone.remaining(), [ClonePart::Routes]);
    }

    /// A member querying a clone into another organization's tenant receives
    /// not found.
    #[test]
    fn a_clone_of_another_organization_is_not_found() {
        let (uc, id) = holding(
            OrganizationId::new(),
            FakeOrgActors::in_role(OrgRole::Owner),
        );

        let result = read(&uc, id);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out session cannot read a tenant clone's progress.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (uc, id) = holding(
            test_ctx().organization_id(),
            FakeOrgActors::refusing(Refusal::SignedOut),
        );

        let result = read(&uc, id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
