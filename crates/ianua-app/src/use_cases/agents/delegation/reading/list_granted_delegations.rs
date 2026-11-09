//! List granted delegations: the delegations the caller gave agents.
//!
//! A person sees every agent acting on their authority, the way a consent
//! page lists the apps connected to an account, so they can see what they
//! handed out and revoke what they no longer want.

use std::sync::Arc;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::DelegationStore;
use crate::use_case::Query;
use crate::use_cases::agents::delegation::{DescribeDelegations, DescribedDelegation};

/// The ports [`ListGrantedDelegationsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListGrantedDelegationsPorts {
    /// Loads the delegations.
    pub delegation_store: Arc<dyn DelegationStore>,
    /// Adds the delegator's name and budget use to each delegation.
    pub describer: Arc<DescribeDelegations>,
    /// Who the caller is in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the delegations the caller granted.
pub struct ListGrantedDelegationsUseCase {
    ports: ListGrantedDelegationsPorts,
}

impl ListGrantedDelegationsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListGrantedDelegationsPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListGrantedDelegationsUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<Vec<DescribedDelegation>, AppError>;

    /// Every delegation the caller granted, through the account they act
    /// with, live or not, each described with its budget use.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        (): (),
    ) -> Result<Vec<DescribedDelegation>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let granted = self
            .ports
            .delegation_store
            .find_by_delegator(&tenant, &authority.who().principal())
            .await
            .or_internal()?;
        Ok(self.ports.describer.describe(&tenant, granted).await)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::CapabilitySet;
    use ianua_domain::types::AgentId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeDelegationStore, caller_person, root_delegation, someone,
    };
    use crate::test_support::{block_on, test_ctx};

    /// One delegation the caller granted, and one Bob granted.
    fn ports() -> ListGrantedDelegationsPorts {
        let delegations = FakeDelegationStore::empty();
        for delegator in [caller_person(), someone("bob@example.test")] {
            let granted = root_delegation(
                delegator.principal(),
                AgentId::new(),
                CapabilitySet::empty(),
            );
            block_on(delegations.save(&test_ctx().tenant(), &granted)).unwrap();
        }
        ListGrantedDelegationsPorts {
            delegation_store: Arc::new(delegations),
            ..ListGrantedDelegationsPorts::fakes()
        }
    }

    fn list(ports: ListGrantedDelegationsPorts) -> Result<Vec<DescribedDelegation>, AppError> {
        block_on(ListGrantedDelegationsUseCase::new(ports).execute(&test_ctx(), ()))
    }

    /// Ann lists what she granted. She sees her own delegation, and not
    /// Bob's.
    #[test]
    fn a_person_sees_the_delegations_they_granted() {
        let listed = list(ports()).unwrap();

        assert_eq!(listed.len(), 1);
        assert_eq!(
            *listed[0].delegation.delegator(),
            caller_person().principal()
        );
    }

    /// A signed-out caller cannot list the delegations they granted.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let ports = ListGrantedDelegationsPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports()
        };

        let result = list(ports);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
