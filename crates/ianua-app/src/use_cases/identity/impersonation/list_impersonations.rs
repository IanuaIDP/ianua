//! List impersonations: those that name the signed-in person as the admin
//! or as the person acted as, or, for someone with full control of users,
//! every one in the tenant.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
use ianua_domain::domains::identity::impersonation::SupportImpersonation;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::SupportImpersonationStore;
use crate::use_case::Query;

/// Which impersonations to list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImpersonationListing {
    /// Those that name the signed-in person, either way.
    Mine,
    /// Every one in the tenant.
    All,
}

/// The ports [`ListImpersonationsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListImpersonationsPorts {
    /// Keeps the requests.
    pub impersonation_store: Arc<dyn SupportImpersonationStore>,
    /// Who the caller is and what they hold in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists support impersonations.
pub struct ListImpersonationsUseCase {
    ports: ListImpersonationsPorts,
}

impl ListImpersonationsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListImpersonationsPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListImpersonationsUseCase {
    type Caller = CallerContext;
    type Input = ImpersonationListing;
    type Output = Result<Vec<SupportImpersonation<ResolvedTenant>>, AppError>;

    /// The impersonations `listing` names, newest first. Ann sees each
    /// request to act as her, so she can approve, decline or end it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session no longer
    ///   counts.
    /// - `AppError::Forbidden` when the caller lists every one without full
    ///   control of users.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        listing: ImpersonationListing,
    ) -> Result<Vec<SupportImpersonation<ResolvedTenant>>, AppError> {
        let tenant = ctx.tenant();
        let store = self.ports.impersonation_store.as_ref();
        match listing {
            ImpersonationListing::Mine => {
                let person = self.ports.tenant_authorities.signed_in(ctx).await?;
                store
                    .list_involving(&tenant, person.account.id())
                    .await
                    .or_internal()
            }
            ImpersonationListing::All => {
                self.ports
                    .tenant_authorities
                    .authority(ctx)
                    .await?
                    .ensure_holds(SystemPermission::Users(UserAction::Manage))
                    .map_err(AppError::from_domain)?;
                store.list_all(&tenant).await.or_internal()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::UserId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::test_caller_id;
    use crate::test_support::identity::{FakeSupportImpersonationStore, impersonation_asked};
    use crate::test_support::{block_on, test_ctx};

    fn list(
        store: FakeSupportImpersonationStore,
        authorities: FakeTenantAuthorities,
        listing: ImpersonationListing,
    ) -> Result<Vec<SupportImpersonation<ResolvedTenant>>, AppError> {
        let use_case = ListImpersonationsUseCase::new(ListImpersonationsPorts {
            impersonation_store: Arc::new(store),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), listing))
    }

    /// Sam asked to act as Ann. Ann sees his request among hers.
    #[test]
    fn the_person_sees_requests_to_act_as_them() {
        let asked = impersonation_asked(UserId::new(), test_caller_id());

        let listed = list(
            FakeSupportImpersonationStore::holding(&asked),
            FakeTenantAuthorities::holding_everything(),
            ImpersonationListing::Mine,
        )
        .unwrap();

        assert_eq!(listed.len(), 1);
    }

    /// A request between two other people is not among Ann's.
    #[test]
    fn requests_between_others_are_not_mine() {
        let asked = impersonation_asked(UserId::new(), UserId::new());

        let listed = list(
            FakeSupportImpersonationStore::holding(&asked),
            FakeTenantAuthorities::holding_everything(),
            ImpersonationListing::Mine,
        )
        .unwrap();

        assert!(listed.is_empty());
    }

    /// Ann has full control of users and sees every request in the tenant.
    #[test]
    fn an_admin_sees_every_request() {
        let asked = impersonation_asked(UserId::new(), UserId::new());

        let listed = list(
            FakeSupportImpersonationStore::holding(&asked),
            FakeTenantAuthorities::holding_everything(),
            ImpersonationListing::All,
        )
        .unwrap();

        assert_eq!(listed.len(), 1);
    }

    /// User-viewing rights do not permit listing every impersonation request.
    #[test]
    fn listing_every_request_needs_full_control_of_users() {
        let result = list(
            FakeSupportImpersonationStore::empty(),
            FakeTenantAuthorities::holding(&[SystemPermission::Users(UserAction::View)]),
            ImpersonationListing::All,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller cannot list their own impersonation requests.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = list(
            FakeSupportImpersonationStore::empty(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            ImpersonationListing::Mine,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
