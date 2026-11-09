//! List log targets: every place the tenant ships its request records to.

use std::sync::Arc;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::proxy::LogShippingStore;
use crate::use_case::Query;
use crate::use_cases::proxy::log_shipping::view::LogTargetView;
use crate::use_cases::routing::lookup::ensure_may_view_routing;

/// The ports [`ListLogTargetsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListLogTargetsPorts {
    /// Keeps the tenant's log shipping targets.
    pub log_shipping_store: Arc<dyn LogShippingStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the tenant's log shipping targets.
pub struct ListLogTargetsUseCase {
    ports: ListLogTargetsPorts,
}

impl ListLogTargetsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListLogTargetsPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListLogTargetsUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<Vec<LogTargetView>, AppError>;

    /// Every target in the tenant, by name, each showing whether it holds a
    /// credential but never the credential.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view routing.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        (): (),
    ) -> Result<Vec<LogTargetView>, AppError> {
        ensure_may_view_routing(self.ports.tenant_authorities.as_ref(), caller).await?;
        let targets = self
            .ports
            .log_shipping_store
            .list(&caller.tenant())
            .await
            .or_internal()?;
        Ok(targets.iter().map(LogTargetView::from).collect())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::proxy::{FakeLogShippingStore, test_log_target};
    use crate::test_support::{block_on, test_ctx};
    use crate::use_cases::proxy::log_shipping::view::CredentialState;

    /// Lists, as `authorities` allow, a store holding `store`.
    fn list(
        store: FakeLogShippingStore,
        authorities: FakeTenantAuthorities,
    ) -> Result<Vec<LogTargetView>, AppError> {
        let use_case = ListLogTargetsUseCase::new(ListLogTargetsPorts {
            log_shipping_store: Arc::new(store),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), ()))
    }

    /// Bob, who may view routing, lists the targets. He sees Ann's SIEM and
    /// that it holds a key, but not the key.
    #[test]
    fn the_tenants_targets_are_listed_without_their_keys() {
        let store = FakeLogShippingStore::holding(test_ctx().tenant_id(), test_log_target());

        let targets = list(store, FakeTenantAuthorities::holding_everything()).unwrap();

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].credential, CredentialState::Set);
    }

    /// A store holding only another tenant's target yields an empty list.
    #[test]
    fn another_tenants_targets_are_not_listed() {
        let store = FakeLogShippingStore::holding(TenantId::new(), test_log_target());

        let targets = list(store, FakeTenantAuthorities::holding_everything()).unwrap();

        assert!(targets.is_empty());
    }

    /// Listing the tenant's SIEM target is forbidden without routing view rights.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let store = FakeLogShippingStore::holding(test_ctx().tenant_id(), test_log_target());

        let result = list(store, FakeTenantAuthorities::holding(&[]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Listing targets with a signed-out session fails authentication.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = list(
            FakeLogShippingStore::default(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
