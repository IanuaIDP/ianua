//! Delete service provider: remove a SAML app. People keep their accounts;
//! they only stop signing in to the app through this platform.

use std::sync::Arc;

use ianua_domain::domains::federation::control::{FederationControl, FederationRight};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::SamlServiceProviderId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::federation::SamlServiceProviderStore;
use crate::use_case::Command;
use crate::use_cases::federation::idp::lookup::existing_service_provider;

/// The ports [`DeleteUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeletePorts {
    /// Keeps the tenant's SAML apps.
    pub service_providers: Arc<dyn SamlServiceProviderStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Removes a SAML app.
pub struct DeleteUseCase {
    ports: DeletePorts,
}

impl DeleteUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DeletePorts) -> Self {
        Self { ports }
    }
}

impl Command for DeleteUseCase {
    type Caller = CallerContext;
    type Input = SamlServiceProviderId;
    type Output = Result<(), AppError>;

    /// Removes the app and records `federation.service_provider_deleted`
    /// once it is gone. Needs the delete right.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` if the caller may not delete connections.
    /// - `AppError::NotFound` if the app doesn't exist.
    /// - `AppError::Internal` on audit or persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        id: SamlServiceProviderId,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = FederationControl::new(&authority);
        control
            .ensure_may(FederationRight::DeleteConnection)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let store = self.ports.service_providers.as_ref();
        let mut app = existing_service_provider(store, &tenant, &id).await?;
        app.delete(&control).map_err(AppError::from_domain)?;

        store.delete(&tenant, &id).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), app.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{FederationAction, SystemPermission};
    use ianua_domain::domains::federation::connection_status::ConnectionStatus;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::federation::{FakeSamlServiceProviderStore, test_service_provider};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn seeded() -> (Arc<FakeSamlServiceProviderStore>, SamlServiceProviderId) {
        let id = SamlServiceProviderId::new();
        let app = test_service_provider(id, ConnectionStatus::Active);
        let store = FakeSamlServiceProviderStore::holding(&test_ctx().tenant(), [app]);
        (Arc::new(store), id)
    }

    fn delete(
        store: Arc<FakeSamlServiceProviderStore>,
        authorities: FakeTenantAuthorities,
        audit: &Arc<FakeEventDispatcher>,
        id: SamlServiceProviderId,
    ) -> Result<(), AppError> {
        let use_case = DeleteUseCase::new(DeletePorts {
            service_providers: store,
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), id))
    }

    /// Fay removes Salesforce. It is gone and its removal is recorded.
    #[test]
    fn an_app_is_removed_and_recorded() {
        let (store, id) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());

        delete(
            store.clone(),
            FakeTenantAuthorities::holding_everything(),
            &audit,
            id,
        )
        .unwrap();

        assert_eq!(store.count(), 0);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["federation.service_provider_deleted"]
        );
    }

    /// Fay names an app Acme does not have. It is not found.
    #[test]
    fn an_unknown_app_is_not_found() {
        let (store, _) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = delete(
            store,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            SamlServiceProviderId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Update rights cannot delete Salesforce; the forbidden attempt
    /// leaves the app stored and records no deletion.
    #[test]
    fn the_update_right_removes_no_app() {
        let (store, id) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());
        let update = [SystemPermission::Federation(FederationAction::Update)];

        let result = delete(
            store.clone(),
            FakeTenantAuthorities::holding(&update),
            &audit,
            id,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 1);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot delete the configured SAML app.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = delete(
            store,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &audit,
            id,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
