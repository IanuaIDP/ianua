//! Change service provider status: switch a SAML app on or off.

use std::sync::Arc;

use ianua_domain::domains::federation::connection_status::ConnectionStatus;
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

/// Which app to switch, and to what.
pub struct ChangeStatusRequest {
    /// The app.
    pub id: SamlServiceProviderId,
    /// On or off.
    pub status: ConnectionStatus,
}

/// The ports [`ChangeStatusUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeStatusPorts {
    /// Keeps the tenant's SAML apps.
    pub service_providers: Arc<dyn SamlServiceProviderStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Switches a SAML app on or off.
pub struct ChangeStatusUseCase {
    ports: ChangeStatusPorts,
}

impl ChangeStatusUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ChangeStatusPorts) -> Self {
        Self { ports }
    }
}

impl Command for ChangeStatusUseCase {
    type Caller = CallerContext;
    type Input = ChangeStatusRequest;
    type Output = Result<(), AppError>;

    /// Switches the app and records `federation.service_provider_updated`.
    /// Switching it off answers no more sign-ins to it, which anyone who may
    /// update connections may do in an incident; switching it back on needs
    /// the full federation right.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` if the caller lacks the right the switch
    ///   needs.
    /// - `AppError::NotFound` if the app doesn't exist.
    /// - `AppError::Domain` if it is already in that status.
    /// - `AppError::Internal` on audit or persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: ChangeStatusRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = FederationControl::new(&authority);
        control
            .ensure_may(FederationRight::EditConnection)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let store = self.ports.service_providers.as_ref();
        let mut app = existing_service_provider(store, &tenant, &request.id).await?;
        let switched = match request.status {
            ConnectionStatus::Active => app.activate(&control),
            ConnectionStatus::Disabled => app.disable(&control),
        };
        switched.map_err(AppError::from_domain)?;

        store.save(&tenant, &app).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), app.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{FederationAction, SystemPermission};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::federation::{FakeSamlServiceProviderStore, test_service_provider};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn seeded(
        status: ConnectionStatus,
    ) -> (Arc<FakeSamlServiceProviderStore>, SamlServiceProviderId) {
        let id = SamlServiceProviderId::new();
        let app = test_service_provider(id, status);
        let store = FakeSamlServiceProviderStore::holding(&test_ctx().tenant(), [app]);
        (Arc::new(store), id)
    }

    fn switch(
        store: Arc<FakeSamlServiceProviderStore>,
        authorities: FakeTenantAuthorities,
        audit: &Arc<FakeEventDispatcher>,
        request: ChangeStatusRequest,
    ) -> Result<(), AppError> {
        let use_case = ChangeStatusUseCase::new(ChangeStatusPorts {
            service_providers: store,
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), request))
    }

    fn status_of(
        store: &FakeSamlServiceProviderStore,
        id: &SamlServiceProviderId,
    ) -> ConnectionStatus {
        block_on(store.find_by_id(&test_ctx().tenant(), id))
            .unwrap()
            .unwrap()
            .status()
    }

    /// Salesforce leaks assertions in an incident. Sam, who may update
    /// connections, switches it off; it is answered no more, and the change
    /// is recorded.
    #[test]
    fn the_update_right_switches_an_app_off() {
        let (store, id) = seeded(ConnectionStatus::Active);
        let audit = Arc::new(FakeEventDispatcher::new());
        let update = [SystemPermission::Federation(FederationAction::Update)];
        let request = ChangeStatusRequest {
            id,
            status: ConnectionStatus::Disabled,
        };

        switch(
            store.clone(),
            FakeTenantAuthorities::holding(&update),
            &audit,
            request,
        )
        .unwrap();

        assert_eq!(status_of(&store, &id), ConnectionStatus::Disabled);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["federation.service_provider_updated"]
        );
    }

    /// Fay switches on an app that is on already. She is told it is in the
    /// wrong state.
    #[test]
    fn an_app_already_on_cannot_be_switched_on() {
        let (store, id) = seeded(ConnectionStatus::Active);
        let audit = Arc::new(FakeEventDispatcher::new());
        let request = ChangeStatusRequest {
            id,
            status: ConnectionStatus::Active,
        };

        let result = switch(
            store,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            request,
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Fay names an app Acme does not have. It is not found.
    #[test]
    fn an_unknown_app_is_not_found() {
        let (store, _) = seeded(ConnectionStatus::Active);
        let audit = Arc::new(FakeEventDispatcher::new());
        let request = ChangeStatusRequest {
            id: SamlServiceProviderId::new(),
            status: ConnectionStatus::Disabled,
        };

        let result = switch(
            store,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            request,
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Update rights cannot reactivate a disabled app; it stays disabled
    /// and no status change is audited.
    #[test]
    fn the_update_right_does_not_switch_an_app_back_on() {
        let (store, id) = seeded(ConnectionStatus::Disabled);
        let audit = Arc::new(FakeEventDispatcher::new());
        let update = [SystemPermission::Federation(FederationAction::Update)];
        let request = ChangeStatusRequest {
            id,
            status: ConnectionStatus::Active,
        };

        let result = switch(
            store.clone(),
            FakeTenantAuthorities::holding(&update),
            &audit,
            request,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(status_of(&store, &id), ConnectionStatus::Disabled);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot disable a SAML app.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = seeded(ConnectionStatus::Active);
        let audit = Arc::new(FakeEventDispatcher::new());
        let request = ChangeStatusRequest {
            id,
            status: ConnectionStatus::Disabled,
        };

        let result = switch(
            store,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &audit,
            request,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
