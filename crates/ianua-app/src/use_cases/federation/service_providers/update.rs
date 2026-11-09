//! Update service provider: change how a SAML app is answered.

use std::sync::Arc;

use ianua_domain::domains::federation::control::{FederationControl, FederationRight};
use ianua_domain::domains::federation::service_provider::SamlServiceProviderChange;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::SamlServiceProviderId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::federation::SamlServiceProviderStore;
use crate::use_case::Command;
use crate::use_cases::federation::idp::lookup::existing_service_provider;

/// The changes to make to an app.
pub struct UpdateRequest {
    /// The app.
    pub id: SamlServiceProviderId,
    /// Each change, made together or not at all.
    pub changes: Vec<SamlServiceProviderChange>,
}

/// The ports [`UpdateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdatePorts {
    /// Keeps the tenant's SAML apps.
    pub service_providers: Arc<dyn SamlServiceProviderStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes how a SAML app is answered.
pub struct UpdateUseCase {
    ports: UpdatePorts,
}

impl UpdateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: UpdatePorts) -> Self {
        Self { ports }
    }
}

impl Command for UpdateUseCase {
    type Caller = CallerContext;
    type Input = UpdateRequest;
    type Output = Result<(), AppError>;

    /// Makes every change and records `federation.service_provider_updated`
    /// once. The app decides what each needs: one that sends the app more
    /// of a person, sends it to more places or checks it less needs the
    /// full federation right; one that only narrows what it gets needs the
    /// update right. A request with no change changes and records nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` if the caller lacks the right a change needs.
    /// - `AppError::NotFound` if the app doesn't exist.
    /// - `AppError::Internal` on audit or persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: UpdateRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = FederationControl::new(&authority);
        control
            .ensure_may(FederationRight::EditConnection)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let store = self.ports.service_providers.as_ref();
        let mut app = existing_service_provider(store, &tenant, &request.id).await?;
        if request.changes.is_empty() {
            return Ok(());
        }
        app.update(request.changes, &control)
            .map_err(AppError::from_domain)?;

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
    use ianua_domain::domains::federation::connection_status::ConnectionStatus;
    use ianua_domain::domains::federation::service_provider::{
        AcsUrls, SamlServiceProviderSettings,
    };
    use ianua_domain::types::{HttpsUrl, Label};

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

    fn update(
        store: Arc<FakeSamlServiceProviderStore>,
        authorities: FakeTenantAuthorities,
        audit: &Arc<FakeEventDispatcher>,
        request: UpdateRequest,
    ) -> Result<(), AppError> {
        let use_case = UpdateUseCase::new(UpdatePorts {
            service_providers: store,
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), request))
    }

    fn saved_settings(
        store: &FakeSamlServiceProviderStore,
        id: &SamlServiceProviderId,
    ) -> SamlServiceProviderSettings {
        block_on(store.find_by_id(&test_ctx().tenant(), id))
            .unwrap()
            .unwrap()
            .settings()
            .clone()
    }

    /// Another address for Salesforce's assertions, `eu.acme.com`.
    fn added_address() -> SamlServiceProviderChange {
        SamlServiceProviderChange::AcsUrls(
            AcsUrls::new(
                HttpsUrl::new("https://app.acme.com/saml/acs").unwrap(),
                vec![HttpsUrl::new("https://eu.app.acme.com/saml/acs").unwrap()],
            )
            .unwrap(),
        )
    }

    /// Fay renames Salesforce and adds its EU address. Both are saved, and
    /// one update is recorded.
    #[test]
    fn the_changes_are_saved_and_recorded_once() {
        let (store, id) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());
        let request = UpdateRequest {
            id,
            changes: vec![
                SamlServiceProviderChange::Rename(Label::new("name", "Salesforce EU").unwrap()),
                added_address(),
            ],
        };

        update(
            store.clone(),
            FakeTenantAuthorities::holding_everything(),
            &audit,
            request,
        )
        .unwrap();

        assert_eq!(saved_settings(&store, &id).acs_urls.others().len(), 1);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["federation.service_provider_updated"]
        );
    }

    /// Fay names an app Acme does not have. It is not found.
    #[test]
    fn an_unknown_app_is_not_found() {
        let (store, _) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());
        let request = UpdateRequest {
            id: SamlServiceProviderId::new(),
            changes: vec![added_address()],
        };

        let result = update(
            store,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            request,
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Update rights cannot add an assertion destination; Salesforce keeps
    /// its sole address and no update event is recorded.
    #[test]
    fn the_update_right_adds_no_address() {
        let (store, id) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());
        let update_only = [SystemPermission::Federation(FederationAction::Update)];
        let request = UpdateRequest {
            id,
            changes: vec![added_address()],
        };

        let result = update(
            store.clone(),
            FakeTenantAuthorities::holding(&update_only),
            &audit,
            request,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(saved_settings(&store, &id).acs_urls.others().is_empty());
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot add an assertion destination to the app.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());
        let request = UpdateRequest {
            id,
            changes: vec![added_address()],
        };

        let result = update(
            store,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &audit,
            request,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
