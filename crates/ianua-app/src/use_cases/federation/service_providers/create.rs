//! Create service provider: add a SAML app the tenant's people sign in to,
//! with this platform as their identity provider.

use std::sync::Arc;

use ianua_domain::domains::federation::control::{FederationControl, FederationRight};
use ianua_domain::domains::federation::service_provider::{
    NewSamlServiceProvider, SamlServiceProvider, SamlServiceProviderSettings,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{Label, SamlEntityId, SamlServiceProviderId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::federation::SamlServiceProviderStore;
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// The SAML app to add.
pub struct CreateRequest {
    /// The name shown in the app list.
    pub name: Label,
    /// The app's entity id, which its requests name as their issuer.
    pub entity_id: SamlEntityId,
    /// How it is answered.
    pub settings: SamlServiceProviderSettings,
}

/// The ports [`CreateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CreatePorts {
    /// Keeps the tenant's SAML apps.
    pub service_providers: Arc<dyn SamlServiceProviderStore>,
    /// Checks the plan has room for another app.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Adds a SAML app to the caller's tenant.
pub struct CreateUseCase {
    ports: CreatePorts,
}

impl CreateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CreatePorts) -> Self {
        Self { ports }
    }

    /// Refuses an app beyond the plan's ceiling.
    async fn ensure_within_limit(&self, ctx: &CallerContext) -> Result<(), AppError> {
        self.ports
            .limit_enforcer
            .check_tenant_limit(
                ctx.plan_limits(),
                &ctx.tenant(),
                ResourceKind::SamlServiceProviders,
            )
            .await
            .map_err(AppError::from_domain)
    }

    /// Refuses an entity id another app of the tenant already has: a
    /// request naming it would be answered for whichever is read first.
    async fn ensure_entity_id_free(
        &self,
        tenant: &ScopedTenant,
        entity_id: &SamlEntityId,
    ) -> Result<(), AppError> {
        let taken = self
            .ports
            .service_providers
            .find_by_entity_id(tenant, entity_id)
            .await
            .or_internal()?;
        if taken.is_some() {
            return Err(AppError::Conflict(message!(
                "federation-another-saml-app-has-this-entity",
                "another SAML app has this entity id"
            )));
        }
        Ok(())
    }
}

impl Command for CreateUseCase {
    type Caller = CallerContext;
    type Input = CreateRequest;
    type Output = Result<SamlServiceProviderId, AppError>;

    /// Adds an active SAML app and records
    /// `federation.service_provider_created`. An app is told who people
    /// are, so this needs the create right and the full federation right.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` if the caller may not create connections or
    ///   manage federation, or the plan's limit is reached.
    /// - `AppError::Conflict` if another app has the entity id.
    /// - `AppError::Internal` on audit or persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: CreateRequest,
    ) -> Result<SamlServiceProviderId, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = FederationControl::new(&authority);
        control
            .ensure_may(FederationRight::CreateConnection)
            .map_err(AppError::from_domain)?;
        self.ensure_within_limit(ctx).await?;
        let tenant = ctx.tenant();
        self.ensure_entity_id_free(&tenant, &request.entity_id)
            .await?;
        let mut app = new_app(request, &control)?;

        self.ports
            .service_providers
            .save(&tenant, &app)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), app.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(*app.id())
    }
}

/// The app `request` describes, as `control` adds it.
///
/// # Errors
///
/// - `AppError::Forbidden` if the person may not create connections or
///   manage federation.
fn new_app(
    request: CreateRequest,
    control: &FederationControl<'_>,
) -> Result<SamlServiceProvider<ResolvedTenant>, AppError> {
    SamlServiceProvider::create(
        NewSamlServiceProvider {
            id: SamlServiceProviderId::new(),
            name: request.name,
            entity_id: request.entity_id,
            settings: request.settings,
        },
        control,
    )
    .map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{FederationAction, SystemPermission};
    use ianua_domain::domains::federation::connection_status::ConnectionStatus;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::federation::{
        FakeSamlServiceProviderStore, TEST_APP_ENTITY_ID, test_app_settings, test_service_provider,
    };
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };

    fn request() -> CreateRequest {
        CreateRequest {
            name: Label::new("name", "Salesforce").unwrap(),
            entity_id: SamlEntityId::new(TEST_APP_ENTITY_ID).unwrap(),
            settings: test_app_settings(),
        }
    }

    fn create(
        ports: CreatePorts,
        audit: &Arc<FakeEventDispatcher>,
    ) -> Result<SamlServiceProviderId, AppError> {
        let use_case = CreateUseCase::new(ports);
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), request()))
    }

    fn ports_over(
        store: Arc<FakeSamlServiceProviderStore>,
        authorities: FakeTenantAuthorities,
    ) -> CreatePorts {
        CreatePorts {
            service_providers: store,
            tenant_authorities: Arc::new(authorities),
            ..CreatePorts::fakes()
        }
    }

    /// Fay adds Salesforce as a SAML app. It is saved active and its
    /// creation is recorded.
    #[test]
    fn an_app_is_added_and_recorded() {
        let store = Arc::new(FakeSamlServiceProviderStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());

        let id = create(
            ports_over(store.clone(), FakeTenantAuthorities::holding_everything()),
            &audit,
        )
        .unwrap();

        let saved = block_on(store.find_by_id(&test_ctx().tenant(), &id))
            .unwrap()
            .unwrap();
        assert_eq!(saved.status(), ConnectionStatus::Active);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["federation.service_provider_created"]
        );
    }

    /// Fay adds Salesforce a second time. The entity id is taken, so it is
    /// refused and nothing more is saved.
    #[test]
    fn an_entity_id_already_used_conflicts() {
        let existing =
            test_service_provider(SamlServiceProviderId::new(), ConnectionStatus::Active);
        let store = Arc::new(FakeSamlServiceProviderStore::holding(
            &test_ctx().tenant(),
            [existing],
        ));
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = create(
            ports_over(store.clone(), FakeTenantAuthorities::holding_everything()),
            &audit,
        );

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(store.count(), 1);
    }

    /// A full plan forbids another SAML app without saving an app or
    /// recording its creation.
    #[test]
    fn a_full_plan_refuses_another_app() {
        let store = Arc::new(FakeSamlServiceProviderStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());
        let ports = CreatePorts {
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..ports_over(store.clone(), FakeTenantAuthorities::holding_everything())
        };

        let result = create(ports, &audit);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Creation rights without federation-management authority cannot add
    /// a SAML app; storage and audit remain empty.
    #[test]
    fn the_create_right_alone_adds_no_app() {
        let store = Arc::new(FakeSamlServiceProviderStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());
        let create_only = [SystemPermission::Federation(FederationAction::Create)];

        let result = create(
            ports_over(store.clone(), FakeTenantAuthorities::holding(&create_only)),
            &audit,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot add a SAML app to the tenant.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let store = Arc::new(FakeSamlServiceProviderStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = create(
            ports_over(store, FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            &audit,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
