//! Create log target: name a place the tenant's request records are shipped
//! to.

use std::sync::Arc;

use ianua_domain::domains::proxy::log_shipping::{
    LogDestination, LogFormat, LogShippingTarget, LogTargetSettings, ShippedRecords,
};
use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Label, LogShippingTargetId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SecretEncryptor;
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::ports::proxy::LogShippingStore;
use crate::services::limits::room::ensure_room_in_tenant;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::proxy::log_shipping::credential::{credential_place, sealed_credential};
use crate::use_cases::proxy::log_shipping::view::LogTargetView;

/// What a new log shipping target is made of.
pub struct CreateLogTargetRequest {
    /// Its name, unique within the tenant.
    pub name: Label,
    /// Where records go.
    pub destination: LogDestination,
    /// The API key, token or access key the destination takes, as the tenant
    /// typed it. Sealed before it is kept.
    pub credential: Option<Secret>,
    /// Which records are sent.
    pub records: ShippedRecords,
    /// The shape each record is written in.
    pub format: LogFormat,
}

/// The ports [`CreateLogTargetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CreateLogTargetPorts {
    /// Keeps the tenant's log shipping targets.
    pub log_shipping_store: Arc<dyn LogShippingStore>,
    /// Seals the credential before it is kept.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// The tenant's plan limits.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Creates a log shipping target.
pub struct CreateLogTargetUseCase {
    ports: CreateLogTargetPorts,
}

impl CreateLogTargetUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CreateLogTargetPorts) -> Self {
        Self { ports }
    }

    /// The target `request` describes for `tenant`, its credential sealed,
    /// made by `by`.
    async fn new_target(
        &self,
        tenant: &ScopedTenant,
        request: CreateLogTargetRequest,
        by: &RoutingControl<'_>,
    ) -> Result<LogShippingTarget<ResolvedTenant>, AppError> {
        let id = LogShippingTargetId::new();
        let place = credential_place(tenant, &id);
        let credential =
            sealed_credential(self.ports.encryptor.as_ref(), request.credential, &place).await?;
        let settings = LogTargetSettings {
            destination: request.destination,
            credential,
            records: request.records,
            format: request.format,
        };
        LogShippingTarget::create(id, request.name, settings, by).map_err(AppError::from_domain)
    }
}

impl Command for CreateLogTargetUseCase {
    type Caller = CallerContext;
    type Input = CreateLogTargetRequest;
    type Output = Result<LogTargetView, AppError>;

    /// Creates the target, active, and records `proxy.log_target_created`,
    /// naming the kind of destination but never its address or credential.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not create routing, or
    ///   the plan's log target limit is reached.
    /// - `AppError::Domain` when the destination needs a credential and none
    ///   is given.
    /// - `AppError::Conflict` when another target in the tenant has the name.
    /// - `AppError::Internal` on sealing, storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: CreateLogTargetRequest,
    ) -> Result<LogTargetView, AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = RoutingControl::new(&authority);
        control
            .ensure_may(RoutingRight::Create)
            .map_err(AppError::from_domain)?;
        ensure_room_in_tenant(
            self.ports.limit_enforcer.as_ref(),
            caller,
            ResourceKind::LogTargets,
        )
        .await?;
        let tenant = caller.tenant();
        let mut target = self.new_target(&tenant, request, &control).await?;
        self.ports
            .log_shipping_store
            .save(&tenant, &target)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&caller.actor(), target.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(LogTargetView::from(&target))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::audit::streaming::DatadogSite;
    use ianua_domain::domains::authorization::permission::{RoutingAction, SystemPermission};
    use ianua_domain::domains::proxy::log_shipping::ShippingCredential;
    use ianua_domain::types::PublicHttpsUrl;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::proxy::{
        FakeLogShippingStore, TEST_SHIPPING_KEY, log_target_name, shipping_key_place,
    };
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };
    use crate::use_cases::proxy::log_shipping::view::CredentialState;

    /// The store, the audit trail and the use case a test works with.
    struct Fixture {
        targets: Arc<FakeLogShippingStore>,
        audit: Arc<FakeEventDispatcher>,
        use_case: CreateLogTargetUseCase,
    }

    /// A fixture whose caller holds what `authorities` say.
    fn fixture(authorities: FakeTenantAuthorities) -> Fixture {
        let targets = Arc::new(FakeLogShippingStore::default());
        Fixture {
            use_case: CreateLogTargetUseCase::new(CreateLogTargetPorts {
                log_shipping_store: targets.clone(),
                tenant_authorities: Arc::new(authorities),
                ..CreateLogTargetPorts::fakes()
            }),
            targets,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    /// Ann's SIEM collector, with her API key.
    fn siem() -> CreateLogTargetRequest {
        CreateLogTargetRequest {
            name: log_target_name("siem"),
            destination: LogDestination::Https(
                PublicHttpsUrl::new("https://siem.example.com/ingest").unwrap(),
            ),
            credential: Some(Secret::new(TEST_SHIPPING_KEY)),
            records: ShippedRecords::All,
            format: LogFormat::JsonLines,
        }
    }

    /// Runs the use case with `request`.
    fn run(f: &Fixture, request: CreateLogTargetRequest) -> Result<LogTargetView, AppError> {
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), request),
        )
    }

    /// Ann ships her tenant's records to her SIEM. The target is kept with
    /// her key sealed, she is shown only that a key is set, and the creation
    /// is recorded.
    #[test]
    fn a_target_is_kept_with_its_key_sealed() {
        let f = fixture(FakeTenantAuthorities::holding_everything());

        let view = run(&f, siem()).unwrap();

        let stored = f.targets.stored(test_ctx().tenant_id(), &view.id).unwrap();
        let ShippingCredential::Sealed(sealed) = stored.credential() else {
            panic!("the key was not kept");
        };
        assert_eq!(
            *sealed,
            FakeEncryptor::sealed_for(TEST_SHIPPING_KEY, &shipping_key_place(&view.id))
        );
        assert_eq!(view.credential, CredentialState::Set);
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            ["proxy.log_target_created"]
        );
    }

    /// Ann ships to Datadog but gives no API key, which Datadog would need
    /// for every batch. It is refused and nothing is kept.
    #[test]
    fn a_destination_needing_a_key_is_refused_without_one() {
        let f = fixture(FakeTenantAuthorities::holding_everything());

        let result = run(
            &f,
            CreateLogTargetRequest {
                destination: LogDestination::Datadog(DatadogSite::Eu1),
                credential: None,
                ..siem()
            },
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(f.targets.count(), 0);
    }

    /// Ann adds a second target named `siem`. It is refused as a conflict.
    #[test]
    fn a_second_target_by_one_name_is_a_conflict() {
        let f = fixture(FakeTenantAuthorities::holding_everything());
        run(&f, siem()).unwrap();

        let again = run(&f, siem());

        assert!(matches!(again, Err(AppError::Conflict(_))));
        assert_eq!(f.targets.count(), 1);
    }

    /// A routing viewer cannot create a SIEM target; neither a target nor a
    /// creation audit record is saved.
    #[test]
    fn a_caller_without_the_create_right_is_refused() {
        let viewer =
            FakeTenantAuthorities::holding(&[SystemPermission::Routing(RoutingAction::View)]);
        let f = fixture(viewer);

        let result = run(&f, siem());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(f.targets.count(), 0);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Creating a target with a signed-out session fails authentication and
    /// leaves the target store empty.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = run(&f, siem());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(f.targets.count(), 0);
    }

    /// Ann's tenant already ships to as many targets as its plan allows.
    /// Her new one is refused, and nothing is kept or recorded.
    #[test]
    fn a_target_past_the_plan_limit_is_refused() {
        let targets = Arc::new(FakeLogShippingStore::default());
        let f = Fixture {
            use_case: CreateLogTargetUseCase::new(CreateLogTargetPorts {
                log_shipping_store: targets.clone(),
                limit_enforcer: Arc::new(RejectingLimitEnforcer),
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding_everything()),
                ..CreateLogTargetPorts::fakes()
            }),
            targets,
            audit: Arc::new(FakeEventDispatcher::new()),
        };

        let result = run(&f, siem());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(f.targets.count(), 0);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }
}
