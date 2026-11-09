//! Change log target: rename a log shipping target, or change where and
//! what it ships.

use std::sync::Arc;

use ianua_domain::domains::proxy::log_shipping::{
    LogDestination, LogFormat, LogShippingTarget, LogTargetSettings, ShippedRecords,
};
use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{Label, LogShippingTargetId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SecretEncryptor;
use crate::ports::proxy::LogShippingStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::proxy::log_shipping::credential::{
    CredentialChange, changed_credential, credential_place,
};
use crate::use_cases::proxy::log_shipping::lookup::existing_log_target;
use crate::use_cases::proxy::log_shipping::view::LogTargetView;

/// The target to change, and what it becomes.
pub struct ChangeLogTargetRequest {
    /// The saved destination whose delivery settings will change.
    pub target_id: LogShippingTargetId,
    /// Its new name, or `None` to keep it.
    pub name: Option<Label>,
    /// Where records go from now on.
    pub destination: LogDestination,
    /// What happens to its credential.
    pub credential: CredentialChange,
    /// Which records are sent from now on.
    pub records: ShippedRecords,
    /// The shape each record is written in from now on.
    pub format: LogFormat,
}

/// The ports [`ChangeLogTargetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeLogTargetPorts {
    /// Keeps the tenant's log shipping targets.
    pub log_shipping_store: Arc<dyn LogShippingStore>,
    /// Seals a new credential before it is kept.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes a log shipping target.
pub struct ChangeLogTargetUseCase {
    ports: ChangeLogTargetPorts,
}

impl ChangeLogTargetUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ChangeLogTargetPorts) -> Self {
        Self { ports }
    }

    /// Gives `tenant`'s `target` what `request` asks for, as `by`.
    async fn change(
        &self,
        tenant: &ScopedTenant,
        target: &mut LogShippingTarget<ResolvedTenant>,
        request: ChangeLogTargetRequest,
        by: &RoutingControl<'_>,
    ) -> Result<(), AppError> {
        let place = credential_place(tenant, target.id());
        let credential = changed_credential(
            self.ports.encryptor.as_ref(),
            target.credential(),
            request.credential,
            &place,
        )
        .await?;
        let settings = LogTargetSettings {
            destination: request.destination,
            credential,
            records: request.records,
            format: request.format,
        };
        target
            .change_settings(settings, by)
            .map_err(AppError::from_domain)?;
        let Some(name) = request.name else {
            return Ok(());
        };
        target.rename(name, by).map_err(AppError::from_domain)
    }
}

impl Command for ChangeLogTargetUseCase {
    type Caller = CallerContext;
    type Input = ChangeLogTargetRequest;
    type Output = Result<LogTargetView, AppError>;

    /// Changes the target and records one `proxy.log_target_changed`,
    /// naming the kind of destination but never its address or credential.
    /// A new credential is sealed before it is kept.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without routing-update rights.
    /// - `AppError::NotFound` for a missing tenant target; `Domain` for a destination left without a required credential.
    /// - `AppError::Conflict` for another target's name; `Internal` on sealing, storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: ChangeLogTargetRequest,
    ) -> Result<LogTargetView, AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = RoutingControl::new(&authority);
        control
            .ensure_may(RoutingRight::Update)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let store = self.ports.log_shipping_store.as_ref();
        let mut target = existing_log_target(store, &tenant, &request.target_id).await?;
        self.change(&tenant, &mut target, request, &control).await?;
        store
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
    use ianua_domain::domains::authorization::permission::{RoutingAction, SystemPermission};
    use ianua_domain::domains::proxy::log_shipping::{
        BucketName, BucketRegion, ShippingCredential,
    };
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::PublicHttpsUrl;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::proxy::{
        FakeLogShippingStore, TEST_SHIPPING_KEY, log_target_name, shipping_key_place,
        test_log_target,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The store, the audit trail and the use case a test works with.
    struct Fixture {
        targets: Arc<FakeLogShippingStore>,
        audit: Arc<FakeEventDispatcher>,
        target_id: LogShippingTargetId,
        use_case: ChangeLogTargetUseCase,
    }

    /// A fixture holding Ann's SIEM target, whose caller holds what
    /// `authorities` say.
    fn fixture(authorities: FakeTenantAuthorities) -> Fixture {
        let target = test_log_target();
        let target_id = *target.id();
        let targets = Arc::new(FakeLogShippingStore::holding(
            test_ctx().tenant_id(),
            target,
        ));
        Fixture {
            use_case: ChangeLogTargetUseCase::new(ChangeLogTargetPorts {
                log_shipping_store: targets.clone(),
                tenant_authorities: Arc::new(authorities),
                ..ChangeLogTargetPorts::fakes()
            }),
            targets,
            audit: Arc::new(FakeEventDispatcher::new()),
            target_id,
        }
    }

    /// A change of Ann's target to refusals only, sent to `destination`,
    /// doing `credential` to its key.
    fn change(
        f: &Fixture,
        destination: LogDestination,
        credential: CredentialChange,
    ) -> ChangeLogTargetRequest {
        ChangeLogTargetRequest {
            target_id: f.target_id,
            name: None,
            destination,
            credential,
            records: ShippedRecords::DeniedOnly,
            format: LogFormat::JsonLines,
        }
    }

    /// Ann's SIEM collector.
    fn siem() -> LogDestination {
        LogDestination::Https(PublicHttpsUrl::new("https://siem.example.com/ingest").unwrap())
    }

    /// Ann's log bucket, which needs a key.
    fn bucket() -> LogDestination {
        LogDestination::Bucket {
            endpoint: PublicHttpsUrl::new("https://s3.eu-central-1.amazonaws.com").unwrap(),
            region: BucketRegion::new("eu-central-1").unwrap(),
            bucket: BucketName::new("acme-gateway-logs").unwrap(),
        }
    }

    /// Runs the use case with `request`.
    fn run(f: &Fixture, request: ChangeLogTargetRequest) -> Result<LogTargetView, AppError> {
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), request),
        )
    }

    /// The target as stored.
    fn stored(f: &Fixture) -> LogShippingTarget<ResolvedTenant> {
        f.targets
            .stored(test_ctx().tenant_id(), &f.target_id)
            .unwrap()
    }

    /// Ann narrows her target to refusals and renames it, keeping her key.
    /// It ships refusals under the new name with the same sealed key, and
    /// one change is recorded.
    #[test]
    fn a_target_is_changed_and_keeps_its_key() {
        let f = fixture(FakeTenantAuthorities::holding_everything());
        let request = ChangeLogTargetRequest {
            name: Some(log_target_name("siem-eu")),
            ..change(&f, siem(), CredentialChange::Keep)
        };

        run(&f, request).unwrap();

        let target = stored(&f);
        assert_eq!(target.records(), ShippedRecords::DeniedOnly);
        assert_eq!(target.name(), &log_target_name("siem-eu"));
        let ShippingCredential::Sealed(sealed) = target.credential() else {
            panic!("the key was dropped");
        };
        assert_eq!(
            *sealed,
            FakeEncryptor::sealed_for(TEST_SHIPPING_KEY, &shipping_key_place(&f.target_id))
        );
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            ["proxy.log_target_changed"]
        );
    }

    /// Ann moves her target to a bucket with a new access key. The new key
    /// is kept sealed in place of the old one.
    #[test]
    fn a_new_key_is_sealed_in_place_of_the_old() {
        let f = fixture(FakeTenantAuthorities::holding_everything());
        let new_key = CredentialChange::Replace(Secret::new("bucket-key-2"));

        run(&f, change(&f, bucket(), new_key)).unwrap();

        let ShippingCredential::Sealed(sealed) = stored(&f).credential().clone() else {
            panic!("the key was dropped");
        };
        assert_eq!(
            sealed,
            FakeEncryptor::sealed_for("bucket-key-2", &shipping_key_place(&f.target_id))
        );
    }

    /// Ann moves her target to a bucket and removes its key, which the
    /// bucket would need. It is refused and the target stays as it was.
    #[test]
    fn a_destination_needing_a_key_is_refused_without_one() {
        let f = fixture(FakeTenantAuthorities::holding_everything());

        let result = run(&f, change(&f, bucket(), CredentialChange::Remove));

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(stored(&f).destination(), &siem());
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Ann names a target the tenant does not have. It is not found.
    #[test]
    fn an_unknown_target_is_not_found() {
        let f = fixture(FakeTenantAuthorities::holding_everything());
        let request = ChangeLogTargetRequest {
            target_id: LogShippingTargetId::new(),
            ..change(&f, siem(), CredentialChange::Keep)
        };

        let result = run(&f, request);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A routing viewer cannot redirect the target to her server; its SIEM
    /// destination remains and no change is audited.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let viewer =
            FakeTenantAuthorities::holding(&[SystemPermission::Routing(RoutingAction::View)]);
        let f = fixture(viewer);
        let mallorys = LogDestination::Https(
            PublicHttpsUrl::new("https://mallory.example.net/collect").unwrap(),
        );

        let result = run(&f, change(&f, mallorys, CredentialChange::Remove));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(stored(&f).destination(), &siem());
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Changing a target with a signed-out session fails authentication.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = run(&f, change(&f, siem(), CredentialChange::Keep));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
