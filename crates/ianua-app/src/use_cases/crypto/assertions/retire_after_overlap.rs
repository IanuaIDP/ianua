//! The background sweep that retires assertion keys once they have been
//! rotated out for the whole overlap, so the published set says for good
//! that upstreams no longer accept them.

use std::sync::Arc;

use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, Lifetime, TenantId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::crypto::{AssertionKeyStore, CrossTenantAssertionKeys};
use crate::ports::runtime::UnitOfWork;
use crate::services::kept_together::kept_together;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// The ports [`RetireAfterOverlapUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RetireAfterOverlapPorts {
    /// Loads and saves each tenant's assertion keys.
    pub keys: Arc<dyn AssertionKeyStore>,
    /// Finds the tenants holding a key rotated out but not yet retired.
    pub key_sets: Arc<dyn CrossTenantAssertionKeys>,
    /// Keeps each tenant's retirements and the record of them together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Retires every assertion key rotated out longer than the overlap ago.
///
/// It runs as a periodic job of the platform, with nobody asking. Until it
/// runs, the published set already leaves such a key out, since publishing
/// is judged from the clock; this makes the stored standing say so too.
/// Each key retired is recorded against its tenant, by the platform, and
/// nobody is notified.
pub struct RetireAfterOverlapUseCase {
    ports: RetireAfterOverlapPorts,
    overlap: Lifetime,
}

impl RetireAfterOverlapUseCase {
    /// A use case working through `ports`, retiring keys rotated out longer
    /// than `overlap` ago: the overlap the rotation schedule publishes them
    /// for.
    #[must_use]
    pub fn new(ports: RetireAfterOverlapPorts, overlap: Lifetime) -> Self {
        Self { ports, overlap }
    }

    /// Retires the keys of `tenant_id` whose overlap is over, saves the set
    /// and records one `crypto.assertion_key_retired` per key, by the
    /// platform. Returns how many it retired.
    async fn retired_in(
        &self,
        auditor: &RequestAuditor,
        tenant_id: TenantId,
    ) -> Result<usize, AppError> {
        let tenant = ScopedTenant::for_background(tenant_id);
        let Some(mut keys) = self.ports.keys.find(&tenant).await.or_internal()? else {
            return Ok(0);
        };
        let retired = keys
            .retire_after_overlap(self.overlap)
            .map_err(AppError::from_domain)?;
        if retired.is_empty() {
            return Ok(0);
        }
        self.ports.keys.save(&tenant, &keys).await.or_internal()?;
        auditor
            .with_tenant(tenant_id)
            .dispatch_by(&ActorRef::System, keys.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(retired.len())
    }
}

impl Command for RetireAfterOverlapUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<usize, AppError>;

    /// Retires, in every tenant, the assertion keys rotated out longer than
    /// the overlap ago, and records `crypto.assertion_key_retired` for each
    /// against its own tenant. Returns how many it retired.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the tenants to sweep cannot be listed. A
    ///   tenant whose keys cannot be retired, saved or recorded is logged
    ///   and left for the next sweep, with nothing of it kept: its
    ///   retirements and their record are one unit.
    async fn execute(&self, (): &(), auditor: &RequestAuditor, (): ()) -> Result<usize, AppError> {
        let tenants = self
            .ports
            .key_sets
            .tenants_with_rotated_keys()
            .await
            .or_internal()?;
        let mut retired: usize = 0;
        let unit = self.ports.unit_of_work.as_ref();
        for tenant_id in tenants {
            match kept_together(unit, self.retired_in(auditor, tenant_id)).await {
                Ok(count) => retired = retired.saturating_add(count),
                Err(error) => tracing::warn!(
                    %tenant_id,
                    %error,
                    "retiring assertion keys after their overlap failed; left for the next sweep"
                ),
            }
        }
        Ok(retired)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::crypto::assertion_key::{
        AssertionKey, AssertionKeySet, NewAssertionKey,
    };
    use ianua_domain::domains::crypto::key_status::KeyStatus;
    use ianua_domain::domains::crypto::rotation::KeyRotationSchedule;
    use ianua_domain::shared::clock;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{KeyId, PublicKeyPem};
    use time::Duration;

    use super::*;
    use crate::ports::runtime::Settlement;
    use crate::ports::shared::EventDispatcher;
    use crate::test_support::crypto::FakeAssertionKeyStore;
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, RecordingUnitOfWork, block_on, test_auditor,
        test_ctx,
    };

    const RETIRED: &str = "crypto.assertion_key_retired";

    fn key(kid: &str) -> AssertionKey {
        AssertionKey::create(NewAssertionKey {
            kid: KeyId::new(kid).unwrap(),
            public_key: PublicKeyPem::new(
                "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n",
            )
            .unwrap(),
            private_key: Secret::new(format!("private-{kid}")),
        })
    }

    /// The test tenant's set, `old` rotated out onto `new` `ago` before now.
    fn rotated(ago: Duration) -> Arc<FakeAssertionKeyStore> {
        let schedule = KeyRotationSchedule::FOR_ASSERTION_KEYS;
        let start = clock::now() - ago;
        let mut set = {
            let _frozen = clock::freeze(start - Duration::days(31));
            AssertionKeySet::new(key("old"))
        };
        {
            let _frozen = clock::freeze(start);
            set.rotate_by_age(&schedule, key("new"), start).unwrap();
        }
        Arc::new(FakeAssertionKeyStore::holding(&set))
    }

    /// The sweep over `store`, recording to `audit`, each tenant in a unit
    /// of `unit`.
    fn sweep_over(
        store: &Arc<FakeAssertionKeyStore>,
        audit: Arc<dyn EventDispatcher>,
        unit: Arc<RecordingUnitOfWork>,
    ) -> usize {
        let use_case = RetireAfterOverlapUseCase::new(
            RetireAfterOverlapPorts {
                keys: store.clone(),
                key_sets: store.clone(),
                unit_of_work: unit,
            },
            KeyRotationSchedule::FOR_ASSERTION_KEYS.overlap(),
        );
        block_on(use_case.execute(&(), &test_auditor(audit), ())).unwrap()
    }

    /// What one sweep did: how many it retired, and what it recorded.
    struct Swept {
        retired: usize,
        audit: Arc<FakeEventDispatcher>,
    }

    fn sweep(store: &Arc<FakeAssertionKeyStore>) -> Swept {
        let audit = Arc::new(FakeEventDispatcher::new());
        let retired = sweep_over(store, audit.clone(), Arc::default());
        Swept { retired, audit }
    }

    fn status_of(store: &FakeAssertionKeyStore, kid: &str) -> KeyStatus {
        let set = store.set_of(test_ctx().tenant_id()).unwrap();
        set.keys()
            .iter()
            .find(|key| key.kid().as_str() == kid)
            .unwrap()
            .status()
    }

    /// Acme's old key was rotated out two days ago, past the day's overlap.
    /// The sweep retires it, leaves the new one signing, and records the
    /// retirement in Acme's tenant.
    #[test]
    fn a_key_past_its_overlap_is_retired_and_recorded() {
        let store = rotated(Duration::days(2));

        let swept = sweep(&store);

        assert_eq!(swept.retired, 1);
        assert_eq!(status_of(&store, "old"), KeyStatus::Revoked);
        assert_eq!(status_of(&store, "new"), KeyStatus::Active);
        assert_eq!(swept.audit.records.lock().unwrap().as_slice(), [RETIRED]);
        assert_eq!(swept.audit.tenant_of(RETIRED), Some(test_ctx().tenant_id()));
    }

    /// A key rotated out an hour ago is still within its overlap, so an
    /// assertion it signed a moment before still verifies. Nothing is
    /// retired or recorded.
    #[test]
    fn a_key_within_its_overlap_is_left() {
        let store = rotated(Duration::HOUR);

        let swept = sweep(&store);

        assert_eq!(swept.retired, 0);
        assert_eq!(status_of(&store, "old"), KeyStatus::Rotated);
        assert!(swept.audit.records.lock().unwrap().is_empty());
    }

    /// An audit failure excludes the assertion-key retirement from the
    /// count and settles its unit of work as a rollback.
    #[test]
    fn a_retirement_that_cannot_be_recorded_is_rolled_back() {
        let store = rotated(Duration::days(2));
        let unit = Arc::new(RecordingUnitOfWork::default());

        let retired = sweep_over(&store, Arc::new(FailingEventDispatcher), unit.clone());

        assert_eq!(retired, 0);
        assert_eq!(unit.settlements(), [Settlement::Rollback]);
    }
}
