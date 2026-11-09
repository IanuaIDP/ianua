//! The background job that gives each tenant a new assertion key once the
//! one that signs is older than the schedule allows, or once nothing
//! signs, and a first one to an active tenant that holds none, made before
//! tenant setup made one. The old key stays published for the schedule's
//! overlap, and the sweep that retires keys takes it out after that.

use std::sync::Arc;

use ianua_domain::domains::crypto::assertion_key::AssertionKeySet;
use ianua_domain::domains::crypto::rotation::KeyRotationSchedule;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, TenantId};
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::crypto::{AssertionKeyStore, CrossTenantAssertionKeys, KeyGenerator};
use crate::ports::runtime::UnitOfWork;
use crate::services::kept_together::kept_together;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::crypto::key_steps::generated_assertion_key;

/// The ports [`RotateByAgeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RotateByAgePorts {
    /// Loads and saves each tenant's assertion keys.
    pub keys: Arc<dyn AssertionKeyStore>,
    /// Finds the tenants whose assertion key may be due.
    pub key_sets: Arc<dyn CrossTenantAssertionKeys>,
    /// Generates the new keys.
    pub key_generator: Arc<dyn KeyGenerator>,
    /// Keeps each tenant's new key and the record of it together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Rotates every tenant's assertion key older than the schedule's longest
/// age.
///
/// It runs as a periodic job of the platform, with nobody asking, and
/// records each key it makes or rotates against its tenant, by the
/// platform. Nobody is notified: no person can change these keys or act on
/// their rotation.
pub struct RotateByAgeUseCase {
    ports: RotateByAgePorts,
    schedule: KeyRotationSchedule,
}

impl RotateByAgeUseCase {
    /// A use case working through `ports`, rotating on `schedule`. Its
    /// overlap is how long the published set keeps a rotated key.
    #[must_use]
    pub fn new(ports: RotateByAgePorts, schedule: KeyRotationSchedule) -> Self {
        Self { ports, schedule }
    }

    /// Rotates the assertion key of `tenant_id` at `now` when it is due, or
    /// gives it a first one when it holds none, saves the set and records
    /// what changed. Returns how many keys it made: one, or none.
    async fn rotated_in(
        &self,
        auditor: &RequestAuditor,
        tenant_id: TenantId,
        now: OffsetDateTime,
    ) -> Result<usize, AppError> {
        let tenant = ScopedTenant::for_background(tenant_id);
        let Some(mut keys) = self.ports.keys.find(&tenant).await.or_internal()? else {
            return self.first_key_in(auditor, &tenant).await;
        };
        if !keys.is_due(&self.schedule, now) {
            return Ok(0);
        }
        let new_key = generated_assertion_key(self.ports.key_generator.as_ref()).await?;
        keys.rotate_by_age(&self.schedule, new_key, now)
            .map_err(AppError::from_domain)?;
        self.kept(auditor, &tenant, keys).await
    }

    /// Gives `tenant`, which holds no assertion key, its first, as its
    /// setup would have. Returns one.
    ///
    /// Saving a first key where another run made one meanwhile is refused
    /// by the store, so two runs never leave two keys signing.
    async fn first_key_in(
        &self,
        auditor: &RequestAuditor,
        tenant: &ScopedTenant,
    ) -> Result<usize, AppError> {
        let first = generated_assertion_key(self.ports.key_generator.as_ref()).await?;
        let keys = AssertionKeySet::<ResolvedTenant>::new(first);
        self.kept(auditor, tenant, keys).await
    }

    /// Saves `keys` for `tenant` and records what they raised, by the
    /// platform. Returns one: the key made.
    async fn kept(
        &self,
        auditor: &RequestAuditor,
        tenant: &ScopedTenant,
        mut keys: AssertionKeySet<ResolvedTenant>,
    ) -> Result<usize, AppError> {
        self.ports.keys.save(tenant, &keys).await.or_internal()?;
        auditor
            .with_tenant(**tenant)
            .dispatch_by(&ActorRef::System, keys.take_events(tenant))
            .await
            .or_internal()?;
        Ok(1)
    }
}

impl Command for RotateByAgeUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<usize, AppError>;

    /// Rotates, in every tenant, the assertion key older than the
    /// schedule's longest age, or gives a key to a tenant where nothing
    /// signs or that holds none at all, and records
    /// `crypto.assertion_key_rotated` or `crypto.assertion_key_created`
    /// for each against its own tenant. Returns how many keys it made.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the tenants to sweep cannot be listed. A
    ///   tenant whose key cannot be generated, rotated, saved or recorded is
    ///   logged and left for the next run, its old key still signing and
    ///   nothing of it kept: the new key and its record are one unit.
    async fn execute(&self, (): &(), auditor: &RequestAuditor, (): ()) -> Result<usize, AppError> {
        let now = clock::now();
        let tenants = self
            .ports
            .key_sets
            .tenants_due(self.schedule.due_before(now))
            .await
            .or_internal()?;
        let mut rotated: usize = 0;
        let unit = self.ports.unit_of_work.as_ref();
        for tenant_id in tenants {
            match kept_together(unit, self.rotated_in(auditor, tenant_id, now)).await {
                Ok(count) => rotated = rotated.saturating_add(count),
                Err(error) => tracing::warn!(
                    %tenant_id,
                    %error,
                    "rotating an assertion key by age failed; left for the next run"
                ),
            }
        }
        Ok(rotated)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::crypto::assertion_key::{
        AssertionKey, AssertionKeySet, NewAssertionKey,
    };
    use ianua_domain::domains::crypto::key_status::KeyStatus;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{KeyId, PublicKeyPem};
    use time::Duration;

    use super::*;
    use crate::ports::runtime::Settlement;
    use crate::ports::shared::EventDispatcher;
    use crate::test_support::crypto::{FakeAssertionKeyStore, FakeKeyGenerator};
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, RecordingUnitOfWork, block_on, test_auditor,
        test_ctx,
    };

    const ROTATED: &str = "crypto.assertion_key_rotated";
    const CREATED: &str = "crypto.assertion_key_created";

    /// A key under `kid`, made `ago` before now.
    fn made_ago(kid: &str, ago: Duration) -> AssertionKey {
        let _frozen = clock::freeze(clock::now() - ago);
        AssertionKey::create(NewAssertionKey {
            kid: KeyId::new(kid).unwrap(),
            public_key: PublicKeyPem::new(
                "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n",
            )
            .unwrap(),
            private_key: Secret::new(format!("private-{kid}")),
        })
    }

    /// The sweep over `store`, recording to `audit`, each tenant in a unit
    /// of `unit`.
    fn sweep_over(
        store: &Arc<FakeAssertionKeyStore>,
        audit: Arc<dyn EventDispatcher>,
        unit: Arc<RecordingUnitOfWork>,
    ) -> usize {
        let use_case = RotateByAgeUseCase::new(
            RotateByAgePorts {
                keys: store.clone(),
                key_sets: store.clone(),
                key_generator: Arc::new(FakeKeyGenerator::new()),
                unit_of_work: unit,
            },
            KeyRotationSchedule::FOR_ASSERTION_KEYS,
        );
        block_on(use_case.execute(&(), &test_auditor(audit), ())).unwrap()
    }

    /// What one sweep over the test tenant holding `key` did.
    struct Ran {
        rotated: usize,
        store: Arc<FakeAssertionKeyStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    fn run(key: AssertionKey) -> Ran {
        let store = Arc::new(FakeAssertionKeyStore::holding(&AssertionKeySet::new(key)));
        let audit = Arc::new(FakeEventDispatcher::new());
        let unit = Arc::new(RecordingUnitOfWork::default());
        let rotated = sweep_over(&store, audit.clone(), unit);
        Ran {
            rotated,
            store,
            audit,
        }
    }

    /// Acme's assertion key has signed for 31 days. The sweep rotates it
    /// onto a new ES256 key, keeps the old one published, and records the
    /// rotation in Acme's tenant.
    #[test]
    fn an_old_assertion_key_is_rotated_and_recorded() {
        let ran = run(made_ago("old", Duration::days(31)));

        let set = ran.store.set_of(test_ctx().tenant_id()).unwrap();
        let signer = set.signing_key().unwrap();
        assert_eq!(ran.rotated, 1);
        assert_ne!(signer.kid().as_str(), "old");
        assert_eq!(signer.algorithm(), AssertionKey::ALGORITHM);
        assert_eq!(set.keys()[0].status(), KeyStatus::Rotated);
        assert_eq!(ran.audit.records.lock().unwrap().as_slice(), [ROTATED]);
        assert_eq!(ran.audit.tenant_of(ROTATED), Some(test_ctx().tenant_id()));
    }

    /// An active tenant with no assertion keys receives one signing key
    /// and a creation event; a second sweep creates neither again.
    #[test]
    fn a_tenant_without_keys_is_given_its_first() {
        let store = Arc::new(FakeAssertionKeyStore::empty());
        store.activate(test_ctx().tenant_id());
        let audit = Arc::new(FakeEventDispatcher::new());

        let first = sweep_over(&store, audit.clone(), Arc::default());
        let again = sweep_over(&store, audit.clone(), Arc::default());

        let set = store.set_of(test_ctx().tenant_id()).unwrap();
        assert_eq!((first, again), (1, 0));
        assert_eq!(set.keys().len(), 1);
        assert!(set.signing_key().is_some());
        assert_eq!(audit.records.lock().unwrap().as_slice(), [CREATED]);
    }

    /// A key made a week ago is not due. Nothing is rotated or recorded.
    #[test]
    fn a_young_assertion_key_is_left_alone() {
        let ran = run(made_ago("young", Duration::days(7)));

        let set = ran.store.set_of(test_ctx().tenant_id()).unwrap();
        assert_eq!(ran.rotated, 0);
        assert_eq!(set.keys().len(), 1);
        assert!(ran.audit.records.lock().unwrap().is_empty());
    }

    /// An audit failure excludes the assertion-key rotation from the count
    /// and settles its unit of work as a rollback.
    #[test]
    fn a_rotation_that_cannot_be_recorded_is_rolled_back() {
        let old = made_ago("old", Duration::days(31));
        let store = Arc::new(FakeAssertionKeyStore::holding(&AssertionKeySet::new(old)));
        let unit = Arc::new(RecordingUnitOfWork::default());

        let rotated = sweep_over(&store, Arc::new(FailingEventDispatcher), unit.clone());

        assert_eq!(rotated, 0);
        assert_eq!(unit.settlements(), [Settlement::Rollback]);
    }

    /// Acme's key is rotated. Saving the new key and recording it are one
    /// unit, kept together.
    #[test]
    fn a_rotation_and_its_record_are_kept_as_one_unit() {
        let old = made_ago("old", Duration::days(31));
        let store = Arc::new(FakeAssertionKeyStore::holding(&AssertionKeySet::new(old)));
        let unit = Arc::new(RecordingUnitOfWork::default());

        sweep_over(&store, Arc::new(FakeEventDispatcher::new()), unit.clone());

        assert_eq!(unit.settlements(), [Settlement::Commit]);
    }
}
