//! The background job that rotates each tenant's signing key once it is
//! older than the platform's schedule allows. The old key stays published
//! for the schedule's overlap, and the sweep that revokes keys after their
//! grace takes it out after that.

use std::sync::Arc;

use ianua_domain::domains::crypto::rotation::KeyRotationSchedule;
use ianua_domain::domains::crypto::signing_key::{SigningAlgorithm, SigningKey, SigningKeySet};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::TenantId;
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::crypto::{CrossTenantKeySets, KeyGenerator, MigrationStore, SigningKeyStore};
use crate::ports::runtime::UnitOfWork;
use crate::services::kept_together::kept_together;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::crypto::key_steps::{generated_signing_key, save_key_set};

/// The ports [`RotateByAgeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RotateByAgePorts {
    /// Loads and saves each tenant's key set.
    pub key_store: Arc<dyn SigningKeyStore>,
    /// Finds the tenants whose signing key may be due.
    pub key_sets: Arc<dyn CrossTenantKeySets>,
    /// Generates the new keys.
    pub key_generator: Arc<dyn KeyGenerator>,
    /// Says whether a tenant is moving to another algorithm.
    pub migration_store: Arc<dyn MigrationStore>,
    /// Keeps each tenant's rotation and the record of it together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Rotates every signing key older than the schedule's longest age.
///
/// It runs as a periodic job of the platform, with nobody asking. A tenant
/// moving to another algorithm is left alone: its migration decides which
/// key signs until it ends.
pub struct RotateByAgeUseCase {
    ports: RotateByAgePorts,
    schedule: KeyRotationSchedule,
}

/// A tenant's key set whose signing key is due, with that key's algorithm.
struct DueKeySet {
    key_set: SigningKeySet<ResolvedTenant>,
    algorithm: SigningAlgorithm,
}

impl RotateByAgeUseCase {
    /// A use case working through `ports`, rotating on `schedule`. Its
    /// overlap is the grace the JWKS publishes rotated keys for.
    #[must_use]
    pub fn new(ports: RotateByAgePorts, schedule: KeyRotationSchedule) -> Self {
        Self { ports, schedule }
    }

    /// Rotates the signing key of `tenant_id` at `now` when it is due,
    /// saves the set and records `crypto.key_rotated` by the platform.
    /// Returns how many keys it rotated: one, or none.
    async fn rotated_in(
        &self,
        auditor: &RequestAuditor,
        tenant_id: TenantId,
        now: OffsetDateTime,
    ) -> Result<usize, AppError> {
        let tenant = ScopedTenant::for_background(tenant_id);
        let Some(due) = self.due(&tenant, now).await? else {
            return Ok(0);
        };
        let DueKeySet {
            mut key_set,
            algorithm,
        } = due;
        let new_key = generated_signing_key(self.ports.key_generator.as_ref(), algorithm).await?;
        self.schedule
            .rotate(&mut key_set, new_key, now)
            .map_err(AppError::from_domain)?;
        save_key_set(self.ports.key_store.as_ref(), &tenant, &key_set).await?;
        let events: Vec<DomainEvent> = key_set
            .take_events(&tenant)
            .into_iter()
            .map(DomainEvent::system)
            .collect();
        auditor
            .with_tenant(tenant_id)
            .dispatch(&events)
            .await
            .or_internal()?;
        Ok(1)
    }

    /// The key set of `tenant` when its signing key is due at `now` and no
    /// migration is under way.
    async fn due(
        &self,
        tenant: &ScopedTenant,
        now: OffsetDateTime,
    ) -> Result<Option<DueKeySet>, AppError> {
        let migrating = self
            .ports
            .migration_store
            .find_active(tenant)
            .await
            .or_internal()?;
        if migrating.is_some() {
            return Ok(None);
        }
        let Some(key_set) = self.ports.key_store.find(tenant).await.or_internal()? else {
            return Ok(None);
        };
        let algorithm = self
            .schedule
            .due_key(&key_set, now)
            .map(SigningKey::algorithm);
        Ok(algorithm.map(|algorithm| DueKeySet { key_set, algorithm }))
    }
}

impl Command for RotateByAgeUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<usize, AppError>;

    /// Rotates, in every tenant, the signing key older than the schedule's
    /// longest age, and records `crypto.key_rotated` for each against its
    /// own tenant. Returns how many keys it rotated.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the tenants to sweep cannot be listed. A
    ///   tenant whose key cannot be generated, rotated, saved or recorded is
    ///   logged and left for the next run, with nothing of it kept: its
    ///   rotation and the record of it are one unit.
    async fn execute(&self, (): &(), auditor: &RequestAuditor, (): ()) -> Result<usize, AppError> {
        let now = clock::now();
        let tenants = self
            .ports
            .key_sets
            .tenants_with_keys_made_before(self.schedule.due_before(now))
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
                    "rotating a signing key by age failed; left for the next run"
                ),
            }
        }
        Ok(rotated)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::crypto::key_status::{KeyState, KeyStatus};
    use ianua_domain::domains::crypto::signing_key::SigningKeyRow;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{Expiry, KeyId, Lifetime, PublicKeyPem};
    use time::Duration;

    use super::*;
    use crate::test_support::crypto::{
        FakeKeyGenerator, FakeMigrationStore, FakeSigningKeyStore, started_migration,
    };
    use crate::test_support::{
        FakeEventDispatcher, RecordingUnitOfWork, block_on, test_auditor, test_ctx,
    };

    /// Rotating every ninety days, a rotated key published for a day.
    fn quarterly() -> KeyRotationSchedule {
        KeyRotationSchedule::new(
            Lifetime::seconds(90 * 86_400).unwrap(),
            Lifetime::seconds(86_400).unwrap(),
        )
        .unwrap()
    }

    /// An active key under `kid`, made `ago` before now.
    fn signing_for(kid: &str, ago: Duration) -> SigningKey {
        SigningKey::reconstitute(SigningKeyRow {
            kid: KeyId::new(kid).unwrap(),
            algorithm: SigningAlgorithm::Es256,
            public_key: PublicKeyPem::new(
                "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n",
            )
            .unwrap(),
            private_key: Secret::new(format!("private-{kid}")),
            state: KeyState::Active,
            created_at: clock::now() - ago,
            expires_at: Expiry::Never,
        })
        .unwrap()
    }

    /// What the job did, and where it wrote.
    struct Ran {
        rotated: usize,
        store: Arc<FakeSigningKeyStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    /// Runs the job over the test tenant holding `key`, with `migrations`.
    fn run(key: SigningKey, migrations: FakeMigrationStore) -> Ran {
        let store = Arc::new(FakeSigningKeyStore::holding(
            SigningKeySet::from_keys(vec![key]).unwrap(),
        ));
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = RotateByAgeUseCase::new(
            RotateByAgePorts {
                key_store: store.clone(),
                key_sets: store.clone(),
                key_generator: Arc::new(FakeKeyGenerator::new()),
                migration_store: Arc::new(migrations),
                unit_of_work: Arc::new(RecordingUnitOfWork::default()),
            },
            quarterly(),
        );
        let rotated = block_on(use_case.execute(&(), &test_auditor(audit.clone()), ())).unwrap();
        Ran {
            rotated,
            store,
            audit,
        }
    }

    /// Acme's key has signed for ninety-one days. The job rotates it onto a
    /// new key of the same algorithm, keeps the old one published, and
    /// records the rotation against Acme.
    #[test]
    fn an_old_key_is_rotated() {
        let ran = run(
            signing_for("key-old", Duration::days(91)),
            FakeMigrationStore::empty(),
        );

        let set = ran.store.set_of(test_ctx().tenant_id()).unwrap();
        let signer = set.active_key(clock::now()).unwrap();
        assert_eq!(ran.rotated, 1);
        assert_ne!(signer.kid().as_str(), "key-old");
        assert_eq!(signer.algorithm(), SigningAlgorithm::Es256);
        assert_eq!(set.keys()[0].status(), KeyStatus::Rotated);
        assert_eq!(
            ran.audit.tenant_of("crypto.key_rotated"),
            Some(test_ctx().tenant_id())
        );
    }

    /// A key made a month ago is not due. Nothing is rotated or recorded.
    #[test]
    fn a_young_key_is_left_alone() {
        let ran = run(
            signing_for("key-1", Duration::days(30)),
            FakeMigrationStore::empty(),
        );

        assert_eq!(ran.rotated, 0);
        assert!(ran.audit.records.lock().unwrap().is_empty());
    }

    /// An active algorithm migration prevents age-based rotation even when
    /// the stored key is due, and no rotation event is recorded.
    #[test]
    fn a_tenant_mid_migration_is_left_alone() {
        let (_, migration) = started_migration();

        let ran = run(
            signing_for("key-old", Duration::days(91)),
            FakeMigrationStore::holding(&migration),
        );

        assert_eq!(ran.rotated, 0);
        assert!(ran.audit.records.lock().unwrap().is_empty());
    }
}
