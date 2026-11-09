//! The background sweep that revokes signing keys once they have been
//! rotated out for the whole grace period, so the JWKS stops publishing
//! them and tokens they signed stop verifying.

use std::sync::Arc;

use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{Lifetime, TenantId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::crypto::{CrossTenantKeySets, SigningKeyStore};
use crate::ports::runtime::UnitOfWork;
use crate::services::kept_together::kept_together;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::crypto::key_steps::save_key_set;

/// The ports [`RevokeAfterGraceUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RevokeAfterGracePorts {
    /// Loads and saves each tenant's key set.
    pub key_store: Arc<dyn SigningKeyStore>,
    /// Finds the tenants holding a key rotated out but not yet revoked.
    pub key_sets: Arc<dyn CrossTenantKeySets>,
    /// Keeps each tenant's revocations and the record of them together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Revokes every signing key that has stayed published for the whole grace
/// period since it was rotated out.
///
/// It runs as a periodic job of the platform, with nobody asking. Until it
/// runs, the JWKS already leaves such a key out, since publishing is judged
/// from the clock; this sweep makes the stored state say so too.
pub struct RevokeAfterGraceUseCase {
    ports: RevokeAfterGracePorts,
    grace: Lifetime,
}

impl RevokeAfterGraceUseCase {
    /// A use case working through `ports`, revoking keys rotated out longer
    /// than `grace` ago. It is the same grace the JWKS publishes keys for.
    #[must_use]
    pub fn new(ports: RevokeAfterGracePorts, grace: Lifetime) -> Self {
        Self { ports, grace }
    }

    /// Revokes the keys of `tenant_id` whose grace is over, saves the set
    /// and records one `crypto.key_revoked` per key, by the platform.
    /// Returns how many keys it revoked.
    async fn revoked_in(
        &self,
        auditor: &RequestAuditor,
        tenant_id: TenantId,
    ) -> Result<usize, AppError> {
        let tenant = ScopedTenant::for_background(tenant_id);
        let key_store = self.ports.key_store.as_ref();
        let Some(mut key_set) = key_store.find(&tenant).await.or_internal()? else {
            return Ok(0);
        };
        let revoked = key_set
            .revoke_after_grace(self.grace)
            .map_err(AppError::from_domain)?;
        if revoked.is_empty() {
            return Ok(0);
        }
        save_key_set(key_store, &tenant, &key_set).await?;
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
        Ok(events.len())
    }
}

impl Command for RevokeAfterGraceUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<usize, AppError>;

    /// Revokes, in every tenant, the keys rotated out longer than the grace
    /// period ago, and records `crypto.key_revoked` for each against its own
    /// tenant. Returns how many keys it revoked.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the tenants to sweep cannot be listed. A
    ///   tenant whose keys cannot be revoked, saved or recorded is logged and
    ///   left for the next sweep, with nothing of it kept: its revocations
    ///   and their record are one unit.
    async fn execute(&self, (): &(), auditor: &RequestAuditor, (): ()) -> Result<usize, AppError> {
        let tenants = self
            .ports
            .key_sets
            .tenants_with_rotated_keys()
            .await
            .or_internal()?;
        let mut revoked = 0;
        let unit = self.ports.unit_of_work.as_ref();
        for tenant_id in tenants {
            match kept_together(unit, self.revoked_in(auditor, tenant_id)).await {
                Ok(count) => revoked += count,
                Err(error) => tracing::warn!(
                    %tenant_id,
                    %error,
                    "revoking keys after their grace failed; left for the next sweep"
                ),
            }
        }
        Ok(revoked)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::crypto::key_status::{KeyState, KeyStatus};
    use ianua_domain::domains::crypto::signing_key::{
        SigningAlgorithm, SigningKey, SigningKeyRow, SigningKeySet,
    };
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::clock;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{Expiry, KeyId, PublicKeyPem};
    use time::Duration;

    use super::*;
    use crate::ports::runtime::Settlement;
    use crate::ports::shared::EventDispatcher;
    use crate::test_support::crypto::{FakeSigningKeyStore, test_signing_key};
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, RecordingUnitOfWork, block_on, test_auditor,
        test_ctx,
    };

    fn grace() -> Lifetime {
        Lifetime::seconds(3600).unwrap()
    }

    /// A key under `kid` rotated out `ago` before now.
    fn rotated(kid: &str, ago: Duration) -> SigningKey {
        let now = clock::now();
        SigningKey::reconstitute(SigningKeyRow {
            kid: KeyId::new(kid).unwrap(),
            algorithm: SigningAlgorithm::Rs256,
            public_key: PublicKeyPem::new(
                "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n",
            )
            .unwrap(),
            private_key: Secret::new(format!("private-{kid}")),
            state: KeyState::Rotated { at: now - ago },
            created_at: now - Duration::days(30),
            expires_at: Expiry::Never,
        })
        .unwrap()
    }

    /// `key-new` signing, beside the rotated `keys`.
    fn set_with(keys: Vec<SigningKey>) -> SigningKeySet<ResolvedTenant> {
        let signer = test_signing_key("key-new", SigningAlgorithm::Rs256);
        SigningKeySet::from_keys([vec![signer], keys].concat()).unwrap()
    }

    struct Swept {
        revoked: usize,
        audit: Arc<FakeEventDispatcher>,
    }

    fn sweep(store: Arc<FakeSigningKeyStore>) -> Swept {
        let audit = Arc::new(FakeEventDispatcher::new());
        let revoked = sweep_through(
            store,
            audit.clone(),
            Arc::new(RecordingUnitOfWork::default()),
        );
        Swept { revoked, audit }
    }

    fn sweep_through(
        store: Arc<FakeSigningKeyStore>,
        audit: Arc<dyn EventDispatcher>,
        unit: Arc<RecordingUnitOfWork>,
    ) -> usize {
        let use_case = RevokeAfterGraceUseCase::new(
            RevokeAfterGracePorts {
                key_store: store.clone(),
                key_sets: store,
                unit_of_work: unit,
            },
            grace(),
        );
        block_on(use_case.execute(&(), &test_auditor(audit), ())).unwrap()
    }

    fn status_of(store: &FakeSigningKeyStore, tenant_id: TenantId, kid: &str) -> KeyStatus {
        let set = store.set_of(tenant_id).unwrap();
        set.keys()
            .iter()
            .find(|key| key.kid().as_str() == kid)
            .unwrap()
            .status()
    }

    /// Acme rotated `key-old` out two hours ago and `key-recent` ten minutes
    /// ago, under an hour's grace. The sweep revokes `key-old`, records it,
    /// and leaves `key-recent` published and `key-new` signing.
    #[test]
    fn only_keys_past_their_grace_are_revoked() {
        let store = Arc::new(FakeSigningKeyStore::holding(set_with(vec![
            rotated("key-old", Duration::hours(2)),
            rotated("key-recent", Duration::minutes(10)),
        ])));

        let swept = sweep(store.clone());

        let acme = test_ctx().tenant_id();
        assert_eq!(swept.revoked, 1);
        assert_eq!(status_of(&store, acme, "key-old"), KeyStatus::Revoked);
        assert_eq!(status_of(&store, acme, "key-recent"), KeyStatus::Rotated);
        assert_eq!(status_of(&store, acme, "key-new"), KeyStatus::Active);
        assert_eq!(
            swept.audit.records.lock().unwrap().as_slice(),
            ["crypto.key_revoked"]
        );
    }

    /// Acme and Globex each rotated a key out a day ago. One sweep revokes
    /// both, each in its own tenant.
    #[test]
    fn every_tenant_is_swept() {
        let store = Arc::new(FakeSigningKeyStore::holding(set_with(vec![rotated(
            "key-old",
            Duration::days(1),
        )])));
        let globex = TenantId::new();
        store.put(
            globex,
            set_with(vec![rotated("key-old", Duration::days(1))]),
        );

        let swept = sweep(store.clone());

        assert_eq!(swept.revoked, 2);
        assert_eq!(status_of(&store, globex, "key-old"), KeyStatus::Revoked);
    }

    /// Acme rotated a key out only minutes ago. The sweep revokes nothing,
    /// saves nothing and records nothing.
    #[test]
    fn a_sweep_with_nothing_past_its_grace_changes_nothing() {
        let store = Arc::new(FakeSigningKeyStore::holding(set_with(vec![rotated(
            "key-recent",
            Duration::minutes(5),
        )])));

        let swept = sweep(store.clone());

        assert_eq!(swept.revoked, 0);
        assert_eq!(
            status_of(&store, test_ctx().tenant_id(), "key-recent"),
            KeyStatus::Rotated
        );
        assert!(swept.audit.records.lock().unwrap().is_empty());
    }

    /// Acme's revoked key cannot be recorded. Nothing is counted, and the
    /// revocation is rolled back with its record, left for the next sweep.
    #[test]
    fn a_revocation_that_cannot_be_recorded_is_rolled_back() {
        let store = Arc::new(FakeSigningKeyStore::holding(set_with(vec![rotated(
            "key-old",
            Duration::days(1),
        )])));
        let unit = Arc::new(RecordingUnitOfWork::default());

        let revoked = sweep_through(store, Arc::new(FailingEventDispatcher), unit.clone());

        assert_eq!(revoked, 0);
        assert_eq!(unit.settlements(), [Settlement::Rollback]);
    }

    /// Acme's key past its grace is revoked. Saving it and recording it are
    /// one unit, kept together.
    #[test]
    fn a_revocation_and_its_record_are_kept_as_one_unit() {
        let store = Arc::new(FakeSigningKeyStore::holding(set_with(vec![rotated(
            "key-old",
            Duration::days(1),
        )])));
        let unit = Arc::new(RecordingUnitOfWork::default());

        sweep_through(store, Arc::new(FakeEventDispatcher::new()), unit.clone());

        assert_eq!(unit.settlements(), [Settlement::Commit]);
    }
}
