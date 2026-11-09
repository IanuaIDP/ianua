//! The background sweep that deletes API keys past their expiry and records
//! each one.

use std::sync::Arc;

use ianua_domain::domains::oauth::clients::api_key::ExpiredApiKeys;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::event::DomainEvent;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::oauth::CrossTenantApiKeyStore;
use crate::ports::runtime::UnitOfWork;
use crate::services::kept_together::kept_together;
use crate::use_case::Command;

/// The ports [`ExpireUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ExpirePorts {
    /// Where keys are kept, across every tenant.
    pub key_store: Arc<dyn CrossTenantApiKeyStore>,
    /// Keeps the deletions and their records together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Deletes expired API keys and records `ApiKeyExpired` for each.
///
/// It runs as a periodic job of the platform, with nobody asking. A key
/// leaves the table in one of two ways: revoked by someone, or expired here.
/// Each records its own event.
pub struct ExpireUseCase {
    ports: ExpirePorts,
}

impl ExpireUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ExpirePorts) -> Self {
        Self { ports }
    }

    /// Deletes every key expired by `now` and records each, answering how
    /// many expired.
    async fn swept(
        &self,
        auditor: &RequestAuditor,
        now: time::OffsetDateTime,
    ) -> Result<usize, AppError> {
        let deleted = self
            .ports
            .key_store
            .delete_expired(now)
            .await
            .or_internal()?;
        let expired = ExpiredApiKeys::swept(deleted, now);
        if expired.is_empty() {
            return Ok(0);
        }
        let events: Vec<DomainEvent> = expired
            .events()
            .into_iter()
            .map(DomainEvent::system)
            .collect();
        auditor.dispatch(&events).await.or_internal()?;
        Ok(events.len())
    }
}

impl Command for ExpireUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<usize, AppError>;

    /// Deletes every key expired by now, and records one
    /// `oauth.api_key_expired` per key, by the platform, which drops each
    /// key's cached caller once kept. The deletions and their records are
    /// kept together: a record that cannot be kept leaves every key in
    /// place for the next round. Returns how many keys expired.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the keys cannot be deleted, the cache
    ///   cannot be dropped, or the events cannot be recorded; nothing is
    ///   deleted then.
    async fn execute(&self, _: &(), auditor: &RequestAuditor, _: ()) -> Result<usize, AppError> {
        let swept = self.swept(auditor, clock::now());
        kept_together(self.ports.unit_of_work.as_ref(), swept).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::oauth::clients::api_key::ApiKey;
    use ianua_domain::types::Expiry;
    use time::Duration;

    use super::*;
    use crate::ports::oauth::ApiKeyStore as _;
    use crate::ports::runtime::Settlement;
    use crate::ports::shared::EventDispatcher;
    use crate::test_support::oauth::{FakeApiKeyStore, api_key_row};
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, RecordingUnitOfWork, block_on, test_auditor,
        test_ctx,
    };

    fn store_with(expiries: &[Expiry]) -> Arc<FakeApiKeyStore> {
        let store = Arc::new(FakeApiKeyStore::empty());
        for expiry in expiries {
            let mut row = api_key_row("key", test_ctx().actor());
            row.created_at = clock::now() - Duration::days(1);
            row.expires_at = *expiry;
            let key = ApiKey::reconstitute(row).unwrap();
            block_on(store.insert(&test_ctx().tenant(), &key)).unwrap();
        }
        store
    }

    struct Swept {
        expired: usize,
        audit: Arc<FakeEventDispatcher>,
    }

    fn sweep(store: Arc<FakeApiKeyStore>) -> Swept {
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = ExpireUseCase::new(ExpirePorts {
            key_store: store,
            unit_of_work: Arc::new(RecordingUnitOfWork::default()),
        });
        let expired = block_on(use_case.execute(&(), &test_auditor(audit.clone()), ())).unwrap();
        Swept { expired, audit }
    }

    fn ago(minutes: i64) -> Expiry {
        Expiry::At(clock::now() - Duration::minutes(minutes))
    }

    /// Acme has two keys past their expiry, one that runs another hour and
    /// one that never expires. The sweep deletes the two and records each:
    /// the event the token cache drops each key's cached caller by.
    #[test]
    fn only_expired_keys_are_deleted_and_recorded() {
        let store = store_with(&[
            ago(60),
            ago(5),
            Expiry::At(clock::now() + Duration::hours(1)),
            Expiry::Never,
        ]);

        let swept = sweep(store.clone());

        assert_eq!(swept.expired, 2);
        assert_eq!(store.count(), 2);
        assert_eq!(
            swept.audit.records.lock().unwrap().as_slice(),
            ["oauth.api_key_expired", "oauth.api_key_expired"]
        );
    }

    /// No key has expired. The sweep deletes nothing and records nothing.
    #[test]
    fn a_sweep_with_nothing_expired_changes_nothing() {
        let store = store_with(&[Expiry::At(clock::now() + Duration::hours(1)), Expiry::Never]);

        let swept = sweep(store.clone());

        assert_eq!(swept.expired, 0);
        assert_eq!(store.count(), 2);
        assert!(swept.audit.records.lock().unwrap().is_empty());
    }

    /// An audit failure during API-key expiry fails the sweep and requests
    /// rollback of the unit containing the deletion.
    #[test]
    fn a_record_that_fails_drops_the_deletion() {
        let store = store_with(&[ago(60)]);
        let unit = Arc::new(RecordingUnitOfWork::default());
        let audit: Arc<dyn EventDispatcher> = Arc::new(FailingEventDispatcher);
        let use_case = ExpireUseCase::new(ExpirePorts {
            key_store: store,
            unit_of_work: unit.clone(),
        });

        let swept = block_on(use_case.execute(&(), &test_auditor(audit), ()));

        assert!(swept.is_err());
        assert_eq!(unit.settlements(), [Settlement::Rollback]);
    }
}
