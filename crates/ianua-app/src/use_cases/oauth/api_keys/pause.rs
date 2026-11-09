//! Pausing an API key: it signs in nothing until someone resumes it, and
//! nothing about it is lost meanwhile.

use std::sync::Arc;

use ianua_domain::domains::oauth::control::{OAuthControl, OAuthRight};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ApiKeyId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::oauth::ApiKeyStore;
use crate::use_case::Command;
use crate::use_cases::oauth::lookup::{ensure_key_still_kept, existing_api_key};

/// The ports [`PauseUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PausePorts {
    /// Where keys are kept.
    pub key_store: Arc<dyn ApiKeyStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Pauses an API key.
pub struct PauseUseCase {
    ports: PausePorts,
}

impl PauseUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: PausePorts) -> Self {
        Self { ports }
    }
}

impl Command for PauseUseCase {
    type Caller = CallerContext;
    type Input = ApiKeyId;
    type Output = Result<(), AppError>;

    /// Pauses the key `key_id` for `caller`. Records `oauth.api_key_paused`,
    /// which drops the key's cached caller once kept, so it stops signing
    /// in at once.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not revoke keys.
    /// - `AppError::NotFound` when the tenant has no such key.
    /// - `AppError::Domain` when the key is paused already.
    /// - `AppError::Internal` when the key cannot be read, saved or audited.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        key_id: ApiKeyId,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = OAuthControl::new(&authority);
        control
            .ensure_may(OAuthRight::Revoke)
            .map_err(AppError::from_domain)?;
        let store = self.ports.key_store.as_ref();
        let tenant = caller.tenant();
        let mut key = existing_api_key(store, &tenant, &key_id).await?;
        key.pause(&control).map_err(AppError::from_domain)?;
        ensure_key_still_kept(store.update(&tenant, &key).await)?;
        auditor
            .dispatch_by(&caller.actor(), key.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{ApiKeyAction, SystemPermission};
    use ianua_domain::shared::clock;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::oauth::{FakeApiKeyStore, stored_api_key};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// Ann's CI key, and what pausing it records.
    struct Fixture {
        store: Arc<FakeApiKeyStore>,
        audit: Arc<FakeEventDispatcher>,
        key_id: ApiKeyId,
    }

    impl Fixture {
        fn new() -> Self {
            let key = stored_api_key("CI", test_ctx().actor());
            let key_id = *key.id();
            Self {
                store: Arc::new(FakeApiKeyStore::holding(&test_ctx().tenant(), key)),
                audit: Arc::new(FakeEventDispatcher::new()),
                key_id,
            }
        }

        fn pause_as(&self, authorities: FakeTenantAuthorities) -> Result<(), AppError> {
            let use_case = PauseUseCase::new(PausePorts {
                key_store: self.store.clone(),
                tenant_authorities: Arc::new(authorities),
            });
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.audit.clone()), self.key_id))
        }

        fn key_works(&self) -> bool {
            block_on(self.store.find_by_id(&test_ctx().tenant(), &self.key_id))
                .unwrap()
                .is_some_and(|key| key.is_active(clock::now()))
        }
    }

    /// Ann pauses the CI key. It is kept, signs in no more, and the pause
    /// is recorded.
    #[test]
    fn a_paused_key_is_kept_and_stops_signing_in() {
        let fixture = Fixture::new();

        fixture
            .pause_as(FakeTenantAuthorities::holding_everything())
            .unwrap();

        assert_eq!(fixture.store.count(), 1);
        assert!(!fixture.key_works());
        assert_eq!(
            *fixture.audit.records.lock().unwrap(),
            ["oauth.api_key_paused"]
        );
    }

    /// A caller with only view permission cannot pause the CI key, which
    /// remains active.
    #[test]
    fn a_caller_who_may_not_revoke_keys_pauses_nothing() {
        let fixture = Fixture::new();

        let result = fixture.pause_as(FakeTenantAuthorities::holding(&[
            SystemPermission::ApiKeys(ApiKeyAction::View),
        ]));

        assert!(matches!(
            result,
            Err(AppError::Domain(_) | AppError::Forbidden(_))
        ));
        assert!(fixture.key_works());
    }
}
