//! Resuming a paused API key, so it signs in again as before.

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

/// The ports [`ResumeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ResumePorts {
    /// Where keys are kept.
    pub key_store: Arc<dyn ApiKeyStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Resumes a paused API key.
pub struct ResumeUseCase {
    ports: ResumePorts,
}

impl ResumeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ResumePorts) -> Self {
        Self { ports }
    }
}

impl Command for ResumeUseCase {
    type Caller = CallerContext;
    type Input = ApiKeyId;
    type Output = Result<(), AppError>;

    /// Resumes the paused key `key_id` for `caller`, who must be allowed to
    /// update keys and hold everything it carries. Records
    /// `oauth.api_key_resumed`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update keys, or the
    ///   key carries a permission they do not hold.
    /// - `AppError::NotFound` when the tenant has no such key.
    /// - `AppError::Domain` when the key is not paused.
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
            .ensure_may(OAuthRight::Update)
            .map_err(AppError::from_domain)?;
        let store = self.ports.key_store.as_ref();
        let tenant = caller.tenant();
        let mut key = existing_api_key(store, &tenant, &key_id).await?;
        key.resume(&control).map_err(AppError::from_domain)?;
        ensure_key_still_kept(store.update(&tenant, &key).await)?;
        auditor
            .dispatch_by(&caller.actor(), key.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::oauth::clients::api_key::{ApiKey, ApiKeyRow, KeyStanding};
    use ianua_domain::shared::clock;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::oauth::{FakeApiKeyStore, api_key_row};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// Ann paused the CI key; she resumes it and it signs in again, the
    /// resume recorded.
    #[test]
    fn a_resumed_key_signs_in_again() {
        let row = api_key_row("CI", test_ctx().actor());
        let paused = ApiKeyRow {
            standing: KeyStanding::Paused(row.created_at),
            ..row
        };
        let key = ApiKey::reconstitute(paused).unwrap();
        let key_id = *key.id();
        let store = Arc::new(FakeApiKeyStore::holding(&test_ctx().tenant(), key));
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = ResumeUseCase::new(ResumePorts {
            key_store: store.clone(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding_everything()),
        });

        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), key_id)).unwrap();

        let resumed = block_on(store.find_by_id(&test_ctx().tenant(), &key_id))
            .unwrap()
            .unwrap();
        assert!(resumed.is_active(clock::now()));
        assert_eq!(*audit.records.lock().unwrap(), ["oauth.api_key_resumed"]);
    }
}
