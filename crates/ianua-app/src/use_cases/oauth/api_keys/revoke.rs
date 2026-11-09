//! Revoking an API key for good. A revoked key is deleted.

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
use crate::use_cases::oauth::lookup::existing_api_key;

/// The ports [`RevokeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RevokePorts {
    /// Where keys are kept.
    pub key_store: Arc<dyn ApiKeyStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Revokes an API key. It cannot be undone.
pub struct RevokeUseCase {
    ports: RevokePorts,
}

impl RevokeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RevokePorts) -> Self {
        Self { ports }
    }
}

impl Command for RevokeUseCase {
    type Caller = CallerContext;
    type Input = ApiKeyId;
    type Output = Result<(), AppError>;

    /// Revokes the key `key_id` for `caller` by deleting it. Records
    /// `oauth.api_key_revoked`, naming who revoked it, which drops the
    /// key's cached caller once kept.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not revoke keys.
    /// - `AppError::NotFound` when the tenant has no such key, or it was
    ///   already revoked.
    /// - `AppError::Internal` when the key cannot be read, deleted or
    ///   audited, or the cache cannot be dropped.
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
        key.revoke(&control).map_err(AppError::from_domain)?;
        store.delete(&tenant, &key_id).await.or_internal()?;
        auditor
            .dispatch_by(&caller.actor(), key.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{ApiKeyAction, SystemPermission};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::oauth::{FakeApiKeyStore, stored_api_key};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

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

        fn revoke(&self, key_id: ApiKeyId) -> Result<(), AppError> {
            self.revoke_as(FakeTenantAuthorities::holding_everything(), key_id)
        }

        fn revoke_as(
            &self,
            authorities: FakeTenantAuthorities,
            key_id: ApiKeyId,
        ) -> Result<(), AppError> {
            let use_case = RevokeUseCase::new(RevokePorts {
                key_store: self.store.clone(),
                tenant_authorities: Arc::new(authorities),
            });
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.audit.clone()), key_id))
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann revokes the CI key. It is deleted and the revoke recorded.
    #[test]
    fn a_revoked_key_is_deleted_and_recorded() {
        let fixture = Fixture::new();

        fixture.revoke(fixture.key_id).unwrap();

        assert_eq!(fixture.store.count(), 0);
        assert_eq!(fixture.recorded(), ["oauth.api_key_revoked"]);
    }

    /// Repeating a successful API-key revocation returns not found and
    /// leaves the audit trail at one event.
    #[test]
    fn a_key_is_revoked_only_once() {
        let fixture = Fixture::new();
        fixture.revoke(fixture.key_id).unwrap();

        let result = fixture.revoke(fixture.key_id);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(fixture.recorded().len(), 1);
    }

    /// Revoking an unknown API key returns not found and records no event.
    #[test]
    fn an_unknown_key_is_not_found() {
        let fixture = Fixture::new();

        let result = fixture.revoke(ApiKeyId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(fixture.recorded().is_empty());
    }

    /// A caller with only view permission cannot revoke the CI key, which
    /// remains stored.
    #[test]
    fn a_caller_without_the_revoke_right_is_refused() {
        let fixture = Fixture::new();

        let result = fixture.revoke_as(
            FakeTenantAuthorities::holding(&[SystemPermission::ApiKeys(ApiKeyAction::View)]),
            fixture.key_id,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.store.count(), 1);
    }

    /// A signed-out caller cannot revoke the CI key and leaves it stored.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture::new();

        let result = fixture.revoke_as(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            fixture.key_id,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(fixture.store.count(), 1);
    }
}
