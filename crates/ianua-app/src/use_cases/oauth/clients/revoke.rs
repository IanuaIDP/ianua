//! Revoking an OAuth client for good.

use std::sync::Arc;

use ianua_domain::domains::oauth::control::{OAuthControl, OAuthRight};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::OAuthClientId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::oauth::OAuthClientStore;
use crate::use_case::Command;
use crate::use_cases::oauth::lookup::existing_client;

/// The ports [`RevokeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RevokePorts {
    /// Where clients are kept.
    pub client_store: Arc<dyn OAuthClientStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Revokes an OAuth client. It cannot be undone.
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
    type Input = OAuthClientId;
    type Output = Result<(), AppError>;

    /// Revokes the client `client_id` for `caller`. Records
    /// `oauth.client_revoked`, which drops the cached callers once kept.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not revoke clients.
    /// - `AppError::NotFound` when the tenant has no such client.
    /// - `AppError::Domain` when the client is already revoked.
    /// - `AppError::Internal` when the client cannot be read, saved or
    ///   audited, or the cache cannot be dropped.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        client_id: OAuthClientId,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = OAuthControl::new(&authority);
        control
            .ensure_may(OAuthRight::Revoke)
            .map_err(AppError::from_domain)?;
        let store = self.ports.client_store.as_ref();
        let tenant = caller.tenant();
        let mut client = existing_client(store, &tenant, &client_id).await?;
        client.revoke(&control).map_err(AppError::from_domain)?;
        store.save(&tenant, &client).await.or_internal()?;
        auditor
            .dispatch_by(&caller.actor(), client.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::oauth::clients::client::GrantType;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::oauth::{FakeOAuthClientStore, stored_client};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Fixture {
        store: Arc<FakeOAuthClientStore>,
        audit: Arc<FakeEventDispatcher>,
        client_id: OAuthClientId,
    }

    impl Fixture {
        fn new() -> Self {
            let client = stored_client("Portal", &[GrantType::AuthorizationCode]);
            let client_id = *client.id();
            Self {
                store: Arc::new(FakeOAuthClientStore::holding(&test_ctx().tenant(), client)),
                audit: Arc::new(FakeEventDispatcher::new()),
                client_id,
            }
        }

        fn revoke(&self, client_id: OAuthClientId) -> Result<(), AppError> {
            self.revoke_as(FakeTenantAuthorities::holding_everything(), client_id)
        }

        fn revoke_as(
            &self,
            authorities: FakeTenantAuthorities,
            client_id: OAuthClientId,
        ) -> Result<(), AppError> {
            let use_case = RevokeUseCase::new(RevokePorts {
                client_store: self.store.clone(),
                tenant_authorities: Arc::new(authorities),
            });
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.audit.clone()), client_id))
        }

        fn is_active(&self) -> bool {
            block_on(self.store.find_by_id(&test_ctx().tenant(), &self.client_id))
                .unwrap()
                .unwrap()
                .is_active()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann revokes the portal. It is kept revoked and the revoke recorded.
    #[test]
    fn a_revoked_client_is_kept_revoked_and_recorded() {
        let fixture = Fixture::new();

        fixture.revoke(fixture.client_id).unwrap();

        assert!(!fixture.is_active());
        assert_eq!(fixture.recorded(), ["oauth.client_revoked"]);
    }

    /// Revoking an unknown OAuth client returns not found and records no event.
    #[test]
    fn an_unknown_client_is_not_found() {
        let fixture = Fixture::new();

        let result = fixture.revoke(OAuthClientId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(fixture.recorded().is_empty());
    }

    /// Repeating the portal's revocation is refused and leaves the audit
    /// trail at one event.
    #[test]
    fn a_client_is_revoked_only_once() {
        let fixture = Fixture::new();
        fixture.revoke(fixture.client_id).unwrap();

        let result = fixture.revoke(fixture.client_id);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(fixture.recorded().len(), 1);
    }

    /// A caller with no permissions cannot revoke the portal, which stays active.
    #[test]
    fn a_caller_without_the_revoke_right_is_refused() {
        let fixture = Fixture::new();

        let result = fixture.revoke_as(FakeTenantAuthorities::holding(&[]), fixture.client_id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(fixture.is_active());
    }

    /// A signed-out caller cannot revoke the portal, which stays active.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture::new();

        let result = fixture.revoke_as(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            fixture.client_id,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(fixture.is_active());
    }
}
