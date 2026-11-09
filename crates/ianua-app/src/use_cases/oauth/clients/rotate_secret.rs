//! Rotating an OAuth client's secret, the old one kept for an overlap so
//! the app's servers can move without an outage, or stopped at once after
//! a leak.

use std::sync::Arc;

use ianua_domain::domains::oauth::control::{OAuthControl, OAuthRight};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{OAuthClientId, RotationOverlap};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::oauth::{ClientSecretGenerator, OAuthClientStore};
use crate::use_case::Command;
use crate::use_cases::oauth::lookup::existing_client;

/// Which secret to rotate, and how long the old one keeps working.
pub struct RotateSecretRequest {
    /// The registered application receiving a replacement credential.
    pub client_id: OAuthClientId,
    /// How long the old secret keeps working beside the new one.
    pub overlap: RotationOverlap,
}

/// The ports [`RotateSecretUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RotateSecretPorts {
    /// Where clients are kept.
    pub client_store: Arc<dyn OAuthClientStore>,
    /// Makes the new secret.
    pub secret_generator: Arc<dyn ClientSecretGenerator>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Gives a client a new secret.
pub struct RotateSecretUseCase {
    ports: RotateSecretPorts,
}

impl RotateSecretUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RotateSecretPorts) -> Self {
        Self { ports }
    }
}

impl Command for RotateSecretUseCase {
    type Caller = CallerContext;
    type Input = RotateSecretRequest;
    type Output = Result<Secret, AppError>;

    /// Gives the client `req` names a new secret, keeping the old one for
    /// the overlap asked, and records `oauth.client_secret_rotated`. The raw
    /// secret comes back once; only its hash is kept.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without client-update rights.
    /// - `AppError::NotFound` for a missing tenant client; `Conflict` for a revoked client or one without a secret.
    /// - `AppError::Domain` for overlap beyond thirty days; `Internal` on secret generation, save or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        req: RotateSecretRequest,
    ) -> Result<Secret, AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = OAuthControl::new(&authority);
        control
            .ensure_may(OAuthRight::Update)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let store = self.ports.client_store.as_ref();
        let mut client = existing_client(store, &tenant, &req.client_id).await?;
        let made = self
            .ports
            .secret_generator
            .generate_secret()
            .await
            .or_internal()?;
        client
            .rotate_secret(made.secret_hash, req.overlap, &control)
            .map_err(AppError::from_domain)?;
        store.save(&tenant, &client).await.or_internal()?;
        auditor
            .dispatch_by(&caller.actor(), client.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(made.raw_secret)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::oauth::clients::client::{GrantType, OAuthClient};
    use ianua_domain::domains::oauth::clients::credential::ClientCredential;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::clock;
    use ianua_domain::types::Lifetime;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::oauth::{
        FakeOAuthClientStore, TEST_CLIENT_SECRET, hash_of, public_client, stored_client,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The tenant holding one client, and what rotating its secret records.
    struct Fixture {
        store: Arc<FakeOAuthClientStore>,
        client_id: OAuthClientId,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        /// The tenant holding `client`.
        fn holding(client: OAuthClient<ResolvedTenant>) -> Self {
            Self {
                client_id: *client.id(),
                store: Arc::new(FakeOAuthClientStore::holding(&test_ctx().tenant(), client)),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        /// The tenant holding the portal, which holds a secret.
        fn portal() -> Self {
            Self::holding(stored_client("Portal", &[GrantType::AuthorizationCode]))
        }

        /// What rotating with `overlap`, as `authorities` allow, answers.
        fn rotate_as(
            &self,
            authorities: FakeTenantAuthorities,
            overlap: RotationOverlap,
        ) -> Result<Secret, AppError> {
            let use_case = RotateSecretUseCase::new(RotateSecretPorts {
                client_store: self.store.clone(),
                tenant_authorities: Arc::new(authorities),
                ..RotateSecretPorts::fakes()
            });
            let req = RotateSecretRequest {
                client_id: self.client_id,
                overlap,
            };
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.audit.clone()), req))
        }

        /// What rotating with `overlap`, as someone who may, answers.
        fn rotate(&self, overlap: RotationOverlap) -> Result<Secret, AppError> {
            self.rotate_as(FakeTenantAuthorities::holding_everything(), overlap)
        }

        /// The hashes the kept client accepts now.
        fn accepted(&self) -> Vec<String> {
            let client = block_on(self.store.find_by_id(&test_ctx().tenant(), &self.client_id))
                .unwrap()
                .unwrap();
            client
                .credential()
                .secrets_accepted_at(clock::now())
                .into_iter()
                .map(|hash| hash.as_str().to_owned())
                .collect()
        }
    }

    /// Keeps the previous client secret usable for 86,400 seconds after rotation.
    fn a_day() -> RotationOverlap {
        RotationOverlap::For(Lifetime::seconds(86_400).unwrap())
    }

    /// Ann rotates the portal's secret with a day's overlap. She is shown the
    /// new one; both the new and the old work for the day, and the rotation
    /// is recorded.
    #[test]
    fn a_rotation_keeps_the_old_secret_for_the_overlap() {
        let fixture = Fixture::portal();

        let secret = fixture.rotate(a_day()).unwrap();

        let accepted = fixture.accepted();
        assert!(accepted.contains(&hash_of(secret.expose()).as_str().to_owned()));
        assert!(accepted.contains(&hash_of(TEST_CLIENT_SECRET).as_str().to_owned()));
        assert_eq!(
            fixture.audit.records.lock().unwrap().as_slice(),
            ["oauth.client_secret_rotated"]
        );
    }

    /// Immediate rotation leaves one accepted secret and removes the old
    /// secret from the client's accepted hashes.
    #[test]
    fn an_immediate_rotation_stops_the_old_secret() {
        let fixture = Fixture::portal();

        fixture.rotate(RotationOverlap::Immediate).unwrap();

        assert_eq!(fixture.accepted().len(), 1);
        assert!(
            !fixture
                .accepted()
                .contains(&hash_of(TEST_CLIENT_SECRET).as_str().to_owned())
        );
    }

    /// Rotating a public client's nonexistent secret returns conflict and
    /// preserves its public credential.
    #[test]
    fn a_public_client_has_no_secret_to_rotate() {
        let fixture = Fixture::holding(public_client("SPA", &[GrantType::AuthorizationCode]));

        let result = fixture.rotate(a_day());

        assert!(matches!(result, Err(AppError::Conflict(_))));
        let client = block_on(
            fixture
                .store
                .find_by_id(&test_ctx().tenant(), &fixture.client_id),
        )
        .unwrap()
        .unwrap();
        assert_eq!(client.credential(), &ClientCredential::Public);
    }

    /// A year-long secret overlap is refused and records no rotation event.
    #[test]
    fn an_overlap_beyond_thirty_days_is_refused() {
        let fixture = Fixture::portal();

        let result = fixture.rotate(RotationOverlap::For(
            Lifetime::seconds(365 * 86_400).unwrap(),
        ));

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(fixture.audit.records.lock().unwrap().is_empty());
    }

    /// A caller with no permissions cannot rotate the portal's secret, and
    /// the original hash remains the only accepted one.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let fixture = Fixture::portal();

        let result = fixture.rotate_as(FakeTenantAuthorities::holding(&[]), a_day());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.accepted(), [hash_of(TEST_CLIENT_SECRET).as_str()]);
    }

    /// A signed-out caller receives unauthenticated when rotating a client secret.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture::portal();

        let result =
            fixture.rotate_as(FakeTenantAuthorities::refusing(Refusal::SignedOut), a_day());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Rotating an unknown client's secret returns not found.
    #[test]
    fn an_unknown_client_is_not_found() {
        let fixture = Fixture {
            client_id: OAuthClientId::new(),
            ..Fixture::portal()
        };

        let result = fixture.rotate(a_day());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
