//! Token revocation (RFC 7009): a client ends one of its own tokens, as it
//! does when a person signs out of it.
//!
//! A client revokes only what it holds. A token that is unknown, already
//! ended or another client's is answered the same as one revoked here, so
//! a caller learns nothing about tokens it does not hold. Revoking a
//! refresh token ends its whole family.

use std::sync::Arc;

use ianua_domain::domains::oauth::clients::client::OAuthClient;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, Issuer};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::input::validate_token;
use crate::ports::oauth::RefreshTokenStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::oauth::presented::{PresentedTokenPorts, presented_access_token};
use crate::use_cases::oauth::token::client_auth::{
    Asking, ClientAuthPorts, ClientProof, authenticated_client,
};
use crate::use_cases::oauth::token::refusal::TokenError;

/// Which kind of token the client says it revokes (`token_type_hint`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeHint {
    /// An access token: looked for first.
    AccessToken,
    /// A refresh token: looked for first.
    RefreshToken,
    /// No hint: an access token is looked for first.
    NotGiven,
}

/// What a client revokes.
pub struct RevokeRequest {
    /// How the client proves itself.
    pub client: ClientProof,
    /// The tenant's issuer.
    pub issuer: Issuer,
    /// The raw token.
    pub token: Secret,
    /// Which kind the client says it is.
    pub hint: TypeHint,
}

/// The ports [`RevokeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RevokePorts {
    /// How the client proves itself.
    pub client_auth: ClientAuthPorts,
    /// Finds an access token's record.
    pub presented: PresentedTokenPorts,
    /// Where refresh tokens are kept.
    pub refresh_token_store: Arc<dyn RefreshTokenStore>,
}

/// Revokes a client's own token.
pub struct RevokeUseCase {
    ports: RevokePorts,
}

impl RevokeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RevokePorts) -> Self {
        Self { ports }
    }

    /// Revokes the access token `raw`, if `client` holds it, with what the
    /// revoke raised. `None` when no token of the client's is found for it.
    async fn revoked_access(
        &self,
        asking: Asking<'_>,
        client: &OAuthClient<ResolvedTenant>,
        raw: &Secret,
    ) -> Result<Option<Vec<DomainEvent>>, AppError> {
        let found = presented_access_token(&self.ports.presented, asking, raw).await?;
        let Some(mut token) = found.filter(|token| token.belongs_to(client.id())) else {
            return Ok(None);
        };
        token
            .revoke_by_holder(client)
            .map_err(AppError::from_domain)?;
        self.ports
            .presented
            .access_token_store
            .save(asking.tenant, &token)
            .await
            .or_internal()?;
        Ok(Some(token.take_events(asking.tenant)))
    }

    /// Revokes the family of the refresh token `raw`, if `client` holds it,
    /// with what the revoke raised. `None` when no token of the client's is
    /// found for it.
    async fn revoked_refresh(
        &self,
        tenant: &ScopedTenant,
        client: &OAuthClient<ResolvedTenant>,
        raw: &Secret,
    ) -> Result<Option<Vec<DomainEvent>>, AppError> {
        let hasher = self.ports.presented.code_hasher.as_ref();
        let hash = hasher.hash_code(raw).await.or_internal()?;
        let store = self.ports.refresh_token_store.as_ref();
        let found = store.find_by_hash(tenant, &hash).await.or_internal()?;
        let Some(mut token) = found.filter(|token| token.belongs_to(client.id())) else {
            return Ok(None);
        };
        let now = clock::now();
        token
            .revoke_by_holder(client, now)
            .map_err(AppError::from_domain)?;
        store
            .revoke_family(tenant, token.family(), now)
            .await
            .or_internal()?;
        Ok(Some(token.take_events(tenant)))
    }

    /// Revokes `raw` as the kind `hint` names first, then as the other,
    /// with what the revoke raised.
    async fn revoked(
        &self,
        asking: Asking<'_>,
        client: &OAuthClient<ResolvedTenant>,
        req: &RevokeRequest,
    ) -> Result<Vec<DomainEvent>, AppError> {
        let raw = &req.token;
        let first = match req.hint {
            TypeHint::RefreshToken => self.revoked_refresh(asking.tenant, client, raw).await?,
            TypeHint::AccessToken | TypeHint::NotGiven => {
                self.revoked_access(asking, client, raw).await?
            }
        };
        if let Some(events) = first {
            return Ok(events);
        }
        let second = match req.hint {
            TypeHint::RefreshToken => self.revoked_access(asking, client, raw).await?,
            TypeHint::AccessToken | TypeHint::NotGiven => {
                self.revoked_refresh(asking.tenant, client, raw).await?
            }
        };
        Ok(second.unwrap_or_default())
    }
}

impl Command for RevokeUseCase {
    type Caller = ScopedTenant;
    type Input = RevokeRequest;
    type Output = Result<(), TokenError>;

    /// Revokes the token `req` names in `tenant`, if the client that proved
    /// itself holds it, and answers alike whether it did. A token the
    /// client revokes records `oauth.token_revoked`, with the client as
    /// actor; one it does not hold, or revoked already, records nothing.
    ///
    /// # Errors
    ///
    /// - `invalid_client` when the client does not prove itself.
    /// - `TokenError::Failed` when hashing, a lookup, a write or the record
    ///   fails.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        req: RevokeRequest,
    ) -> Result<(), TokenError> {
        let asking = Asking {
            tenant,
            issuer: &req.issuer,
        };
        let client = authenticated_client(&self.ports.client_auth, asking, &req.client).await?;
        if validate_token("token", req.token.expose()).is_err() {
            return Ok(());
        }
        let events = self.revoked(asking, &client, &req).await?;
        auditor
            .dispatch_by(&ActorRef::OAuthClient(*client.id()), events)
            .await
            .or_internal()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::oauth::clients::client::GrantType;
    use ianua_domain::domains::oauth::grants::access_token::TokenSubject;
    use ianua_domain::domains::oauth::grants::refresh_token::RefreshState;

    use super::*;
    use crate::ports::oauth::OAuthClientStore as _;
    use crate::test_support::oauth::{
        FakeAccessTokenStore, FakeRefreshTokenStore, TEST_ACCESS_TOKEN, TEST_REFRESH_TOKEN,
        TokenEndpoint, access_token, basic_proof, hash_of, refresh_row, stored_client, test_issuer,
    };
    use crate::test_support::{block_on, test_auditor, test_ctx};

    /// The portal, holding an access token and a refresh token for Ann.
    fn portal() -> TokenEndpoint {
        let client = stored_client(
            "Portal",
            &[GrantType::AuthorizationCode, GrantType::RefreshToken],
        );
        let mut endpoint = TokenEndpoint::serving(client);
        let tenant = test_ctx().tenant();
        let held = access_token(&endpoint.client, TokenSubject::Person(endpoint.ann));
        endpoint.tokens = Arc::new(FakeAccessTokenStore::holding(&tenant, held));
        let refresh = refresh_row(&endpoint.client, endpoint.ann);
        endpoint.refresh = Arc::new(FakeRefreshTokenStore::holding(&tenant, refresh));
        endpoint
    }

    /// What `client` revoking `token`, hinted as `hint`, answers at
    /// `endpoint`.
    fn revoke(
        endpoint: &TokenEndpoint,
        client: ClientProof,
        token: &str,
        hint: TypeHint,
    ) -> Result<(), TokenError> {
        let use_case = RevokeUseCase::new(RevokePorts {
            client_auth: endpoint.client_auth(),
            presented: endpoint.presented(),
            refresh_token_store: endpoint.refresh.clone(),
        });
        let req = RevokeRequest {
            client,
            issuer: test_issuer(),
            token: Secret::new(token.to_owned()),
            hint,
        };
        let auditor = test_auditor(endpoint.audit.clone());
        block_on(use_case.execute(&test_ctx().tenant(), &auditor, req))
    }

    /// Whether the portal's access token is revoked.
    fn access_is_revoked(endpoint: &TokenEndpoint) -> bool {
        endpoint.tokens.all()[0].revoked_at().is_some()
    }

    /// Ann signs out of the portal, which revokes its access token. The
    /// token stops working.
    #[test]
    fn a_client_revokes_its_access_token() {
        let endpoint = portal();

        revoke(
            &endpoint,
            basic_proof(&endpoint.client),
            TEST_ACCESS_TOKEN,
            TypeHint::NotGiven,
        )
        .unwrap();

        assert!(access_is_revoked(&endpoint));
        assert_eq!(endpoint.recorded(), ["oauth.token_revoked"]);
    }

    /// The portal revokes its refresh token twice, as a retrying client
    /// does. The revoke is recorded once.
    #[test]
    fn a_refresh_token_revoked_twice_is_recorded_once() {
        let endpoint = portal();
        let again = || {
            revoke(
                &endpoint,
                basic_proof(&endpoint.client),
                TEST_REFRESH_TOKEN,
                TypeHint::RefreshToken,
            )
        };

        again().unwrap();
        again().unwrap();

        assert_eq!(endpoint.recorded(), ["oauth.token_revoked"]);
    }

    /// The portal revokes its refresh token. Its whole family ends.
    #[test]
    fn a_client_revokes_its_refresh_token() {
        let endpoint = portal();

        revoke(
            &endpoint,
            basic_proof(&endpoint.client),
            TEST_REFRESH_TOKEN,
            TypeHint::RefreshToken,
        )
        .unwrap();

        assert!(matches!(
            endpoint.refresh.state_of(&hash_of(TEST_REFRESH_TOKEN)),
            Some(RefreshState::Revoked { .. })
        ));
    }

    /// The portal sends the refresh token with the access token hint. It
    /// is still found and revoked.
    #[test]
    fn a_wrong_hint_still_finds_the_token() {
        let endpoint = portal();

        revoke(
            &endpoint,
            basic_proof(&endpoint.client),
            TEST_REFRESH_TOKEN,
            TypeHint::AccessToken,
        )
        .unwrap();

        assert!(matches!(
            endpoint.refresh.state_of(&hash_of(TEST_REFRESH_TOKEN)),
            Some(RefreshState::Revoked { .. })
        ));
    }

    /// Revoking another client's access token returns success while leaving
    /// the token unrevoked and recording no event.
    #[test]
    fn another_clients_token_is_left_alone() {
        let endpoint = portal();
        let mallorys = stored_client("Mallory's", &[GrantType::AuthorizationCode]);
        block_on(endpoint.clients.save(&test_ctx().tenant(), &mallorys)).unwrap();

        let result = revoke(
            &endpoint,
            basic_proof(&mallorys),
            TEST_ACCESS_TOKEN,
            TypeHint::NotGiven,
        );

        assert!(result.is_ok());
        assert!(!access_is_revoked(&endpoint));
        assert!(endpoint.recorded().is_empty());
    }

    /// A token nobody issued is revoked. The answer is the same.
    #[test]
    fn an_unknown_token_is_answered_alike() {
        let endpoint = portal();

        let result = revoke(
            &endpoint,
            basic_proof(&endpoint.client),
            "never-issued",
            TypeHint::NotGiven,
        );

        assert!(result.is_ok());
    }

    /// A guessed client secret cannot authorize revocation. The request is
    /// refused and the access token remains unrevoked.
    #[test]
    fn an_unproved_client_is_refused() {
        let endpoint = portal();

        let result = revoke(
            &endpoint,
            ClientProof::BasicSecret {
                client_id: endpoint.client.client_id_value().clone(),
                secret: Secret::new("guess"),
            },
            TEST_ACCESS_TOKEN,
            TypeHint::NotGiven,
        );

        assert!(matches!(result, Err(TokenError::Refused { .. })));
        assert!(!access_is_revoked(&endpoint));
    }
}
