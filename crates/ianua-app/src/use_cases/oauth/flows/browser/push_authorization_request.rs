//! Pushed authorization requests (RFC 9126): a client proves itself and
//! sends its authorization request straight to the server, then sends the
//! browser on with only the `request_uri` it got back.
//!
//! The parameters never pass through the browser, so nobody changes the
//! scopes or the redirect on the way.

use std::sync::Arc;

use ianua_domain::domains::oauth::grants::pushed_request::{
    PushedParameters, PushedRequest, RequestUri,
};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, Issuer, PushedRequestId};
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::OrInternal;
use crate::ports::oauth::PushedRequestStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::oauth::token::client_auth::{
    Asking, ClientAuthPorts, ClientProof, authenticated_client,
};
use crate::use_cases::oauth::token::refusal::TokenError;

/// What a client pushes.
pub struct PushRequest {
    /// How the client proves itself.
    pub client: ClientProof,
    /// The tenant's issuer.
    pub issuer: Issuer,
    /// The authorization request's parameters.
    pub parameters: PushedParameters,
}

/// The `request_uri` a pushed request is named by.
pub struct PushedRequestResult {
    /// The `request_uri` the browser is sent on with.
    pub request_uri: RequestUri,
    /// When it stops being usable: sixty seconds from now.
    pub expires_at: OffsetDateTime,
}

/// The ports [`PushAuthorizationRequestUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PushAuthorizationRequestPorts {
    /// How the client proves itself.
    pub client_auth: ClientAuthPorts,
    /// Where pushed requests are kept.
    pub pushed_store: Arc<dyn PushedRequestStore>,
}

/// Takes a client's pushed authorization request.
pub struct PushAuthorizationRequestUseCase {
    ports: PushAuthorizationRequestPorts,
}

impl PushAuthorizationRequestUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: PushAuthorizationRequestPorts) -> Self {
        Self { ports }
    }
}

impl Command for PushAuthorizationRequestUseCase {
    type Caller = ScopedTenant;
    type Input = PushRequest;
    type Output = Result<PushedRequestResult, TokenError>;

    /// Takes the request `req` pushes in `tenant`, once it passes the
    /// screen a browser's would, names it by a fresh `request_uri`, and
    /// records `oauth.authorization_request_pushed` with the client as
    /// actor.
    ///
    /// # Errors
    ///
    /// - `invalid_client` when the client does not prove itself.
    /// - `invalid_request`, `unauthorized_client`,
    ///   `unsupported_response_type` or `invalid_scope` when the request
    ///   would not pass the screen; a redirect the client did not register
    ///   is `invalid_request`, since the client proved itself.
    /// - `TokenError::Failed` when the request cannot be kept or recorded.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        req: PushRequest,
    ) -> Result<PushedRequestResult, TokenError> {
        let asking = Asking {
            tenant,
            issuer: &req.issuer,
        };
        let client = authenticated_client(&self.ports.client_auth, asking, &req.client).await?;
        let mut pushed = PushedRequest::push(PushedRequestId::new(), &client, req.parameters)?;
        self.ports
            .pushed_store
            .insert(tenant, &pushed)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(
                &ActorRef::OAuthClient(*client.id()),
                pushed.take_events(tenant),
            )
            .await
            .or_internal()?;
        Ok(PushedRequestResult {
            request_uri: pushed.request_uri(),
            expires_at: pushed.expires_at(),
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::oauth::clients::client::GrantType;
    use ianua_domain::domains::oauth::grants::authorization_code::{CodeChallenge, NonceSent};
    use ianua_domain::domains::oauth::grants::authorization_request::{
        AskedFlow, AskedPrompts, AskedRequest, AskedScopes, MaxAge, RequestedAcr, ResponseMode,
    };
    use ianua_domain::domains::oauth::grants::pushed_request::StateSent;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{RedirectUri, Scope};

    use super::*;
    use crate::test_support::oauth::{
        FakePushedRequestStore, TEST_CLIENT_SECRET, TEST_REDIRECT, TEST_VERIFIER, TokenEndpoint,
        stored_client, test_issuer,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::oauth::token::refusal::OAuthErrorCode;

    /// A code request for `scope`, answered at `redirect`.
    fn parameters(redirect: &str, scope: &str) -> PushedParameters {
        PushedParameters {
            redirect_uri: RedirectUri::new(redirect).unwrap(),
            asked: AskedRequest {
                flow: AskedFlow::CodeWithS256Challenge,
                scopes: AskedScopes::Named(vec![Scope::new(scope).unwrap()]),
                prompts: AskedPrompts::Named(Vec::new()),
                response_mode: ResponseMode::Query,
            },
            max_age: MaxAge::Any,
            acr: RequestedAcr::Any,
            code_challenge: CodeChallenge::new(TEST_VERIFIER).unwrap(),
            nonce: NonceSent::NotSent,
            state: StateSent::NotSent,
        }
    }

    /// What `client` pushing `parameters` answers, kept in `store`.
    fn push(
        endpoint: &TokenEndpoint,
        store: &Arc<FakePushedRequestStore>,
        client: ClientProof,
        parameters: PushedParameters,
    ) -> Result<PushedRequestResult, TokenError> {
        push_recorded(endpoint, store, client, parameters).0
    }

    /// What `client` pushing `parameters` answers, kept in `store`, with
    /// the events it recorded.
    fn push_recorded(
        endpoint: &TokenEndpoint,
        store: &Arc<FakePushedRequestStore>,
        client: ClientProof,
        parameters: PushedParameters,
    ) -> (Result<PushedRequestResult, TokenError>, Vec<String>) {
        let use_case = PushAuthorizationRequestUseCase::new(PushAuthorizationRequestPorts {
            client_auth: endpoint.client_auth(),
            pushed_store: store.clone(),
        });
        let req = PushRequest {
            client,
            issuer: test_issuer(),
            parameters,
        };
        let dispatcher = Arc::new(FakeEventDispatcher::new());
        let auditor = test_auditor(dispatcher.clone());
        let result = block_on(use_case.execute(&test_ctx().tenant(), &auditor, req));
        let recorded = dispatcher.records.lock().unwrap().clone();
        (result, recorded)
    }

    /// The portal's real secret.
    fn portal_secret() -> Secret {
        Secret::new(TEST_CLIENT_SECRET)
    }

    /// The endpoint serving the portal.
    fn portal() -> TokenEndpoint {
        TokenEndpoint::serving(stored_client("Portal", &[GrantType::AuthorizationCode]))
    }

    /// The endpoint's client proving itself with `secret`.
    fn proof(endpoint: &TokenEndpoint, secret: Secret) -> ClientProof {
        ClientProof::BasicSecret {
            client_id: endpoint.client.client_id_value().clone(),
            secret,
        }
    }

    /// The portal pushes a proper request. It gets a `request_uri`, good for
    /// sixty seconds, and the request is kept, unused.
    #[test]
    fn a_proper_request_is_pushed() {
        let endpoint = portal();
        let store = Arc::new(FakePushedRequestStore::empty());

        let pushed = push(
            &endpoint,
            &store,
            proof(&endpoint, portal_secret()),
            parameters(TEST_REDIRECT, "read"),
        )
        .unwrap();

        assert_eq!(store.count(), 1);
        assert!(!store.is_used(pushed.request_uri.id()));
    }

    /// The portal pushes a proper request. The push is recorded; a refused
    /// one records nothing.
    #[test]
    fn a_pushed_request_is_recorded() {
        let endpoint = portal();
        let store = Arc::new(FakePushedRequestStore::empty());

        let (_, kept) = push_recorded(
            &endpoint,
            &store,
            proof(&endpoint, portal_secret()),
            parameters(TEST_REDIRECT, "read"),
        );
        let (_, refused) = push_recorded(
            &endpoint,
            &store,
            proof(&endpoint, portal_secret()),
            parameters(TEST_REDIRECT, "admin"),
        );

        assert_eq!(kept, ["oauth.authorization_request_pushed"]);
        assert!(refused.is_empty());
    }

    /// An authenticated client pushing an unregistered redirect receives
    /// invalid_request, and no pushed request is stored.
    #[test]
    fn an_unregistered_redirect_is_refused() {
        let endpoint = portal();
        let store = Arc::new(FakePushedRequestStore::empty());

        let result = push(
            &endpoint,
            &store,
            proof(&endpoint, portal_secret()),
            parameters("https://evil.example/callback", "read"),
        );

        assert_eq!(
            result.err().and_then(|refusal| refusal.code()),
            Some(OAuthErrorCode::InvalidRequest)
        );
        assert_eq!(store.count(), 0);
    }

    /// Pushing an ungranted scope returns invalid_scope to the client.
    #[test]
    fn a_scope_the_client_was_not_given_is_refused() {
        let endpoint = portal();
        let store = Arc::new(FakePushedRequestStore::empty());

        let result = push(
            &endpoint,
            &store,
            proof(&endpoint, portal_secret()),
            parameters(TEST_REDIRECT, "admin"),
        );

        assert_eq!(
            result.err().and_then(|refusal| refusal.code()),
            Some(OAuthErrorCode::InvalidScope)
        );
    }

    /// Pushing with a wrong client secret returns invalid_client and stores
    /// no request.
    #[test]
    fn an_unproved_client_is_refused() {
        let endpoint = portal();
        let store = Arc::new(FakePushedRequestStore::empty());

        let result = push(
            &endpoint,
            &store,
            proof(&endpoint, Secret::new("guess")),
            parameters(TEST_REDIRECT, "read"),
        );

        assert_eq!(
            result.err().and_then(|refusal| refusal.code()),
            Some(OAuthErrorCode::InvalidClient)
        );
        assert_eq!(store.count(), 0);
    }
}
