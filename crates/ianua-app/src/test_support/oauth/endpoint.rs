//! The token endpoint as a test sets it up: one client, one person, and
//! the stores and signer everything it hands out goes through.

use std::sync::Arc;

use ianua_domain::domains::oauth::clients::client::OAuthClient;
use ianua_domain::domains::oauth::clients::lifetimes::{RefreshLifetimes, TokenTerms};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Issuer, Lifetime, UserId};

use crate::test_support::authentication::FakeSessionStore;
use crate::test_support::crypto::{FakeJwtSigner, FakeSigningKeyStore, premigration_keys};
use crate::test_support::identity::FakeUserStore;
use crate::test_support::oauth::{
    FakeAccessTokenStore, FakeOAuthClientStore, FakeRefreshTokenStore, TEST_CLIENT_SECRET,
    TEST_DPOP_URL, signed_in_session,
};
use crate::test_support::{Fake, FakeEventDispatcher, test_ctx, test_session_id};
use crate::use_cases::oauth::flows::{ResolveAccessTokenPorts, ResolveAccessTokenUseCase};
use crate::use_cases::oauth::presented::PresentedTokenPorts;
use crate::use_cases::oauth::sender::{DpopHeader, SenderEvidence};
use crate::use_cases::oauth::token::client_auth::{ClientAuthPorts, ClientProof};
use crate::use_cases::oauth::token::issuing::IssuingPorts;
use crate::use_cases::oauth::token::refusal::{OAuthErrorCode, TokenError};

/// The issuer every token endpoint test serves.
pub const TEST_ISSUER: &str = "https://auth.acme.example";

/// The issuer every token endpoint test serves, as its type.
#[must_use]
pub fn test_issuer() -> Issuer {
    Issuer::new(TEST_ISSUER).expect("a valid issuer")
}

/// The platform's token terms in tests: access tokens for an hour, ID
/// tokens for five minutes, refresh tokens idle for a day in a family of
/// thirty.
#[must_use]
pub fn test_terms() -> TokenTerms {
    let seconds = |count| Lifetime::seconds(count).expect("a valid lifetime");
    let refresh =
        RefreshLifetimes::new(seconds(86_400), seconds(30 * 86_400)).expect("a day within thirty");
    TokenTerms::new(seconds(3600), seconds(300), refresh).expect("terms within a day")
}

/// `client` proving itself with [`TEST_CLIENT_SECRET`] in the
/// `Authorization` header.
#[must_use]
pub fn basic_proof(client: &OAuthClient<ResolvedTenant>) -> ClientProof {
    ClientProof::BasicSecret {
        client_id: client.client_id_value().clone(),
        secret: Secret::new(TEST_CLIENT_SECRET.to_owned()),
    }
}

/// The stores, signer and records behind a token endpoint serving one
/// client and one person, Ann, signed in to the test session.
pub struct TokenEndpoint {
    /// The person whose test session authorizes token issuance.
    pub ann: UserId,
    /// The registered application exercising this endpoint.
    pub client: OAuthClient<ResolvedTenant>,
    /// Where clients are kept; the client is.
    pub clients: Arc<FakeOAuthClientStore>,
    /// Where access tokens are kept.
    pub tokens: Arc<FakeAccessTokenStore>,
    /// Where refresh tokens are kept.
    pub refresh: Arc<FakeRefreshTokenStore>,
    /// Where accounts are kept; Ann's is.
    pub users: Arc<FakeUserStore>,
    /// Where sessions are kept; Ann's test session is.
    pub sessions: Arc<FakeSessionStore>,
    /// Where signing keys are kept; the tenant has one.
    pub keys: Arc<FakeSigningKeyStore>,
    /// The signer, which keeps what it signed.
    pub signer: Arc<FakeJwtSigner>,
    /// Where audit records go.
    pub audit: Arc<FakeEventDispatcher>,
}

impl TokenEndpoint {
    /// A token endpoint serving `client`, kept in the test tenant.
    #[must_use]
    pub fn serving(client: OAuthClient<ResolvedTenant>) -> Self {
        let ann = UserId::new();
        let tenant = test_ctx().tenant();
        Self {
            ann,
            clients: Arc::new(FakeOAuthClientStore::holding(&tenant, client.clone())),
            client,
            tokens: Arc::new(FakeAccessTokenStore::empty()),
            refresh: Arc::new(FakeRefreshTokenStore::empty()),
            users: Arc::new(FakeUserStore::with_user(ann, "ann@acme.example")),
            sessions: Arc::new(FakeSessionStore::with_session(signed_in_session(
                test_session_id(),
                ann,
            ))),
            keys: Arc::new(FakeSigningKeyStore::holding(premigration_keys())),
            signer: Arc::new(FakeJwtSigner::default()),
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    /// The client proving itself through this endpoint's stores.
    #[must_use]
    pub fn client_auth(&self) -> ClientAuthPorts {
        ClientAuthPorts {
            client_store: self.clients.clone(),
            ..ClientAuthPorts::fakes()
        }
    }

    /// Tokens made and kept through this endpoint's stores and signer.
    #[must_use]
    pub fn issuing(&self) -> IssuingPorts {
        IssuingPorts {
            access_token_store: self.tokens.clone(),
            refresh_token_store: self.refresh.clone(),
            key_store: self.keys.clone(),
            jwt_signer: self.signer.clone(),
            users: self.users.clone(),
            ..IssuingPorts::fakes()
        }
    }

    /// Presented access tokens found through this endpoint's stores.
    #[must_use]
    pub fn presented(&self) -> PresentedTokenPorts {
        PresentedTokenPorts {
            access_token_store: self.tokens.clone(),
            key_store: self.keys.clone(),
            ..PresentedTokenPorts::fakes()
        }
    }

    /// Access tokens resolved through this endpoint's stores, with no
    /// `DPoP` proof checking out.
    #[must_use]
    pub fn resolver(&self) -> Arc<ResolveAccessTokenUseCase> {
        Arc::new(ResolveAccessTokenUseCase::new(ResolveAccessTokenPorts {
            presented: self.presented(),
            client_store: self.clients.clone(),
            user_store: self.users.clone(),
            ..ResolveAccessTokenPorts::fakes()
        }))
    }

    /// The audit records written, by event name, in order.
    #[must_use]
    pub fn recorded(&self) -> Vec<String> {
        self.audit.records.lock().unwrap().clone()
    }

    /// The claim sets the signer was asked to sign, in order.
    #[must_use]
    pub fn signed_claims(&self) -> Vec<String> {
        self.signer.signed.lock().unwrap().clone()
    }
}

/// A request that carried nothing to prove its holder.
#[must_use]
pub fn no_proof() -> SenderEvidence {
    SenderEvidence::nothing("POST", TEST_DPOP_URL)
}

/// A request carrying a `DPoP` proof, which the endpoint's verifier reads.
#[must_use]
pub fn dpop_sent() -> SenderEvidence {
    SenderEvidence {
        dpop: DpopHeader::Sent(Secret::new("a.dpop.proof")),
        ..no_proof()
    }
}

/// The error code `result` was refused with, if it was refused.
#[must_use]
pub fn refused_with<T>(result: &Result<T, TokenError>) -> Option<OAuthErrorCode> {
    result.as_ref().err().and_then(TokenError::code)
}

impl Fake for Arc<ResolveAccessTokenUseCase> {
    fn fake() -> Self {
        Arc::new(ResolveAccessTokenUseCase::new(
            ResolveAccessTokenPorts::fakes(),
        ))
    }
}
