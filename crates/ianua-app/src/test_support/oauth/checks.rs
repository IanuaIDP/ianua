//! Fakes for what the signer's side checks or works out about OAuth JWTs,
//! the `DPoP` proofs clients send, and for telling an app's server of a
//! sign-out.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::crypto::signing_key::{SigningAlgorithm, SigningKeySet};
use ianua_domain::domains::crypto::verifying_key::VerifyingKey;
use ianua_domain::domains::oauth::clients::credential::ClientKeys;
use ianua_domain::domains::oauth::grants::id_token::AccessTokenHash;
use ianua_domain::domains::oauth::grants::token_binding::JwkThumbprint;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ClientId, HttpsUrl, Issuer, OAuthClientId, TenantId, TokenId};
use time::{Duration, OffsetDateTime};

use crate::ports::TenantScoped;
use crate::ports::oauth::{
    AccessTokenJwtVerifier, AssertionReplayGuard, AtHashCalculator, BackChannelLogoutSender,
    ClientAssertionVerifier, DpopProofVerifier, DpopReplayGuard, DpopUse, HintClaims,
    IdTokenHintVerifier, PresentedJwt, SignedDpopProof, VerifiedAssertion,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;

/// What every fake signer prefixes a signed client assertion with.
const SIGNED_ASSERTION: &str = "signed-assertion.";

/// A client assertion the fake verifier accepts as signed by `client`, with
/// the `jti` `jti`.
#[must_use]
pub fn signed_assertion(client: &ClientId, jti: &str) -> Secret {
    Secret::new(format!("{SIGNED_ASSERTION}{}.{jti}", client.as_str()))
}

/// Client assertion verifier that accepts what [`signed_assertion`] makes,
/// whatever keys the client registered, and refuses anything else.
pub struct FakeClientAssertionVerifier;

#[async_trait]
impl ClientAssertionVerifier for FakeClientAssertionVerifier {
    async fn verify(
        &self,
        assertion: &Secret,
        _keys: &ClientKeys,
        _issuer: &Issuer,
    ) -> Result<VerifiedAssertion, DomainError> {
        let refused = || DomainError::unauthorized("the client assertion does not check out");
        let signed = assertion
            .expose()
            .strip_prefix(SIGNED_ASSERTION)
            .ok_or_else(refused)?;
        let (client, jti) = signed.split_once('.').ok_or_else(refused)?;
        Ok(VerifiedAssertion {
            client: ClientId::new(client)?,
            jti: TokenId::new(jti)?,
            expires_at: clock::now() + Duration::minutes(1),
        })
    }
}

impl Fake for Arc<dyn ClientAssertionVerifier> {
    fn fake() -> Self {
        Arc::new(FakeClientAssertionVerifier)
    }
}

/// In-memory record of the client assertions already used.
#[derive(Default)]
pub struct FakeAssertionReplayGuard {
    used: Mutex<Vec<(TenantId, OAuthClientId, TokenId)>>,
}

impl TenantScoped for FakeAssertionReplayGuard {}

#[async_trait]
impl AssertionReplayGuard for FakeAssertionReplayGuard {
    async fn first_use(
        &self,
        tenant_id: &ScopedTenant,
        client: &OAuthClientId,
        jti: &TokenId,
        _until: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let mut used = self.used.lock().unwrap();
        let entry = (**tenant_id, *client, jti.clone());
        if used.contains(&entry) {
            return Ok(false);
        }
        used.push(entry);
        Ok(true)
    }
}

impl Fake for Arc<dyn AssertionReplayGuard> {
    fn fake() -> Self {
        Arc::new(FakeAssertionReplayGuard::default())
    }
}

/// The address the test `DPoP` proofs are made for.
pub const TEST_DPOP_URL: &str = "https://auth.acme.com/oauth/token";

/// `DPoP` proof verifier answering what a test says for every proof.
pub struct FakeDpopVerifier {
    answer: Option<SignedDpopProof>,
}

impl FakeDpopVerifier {
    /// A verifier reading `proof` from every proof sent.
    #[must_use]
    pub fn accepting(proof: SignedDpopProof) -> Self {
        Self {
            answer: Some(proof),
        }
    }

    /// A verifier refusing every proof, as one whose signature does not
    /// hold.
    #[must_use]
    pub fn refusing() -> Self {
        Self { answer: None }
    }
}

#[async_trait]
impl DpopProofVerifier for FakeDpopVerifier {
    async fn verify(
        &self,
        _proof: &Secret,
        _sent_for: DpopUse<'_>,
    ) -> Result<SignedDpopProof, DomainError> {
        self.answer
            .clone()
            .ok_or_else(|| DomainError::unauthorized("the DPoP proof does not check out"))
    }
}

impl Fake for Arc<dyn DpopProofVerifier> {
    fn fake() -> Self {
        Arc::new(FakeDpopVerifier::refusing())
    }
}

/// In-memory record of the `DPoP` proofs already used.
#[derive(Default)]
pub struct FakeDpopReplayGuard {
    used: Mutex<Vec<(TenantId, JwkThumbprint, TokenId)>>,
}

impl TenantScoped for FakeDpopReplayGuard {}

#[async_trait]
impl DpopReplayGuard for FakeDpopReplayGuard {
    async fn first_use(
        &self,
        tenant_id: &ScopedTenant,
        thumbprint: &JwkThumbprint,
        jti: &TokenId,
        _until: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let mut used = self.used.lock().unwrap();
        let entry = (**tenant_id, thumbprint.clone(), jti.clone());
        if used.contains(&entry) {
            return Ok(false);
        }
        used.push(entry);
        Ok(true)
    }
}

impl Fake for Arc<dyn DpopReplayGuard> {
    fn fake() -> Self {
        Arc::new(FakeDpopReplayGuard::default())
    }
}

/// The `at_hash` every fake works out: the same for every token.
pub const TEST_AT_HASH: &str = "fake-at-hash";

/// `at_hash` calculator answering [`TEST_AT_HASH`] for every token.
pub struct FakeAtHashCalculator;

#[async_trait]
impl AtHashCalculator for FakeAtHashCalculator {
    async fn at_hash(
        &self,
        _access_token: &Secret,
        _algorithm: SigningAlgorithm,
    ) -> Result<AccessTokenHash, DomainError> {
        Ok(AccessTokenHash::new(TEST_AT_HASH)?)
    }
}

impl Fake for Arc<dyn AtHashCalculator> {
    fn fake() -> Self {
        Arc::new(FakeAtHashCalculator)
    }
}

/// `id_token_hint` verifier answering what a test says for every hint.
pub struct FakeIdTokenHintVerifier {
    answer: Option<HintClaims>,
}

impl FakeIdTokenHintVerifier {
    /// A verifier reading `claims` from every hint.
    #[must_use]
    pub fn reading(claims: HintClaims) -> Self {
        Self {
            answer: Some(claims),
        }
    }

    /// A verifier refusing every hint, as one the tenant never signed.
    #[must_use]
    pub fn refusing() -> Self {
        Self { answer: None }
    }
}

#[async_trait]
impl IdTokenHintVerifier for FakeIdTokenHintVerifier {
    async fn verify(
        &self,
        _hint: &Secret,
        _keys: &SigningKeySet<ResolvedTenant>,
        _issuer: &Issuer,
    ) -> Result<HintClaims, DomainError> {
        self.answer
            .clone()
            .ok_or_else(|| DomainError::unauthorized("the tenant did not sign this hint"))
    }
}

impl Fake for Arc<dyn IdTokenHintVerifier> {
    fn fake() -> Self {
        Arc::new(FakeIdTokenHintVerifier::refusing())
    }
}

/// JWT access token verifier that knows what the fake JWT signer makes:
/// `header.{claims}.sig_{kid}`. Such a token is signed, found by its
/// claims' `jti`; anything else is opaque.
pub struct FakeAccessTokenJwtVerifier;

#[async_trait]
impl AccessTokenJwtVerifier for FakeAccessTokenJwtVerifier {
    async fn classify(
        &self,
        token: &Secret,
        _keys: &[VerifyingKey],
        _issuer: &Issuer,
    ) -> Result<PresentedJwt, DomainError> {
        let Some(signed) = token.expose().strip_prefix("header.") else {
            return Ok(PresentedJwt::Opaque);
        };
        let Some((claims, _)) = signed.rsplit_once(".sig_") else {
            return Ok(PresentedJwt::Refused);
        };
        let jti = serde_json::from_str::<serde_json::Value>(claims)
            .ok()
            .and_then(|claims| {
                claims
                    .get("jti")
                    .and_then(|jti| jti.as_str())
                    .map(str::to_owned)
            });
        let Some(jti) = jti else {
            return Ok(PresentedJwt::Refused);
        };
        Ok(PresentedJwt::Signed(TokenId::new(jti)?))
    }
}

impl Fake for Arc<dyn AccessTokenJwtVerifier> {
    fn fake() -> Self {
        Arc::new(FakeAccessTokenJwtVerifier)
    }
}

/// Back-channel logout sender that records each delivery, or fails each.
#[derive(Default)]
pub struct FakeBackChannelLogoutSender {
    /// Each address a logout token was posted to, with the token, in order.
    pub delivered: Mutex<Vec<(String, String)>>,
    failing: bool,
}

impl FakeBackChannelLogoutSender {
    /// A sender whose every app answers.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A sender whose every app is unreachable.
    #[must_use]
    pub fn failing() -> Self {
        Self {
            failing: true,
            ..Self::default()
        }
    }
}

#[async_trait]
impl BackChannelLogoutSender for FakeBackChannelLogoutSender {
    async fn deliver(&self, uri: &HttpsUrl, logout_token: &Secret) -> Result<(), DomainError> {
        if self.failing {
            return Err(DomainError::infra_msg("the app's server did not answer"));
        }
        self.delivered
            .lock()
            .unwrap()
            .push((uri.as_str().to_owned(), logout_token.expose().to_owned()));
        Ok(())
    }
}

impl Fake for Arc<dyn BackChannelLogoutSender> {
    fn fake() -> Self {
        Arc::new(FakeBackChannelLogoutSender::new())
    }
}
