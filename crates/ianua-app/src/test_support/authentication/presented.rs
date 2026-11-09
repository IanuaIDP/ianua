//! Fakes for reading what a request presents at the gateway: the tenant's
//! tokens, consumers' tokens and consumers' API keys, and the check that
//! reads them.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Audience, HttpsUrl, Issuer, KeyPrefix, TokenHash};

use crate::ports::authentication::{
    AppSessionToken, ClaimedPass, ClaimedToken, ConsumerKeyDigests, ConsumerToken,
    ConsumerTokenVerifier, ExpectedSession, ExpectedToken, PresentedKey, PresentedTokens,
    RunPassToken, TenantToken, TokenFault, TokenReading,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::{Fake, test_ctx};
use crate::use_cases::proxy::credentials::{AuthenticatePorts, AuthenticateUseCase};

/// What a fake reader answers: a reading, or that the keys could not be
/// read.
#[derive(Debug, Clone)]
pub enum FakeAnswer<T> {
    /// This reading.
    Answers(TokenReading<T>),
    /// The keys could not be read.
    Unreachable,
}

impl<T: Clone> FakeAnswer<T> {
    /// The reading, or the error of keys that could not be read.
    fn given(&self) -> Result<TokenReading<T>, DomainError> {
        match self {
            Self::Answers(reading) => Ok(reading.clone()),
            Self::Unreachable => Err(DomainError::infra_msg("the keys could not be read")),
        }
    }
}

/// Reader of the tenant's tokens answering what a test says, refusing
/// every token by default.
///
/// It holds a token to the audience it was minted for, when a test names
/// one, as the real reader does.
pub struct FakePresentedTokens {
    /// What every token claims, unchecked.
    pub claimed: Option<ClaimedToken>,
    /// The answer for a bearer token.
    pub bearer: FakeAnswer<TenantToken>,
    /// The answer for an app session cookie.
    pub session: FakeAnswer<AppSessionToken>,
    /// The audience the tokens were minted for; any when `None`.
    pub minted_for: Option<Audience>,
    /// What every run pass claims, unchecked.
    pub claimed_pass: Option<ClaimedPass>,
    /// The answer for a run pass.
    pub pass: FakeAnswer<RunPassToken>,
}

impl Default for FakePresentedTokens {
    fn default() -> Self {
        Self {
            claimed: None,
            bearer: FakeAnswer::Answers(TokenReading::Refused(TokenFault::Invalid)),
            session: FakeAnswer::Answers(TokenReading::Refused(TokenFault::Invalid)),
            minted_for: None,
            claimed_pass: None,
            pass: FakeAnswer::Answers(TokenReading::Refused(TokenFault::Invalid)),
        }
    }
}

impl FakePresentedTokens {
    /// A reader taking every run pass as `pass`.
    #[must_use]
    pub fn reading_pass(pass: RunPassToken) -> Self {
        Self {
            claimed_pass: Some(ClaimedPass {
                tenant_id: test_ctx().tenant_id(),
                reaches: pass.reaches,
            }),
            pass: FakeAnswer::Answers(TokenReading::Read(pass)),
            ..Self::default()
        }
    }

    /// A reader taking every bearer token as `token`.
    #[must_use]
    pub fn reading_bearer(token: TenantToken) -> Self {
        Self {
            bearer: FakeAnswer::Answers(TokenReading::Read(token)),
            ..Self::default()
        }
    }

    /// A reader taking every app session cookie as `session`.
    #[must_use]
    pub fn reading_session(session: AppSessionToken) -> Self {
        Self {
            session: FakeAnswer::Answers(TokenReading::Read(session)),
            ..Self::default()
        }
    }

    /// A reader refusing every token for `fault`.
    #[must_use]
    pub fn refusing(fault: TokenFault) -> Self {
        Self {
            bearer: FakeAnswer::Answers(TokenReading::Refused(fault)),
            session: FakeAnswer::Answers(TokenReading::Refused(fault)),
            ..Self::default()
        }
    }

    /// A reader whose keys cannot be read.
    #[must_use]
    pub fn unreachable() -> Self {
        Self {
            bearer: FakeAnswer::Unreachable,
            session: FakeAnswer::Unreachable,
            ..Self::default()
        }
    }

    /// The answer for a token asked to name `audience`.
    fn for_audience<T: Clone>(
        &self,
        answer: &FakeAnswer<T>,
        audience: &Audience,
    ) -> Result<TokenReading<T>, DomainError> {
        let named = self
            .minted_for
            .as_ref()
            .is_none_or(|minted| minted == audience);
        if !named {
            return Ok(TokenReading::Refused(TokenFault::WrongAudience));
        }
        answer.given()
    }
}

#[async_trait]
impl PresentedTokens for FakePresentedTokens {
    fn claimed(&self, _: &Secret) -> Option<ClaimedToken> {
        self.claimed.clone()
    }

    async fn read_bearer(
        &self,
        _: &ScopedTenant,
        _: &Secret,
        expected: ExpectedToken<'_>,
    ) -> Result<TokenReading<TenantToken>, DomainError> {
        self.for_audience(&self.bearer, expected.audience)
    }

    async fn read_app_session(
        &self,
        _: &ScopedTenant,
        _: &Secret,
        expected: ExpectedSession<'_>,
    ) -> Result<TokenReading<AppSessionToken>, DomainError> {
        self.for_audience(&self.session, expected.audience)
    }

    fn claimed_pass(&self, _: &Secret) -> Option<ClaimedPass> {
        self.claimed_pass
    }

    async fn read_run_pass(
        &self,
        _: &ScopedTenant,
        _: &Secret,
        _: &Issuer,
    ) -> Result<TokenReading<RunPassToken>, DomainError> {
        self.pass.given()
    }
}

/// Checker of consumers' tokens answering what a test says, refusing every
/// token by default.
pub struct FakeConsumerTokenVerifier(pub FakeAnswer<ConsumerToken>);

impl Default for FakeConsumerTokenVerifier {
    fn default() -> Self {
        Self(FakeAnswer::Answers(TokenReading::Refused(
            TokenFault::Invalid,
        )))
    }
}

#[async_trait]
impl ConsumerTokenVerifier for FakeConsumerTokenVerifier {
    async fn verify(
        &self,
        _: &Secret,
        _: &HttpsUrl,
        _: ExpectedToken<'_>,
    ) -> Result<TokenReading<ConsumerToken>, DomainError> {
        self.0.given()
    }
}

/// Reader of consumer API keys written `prefix.digest`, such as
/// `sk_live_abc.hash123`: a key starting `sk_` reads as that prefix and
/// digest, anything else as no consumer key.
#[derive(Default)]
pub struct FakeConsumerKeyDigests;

impl ConsumerKeyDigests for FakeConsumerKeyDigests {
    fn presented(&self, key: &Secret) -> Option<PresentedKey> {
        let (prefix, digest) = key.expose().split_once('.')?;
        if !prefix.starts_with("sk_") {
            return None;
        }
        Some(PresentedKey {
            prefix: KeyPrefix::new(prefix).ok()?,
            digest: TokenHash::from_stored(digest.to_owned()),
        })
    }
}

impl Fake for Arc<dyn PresentedTokens> {
    fn fake() -> Self {
        Arc::new(FakePresentedTokens::default())
    }
}

impl Fake for Arc<dyn ConsumerTokenVerifier> {
    fn fake() -> Self {
        Arc::new(FakeConsumerTokenVerifier::default())
    }
}

impl Fake for Arc<dyn ConsumerKeyDigests> {
    fn fake() -> Self {
        Arc::new(FakeConsumerKeyDigests)
    }
}

impl Fake for Arc<AuthenticateUseCase> {
    fn fake() -> Self {
        Arc::new(AuthenticateUseCase::new(AuthenticatePorts::fakes()))
    }
}
