//! Fakes that make and check OAuth codes and secrets. Every fake hashes the
//! same way, [`hash_of`], so a hash one makes is one the others recognise.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::oauth::grants::authorization_code::{
    CodeChallenge, CodeChallengeMethod,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{DeviceUserCode, TokenHash};

use crate::ports::oauth::{CodeHasher, PkceVerifier};
use crate::test_support::Fake;

/// The hash every OAuth fake keeps for the raw value `raw`.
#[must_use]
pub fn hash_of(raw: &str) -> TokenHash {
    TokenHash::from_stored(format!("hash:{raw}"))
}

/// Code hasher that counts the codes it makes: `code_1`, `device_2`,
/// `ABCD-0003`, each hashed with [`hash_of`].
#[derive(Default)]
pub struct FakeCodeHasher {
    made: Mutex<u32>,
}

impl FakeCodeHasher {
    /// A hasher that has made no code yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn next(&self) -> u32 {
        let mut made = self.made.lock().unwrap();
        *made += 1;
        *made
    }

    fn raw_and_hash(&self, kind: &str) -> (Secret, TokenHash) {
        let raw = format!("{kind}_{}", self.next());
        let hash = hash_of(&raw);
        (Secret::new(raw), hash)
    }
}

#[async_trait]
impl CodeHasher for FakeCodeHasher {
    async fn hash_code(&self, raw_code: &Secret) -> Result<TokenHash, DomainError> {
        Ok(hash_of(raw_code.expose()))
    }

    async fn generate_code(&self) -> Result<(Secret, TokenHash), DomainError> {
        Ok(self.raw_and_hash("code"))
    }

    async fn generate_user_code(&self) -> Result<DeviceUserCode, DomainError> {
        Ok(DeviceUserCode::new(format!("ABCD-{:04}", self.next()))?)
    }

    async fn generate_device_code(&self) -> Result<(Secret, TokenHash), DomainError> {
        Ok(self.raw_and_hash("device"))
    }
}

impl Fake for Arc<dyn CodeHasher> {
    fn fake() -> Self {
        Arc::new(FakeCodeHasher::new())
    }
}

/// PKCE verifier whose challenge is the verifier's own text: a code made
/// with challenge `c` is redeemed by sending `c` as the verifier.
pub struct FakePkceVerifier;

#[async_trait]
impl PkceVerifier for FakePkceVerifier {
    async fn challenge_for(
        &self,
        verifier: &Secret,
        _method: CodeChallengeMethod,
    ) -> Result<CodeChallenge, DomainError> {
        Ok(CodeChallenge::new(verifier.expose())?)
    }
}

/// PKCE verifier that finds every verifier malformed.
pub struct RejectingPkceVerifier;

#[async_trait]
impl PkceVerifier for RejectingPkceVerifier {
    async fn challenge_for(
        &self,
        _verifier: &Secret,
        _method: CodeChallengeMethod,
    ) -> Result<CodeChallenge, DomainError> {
        Err(DomainError::invalid("the code verifier is malformed"))
    }
}

impl Fake for Arc<dyn PkceVerifier> {
    fn fake() -> Self {
        Arc::new(FakePkceVerifier)
    }
}
