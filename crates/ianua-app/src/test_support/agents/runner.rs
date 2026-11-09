//! The runner's ports, in memory: a key that is held or refused, tokens
//! counted as they are exchanged, and proofs that say what they name.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::agents::authority::capability::TokenBinding;
use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::KeyId;

use crate::ports::agents::{
    ProofRequest, RunnerKey, RunnerKeys, RunnerProofs, RunnerTokens, TaskToken,
};
use crate::test_support::Fake;

/// The runner's key: one that is held, or an attestation the platform
/// refused.
pub struct FakeRunnerKeys {
    held: Option<RunnerKey>,
}

impl FakeRunnerKeys {
    /// A runner holding the key `k1`.
    ///
    /// # Panics
    ///
    /// Never: `k1` is a valid key id.
    #[must_use]
    pub fn holding() -> Self {
        Self {
            held: Some(RunnerKey {
                kid: KeyId::new("k1").expect("a valid key id"),
                algorithm: SigningAlgorithm::EdDsa,
                private_key: Secret::new("not a key"),
            }),
        }
    }

    /// A runner whose attestation the platform refuses.
    #[must_use]
    pub fn refusing() -> Self {
        Self { held: None }
    }
}

#[async_trait]
impl RunnerKeys for FakeRunnerKeys {
    async fn current(&self) -> Result<RunnerKey, DomainError> {
        self.held
            .clone()
            .ok_or_else(|| DomainError::unauthorized("the attestation was refused"))
    }
}

/// Task tokens kept by binding, as `token-<binding>`, each exchanged once
/// until it is forgotten. Remembers every binding asked for and counts the
/// exchanges.
#[derive(Default)]
pub struct FakeRunnerTokens {
    held: Mutex<HashMap<TokenBindingKey, TaskToken>>,
    asked: Mutex<Vec<TokenBinding>>,
    exchanges: Mutex<usize>,
}

/// A binding as a map key.
type TokenBindingKey = &'static str;

/// The name a fake token carries for `binding`.
fn named(binding: TokenBinding) -> TokenBindingKey {
    match binding {
        TokenBinding::Bearer => "bearer",
        TokenBinding::ProofOfPossession => "proof_of_possession",
    }
}

impl FakeRunnerTokens {
    /// Every binding a token was asked for, in order.
    #[must_use]
    pub fn asked(&self) -> Vec<TokenBinding> {
        self.asked.lock().unwrap().clone()
    }

    /// How many tokens were exchanged.
    #[must_use]
    pub fn exchanges(&self) -> usize {
        *self.exchanges.lock().unwrap()
    }
}

#[async_trait]
impl RunnerTokens for FakeRunnerTokens {
    async fn current(
        &self,
        _key: &RunnerKey,
        binding: TokenBinding,
    ) -> Result<TaskToken, DomainError> {
        self.asked.lock().unwrap().push(binding);
        let mut held = self.held.lock().unwrap();
        let token = held.entry(named(binding)).or_insert_with(|| {
            *self.exchanges.lock().unwrap() += 1;
            TaskToken::new(format!("token-{}", named(binding)))
        });
        Ok(token.clone())
    }

    async fn forget(&self, binding: TokenBinding) {
        self.held.lock().unwrap().remove(named(binding));
    }
}

/// Proofs that read `<method> <target>`, each remembered.
#[derive(Default)]
pub struct FakeRunnerProofs {
    made: Mutex<Vec<String>>,
}

impl FakeRunnerProofs {
    /// What each proof made named, in order.
    #[must_use]
    pub fn made(&self) -> Vec<String> {
        self.made.lock().unwrap().clone()
    }
}

impl RunnerProofs for FakeRunnerProofs {
    fn proof(&self, _key: &RunnerKey, request: &ProofRequest<'_>) -> Result<Secret, DomainError> {
        let named = format!("{} {}", request.method.as_str(), request.target);
        self.made.lock().unwrap().push(named.clone());
        Ok(Secret::new(named))
    }
}

impl Fake for Arc<dyn RunnerKeys> {
    fn fake() -> Self {
        Arc::new(FakeRunnerKeys::holding())
    }
}

impl Fake for Arc<dyn RunnerTokens> {
    fn fake() -> Self {
        Arc::new(FakeRunnerTokens::default())
    }
}

impl Fake for Arc<dyn RunnerProofs> {
    fn fake() -> Self {
        Arc::new(FakeRunnerProofs::default())
    }
}
