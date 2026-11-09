//! Forget: drop the token a destination refused, so the next request from
//! the agent is sent with a new one.
//!
//! A token stops being taken before its end when a person revokes the
//! delegation behind it or the agent's key rotates. The runner hears that
//! as the destination refusing the token, and exchanges anew rather than
//! keep sending one that no longer counts. Nothing is recorded here.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::capability::TokenBinding;

use crate::ports::agents::RunnerTokens;
use crate::use_case::Query;

/// The ports [`ForgetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ForgetPorts {
    /// The task tokens the runner holds.
    pub tokens: Arc<dyn RunnerTokens>,
}

/// Drops refused task tokens.
pub struct ForgetUseCase {
    ports: ForgetPorts,
}

impl ForgetUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ForgetPorts) -> Self {
        Self { ports }
    }
}

impl Query for ForgetUseCase {
    type Caller = ();
    type Input = TokenBinding;
    type Output = ();

    /// Drops the held token of `binding`.
    async fn execute(&self, _caller: &(), binding: TokenBinding) {
        self.ports.tokens.forget(binding).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::agents::RunnerKeys;
    use crate::test_support::agents::{FakeRunnerKeys, FakeRunnerTokens};
    use crate::test_support::block_on;

    /// The gateway refused the bound token after Ann revoked the
    /// delegation. Once forgotten, the next request exchanges a new one,
    /// and the relay's bearer token is kept.
    #[test]
    fn a_forgotten_token_is_exchanged_again() {
        let tokens = Arc::new(FakeRunnerTokens::default());
        let key = block_on(FakeRunnerKeys::holding().current()).unwrap();
        block_on(tokens.current(&key, TokenBinding::ProofOfPossession)).unwrap();
        block_on(tokens.current(&key, TokenBinding::Bearer)).unwrap();
        let use_case = ForgetUseCase::new(ForgetPorts {
            tokens: tokens.clone(),
        });

        block_on(use_case.execute(&(), TokenBinding::ProofOfPossession));
        block_on(tokens.current(&key, TokenBinding::ProofOfPossession)).unwrap();
        block_on(tokens.current(&key, TokenBinding::Bearer)).unwrap();

        assert_eq!(tokens.exchanges(), 3);
    }
}
