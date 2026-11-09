//! A browser asks for the puzzle a sign-in under pressure must solve, on a
//! deployment whose challenge provider is the platform's own.
//!
//! The puzzle is set before the browser knows whether it will be asked
//! for one: asking is open to anyone and answers the same for every
//! address, so it says nothing about which accounts exist or whether
//! sign-in is under pressure.

use std::sync::Arc;

use ianua_domain::message;
use ianua_domain::types::{Fact, IpAddress};

use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{ChallengeIssuer, ChallengePuzzle};
use crate::use_case::Query;

/// The ports [`IssueSignInPuzzleUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct IssueSignInPuzzlePorts {
    /// Sets the puzzles, when the deployment's challenge provider is the
    /// platform's own; none when it checks Turnstile.
    pub issuer: Option<Arc<dyn ChallengeIssuer>>,
}

/// Sets a sign-in puzzle for the browser asking.
pub struct IssueSignInPuzzleUseCase {
    ports: IssueSignInPuzzlePorts,
}

impl IssueSignInPuzzleUseCase {
    /// A use case setting puzzles through `ports`.
    #[must_use]
    pub fn new(ports: IssueSignInPuzzlePorts) -> Self {
        Self { ports }
    }
}

impl Query for IssueSignInPuzzleUseCase {
    type Caller = ();
    type Input = Fact<IpAddress>;
    type Output = Result<ChallengePuzzle, AppError>;

    /// A fresh puzzle bound to `client_ip`.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the deployment sets no puzzle, as one
    ///   checking Turnstile.
    /// - `AppError::Internal` when no puzzle can be made.
    async fn execute(
        &self,
        (): &(),
        client_ip: Fact<IpAddress>,
    ) -> Result<ChallengePuzzle, AppError> {
        let Some(issuer) = &self.ports.issuer else {
            return Err(AppError::NotFound(message!(
                "authentication-this-deployment-sets-no-sign-in",
                "this deployment sets no sign-in puzzle"
            )));
        };
        issuer.issue(client_ip.as_ref()).or_internal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::authentication::FakeChallengeIssuer;

    /// A browser asks and is set a puzzle.
    #[tokio::test]
    async fn a_puzzle_is_set_for_the_browser_asking() {
        let use_case = IssueSignInPuzzleUseCase::new(IssueSignInPuzzlePorts {
            issuer: Some(Arc::new(FakeChallengeIssuer)),
        });
        let ip = IpAddress::new("203.0.113.7").unwrap();

        let puzzle = use_case.execute(&(), Fact::Known(ip)).await.unwrap();

        assert!(!puzzle.challenge.is_empty());
    }

    /// A deployment without a puzzle issuer returns not found when asked for a challenge.
    #[tokio::test]
    async fn a_deployment_setting_no_puzzle_answers_not_found() {
        let use_case = IssueSignInPuzzleUseCase::new(IssueSignInPuzzlePorts { issuer: None });

        let answer = use_case.execute(&(), Fact::Unknown).await;

        assert!(matches!(answer, Err(AppError::NotFound(_))));
    }
}
