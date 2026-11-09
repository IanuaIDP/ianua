//! The background sweep that removes account connections nobody finished
//! in time, with the credential a service may have issued for one.

use std::sync::Arc;

use ianua_domain::shared::clock;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::ConnectionStates;
use crate::use_case::Command;

/// The most connections one round removes; the next round removes the
/// rest.
const MOST_PER_ROUND: u32 = 500;

/// The ports [`SweepUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SweepPorts {
    /// Removes the expired connections, across every tenant.
    pub states: Arc<dyn ConnectionStates>,
}

/// Removes every connection that stopped being finishable.
///
/// It runs as a periodic job of the platform, with nobody asking. A
/// connection is only ever a person's unfinished sign-in, so removing it
/// is not recorded; an account connected from one was recorded when it
/// was connected.
pub struct SweepUseCase {
    ports: SweepPorts,
}

impl SweepUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SweepPorts) -> Self {
        Self { ports }
    }
}

impl Command for SweepUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<u64, AppError>;

    /// Removes up to a round's worth of expired connections, and how many.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when they cannot be removed; the next round
    /// tries again.
    async fn execute(
        &self,
        _caller: &(),
        _auditor: &RequestAuditor,
        _input: (),
    ) -> Result<u64, AppError> {
        self.ports
            .states
            .remove_expired(clock::now(), MOST_PER_ROUND)
            .await
            .or_internal()
    }
}
