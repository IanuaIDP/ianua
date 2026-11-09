//! Exchanging an account's lasting grant ahead of a call, and the lease
//! that lets one caller at a time do it, across every worker.

use async_trait::async_trait;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::domains::workflows::integration::IntegrationKey;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::IntegrationAccountId;
use uuid::Uuid;

use crate::ports::authentication::SealedAt;
use crate::ports::workflows::Renewal;

/// Dyn-safe port asking an integration about the grant an account holds.
///
/// The adapter opens the sealed credential itself, bounds the exchange with
/// a timeout, and seals what comes back for the same account.
#[async_trait]
pub trait GrantExchanger: Send + Sync {
    /// Whether `credential` holds a grant `integration` should exchange
    /// before the next call. A credential that cannot be opened is not:
    /// the call itself says why.
    async fn is_due(&self, integration: &IntegrationKey, credential: &SealedAt) -> bool;

    /// Exchanges the grant `credential` holds now, and the credential to
    /// keep.
    ///
    /// # Errors
    ///
    /// [`ActionOutcome::Failed`] when the service refuses the grant;
    /// [`ActionOutcome::TurnedAway`] when it cannot be reached in time or
    /// what it issued cannot be sealed.
    async fn exchange(
        &self,
        integration: &IntegrationKey,
        credential: &SealedAt,
    ) -> Result<Renewal, ActionOutcome>;
}

/// Who holds a turn on an account's grant. Each turn has its own, so two
/// calls on one worker wait for each other too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TurnHolder(Uuid);

impl TurnHolder {
    /// A holder no other turn has.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// The value the lease is stored under.
    #[must_use]
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for TurnHolder {
    fn default() -> Self {
        Self::new()
    }
}

/// One caller's turn to exchange an account's grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantTurn {
    /// The account the turn is on.
    pub account: IntegrationAccountId,
    /// Who holds it.
    pub holder: TurnHolder,
}

/// Dyn-safe port for the lease that keeps an account's grant to one
/// exchange at a time. A rotating grant retires its refresh token on every
/// exchange, so a second exchange at the same moment would be refused.
#[async_trait]
pub trait GrantExchangeLease: Send + Sync {
    /// The turn on `account`, waiting a bounded while for whoever holds it.
    /// `None` when the wait ran out. A turn whose holder died lapses by
    /// itself and is taken over.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the lease cannot be taken
    /// or read. The caller makes no exchange then.
    async fn claim_within(
        &self,
        account: &IntegrationAccountId,
    ) -> Result<Option<GrantTurn>, DomainError>;

    /// Ends `turn`. A turn that cannot be ended lapses by itself.
    async fn release(&self, turn: GrantTurn);
}
