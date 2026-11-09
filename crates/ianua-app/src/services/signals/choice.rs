//! The signals one event may go out as about one subject, and which of them
//! each stream is sent.
//!
//! Some events mean something precise and something broader at once. A
//! refresh token used twice revokes the session because the token may be in
//! other hands: a stream that asked for stolen tokens should hear that, and
//! one that asked only for revoked sessions must still hear its session was
//! revoked, or the receiver keeps it open. So such an event offers its
//! signals in order, the most precise first, and each stream is sent the
//! first one it takes, once.

use ianua_domain::domains::signals::signal::SecuritySignal;
use ianua_domain::domains::signals::stream::SignalStream;
use ianua_domain::isolation::scope::ResolvedTenant;

/// What one event means to receivers about one subject: the signals it may
/// go out as, the most precise first.
#[derive(Debug, Clone)]
pub(crate) struct SignalChoice {
    signals: Vec<SecuritySignal>,
}

impl SignalChoice {
    /// The one signal `signal`.
    #[must_use]
    pub(crate) fn only(signal: SecuritySignal) -> Self {
        Self {
            signals: vec![signal],
        }
    }

    /// `signals`, the most precise first, or `None` when there are none.
    #[must_use]
    pub(crate) fn of(signals: Vec<SecuritySignal>) -> Option<Self> {
        if signals.is_empty() {
            return None;
        }
        Some(Self { signals })
    }

    /// The signal `stream` is sent: the first it takes, or `None` when it
    /// takes none of them.
    #[must_use]
    pub(crate) fn for_stream(
        &self,
        stream: &SignalStream<ResolvedTenant>,
    ) -> Option<&SecuritySignal> {
        self.signals.iter().find(|signal| stream.receives(signal))
    }
}
