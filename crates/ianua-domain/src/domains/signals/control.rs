//! Who may change the tenant's signal streams.
//!
//! A stream decides which outside receiver hears of every revoked session
//! and locked account in the tenant, and whether it hears at all. So
//! registering one, and every change a person makes to one, names who makes
//! it and needs the right for it.

use crate::domains::signals::sealed::Sealed;
use crate::shared::errors::DomainError;
use crate::types::SignalStreamId;

/// Whether the person acting may change the tenant's signal streams.
///
/// Sam may only view the streams. Without this check, he points the
/// stream of the payroll app at his own server and reads every security
/// signal the tenant raises, or pauses it so the app never learns a session
/// was revoked. Authorization knows what the person holds and answers with
/// [`TenantAuthority`](crate::domains::authorization::authority::TenantAuthority).
/// Signals sits below authorization, so it names only this rule.
pub trait SignalsControlCheck: Sealed {
    /// Refuses unless the person acting may change signal streams.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when they may not.
    fn ensure_may_change_streams(&self) -> Result<(), DomainError>;

    /// Refuses unless whoever acts may manage the stream `stream`: poll
    /// it, ask it for a verification event and say whom it hears about.
    ///
    /// A person who may change signal streams may manage every one of the
    /// tenant's. A receiver may manage its own stream and no other.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when they may not.
    fn ensure_may_manage(&self, stream: &SignalStreamId) -> Result<(), DomainError> {
        let _ = stream;
        self.ensure_may_change_streams()
    }
}
