//! A stream's receiver managing its own stream.
//!
//! Under the Shared Signals framework a receiver manages its own stream: it
//! polls it, asks it for verification events and says which users and
//! agents it hears about. It does that with the key it was handed when the
//! stream was registered, never with one of the tenant's API keys. A key
//! of the tenant reaches every stream and every user; the payroll app's
//! receiver must reach the payroll app's stream and nothing else.

use crate::domains::signals::control::SignalsControlCheck;
use crate::domains::signals::sealed::Sealed;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::SignalStreamId;

/// Proof that a stream's receiver presented that stream's own key just now.
///
/// Only [`SignalStream::sign_in_receiver`](crate::domains::signals::stream::SignalStream::sign_in_receiver)
/// makes one. It is neither `Clone` nor `Copy`, so one proof answers one
/// request.
#[derive(Debug, PartialEq, Eq)]
pub struct StreamReceiver {
    stream: SignalStreamId,
}

impl StreamReceiver {
    /// The proof for the receiver of `stream`, once its key matched.
    pub(crate) fn of(stream: SignalStreamId) -> Self {
        Self { stream }
    }

    /// The stream whose receiver signed in.
    #[must_use]
    pub fn stream(&self) -> &SignalStreamId {
        &self.stream
    }
}

impl Sealed for StreamReceiver {}

/// A receiver registers no stream and changes none but its own.
impl SignalsControlCheck for StreamReceiver {
    fn ensure_may_change_streams(&self) -> Result<(), DomainError> {
        Err(DomainError::forbidden(message!(
            "signals-a-receiver-manages-only-its-own",
            "a receiver manages only its own stream"
        )))
    }

    fn ensure_may_manage(&self, stream: &SignalStreamId) -> Result<(), DomainError> {
        if stream == &self.stream {
            return Ok(());
        }
        Err(DomainError::forbidden(message!(
            "signals-a-receiver-manages-only-its-own",
            "a receiver manages only its own stream"
        )))
    }
}

/// Who manages a stream: a person of the tenant, with what they hold, or
/// the stream's own receiver.
#[derive(Debug, Clone, Copy)]
pub enum StreamAuthority<'a, P: SignalsControlCheck> {
    /// A person, with what they hold.
    Person(&'a P),
    /// The stream's receiver, signed in with its key.
    Receiver(&'a StreamReceiver),
}

impl<P: SignalsControlCheck> Sealed for StreamAuthority<'_, P> {}

/// Asks the person or the receiver, whichever manages.
impl<P: SignalsControlCheck> SignalsControlCheck for StreamAuthority<'_, P> {
    fn ensure_may_change_streams(&self) -> Result<(), DomainError> {
        match self {
            Self::Person(person) => person.ensure_may_change_streams(),
            Self::Receiver(receiver) => receiver.ensure_may_change_streams(),
        }
    }

    fn ensure_may_manage(&self, stream: &SignalStreamId) -> Result<(), DomainError> {
        match self {
            Self::Person(person) => person.ensure_may_manage(stream),
            Self::Receiver(receiver) => receiver.ensure_may_manage(stream),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The payroll app's receiver manages its own stream.
    #[test]
    fn a_receiver_manages_its_own_stream() {
        let stream = SignalStreamId::new();
        let receiver = StreamReceiver::of(stream);

        assert!(receiver.ensure_may_manage(&stream).is_ok());
    }

    /// A receiver is forbidden from managing another stream or exercising
    /// the tenant's stream management authority.
    #[test]
    fn a_receiver_manages_no_other_stream_and_registers_none() {
        let receiver = StreamReceiver::of(SignalStreamId::new());

        let other = receiver.ensure_may_manage(&SignalStreamId::new());

        assert!(matches!(other, Err(DomainError::Forbidden(_))));
        assert!(matches!(
            receiver.ensure_may_change_streams(),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// A receiver managing through [`StreamAuthority`] is held to its own
    /// stream all the same.
    #[test]
    fn a_manager_asks_the_receiver_it_holds() {
        let stream = SignalStreamId::new();
        let receiver = StreamReceiver::of(stream);
        let manager = StreamAuthority::<StreamReceiver>::Receiver(&receiver);

        assert!(manager.ensure_may_manage(&stream).is_ok());
        assert!(manager.ensure_may_manage(&SignalStreamId::new()).is_err());
    }
}
