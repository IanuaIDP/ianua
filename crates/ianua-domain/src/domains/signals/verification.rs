//! The Shared Signals verification event: a test event a transmitter sends
//! down a stream, so the receiver sees the stream works end to end.
//!
//! It goes out two ways. When an endpoint is set, it carries the challenge
//! the endpoint must echo before it is sent any signal. When a receiver asks
//! for one, it carries back the `state` the receiver chose, if any.

use crate::domains::signals::stream::EndpointChallenge;
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::{PublicHttpsUrl, SignalStreamId};

/// The verification event type the Shared Signals framework defines.
pub const VERIFICATION_EVENT_TYPE: &str =
    "https://schemas.openid.net/secevent/ssf/event-type/verification";

text_value! {
    /// The `state` a receiver asks its verification event to carry back,
    /// so it can match the event to its own request.
    pub struct ReceiverState;
}

impl TextValue for ReceiverState {
    const FIELD: &'static str = "state";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.token(1..=256)
    }
}

/// What a receiver gave when it asked for a verification event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestedState {
    /// A `state` to carry back.
    Given(ReceiverState),
    /// No `state`; the event carries none.
    NotGiven,
}

/// The `state` a verification event carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationState {
    /// The challenge a newly set endpoint must echo.
    Challenge(EndpointChallenge),
    /// The state a receiver asked for.
    Echo(ReceiverState),
    /// None: the receiver asked for none.
    Omitted,
}

impl From<RequestedState> for VerificationState {
    fn from(requested: RequestedState) -> Self {
        match requested {
            RequestedState::Given(state) => Self::Echo(state),
            RequestedState::NotGiven => Self::Omitted,
        }
    }
}

/// A verification event to send down one stream.
///
/// Only a stream makes one: for its endpoint when the endpoint is set, or
/// for an active, verified stream when its receiver asks.
#[derive(Debug, Clone)]
pub struct VerificationEvent {
    stream_id: SignalStreamId,
    endpoint: PublicHttpsUrl,
    state: VerificationState,
}

impl VerificationEvent {
    /// A verification event for `stream_id`, sent to `endpoint` with
    /// `state`.
    pub(crate) fn new(
        stream_id: SignalStreamId,
        endpoint: PublicHttpsUrl,
        state: VerificationState,
    ) -> Self {
        Self {
            stream_id,
            endpoint,
            state,
        }
    }

    /// The stream it is about, which is its subject.
    #[must_use]
    pub fn stream_id(&self) -> &SignalStreamId {
        &self.stream_id
    }

    /// The endpoint it goes to, which is its audience.
    #[must_use]
    pub fn endpoint(&self) -> &PublicHttpsUrl {
        &self.endpoint
    }

    /// The `state` it carries.
    #[must_use]
    pub fn state(&self) -> &VerificationState {
        &self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A receiver's state such as `req-42` is accepted.
    #[test]
    fn a_well_formed_receiver_state_is_accepted() {
        assert!(ReceiverState::new("req-42").is_ok());
    }

    /// An empty state, one with a space and one over 256 characters are
    /// refused.
    #[test]
    fn a_malformed_receiver_state_is_refused() {
        for value in [String::new(), "a b".to_owned(), "a".repeat(257)] {
            assert!(
                ReceiverState::new(value.clone()).is_err(),
                "{value:?} was accepted"
            );
        }
    }
}
