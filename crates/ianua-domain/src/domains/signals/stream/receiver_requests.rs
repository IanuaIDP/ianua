//! What a stream's receiver asks of it under the Shared Signals framework:
//! signing in with its key, subjects added and removed, and verification
//! events.

use crate::domains::signals::control::SignalsControlCheck;
use crate::domains::signals::events::{
    SignalSubjectAdded, SignalSubjectRemoved, SignalVerificationRequested,
};
use crate::domains::signals::receiver::StreamReceiver;
use crate::domains::signals::signal::SignalSubject;
use crate::domains::signals::stream::SignalStream;
use crate::domains::signals::subjects::SubjectChange;
use crate::domains::signals::verification::{RequestedState, VerificationEvent};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::TokenHash;

impl<T: TenantScope> SignalStream<T> {
    /// Proof that this stream's receiver presented `presented`, the digest
    /// of the key it was handed when the stream was registered.
    ///
    /// The key manages this stream and no other, so a receiver never needs
    /// one of the tenant's API keys, which reach every stream and user.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Unauthorized`] when `presented` is not this
    ///   stream's key.
    pub fn sign_in_receiver(&self, presented: &TokenHash) -> Result<StreamReceiver, DomainError> {
        if &self.receiver_key != presented {
            return Err(DomainError::unauthorized(message!(
                "signals-this-key-does-not-manage-the",
                "this key does not manage the stream"
            )));
        }
        Ok(StreamReceiver::of(self.id))
    }

    /// Makes the stream hear about `subject`, on behalf of `by`. Raises
    /// `signals.subject_added` when that changed what it hears; adding one
    /// it already hears about changes and raises nothing.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not manage this stream.
    /// - [`DomainError::Validation`] when the stream already lists the most
    ///   subjects it keeps.
    pub fn add_subject(
        &mut self,
        subject: SignalSubject,
        by: &impl SignalsControlCheck,
    ) -> Result<(), DomainError> {
        by.ensure_may_manage(&self.id)?;
        if self.subjects.add(subject)? == SubjectChange::AlreadySo {
            return Ok(());
        }
        self.touch();
        self.raised.raise(SignalSubjectAdded {
            stream_id: self.id,
            endpoint: self.endpoint.origin(),
            subject,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Makes the stream stop hearing about `subject`, on behalf of `by`.
    /// Raises `signals.subject_removed` when that changed what it hears.
    ///
    /// Sam may only view the streams. Without the check, he removes himself
    /// from the payroll app's stream, and the app never learns his session
    /// was revoked.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not manage this stream.
    /// - [`DomainError::Validation`] when the stream already lists the most
    ///   subjects it keeps.
    pub fn remove_subject(
        &mut self,
        subject: SignalSubject,
        by: &impl SignalsControlCheck,
    ) -> Result<(), DomainError> {
        by.ensure_may_manage(&self.id)?;
        if self.subjects.remove(subject)? == SubjectChange::AlreadySo {
            return Ok(());
        }
        self.touch();
        self.raised.raise(SignalSubjectRemoved {
            stream_id: self.id,
            endpoint: self.endpoint.origin(),
            subject,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// The verification event the receiver asked for, carrying back
    /// `requested`, on behalf of `by`. Raises
    /// `signals.verification_requested`; nothing stored changes.
    ///
    /// Only a stream that may deliver sends one. A paused or disabled
    /// stream, or one whose endpoint has not echoed its challenge, is sent
    /// nothing, so asking cannot make the platform call an endpoint that
    /// never proved it is the receiver's. Each request is recorded, so a
    /// receiver asking again and again shows in the trail.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not manage this stream.
    /// - [`DomainError::Conflict`] unless the stream is active and its
    ///   endpoint verified.
    pub fn request_verification(
        &mut self,
        requested: RequestedState,
        by: &impl SignalsControlCheck,
    ) -> Result<VerificationEvent, DomainError> {
        by.ensure_may_manage(&self.id)?;
        if !self.is_delivering() {
            return Err(DomainError::conflict(message!(
                "signals-only-an-active-stream-with-a",
                "only an active stream with a verified endpoint is sent a verification event"
            )));
        }
        self.raised.raise(SignalVerificationRequested {
            stream_id: self.id,
            endpoint: self.endpoint.origin(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(VerificationEvent::new(
            self.id,
            self.endpoint.clone(),
            requested.into(),
        ))
    }
}
