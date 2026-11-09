//! What a person changes about a stream in one update: where it pushes,
//! how, with which header, and which signal types it hears.

use crate::domains::signals::control::SignalsControlCheck;
use crate::domains::signals::delivery::ReceiverAuthorization;
use crate::domains::signals::events::SignalStreamUpdated;
use crate::domains::signals::signal::SecuritySignalType;
use crate::domains::signals::stream::{
    ChallengeToSend, DeliveryMethod, EndpointChallenge, EndpointVerification, SignalStream,
    StreamUpdate, ensure_names_a_type,
};
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;
use crate::types::PublicHttpsUrl;

impl StreamUpdate {
    /// Whether the update names no field to change.
    #[must_use]
    pub fn changes_nothing(&self) -> bool {
        self.endpoint.is_none()
            && self.delivery_method.is_none()
            && self.signal_types.is_none()
            && self.authorization.is_none()
    }
}

impl<T: TenantScope> SignalStream<T> {
    /// Applies every change `update` names, on behalf of `by`, and hands
    /// back the challenge to send when the endpoint moved. Raises one
    /// `signals.stream_updated` for the whole update; an update naming no
    /// change changes and raises nothing.
    ///
    /// A new endpoint has proved nothing yet, so the stream delivers nothing
    /// to it until it echoes its challenge, see
    /// [`confirm_endpoint`](Self::confirm_endpoint).
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change signal streams.
    /// - [`DomainError::Validation`] when the new signal types name none.
    ///   The stream keeps everything it had.
    pub fn update(
        &mut self,
        update: StreamUpdate,
        by: &impl SignalsControlCheck,
    ) -> Result<Option<ChallengeToSend>, DomainError> {
        by.ensure_may_change_streams()?;
        if update.changes_nothing() {
            return Ok(None);
        }
        if let Some(signal_types) = &update.signal_types {
            ensure_names_a_type(signal_types)?;
        }
        if let Some(delivery_method) = update.delivery_method {
            self.change_delivery_method(delivery_method, by)?;
        }
        if let Some(authorization) = update.authorization {
            self.change_authorization(authorization, by)?;
        }
        if let Some(signal_types) = update.signal_types {
            self.replace_signal_types(signal_types, by)?;
        }
        let to_send = update
            .endpoint
            .map(|(endpoint, challenge)| self.change_endpoint(endpoint, challenge, by))
            .transpose()?;
        self.raised.raise(SignalStreamUpdated {
            stream_id: self.id,
            endpoint: self.endpoint.origin(),
            occurred_at: self.updated_at,
        });
        Ok(to_send)
    }

    /// Changes the receiver's endpoint URL.
    ///
    /// The new endpoint has proved nothing yet. So the stream waits for it
    /// to echo `challenge`, and delivers nothing until it does, see
    /// [`confirm_endpoint`](Self::confirm_endpoint). The challenge comes
    /// back once, to send to the new endpoint.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change signal streams.
    pub(super) fn change_endpoint(
        &mut self,
        endpoint: PublicHttpsUrl,
        challenge: EndpointChallenge,
        by: &impl SignalsControlCheck,
    ) -> Result<ChallengeToSend, DomainError> {
        by.ensure_may_change_streams()?;
        let to_send = ChallengeToSend::new(self.id, &endpoint, &challenge);
        self.endpoint = endpoint;
        self.verification = EndpointVerification::Pending(challenge);
        self.touch();
        Ok(to_send)
    }

    /// Changes the delivery method.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change signal streams.
    pub(super) fn change_delivery_method(
        &mut self,
        delivery_method: DeliveryMethod,
        by: &impl SignalsControlCheck,
    ) -> Result<(), DomainError> {
        by.ensure_may_change_streams()?;
        self.delivery_method = delivery_method;
        self.touch();
        Ok(())
    }

    /// Replaces what a push sends in the `Authorization` header.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change signal streams.
    pub(super) fn change_authorization(
        &mut self,
        authorization: ReceiverAuthorization,
        by: &impl SignalsControlCheck,
    ) -> Result<(), DomainError> {
        by.ensure_may_change_streams()?;
        self.authorization = authorization;
        self.touch();
        Ok(())
    }

    /// Replaces the signal types the stream receives.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change signal streams.
    /// - [`DomainError::Validation`] when `signal_types` names no type. The
    ///   stream keeps the types it had.
    pub(super) fn replace_signal_types(
        &mut self,
        signal_types: Vec<SecuritySignalType>,
        by: &impl SignalsControlCheck,
    ) -> Result<(), DomainError> {
        by.ensure_may_change_streams()?;
        ensure_names_a_type(&signal_types)?;
        self.signal_types = signal_types;
        self.touch();
        Ok(())
    }
}
