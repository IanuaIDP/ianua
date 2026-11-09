//! Confirm endpoint: a stream's endpoint echoes the challenge it was sent,
//! and from then on the stream delivers to it.
//!
//! The receiver calls this, not a person of the tenant: it holds no session
//! here, only the challenge. That challenge is the proof. It went out once,
//! to the endpoint alone, and is never shown to anyone reading the stream.

use std::sync::Arc;

use ianua_domain::domains::signals::stream::EndpointChallenge;
use ianua_domain::types::SignalStreamId;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::signals::{SignalStreamStore, StreamChallenge};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::signals::lookup::existing_stream;

/// The echo an endpoint sends back.
pub struct ConfirmEndpointRequest {
    /// The stream whose endpoint answers.
    pub stream_id: SignalStreamId,
    /// The challenge the endpoint echoes.
    pub echoed: EndpointChallenge,
}

/// The ports [`ConfirmEndpointUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ConfirmEndpointPorts {
    /// Where streams are kept, with the challenge each endpoint was sent.
    pub stream_store: Arc<dyn SignalStreamStore>,
}

/// Verifies a stream's endpoint from the challenge it echoes.
pub struct ConfirmEndpointUseCase {
    ports: ConfirmEndpointPorts,
}

impl ConfirmEndpointUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ConfirmEndpointPorts) -> Self {
        Self { ports }
    }
}

impl Command for ConfirmEndpointUseCase {
    type Caller = ScopedTenant;
    type Input = ConfirmEndpointRequest;
    type Output = Result<(), AppError>;

    /// Marks the stream's endpoint verified when `request` echoes the
    /// challenge stored for it.
    ///
    /// The domain has no event for a verified endpoint, so none is recorded.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the tenant has no such stream, as
    ///   for a tenant that does not exist, so a caller holding no challenge
    ///   learns nothing of which tenants exist.
    /// - `AppError::Forbidden` when the echo is not the challenge the
    ///   endpoint was sent. The endpoint stays unverified.
    /// - `AppError::Domain` when the endpoint is already verified.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        _auditor: &RequestAuditor,
        request: ConfirmEndpointRequest,
    ) -> Result<(), AppError> {
        let store = self.ports.stream_store.as_ref();
        let mut stream = existing_stream(store, tenant, &request.stream_id)
            .await
            .map_err(as_unproven)?;
        stream
            .confirm_endpoint(&request.echoed)
            .map_err(AppError::from_domain)?;
        store
            .save(tenant, &stream, StreamChallenge::Kept)
            .await
            .or_internal()
    }
}

/// A stream the tenant does not have, answered as a challenge that does not
/// hold, the way the API answers a tenant that does not exist.
fn as_unproven(refused: AppError) -> AppError {
    match refused {
        AppError::NotFound(_) => AppError::Unauthenticated,
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::signals::stream::{StreamStatus, StreamVerificationStatus};

    use super::*;
    use crate::test_support::signals::{FakeSignalStreamStore, TEST_CHALLENGE, test_stream};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn seeded(
        verification: StreamVerificationStatus,
    ) -> (Arc<FakeSignalStreamStore>, SignalStreamId) {
        let row = test_stream(StreamStatus::Active, verification);
        let id = row.id;
        let store = FakeSignalStreamStore::holding(test_ctx().tenant_id(), row);
        (Arc::new(store), id)
    }

    fn confirm(
        store: &Arc<FakeSignalStreamStore>,
        stream_id: SignalStreamId,
        echoed: &str,
    ) -> Result<(), AppError> {
        let use_case = ConfirmEndpointUseCase::new(ConfirmEndpointPorts {
            stream_store: store.clone(),
        });
        let request = ConfirmEndpointRequest {
            stream_id,
            echoed: EndpointChallenge::new(echoed).unwrap(),
        };
        block_on(use_case.execute(
            &test_ctx().tenant(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            request,
        ))
    }

    fn verification_of(
        store: &FakeSignalStreamStore,
        id: &SignalStreamId,
    ) -> StreamVerificationStatus {
        block_on(store.find_by_id(&test_ctx().tenant(), id))
            .unwrap()
            .unwrap()
            .verification()
    }

    /// The payroll app's endpoint echoes the challenge it was sent, after
    /// the stream was stored and read back. The endpoint is verified.
    #[test]
    fn the_echoed_challenge_verifies_the_endpoint() {
        let (store, id) = seeded(StreamVerificationStatus::Pending);

        confirm(&store, id, TEST_CHALLENGE).unwrap();

        assert_eq!(
            verification_of(&store, &id),
            StreamVerificationStatus::Verified
        );
    }

    /// Echoing an incorrect challenge is forbidden and leaves endpoint
    /// verification pending.
    #[test]
    fn a_wrong_echo_is_refused() {
        let (store, id) = seeded(StreamVerificationStatus::Pending);

        let result = confirm(&store, id, "a-guess-at-the-challenge-0000000000000");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(
            verification_of(&store, &id),
            StreamVerificationStatus::Pending
        );
    }

    /// An endpoint already verified echoes again. It is refused as a move
    /// the stream cannot make.
    #[test]
    fn a_verified_endpoint_is_not_confirmed_again() {
        let (store, id) = seeded(StreamVerificationStatus::Verified);

        let result = confirm(&store, id, TEST_CHALLENGE);

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Confirming an unknown stream returns an unauthenticated error.
    #[test]
    fn an_unknown_stream_answers_as_unauthenticated() {
        let store = Arc::new(FakeSignalStreamStore::empty());

        let result = confirm(&store, SignalStreamId::new(), TEST_CHALLENGE);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
