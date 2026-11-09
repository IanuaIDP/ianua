//! Update stream: change a signal stream's endpoint, delivery method,
//! `Authorization` header or signal types.

use std::sync::Arc;

use ianua_domain::domains::signals::control::SignalsControlCheck as _;
use ianua_domain::domains::signals::signal::SecuritySignalType;
use ianua_domain::domains::signals::stream::{
    ChallengeToSend, DeliveryMethod, SignalStream, StreamUpdate,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{PublicHttpsUrl, SignalStreamId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SealedFor;
use crate::ports::crypto::SecureTokenGenerator;
use crate::ports::signals::{SignalStreamStore, StreamChallenge};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::signals::lookup::existing_stream;
use crate::use_cases::signals::streams::verification::challenge::fresh_challenge;
use crate::use_cases::signals::streams::verification::receiver_header::{
    ReceiverHeader, header_place, sealed_header,
};
use crate::use_cases::signals::transmit::TransmitPorts;

/// What to change about a stream. `None` leaves a field as it is.
pub struct UpdateRequest {
    /// The stream to change.
    pub stream_id: SignalStreamId,
    /// A new endpoint, which must prove itself again before it is sent
    /// anything.
    pub endpoint: Option<PublicHttpsUrl>,
    /// A new delivery method.
    pub delivery_method: Option<DeliveryMethod>,
    /// What pushes send in the `Authorization` header from now on.
    pub authorization: Option<ReceiverHeader>,
    /// New signal types, at least one.
    pub signal_types: Option<Vec<SecuritySignalType>>,
}

/// The ports [`UpdateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdatePorts {
    /// Where streams are kept.
    pub stream_store: Arc<dyn SignalStreamStore>,
    /// Makes a new endpoint's challenge at random.
    pub token_generator: Arc<dyn SecureTokenGenerator>,
    /// Signs a new endpoint's challenge and pushes or holds it, and seals a
    /// new header.
    pub transmit: TransmitPorts,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes a signal stream's settings.
pub struct UpdateUseCase {
    ports: UpdatePorts,
}

impl UpdateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: UpdatePorts) -> Self {
        Self { ports }
    }

    /// The changes `request` names, with a fresh challenge for a new
    /// endpoint and a new header sealed for `place`.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the header value is refused.
    /// - `AppError::Internal` when no challenge can be made or the header
    ///   cannot be sealed.
    async fn stream_update(
        &self,
        request: UpdateRequest,
        place: &SealedFor,
    ) -> Result<StreamUpdate, AppError> {
        let generator = self.ports.token_generator.as_ref();
        let endpoint = request
            .endpoint
            .map(|endpoint| fresh_challenge(generator).map(|challenge| (endpoint, challenge)))
            .transpose()?;
        let encryptor = self.ports.transmit.encryptor.as_ref();
        let authorization = match request.authorization {
            Some(header) => Some(sealed_header(encryptor, header, place).await?),
            None => None,
        };
        Ok(StreamUpdate {
            endpoint,
            delivery_method: request.delivery_method,
            signal_types: request.signal_types,
            authorization,
        })
    }

    /// Sends `to_send`, the challenge of `tenant`'s `stream` when its
    /// endpoint moved, as a verification event; nothing when it did not.
    async fn challenge_sent(
        &self,
        tenant: &ScopedTenant,
        stream: &SignalStream<ResolvedTenant>,
        to_send: Option<&ChallengeToSend>,
    ) {
        let Some(to_send) = to_send else {
            return;
        };
        let event = to_send.verification_event();
        let transmitter = self.ports.transmit.transmitter();
        transmitter.verify(tenant, stream, &event).await;
    }
}

impl Command for UpdateUseCase {
    type Caller = CallerContext;
    type Input = UpdateRequest;
    type Output = Result<(), AppError>;

    /// Applies every field `request` names and records
    /// `signals.stream_updated`. A request naming none changes and records
    /// nothing. A new endpoint waits on a fresh challenge, sent to it as a
    /// verification event once the stream is stored.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change signal
    ///   streams.
    /// - `AppError::NotFound` when the tenant has no such stream.
    /// - `AppError::Domain` when the new signal types name none, or the
    ///   header value is refused.
    /// - `AppError::Internal` on storage, challenge, sealing or audit
    ///   failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: UpdateRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        authority
            .ensure_may_change_streams()
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let store = self.ports.stream_store.as_ref();
        let mut stream = existing_stream(store, &tenant, &request.stream_id).await?;
        let place = header_place(&tenant, stream.id());
        let update = self.stream_update(request, &place).await?;
        if update.changes_nothing() {
            return Ok(());
        }
        let to_send = stream
            .update(update, &authority)
            .map_err(AppError::from_domain)?;
        store
            .save(&tenant, &stream, challenge_write(to_send.as_ref()))
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&caller.actor(), stream.take_events(&tenant))
            .await
            .or_internal()?;
        self.challenge_sent(&tenant, &stream, to_send.as_ref())
            .await;
        Ok(())
    }
}

/// What the save writes for the endpoint's challenge: the new one when the
/// endpoint moved, the stored one otherwise.
fn challenge_write(to_send: Option<&ChallengeToSend>) -> StreamChallenge<'_> {
    to_send.map_or(StreamChallenge::Kept, StreamChallenge::Issued)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SignalsAction, SystemPermission};
    use ianua_domain::domains::signals::delivery::ReceiverAuthorization;
    use ianua_domain::domains::signals::stream::{StreamStatus, StreamVerificationStatus};
    use ianua_domain::shared::security::secret::Secret;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::crypto::{FakeSigningKeyStore, premigration_keys};
    use crate::test_support::signals::{FakeSignalDeliverer, FakeSignalStreamStore, test_stream};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The use case with the fakes a test looks into.
    struct Update {
        store: Arc<FakeSignalStreamStore>,
        deliverer: Arc<FakeSignalDeliverer>,
        id: SignalStreamId,
        use_case: UpdateUseCase,
    }

    /// An update by a caller holding `authorities` of the payroll app's
    /// verified push stream, in a tenant that has a signing key.
    fn update(authorities: FakeTenantAuthorities) -> Update {
        let row = test_stream(StreamStatus::Active, StreamVerificationStatus::Verified);
        let id = row.id;
        let store = Arc::new(FakeSignalStreamStore::holding(test_ctx().tenant_id(), row));
        let deliverer = Arc::new(FakeSignalDeliverer::new());
        let use_case = UpdateUseCase::new(UpdatePorts {
            stream_store: store.clone(),
            transmit: TransmitPorts {
                deliverer: deliverer.clone(),
                key_store: Arc::new(FakeSigningKeyStore::holding(premigration_keys())),
                ..TransmitPorts::fakes()
            },
            tenant_authorities: Arc::new(authorities),
            ..UpdatePorts::fakes()
        });
        Update {
            store,
            deliverer,
            id,
            use_case,
        }
    }

    /// A request for `stream_id` naming no change.
    fn nothing(stream_id: SignalStreamId) -> UpdateRequest {
        UpdateRequest {
            stream_id,
            endpoint: None,
            delivery_method: None,
            authorization: None,
            signal_types: None,
        }
    }

    /// Runs `request`, recording into `audit`.
    fn run(
        update: &Update,
        audit: &Arc<FakeEventDispatcher>,
        request: UpdateRequest,
    ) -> Result<(), AppError> {
        block_on(
            update
                .use_case
                .execute(&test_ctx(), &test_auditor(audit.clone()), request),
        )
    }

    /// The payroll app's new server.
    fn new_endpoint() -> PublicHttpsUrl {
        PublicHttpsUrl::new("https://new.acme.com/sse").unwrap()
    }

    /// Ann moves the payroll app's stream to its new server. The stream
    /// points there, waits for it to echo a fresh challenge, and the change
    /// is recorded.
    #[test]
    fn a_moved_endpoint_waits_on_a_new_challenge() {
        let update = update(FakeTenantAuthorities::holding_everything());
        let audit = Arc::new(FakeEventDispatcher::new());

        run(
            &update,
            &audit,
            UpdateRequest {
                endpoint: Some(new_endpoint()),
                ..nothing(update.id)
            },
        )
        .unwrap();

        let stream = update.store.stored(&update.id);
        assert_eq!(stream.endpoint(), &new_endpoint());
        assert_eq!(stream.verification(), StreamVerificationStatus::Pending);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["signals.stream_updated"]
        );
    }

    /// The new server is pushed its challenge as a verification event, and
    /// only the new server.
    #[test]
    fn a_moved_endpoint_is_sent_its_challenge() {
        let update = update(FakeTenantAuthorities::holding_everything());

        run(
            &update,
            &Arc::new(FakeEventDispatcher::new()),
            UpdateRequest {
                endpoint: Some(new_endpoint()),
                ..nothing(update.id)
            },
        )
        .unwrap();

        let sent = update.deliverer.challenges();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, new_endpoint());
    }

    /// Ann switches the stream to polling and widens it to locked accounts.
    /// Both apply, the endpoint stays verified and no challenge is sent.
    #[test]
    fn the_delivery_method_and_types_change_without_a_challenge() {
        let update = update(FakeTenantAuthorities::holding_everything());

        run(
            &update,
            &Arc::new(FakeEventDispatcher::new()),
            UpdateRequest {
                delivery_method: Some(DeliveryMethod::Poll),
                signal_types: Some(vec![
                    SecuritySignalType::SessionRevoked,
                    SecuritySignalType::AccountLocked,
                ]),
                ..nothing(update.id)
            },
        )
        .unwrap();

        let stream = update.store.stored(&update.id);
        assert_eq!(stream.delivery_method(), DeliveryMethod::Poll);
        assert_eq!(stream.signal_types().len(), 2);
        assert_eq!(stream.verification(), StreamVerificationStatus::Verified);
        assert!(update.deliverer.pushes.lock().unwrap().is_empty());
    }

    /// The payroll app rotates its token, and Ann sets the new header. The
    /// stream keeps it sealed and its endpoint stays verified.
    #[test]
    fn a_new_header_is_kept_sealed() {
        let update = update(FakeTenantAuthorities::holding_everything());

        run(
            &update,
            &Arc::new(FakeEventDispatcher::new()),
            UpdateRequest {
                authorization: Some(ReceiverHeader::Header(Secret::new("Bearer rotated"))),
                ..nothing(update.id)
            },
        )
        .unwrap();

        let stream = update.store.stored(&update.id);
        assert_eq!(
            stream.authorization(),
            &ReceiverAuthorization::Header(FakeEncryptor::sealed_for(
                "Bearer rotated",
                &header_place(&test_ctx().tenant(), &update.id)
            ))
        );
        assert_eq!(stream.verification(), StreamVerificationStatus::Verified);
    }

    /// Ann empties the stream's signal types. It is refused and the stream
    /// keeps the types it had.
    #[test]
    fn emptying_the_signal_types_is_refused() {
        let update = update(FakeTenantAuthorities::holding_everything());
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = run(
            &update,
            &audit,
            UpdateRequest {
                signal_types: Some(Vec::new()),
                ..nothing(update.id)
            },
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(
            update.store.stored(&update.id).signal_types(),
            [SecuritySignalType::SessionRevoked]
        );
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Ann sends a change naming no field. Nothing changes or is recorded.
    #[test]
    fn a_request_naming_nothing_changes_nothing() {
        let update = update(FakeTenantAuthorities::holding_everything());
        let audit = Arc::new(FakeEventDispatcher::new());

        run(&update, &audit, nothing(update.id)).unwrap();

        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Ann names a stream the tenant does not have. It is not found.
    #[test]
    fn an_unknown_stream_is_not_found() {
        let update = update(FakeTenantAuthorities::holding_everything());

        let result = run(
            &update,
            &Arc::new(FakeEventDispatcher::new()),
            nothing(SignalStreamId::new()),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// An empty update to an unknown stream without stream change rights
    /// returns forbidden rather than exposing its absence.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_stream() {
        let update = update(FakeTenantAuthorities::holding(&[]));

        let result = run(
            &update,
            &Arc::new(FakeEventDispatcher::new()),
            nothing(SignalStreamId::new()),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Stream viewing rights do not permit changing an endpoint; it keeps
    /// its address and nothing is pushed or recorded.
    #[test]
    fn a_caller_without_the_signals_right_is_refused() {
        let update = update(FakeTenantAuthorities::holding(&[
            SystemPermission::Signals(SignalsAction::View),
        ]));
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = run(
            &update,
            &audit,
            UpdateRequest {
                endpoint: Some(new_endpoint()),
                ..nothing(update.id)
            },
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(
            update.store.stored(&update.id).endpoint().as_str(),
            "https://app.acme.com/sse"
        );
        assert!(update.deliverer.pushes.lock().unwrap().is_empty());
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Updating a stream with a signed-out session returns an
    /// unauthenticated error.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let update = update(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = run(
            &update,
            &Arc::new(FakeEventDispatcher::new()),
            nothing(update.id),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
