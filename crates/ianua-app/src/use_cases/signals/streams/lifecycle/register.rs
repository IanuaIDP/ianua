//! Register stream: create a CAEP/SSE signal stream for a relying party, and
//! send its endpoint the challenge it must echo, as a verification event.

use std::sync::Arc;

use ianua_domain::domains::signals::control::SignalsControlCheck as _;
use ianua_domain::domains::signals::signal::SecuritySignalType;
use ianua_domain::domains::signals::stream::{DeliveryMethod, RegisterStreamParams, SignalStream};
use ianua_domain::domains::signals::subjects::DefaultSubjects;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{PublicHttpsUrl, SignalStreamId, TokenHash};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::crypto::SecureTokenGenerator;
use crate::ports::signals::{ReceiverKeys, SignalStreamStore, StreamChallenge};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::signals::streams::verification::challenge::fresh_challenge;
use crate::use_cases::signals::streams::verification::receiver_header::{
    ReceiverHeader, header_place, sealed_header,
};
use crate::use_cases::signals::transmit::TransmitPorts;

/// Request to register a new signal stream.
pub struct RegisterRequest {
    /// The receiver's public endpoint URL.
    pub endpoint: PublicHttpsUrl,
    /// How signals are delivered.
    pub delivery_method: DeliveryMethod,
    /// What pushes send in the `Authorization` header.
    pub authorization: ReceiverHeader,
    /// Which signal types to receive, at least one.
    pub signal_types: Vec<SecuritySignalType>,
    /// Whether the stream starts hearing about every user and agent, or
    /// none until they are added.
    pub default_subjects: DefaultSubjects,
}

/// A stream just registered, with the key its receiver manages it with.
///
/// No `Debug`: it carries the raw key.
pub struct Registered {
    /// The new stream.
    pub stream_id: SignalStreamId,
    /// The key the receiver polls, asks for verification and names its
    /// subjects with. Shown this once and never kept: only its digest is
    /// stored.
    pub receiver_key: Secret,
}

/// The ports [`RegisterUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RegisterPorts {
    /// Where streams are kept.
    pub stream_store: Arc<dyn SignalStreamStore>,
    /// Makes the challenge at random.
    pub token_generator: Arc<dyn SecureTokenGenerator>,
    /// Makes the key the receiver manages the stream with.
    pub receiver_keys: Arc<dyn ReceiverKeys>,
    /// Signs the challenge and pushes or holds it, and seals the receiver's
    /// header.
    pub transmit: TransmitPorts,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Registers a signal stream for the tenant.
pub struct RegisterUseCase {
    ports: RegisterPorts,
}

impl RegisterUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RegisterPorts) -> Self {
        Self { ports }
    }

    /// What the domain registers from `request`, with a fresh challenge,
    /// the header sealed, and the receiver's key kept by `receiver_key`.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the header value is refused.
    /// - `AppError::Internal` when no challenge can be made or the header
    ///   cannot be sealed.
    async fn params(
        &self,
        tenant: &ScopedTenant,
        request: RegisterRequest,
        receiver_key: TokenHash,
    ) -> Result<RegisterStreamParams, AppError> {
        let id = SignalStreamId::new();
        Ok(RegisterStreamParams {
            id,
            endpoint: request.endpoint,
            challenge: fresh_challenge(self.ports.token_generator.as_ref())?,
            delivery_method: request.delivery_method,
            authorization: sealed_header(
                self.ports.transmit.encryptor.as_ref(),
                request.authorization,
                &header_place(tenant, &id),
            )
            .await?,
            receiver_key,
            signal_types: request.signal_types,
            default_subjects: request.default_subjects,
        })
    }
}

impl Command for RegisterUseCase {
    type Caller = CallerContext;
    type Input = RegisterRequest;
    type Output = Result<Registered, AppError>;

    /// Registers the stream `request` describes, records
    /// `signals.stream_registered`, then sends the challenge as a
    /// verification event: pushed to the endpoint, or held for a poll
    /// stream's receiver. The stream delivers nothing until the challenge
    /// is echoed.
    ///
    /// The key the receiver manages the stream with comes back once; only
    /// its digest is kept.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change signal
    ///   streams.
    /// - `AppError::Domain` when the request names no signal type, or the
    ///   header value is refused.
    /// - `AppError::Internal` on storage, challenge, sealing or audit
    ///   failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: RegisterRequest,
    ) -> Result<Registered, AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        authority
            .ensure_may_change_streams()
            .map_err(AppError::from_domain)?;
        let (receiver_key, key_digest) = self.ports.receiver_keys.generate().await.or_internal()?;
        let tenant = caller.tenant();
        let params = self.params(&tenant, request, key_digest).await?;
        let (mut stream, to_send) = SignalStream::<ResolvedTenant>::register(params, &authority)
            .map_err(AppError::from_domain)?;

        self.ports
            .stream_store
            .save(&tenant, &stream, StreamChallenge::Issued(&to_send))
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&caller.actor(), stream.take_events(&tenant))
            .await
            .or_internal()?;
        self.ports
            .transmit
            .transmitter()
            .verify(&tenant, &stream, &to_send.verification_event())
            .await;

        Ok(Registered {
            stream_id: *stream.id(),
            receiver_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SignalsAction, SystemPermission};
    use ianua_domain::domains::signals::delivery::ReceiverAuthorization;
    use ianua_domain::domains::signals::signal::SignalSubject;
    use ianua_domain::domains::signals::stream::StreamVerificationStatus;
    use ianua_domain::types::UserId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::crypto::{FakeSigningKeyStore, premigration_keys};
    use crate::test_support::signals::{
        FakeReceiverKeys, FakeSignalDeliverer, FakeSignalPollQueue, FakeSignalStreamStore,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::signals::streams::{
        ConfirmEndpointPorts, ConfirmEndpointRequest, ConfirmEndpointUseCase,
    };

    /// A push stream at the payroll app for `signal_types`, about everyone,
    /// asking for no header.
    fn request(signal_types: Vec<SecuritySignalType>) -> RegisterRequest {
        RegisterRequest {
            endpoint: PublicHttpsUrl::new("https://app.acme.com/sse").unwrap(),
            delivery_method: DeliveryMethod::Push,
            authorization: ReceiverHeader::NotRequired,
            signal_types,
            default_subjects: DefaultSubjects::All,
        }
    }

    /// The payroll app's stream for revoked sessions.
    fn revoked_sessions() -> RegisterRequest {
        request(vec![SecuritySignalType::SessionRevoked])
    }

    /// The use case with the fakes a test looks into.
    struct Registration {
        store: Arc<FakeSignalStreamStore>,
        deliverer: Arc<FakeSignalDeliverer>,
        queue: Arc<FakeSignalPollQueue>,
        use_case: RegisterUseCase,
    }

    /// A registration by a caller holding `authorities`, in a tenant that
    /// has a signing key.
    fn registration(authorities: FakeTenantAuthorities) -> Registration {
        let store = Arc::new(FakeSignalStreamStore::empty());
        let deliverer = Arc::new(FakeSignalDeliverer::new());
        let queue = Arc::new(FakeSignalPollQueue::empty());
        let use_case = RegisterUseCase::new(RegisterPorts {
            stream_store: store.clone(),
            transmit: TransmitPorts {
                deliverer: deliverer.clone(),
                poll_queue: queue.clone(),
                key_store: Arc::new(FakeSigningKeyStore::holding(premigration_keys())),
                ..TransmitPorts::fakes()
            },
            tenant_authorities: Arc::new(authorities),
            ..RegisterPorts::fakes()
        });
        Registration {
            store,
            deliverer,
            queue,
            use_case,
        }
    }

    /// Runs the registration of `request`, recording into `audit`.
    fn registered(
        registration: &Registration,
        audit: &Arc<FakeEventDispatcher>,
        request: RegisterRequest,
    ) -> Result<Registered, AppError> {
        block_on(
            registration
                .use_case
                .execute(&test_ctx(), &test_auditor(audit.clone()), request),
        )
    }

    /// The id of the stream [`registered`] registers.
    fn register(
        registration: &Registration,
        audit: &Arc<FakeEventDispatcher>,
        request: RegisterRequest,
    ) -> Result<SignalStreamId, AppError> {
        registered(registration, audit, request).map(|made| made.stream_id)
    }

    /// Ann registers the payroll app's stream. She is shown the key its
    /// receiver manages it with once, and the stream keeps only the key's
    /// digest.
    #[test]
    fn the_receivers_key_is_shown_once_and_kept_as_a_digest() {
        let registration = registration(FakeTenantAuthorities::holding_everything());

        let made = registered(
            &registration,
            &Arc::new(FakeEventDispatcher::new()),
            revoked_sessions(),
        )
        .unwrap();

        assert_eq!(made.receiver_key.expose(), "receiver-key-1");
        assert_eq!(
            registration.store.stored(&made.stream_id).receiver_key(),
            &FakeReceiverKeys::digest_of("receiver-key-1")
        );
    }

    /// Ann registers the payroll app's stream for revoked sessions. It is
    /// stored, waiting on its endpoint, and the registration recorded.
    #[test]
    fn a_stream_is_registered_waiting_on_its_endpoint() {
        let registration = registration(FakeTenantAuthorities::holding_everything());
        let audit = Arc::new(FakeEventDispatcher::new());

        let id = register(&registration, &audit, revoked_sessions()).unwrap();

        let stored = registration.store.stored(&id);
        assert_eq!(stored.verification(), StreamVerificationStatus::Pending);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["signals.stream_registered"]
        );
    }

    /// The payroll app's endpoint, and only it, is pushed a signed
    /// verification event carrying the challenge it must echo.
    #[test]
    fn the_endpoint_is_sent_its_challenge_as_a_verification_event() {
        let registration = registration(FakeTenantAuthorities::holding_everything());

        register(
            &registration,
            &Arc::new(FakeEventDispatcher::new()),
            revoked_sessions(),
        )
        .unwrap();

        let sent = registration.deliverer.challenges();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0.as_str(), "https://app.acme.com/sse");
        assert_eq!(registration.deliverer.signal_pushes(), 0);
    }

    /// The payroll app echoes the challenge it was sent, in a later request
    /// that reads the stream back. The challenge was stored with the
    /// stream, so the endpoint is verified.
    #[test]
    fn the_challenge_sent_confirms_the_endpoint_later() {
        let registration = registration(FakeTenantAuthorities::holding_everything());
        let id = register(
            &registration,
            &Arc::new(FakeEventDispatcher::new()),
            revoked_sessions(),
        )
        .unwrap();
        let confirm = ConfirmEndpointUseCase::new(ConfirmEndpointPorts {
            stream_store: registration.store.clone(),
        });

        block_on(confirm.execute(
            &test_ctx().tenant(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            ConfirmEndpointRequest {
                stream_id: id,
                echoed: registration.deliverer.last_challenge(),
            },
        ))
        .unwrap();

        let stored = registration.store.stored(&id);
        assert_eq!(stored.verification(), StreamVerificationStatus::Verified);
    }

    /// Ann registers a stream the payroll app polls. Its challenge waits in
    /// the stream's queue and nothing is pushed.
    #[test]
    fn a_poll_stream_has_its_challenge_queued() {
        let registration = registration(FakeTenantAuthorities::holding_everything());

        let id = register(
            &registration,
            &Arc::new(FakeEventDispatcher::new()),
            RegisterRequest {
                delivery_method: DeliveryMethod::Poll,
                ..revoked_sessions()
            },
        )
        .unwrap();

        assert_eq!(registration.queue.held_for(&id).len(), 1);
        assert!(registration.deliverer.pushes.lock().unwrap().is_empty());
    }

    /// The payroll app asks its pushes to carry `Bearer rcv-token`. The
    /// stream keeps it sealed, and the challenge carries it.
    #[test]
    fn the_receivers_header_is_kept_sealed_and_sent() {
        let registration = registration(FakeTenantAuthorities::holding_everything());

        let id = register(
            &registration,
            &Arc::new(FakeEventDispatcher::new()),
            RegisterRequest {
                authorization: ReceiverHeader::Header(Secret::new("Bearer rcv-token")),
                ..revoked_sessions()
            },
        )
        .unwrap();

        assert_eq!(
            registration.store.stored(&id).authorization(),
            &ReceiverAuthorization::Header(FakeEncryptor::sealed_for(
                "Bearer rcv-token",
                &header_place(&test_ctx().tenant(), &id)
            ))
        );
        let pushed = registration.deliverer.verifications();
        assert_eq!(pushed[0].header().as_deref(), Some("Bearer rcv-token"));
    }

    /// Ann registers a stream that starts with nobody. It hears about Bob
    /// only once he is added.
    #[test]
    fn a_stream_may_start_hearing_about_nobody() {
        let registration = registration(FakeTenantAuthorities::holding_everything());

        let id = register(
            &registration,
            &Arc::new(FakeEventDispatcher::new()),
            RegisterRequest {
                default_subjects: DefaultSubjects::None,
                ..revoked_sessions()
            },
        )
        .unwrap();

        let bob = SignalSubject::User(UserId::new());
        assert!(!registration.store.stored(&id).subjects().covers(&bob));
    }

    /// Ann names no signal type. It is refused, rather than read as every
    /// signal about every user.
    #[test]
    fn a_stream_naming_no_type_is_refused() {
        let registration = registration(FakeTenantAuthorities::holding_everything());
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = register(&registration, &audit, request(Vec::new()));

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(registration.store.count(), 0);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Stream viewing rights do not permit registration; the request is
    /// forbidden without saving a stream, pushing a message or recording an event.
    #[test]
    fn a_caller_without_the_signals_right_is_refused() {
        let registration = registration(FakeTenantAuthorities::holding(&[
            SystemPermission::Signals(SignalsAction::View),
        ]));
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = register(&registration, &audit, revoked_sessions());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(registration.store.count(), 0);
        assert!(registration.deliverer.pushes.lock().unwrap().is_empty());
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Registering a stream with a signed-out session returns an
    /// unauthenticated error.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let registration = registration(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = register(
            &registration,
            &Arc::new(FakeEventDispatcher::new()),
            revoked_sessions(),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
