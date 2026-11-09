//! Dispatch signal: hand one security signal to one stream, pushed to a
//! push stream and held for a poll stream.
//!
//! The worker runs this from a signal job, one per signal and stream, so a
//! slow or unreachable receiver never holds up the request behind it nor
//! another receiver. A push that fails is tried again on the job's backoff
//! until the stream's failures switch it off.

use std::sync::Arc;

use ianua_domain::domains::signals::signal::SecuritySignal;
use ianua_domain::domains::signals::stream::{DeliveryMethod, SignalStream};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{FailureLimit, SignalStreamId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::runtime::UnitOfWork;
use crate::ports::signals::SignalStreamStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::signals::delivery::push::Push;
use crate::use_cases::signals::transmit::TransmitPorts;

/// The ports [`DispatchSignalUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DispatchSignalPorts {
    /// Where streams are kept, and their delivery attempts.
    pub stream_store: Arc<dyn SignalStreamStore>,
    /// Signs the Security Event Token under the tenant's issuer, and pushes
    /// or holds it.
    pub transmit: TransmitPorts,
    /// Keeps a stream switched off and the record of it together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// One signal to hand to one stream.
pub struct DispatchSignalRequest {
    /// The configured recipient of this security event.
    pub stream_id: SignalStreamId,
    /// The signal, under the id it was raised with.
    pub signal: SecuritySignal,
}

/// How handing a signal to a stream went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dispatched {
    /// The receiver took the push.
    Delivered,
    /// The token is held for the receiver to poll.
    Queued,
    /// The push or the hold failed, and the stream stays on.
    Failed,
    /// The push failed and its failures switched the stream off.
    SwitchedOff,
    /// Nothing was sent: the stream is gone, paused, unverified, or does
    /// not take the signal, or the tenant has no key to sign it with.
    Skipped,
}

/// Hands a security signal to one stream.
///
/// No caller asks for it, so its caller is `()`. The signal names its
/// tenant, and the auditor it is handed records only a stream the push
/// switched off.
pub struct DispatchSignalUseCase {
    ports: DispatchSignalPorts,
    disable_after: FailureLimit,
}

impl DispatchSignalUseCase {
    /// A use case working through `ports`, switching a push stream off
    /// after `disable_after` failed pushes in a row. Each failed try of a
    /// signal counts.
    #[must_use]
    pub fn new(ports: DispatchSignalPorts, disable_after: FailureLimit) -> Self {
        Self {
            ports,
            disable_after,
        }
    }

    /// The stream `id` of `tenant`, when it takes `signal` now.
    async fn receiver(
        &self,
        tenant: &ScopedTenant,
        id: &SignalStreamId,
        signal: &SecuritySignal,
    ) -> Result<Option<SignalStream<ResolvedTenant>>, AppError> {
        let stream = self
            .ports
            .stream_store
            .find_by_id(tenant, id)
            .await
            .or_internal()?;
        Ok(stream.filter(|stream| stream.receives(signal)))
    }
}

impl Command for DispatchSignalUseCase {
    type Caller = ();
    type Input = DispatchSignalRequest;
    type Output = Result<Dispatched, AppError>;

    /// Hands `request.signal` to its stream when the stream takes it now:
    /// active, its endpoint verified, listing the signal's type and hearing
    /// about the signal's user or agent.
    ///
    /// A push stream is pushed the signed token, with the `Authorization`
    /// header its receiver asked for. A poll stream has the token held for
    /// its receiver and a `Queued` record. A stream that does not take the
    /// signal gets nothing, not even a record, and a tenant with no signing
    /// key sends nothing rather than sending it unsigned. A stream switched
    /// off by its failures is recorded as `signals.stream_disabled` through
    /// `auditor`, in one unit with the stream it switched off.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the signal's tenant or its organization
    ///   no longer exists.
    /// - `AppError::Internal` when the stream, the tenant, the organization
    ///   or the signing keys cannot be read.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        request: DispatchSignalRequest,
    ) -> Result<Dispatched, AppError> {
        let signal = request.signal;
        let tenant = ScopedTenant::for_background(*signal.tenant_id());
        let Some(stream) = self.receiver(&tenant, &request.stream_id, &signal).await? else {
            return Ok(Dispatched::Skipped);
        };
        let transmitter = self.ports.transmit.transmitter();
        let Some(signing) = transmitter.signing(&tenant).await? else {
            return Ok(Dispatched::Skipped);
        };
        let push = Push {
            streams: self.ports.stream_store.as_ref(),
            transmitter: &transmitter,
            signing: &signing,
            unit: self.ports.unit_of_work.as_ref(),
            auditor,
            tenant: &tenant,
            signal: &signal,
            disable_after: self.disable_after,
        };
        let dispatched = match stream.delivery_method() {
            DeliveryMethod::Push => push.to(stream).await,
            DeliveryMethod::Poll => push.queue(&stream).await,
        };
        Ok(dispatched)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use ianua_domain::domains::crypto::jwt_type::JwtType;
    use ianua_domain::domains::signals::delivery::{ReceiverAuthorization, SignalDeliveryStatus};
    use ianua_domain::domains::signals::signal::{
        NewSecuritySignal, SecuritySignalType, SignalEvent, SignalSubject,
    };
    use ianua_domain::domains::signals::stream::{
        SignalStreamRow, StreamStatus, StreamVerificationStatus,
    };
    use ianua_domain::domains::signals::subjects::StreamSubjects;
    use ianua_domain::shared::clock;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::{AgentId, DeliveryOutcome, HttpsUrl, OrganizationId, UserId};

    use super::*;
    use crate::ports::crypto::{JwtSigner, JwtSigningKey};
    use crate::ports::runtime::Settlement;
    use crate::ports::shared::EventDispatcher;
    use crate::services::issuers::TenantIssuers;
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::crypto::{FakeJwtSigner, FakeSigningKeyStore, premigration_keys};
    use crate::test_support::organization::{org_store_with, test_org};
    use crate::test_support::signals::{
        FakeSignalDeliverer, FakeSignalPollQueue, FakeSignalStreamStore, test_stream,
    };
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_with_id};
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, RecordingUnitOfWork, block_on, test_auditor,
        test_ctx,
    };
    use crate::use_cases::signals::streams::verification::receiver_header::header_place;

    const DISABLE_AFTER: u32 = 3;

    /// Remembers the kind of token each signature was for.
    #[derive(Default)]
    struct TypeRecordingSigner {
        types: Mutex<Vec<JwtType>>,
    }

    #[async_trait]
    impl JwtSigner for TypeRecordingSigner {
        async fn sign_typed(
            &self,
            claims_json: &str,
            typ: JwtType,
            _: JwtSigningKey<'_>,
        ) -> Result<String, DomainError> {
            self.types.lock().unwrap().push(typ);
            Ok(format!("header.{claims_json}.sig_test"))
        }
    }

    /// The fakes a test looks into, the stream it sends to, and the ports
    /// holding them.
    struct Dispatch {
        streams: Arc<FakeSignalStreamStore>,
        deliverer: Arc<FakeSignalDeliverer>,
        queue: Arc<FakeSignalPollQueue>,
        stream_id: SignalStreamId,
        ports: DispatchSignalPorts,
    }

    /// Resolves Acme's prod issuer from its tenant and organization records.
    fn prod_issuers() -> TenantIssuers {
        let organization_id = OrganizationId::new();
        let tenant = test_tenant_with_id(
            test_ctx().tenant_id(),
            organization_id,
            "prod",
            "prod.acme.com",
        );
        TenantIssuers::new(
            Arc::new(FakeTenantStore::holding(tenant)),
            org_store_with([test_org(organization_id, "acme")]),
            HttpsUrl::new("https://idp.example.com").unwrap(),
        )
    }

    /// Acme's prod tenant, whose `row` stream, the tenant and its key are
    /// on file, pushing through `deliverer`.
    fn dispatch_to(row: SignalStreamRow, deliverer: FakeSignalDeliverer) -> Dispatch {
        let stream_id = row.id;
        let streams = Arc::new(FakeSignalStreamStore::holding(test_ctx().tenant_id(), row));
        let deliverer = Arc::new(deliverer);
        let queue = Arc::new(FakeSignalPollQueue::empty());
        let ports = DispatchSignalPorts {
            stream_store: streams.clone(),
            transmit: TransmitPorts {
                key_store: Arc::new(FakeSigningKeyStore::holding(premigration_keys())),
                jwt_signer: Arc::new(FakeJwtSigner::default()),
                deliverer: deliverer.clone(),
                poll_queue: queue.clone(),
                encryptor: Arc::new(FakeEncryptor),
                issuers: prod_issuers(),
            },
            unit_of_work: Arc::new(RecordingUnitOfWork::default()),
        };
        Dispatch {
            streams,
            deliverer,
            queue,
            stream_id,
            ports,
        }
    }

    /// The use case over `ports`.
    fn use_case(ports: DispatchSignalPorts) -> DispatchSignalUseCase {
        DispatchSignalUseCase::new(ports, FailureLimit::new(DISABLE_AFTER).unwrap())
    }

    /// A signal that `subject`'s session was revoked.
    fn revoked_session_of(subject: SignalSubject) -> SecuritySignal {
        SecuritySignal::new(NewSecuritySignal {
            tenant_id: test_ctx().tenant_id(),
            subject,
            event: SignalEvent::SessionRevoked,
            occurred_at: clock::now(),
        })
        .unwrap()
    }

    /// A signal that some user's session was revoked.
    fn revoked_session() -> SecuritySignal {
        revoked_session_of(SignalSubject::User(UserId::new()))
    }

    /// Hands `signal` to the stream `stream_id` through `use_case`,
    /// recording into `audit`.
    fn dispatch_signal(
        use_case: &DispatchSignalUseCase,
        stream_id: SignalStreamId,
        audit: Arc<dyn EventDispatcher>,
        signal: SecuritySignal,
    ) -> Dispatched {
        let request = DispatchSignalRequest { stream_id, signal };
        block_on(use_case.execute(&(), &test_auditor(audit), request)).unwrap()
    }

    /// Hands a revoked session to the fixture's stream, and says how it went.
    fn dispatch(fixture: Dispatch, audit: Arc<dyn EventDispatcher>) -> Dispatched {
        let stream_id = fixture.stream_id;
        dispatch_signal(
            &use_case(fixture.ports),
            stream_id,
            audit,
            revoked_session(),
        )
    }

    /// The payroll app's active push stream, its endpoint verified.
    fn verified_push_stream() -> SignalStreamRow {
        test_stream(StreamStatus::Active, StreamVerificationStatus::Verified)
    }

    fn quiet() -> Arc<dyn EventDispatcher> {
        Arc::new(FakeEventDispatcher::new())
    }

    /// A session is revoked, and the payroll app's verified stream for
    /// revoked sessions is pushed it. The delivered attempt is kept.
    #[test]
    fn a_receiving_push_stream_is_pushed_the_signal() {
        let fixture = dispatch_to(verified_push_stream(), FakeSignalDeliverer::new());
        let (streams, deliverer) = (fixture.streams.clone(), fixture.deliverer.clone());

        let dispatched = dispatch(fixture, quiet());

        assert_eq!(dispatched, Dispatched::Delivered);
        assert_eq!(deliverer.signal_pushes(), 1);
        let attempts = streams.attempts.lock().unwrap();
        assert_eq!(attempts.len(), 1);
        assert_eq!(
            attempts[0].1.delivery.status(),
            SignalDeliveryStatus::Success
        );
    }

    /// The payroll app asked its pushes to carry `Bearer rcv-token`. The
    /// push carries it, opened from its sealed copy.
    #[test]
    fn a_push_carries_the_receivers_header() {
        let mut row = verified_push_stream();
        row.authorization = ReceiverAuthorization::Header(FakeEncryptor::sealed_for(
            "Bearer rcv-token",
            &header_place(&test_ctx().tenant(), &row.id),
        ));
        let fixture = dispatch_to(row, FakeSignalDeliverer::new());
        let deliverer = fixture.deliverer.clone();

        dispatch(fixture, quiet());

        let pushes = deliverer.pushes.lock().unwrap();
        assert_eq!(pushes[0].header().as_deref(), Some("Bearer rcv-token"));
    }

    /// A stream for locked accounts is not pushed a revoked session.
    #[test]
    fn a_stream_not_listing_the_type_is_skipped() {
        let mut row = verified_push_stream();
        row.signal_types = vec![SecuritySignalType::AccountLocked];
        let fixture = dispatch_to(row, FakeSignalDeliverer::new());
        let (streams, deliverer) = (fixture.streams.clone(), fixture.deliverer.clone());

        let dispatched = dispatch(fixture, quiet());

        assert_eq!(dispatched, Dispatched::Skipped);
        assert_eq!(deliverer.signal_pushes(), 0);
        assert!(streams.attempts.lock().unwrap().is_empty());
    }

    /// A stream that hears only about Ann is not pushed Bob's revoked
    /// session.
    #[test]
    fn a_stream_not_hearing_about_the_subject_is_skipped() {
        let ann = SignalSubject::User(UserId::new());
        let mut row = verified_push_stream();
        row.subjects = StreamSubjects::Only(vec![ann]);
        let fixture = dispatch_to(row, FakeSignalDeliverer::new());
        let deliverer = fixture.deliverer.clone();

        dispatch(fixture, quiet());

        assert_eq!(deliverer.signal_pushes(), 0);
    }

    /// The billing agent's session is revoked. The stream hears about every
    /// subject, agents too, and is pushed it.
    #[test]
    fn a_signal_about_an_agent_is_pushed() {
        let fixture = dispatch_to(verified_push_stream(), FakeSignalDeliverer::new());
        let deliverer = fixture.deliverer.clone();
        let stream_id = fixture.stream_id;
        let agent = SignalSubject::Agent(AgentId::new());

        dispatch_signal(
            &use_case(fixture.ports),
            stream_id,
            quiet(),
            revoked_session_of(agent),
        );

        assert_eq!(deliverer.signal_pushes(), 1);
    }

    /// The payroll app's stream was deleted while the signal waited. It is
    /// skipped, so the job ends rather than failing on a stream that is
    /// gone.
    #[test]
    fn a_stream_that_is_gone_is_skipped() {
        let fixture = dispatch_to(verified_push_stream(), FakeSignalDeliverer::new());

        let dispatched = dispatch_signal(
            &use_case(fixture.ports),
            SignalStreamId::new(),
            quiet(),
            revoked_session(),
        );

        assert_eq!(dispatched, Dispatched::Skipped);
    }

    /// Dispatching to an unverified endpoint pushes nothing and stores no
    /// delivery attempt.
    #[test]
    fn a_stream_with_an_unverified_endpoint_is_sent_nothing() {
        let fixture = dispatch_to(
            test_stream(StreamStatus::Active, StreamVerificationStatus::Pending),
            FakeSignalDeliverer::new(),
        );
        let (streams, deliverer) = (fixture.streams.clone(), fixture.deliverer.clone());

        dispatch(fixture, quiet());

        assert!(deliverer.pushes.lock().unwrap().is_empty());
        assert!(streams.attempts.lock().unwrap().is_empty());
    }

    /// A paused stream is sent nothing and keeps no record.
    #[test]
    fn a_paused_stream_is_sent_nothing() {
        let fixture = dispatch_to(
            test_stream(StreamStatus::Paused, StreamVerificationStatus::Verified),
            FakeSignalDeliverer::new(),
        );
        let (streams, deliverer) = (fixture.streams.clone(), fixture.deliverer.clone());

        dispatch(fixture, quiet());

        assert!(deliverer.pushes.lock().unwrap().is_empty());
        assert!(streams.attempts.lock().unwrap().is_empty());
    }

    /// A poll stream has the signed token held for its receiver, gets a
    /// queued record, and is pushed nothing.
    #[test]
    fn a_poll_stream_is_queued_not_pushed() {
        let mut row = verified_push_stream();
        row.delivery_method = DeliveryMethod::Poll;
        let id = row.id;
        let fixture = dispatch_to(row, FakeSignalDeliverer::new());
        let (streams, deliverer, queue) = (
            fixture.streams.clone(),
            fixture.deliverer.clone(),
            fixture.queue.clone(),
        );

        let dispatched = dispatch(fixture, quiet());

        assert_eq!(dispatched, Dispatched::Queued);
        assert!(deliverer.pushes.lock().unwrap().is_empty());
        assert_eq!(queue.held_for(&id).len(), 1);
        let attempts = streams.attempts.lock().unwrap();
        assert_eq!(attempts.len(), 1);
        assert_eq!(
            attempts[0].1.delivery.status(),
            SignalDeliveryStatus::Queued
        );
    }

    /// The tenant has no signing key. Nothing is pushed rather than sent
    /// unsigned.
    #[test]
    fn nothing_is_pushed_without_a_signing_key() {
        let mut fixture = dispatch_to(verified_push_stream(), FakeSignalDeliverer::new());
        fixture.ports.transmit.key_store = Arc::new(FakeSigningKeyStore::empty());
        let (streams, deliverer) = (fixture.streams.clone(), fixture.deliverer.clone());

        let dispatched = dispatch(fixture, quiet());

        assert_eq!(dispatched, Dispatched::Skipped);
        assert!(deliverer.pushes.lock().unwrap().is_empty());
        assert!(streams.attempts.lock().unwrap().is_empty());
    }

    /// The payroll app's receiver is down. The push fails and the stream
    /// stays on, so the signal's job tries it again.
    #[test]
    fn a_failed_push_says_so() {
        let fixture = dispatch_to(
            verified_push_stream(),
            FakeSignalDeliverer::always(DeliveryOutcome::Unreachable),
        );

        assert_eq!(dispatch(fixture, quiet()), Dispatched::Failed);
    }

    /// The payroll app's receiver is down for three pushes in a row. Its
    /// stream is switched off, and that is recorded once.
    #[test]
    fn a_stream_failing_past_the_limit_is_disabled_and_recorded() {
        let row = verified_push_stream();
        let id = row.id;
        let fixture = dispatch_to(
            row,
            FakeSignalDeliverer::always(DeliveryOutcome::Unreachable),
        );
        let streams = fixture.streams.clone();
        let use_case = use_case(fixture.ports);
        let audit = Arc::new(FakeEventDispatcher::new());

        let mut last = Dispatched::Skipped;
        for _ in 0..DISABLE_AFTER {
            last = dispatch_signal(&use_case, id, audit.clone(), revoked_session());
        }

        assert_eq!(last, Dispatched::SwitchedOff);
        assert_eq!(streams.stored(&id).status(), StreamStatus::Disabled);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["signals.stream_disabled"]
        );
    }

    /// The payroll app's receiver fails its last allowed push, and the
    /// switch-off cannot be recorded. The stream and its record are one
    /// unit, so the switch-off is rolled back with the record.
    #[test]
    fn a_switch_off_that_cannot_be_recorded_is_rolled_back() {
        let mut row = verified_push_stream();
        row.consecutive_failures = DISABLE_AFTER - 1;
        let mut fixture = dispatch_to(
            row,
            FakeSignalDeliverer::always(DeliveryOutcome::Unreachable),
        );
        let unit = Arc::new(RecordingUnitOfWork::default());
        fixture.ports.unit_of_work = unit.clone();

        dispatch(fixture, Arc::new(FailingEventDispatcher));

        assert_eq!(unit.settlements(), [Settlement::Rollback]);
    }

    /// A push that worked clears the failure count, so a stream that keeps
    /// working is never switched off.
    #[test]
    fn a_stream_that_keeps_succeeding_is_never_disabled() {
        let row = verified_push_stream();
        let id = row.id;
        let fixture = dispatch_to(row, FakeSignalDeliverer::new());
        let streams = fixture.streams.clone();
        let use_case = use_case(fixture.ports);

        for _ in 0..=DISABLE_AFTER {
            dispatch_signal(&use_case, id, quiet(), revoked_session());
        }

        assert!(streams.stored(&id).is_active());
    }

    /// The receiver checks `iss` against the issuer the tenant's OIDC and
    /// SAML tokens carry. The signed token names that issuer.
    #[test]
    fn the_token_is_issued_by_the_tenants_own_issuer() {
        let mut fixture = dispatch_to(verified_push_stream(), FakeSignalDeliverer::new());
        let signer = Arc::new(FakeJwtSigner::default());
        fixture.ports.transmit.jwt_signer = signer.clone();

        dispatch(fixture, quiet());

        let signed = signer.signed.lock().unwrap();
        assert_eq!(signed.len(), 1);
        assert!(
            signed[0].contains(
                "\"iss\":\"https://idp.example.com/api/v1/organizations/acme/tenants/prod\""
            ),
            "{}",
            signed[0]
        );
    }

    /// The token is typed as a security event, so no receiver can mistake
    /// it for an access token and present it back as a credential.
    #[test]
    fn the_token_is_typed_as_a_security_event() {
        let mut fixture = dispatch_to(verified_push_stream(), FakeSignalDeliverer::new());
        let signer = Arc::new(TypeRecordingSigner::default());
        fixture.ports.transmit.jwt_signer = signer.clone();

        dispatch(fixture, quiet());

        assert_eq!(
            signer.types.lock().unwrap().as_slice(),
            [JwtType::SecurityEvent]
        );
    }
}
