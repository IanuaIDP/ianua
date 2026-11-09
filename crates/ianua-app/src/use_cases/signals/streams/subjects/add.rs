//! Add subject: make a signal stream hear about one more user or agent, as
//! a Shared Signals receiver asks with `add_subject`.

use std::sync::Arc;

use ianua_domain::domains::signals::control::SignalsControlCheck as _;
use ianua_domain::domains::signals::signal::SignalSubject;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::SignalStreamId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::shared::PrincipalExistenceChecker;
use crate::ports::signals::{ReceiverKeys, SignalStreamStore, StreamChallenge};
use crate::use_case::Command;
use crate::use_cases::signals::caller::{ReceiverSignIn, SignalsCaller, StreamActor};
use crate::use_cases::signals::lookup::existing_stream;
use crate::use_cases::signals::streams::subjects::subject::ensure_subject_exists;

/// Which stream should hear about which subject.
pub struct AddSubjectRequest {
    /// The stream to change.
    pub stream_id: SignalStreamId,
    /// The user or agent it should hear about.
    pub subject: SignalSubject,
}

/// The ports [`AddSubjectUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AddSubjectPorts {
    /// Where streams are kept.
    pub stream_store: Arc<dyn SignalStreamStore>,
    /// Whether the user or agent named is the tenant's.
    pub principals: Arc<dyn PrincipalExistenceChecker>,
    /// Hashes the key a receiver presents.
    pub receiver_keys: Arc<dyn ReceiverKeys>,
    /// What a person holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Makes a signal stream hear about a user or agent.
pub struct AddSubjectUseCase {
    ports: AddSubjectPorts,
}

impl AddSubjectUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: AddSubjectPorts) -> Self {
        Self { ports }
    }
}

impl Command for AddSubjectUseCase {
    type Caller = SignalsCaller;
    type Input = AddSubjectRequest;
    type Output = Result<(), AppError>;

    /// Makes the stream hear about `request.subject` and records
    /// `signals.subject_added`. A subject it already hears about changes
    /// and records nothing.
    ///
    /// The stream's own receiver asks with its key; a person who may change
    /// signal streams may ask for any of the tenant's.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the session or key no longer
    ///   counts, or the receiver's key is not its stream's.
    /// - `AppError::Forbidden` when the person may not change signal
    ///   streams, or the receiver names another stream.
    /// - `AppError::NotFound` when the tenant has no such stream, or no
    ///   such user or agent.
    /// - `AppError::Domain` when the stream already lists the most subjects
    ///   it keeps.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &SignalsCaller,
        auditor: &RequestAuditor,
        request: AddSubjectRequest,
    ) -> Result<(), AppError> {
        let tenant = caller.tenant();
        let store = self.ports.stream_store.as_ref();
        let receivers = ReceiverSignIn {
            streams: store,
            keys: self.ports.receiver_keys.as_ref(),
        };
        let actor =
            StreamActor::of(caller, self.ports.tenant_authorities.as_ref(), receivers).await?;
        let mut stream = existing_stream(store, &tenant, &request.stream_id).await?;
        let manager = actor.manager();
        manager
            .ensure_may_manage(stream.id())
            .map_err(AppError::from_domain)?;
        ensure_subject_exists(self.ports.principals.as_ref(), &tenant, &request.subject).await?;
        stream
            .add_subject(request.subject, &manager)
            .map_err(AppError::from_domain)?;

        store
            .save(&tenant, &stream, StreamChallenge::Kept)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&caller.actor(), stream.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SignalsAction, SystemPermission};
    use ianua_domain::domains::signals::stream::{StreamStatus, StreamVerificationStatus};
    use ianua_domain::domains::signals::subjects::StreamSubjects;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{AgentId, UserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::signals::{FakeSignalStreamStore, TEST_RECEIVER_KEY, test_stream};
    use crate::test_support::{
        FakeEventDispatcher, FakePrincipalChecker, block_on, test_auditor, test_ctx,
    };
    use crate::use_cases::signals::caller::ReceiverCaller;

    /// The payroll app's stream, hearing about nobody yet, and its id.
    fn seeded() -> (Arc<FakeSignalStreamStore>, SignalStreamId) {
        let mut row = test_stream(StreamStatus::Active, StreamVerificationStatus::Verified);
        row.subjects = StreamSubjects::Only(Vec::new());
        let id = row.id;
        let store = FakeSignalStreamStore::holding(test_ctx().tenant_id(), row);
        (Arc::new(store), id)
    }

    /// The use case over `store`, for a person holding `authorities`.
    fn use_case(
        store: Arc<FakeSignalStreamStore>,
        authorities: FakeTenantAuthorities,
    ) -> AddSubjectUseCase {
        AddSubjectUseCase::new(AddSubjectPorts {
            stream_store: store,
            tenant_authorities: Arc::new(authorities),
            ..AddSubjectPorts::fakes()
        })
    }

    /// Runs `use_case` as `caller`.
    fn add_as(
        use_case: &AddSubjectUseCase,
        caller: &SignalsCaller,
        audit: &Arc<FakeEventDispatcher>,
        request: AddSubjectRequest,
    ) -> Result<(), AppError> {
        block_on(use_case.execute(caller, &test_auditor(audit.clone()), request))
    }

    /// Runs the use case for a person holding `authorities`.
    fn add(
        store: Arc<FakeSignalStreamStore>,
        authorities: FakeTenantAuthorities,
        audit: &Arc<FakeEventDispatcher>,
        request: AddSubjectRequest,
    ) -> Result<(), AppError> {
        let ann = SignalsCaller::Person(test_ctx());
        add_as(&use_case(store, authorities), &ann, audit, request)
    }

    /// Ann adds Bob to the payroll app's stream. It hears about him from
    /// now on, and the change is recorded.
    #[test]
    fn an_added_user_is_heard_about() {
        let (store, id) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());
        let bob = SignalSubject::User(UserId::new());

        add(
            store.clone(),
            FakeTenantAuthorities::holding_everything(),
            &audit,
            AddSubjectRequest {
                stream_id: id,
                subject: bob,
            },
        )
        .unwrap();

        assert!(store.stored(&id).subjects().covers(&bob));
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["signals.subject_added"]
        );
    }

    /// The payroll app's receiver adds Bob with the key its stream was
    /// registered with. Its stream hears about him, and the change is
    /// recorded.
    #[test]
    fn the_streams_own_receiver_adds_a_subject_with_its_key() {
        let (store, id) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());
        let bob = SignalSubject::User(UserId::new());
        let receiver = SignalsCaller::Receiver(ReceiverCaller {
            tenant: test_ctx().tenant(),
            stream_id: id,
            key: Secret::new(TEST_RECEIVER_KEY),
        });
        let use_case = use_case(
            store.clone(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        add_as(
            &use_case,
            &receiver,
            &audit,
            AddSubjectRequest {
                stream_id: id,
                subject: bob,
            },
        )
        .unwrap();

        assert!(store.stored(&id).subjects().covers(&bob));
        assert_eq!(audit.records.lock().unwrap().len(), 1);
    }

    /// Ann adds the billing agent. The stream hears about it too.
    #[test]
    fn an_added_agent_is_heard_about() {
        let (store, id) = seeded();
        let agent = SignalSubject::Agent(AgentId::new());

        add(
            store.clone(),
            FakeTenantAuthorities::holding_everything(),
            &Arc::new(FakeEventDispatcher::new()),
            AddSubjectRequest {
                stream_id: id,
                subject: agent,
            },
        )
        .unwrap();

        assert!(store.stored(&id).subjects().covers(&agent));
    }

    /// Adding a user absent from the tenant returns not found, leaves the
    /// user outside the stream's subjects and records no event.
    #[test]
    fn a_subject_the_tenant_does_not_have_is_not_found() {
        let (store, id) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());
        let ghost = SignalSubject::User(UserId::new());
        let use_case = AddSubjectUseCase::new(AddSubjectPorts {
            stream_store: store.clone(),
            principals: Arc::new(FakePrincipalChecker::rejecting()),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding_everything()),
            ..AddSubjectPorts::fakes()
        });

        let result = add_as(
            &use_case,
            &SignalsCaller::Person(test_ctx()),
            &audit,
            AddSubjectRequest {
                stream_id: id,
                subject: ghost,
            },
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(!store.stored(&id).subjects().covers(&ghost));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Ann adds Bob twice. The second time changes and records nothing.
    #[test]
    fn adding_a_subject_twice_records_it_once() {
        let (store, id) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());
        let bob = SignalSubject::User(UserId::new());
        let request = || AddSubjectRequest {
            stream_id: id,
            subject: bob,
        };

        for _ in 0..2 {
            add(
                store.clone(),
                FakeTenantAuthorities::holding_everything(),
                &audit,
                request(),
            )
            .unwrap();
        }

        assert_eq!(audit.records.lock().unwrap().len(), 1);
    }

    /// Ann names a stream the tenant does not have. It is not found.
    #[test]
    fn an_unknown_stream_is_not_found() {
        let (store, _) = seeded();

        let result = add(
            store,
            FakeTenantAuthorities::holding_everything(),
            &Arc::new(FakeEventDispatcher::new()),
            AddSubjectRequest {
                stream_id: SignalStreamId::new(),
                subject: SignalSubject::User(UserId::new()),
            },
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Stream viewing rights do not permit adding a subject; the request is
    /// forbidden, the subject remains excluded and no event is recorded.
    #[test]
    fn a_viewer_may_not_add_a_subject() {
        let (store, id) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());
        let mallory = SignalSubject::User(UserId::new());

        let result = add(
            store.clone(),
            FakeTenantAuthorities::holding(&[SystemPermission::Signals(SignalsAction::View)]),
            &audit,
            AddSubjectRequest {
                stream_id: id,
                subject: mallory,
            },
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(!store.stored(&id).subjects().covers(&mallory));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Adding a subject with a signed-out session returns an
    /// unauthenticated error.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = seeded();

        let result = add(
            store,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &Arc::new(FakeEventDispatcher::new()),
            AddSubjectRequest {
                stream_id: id,
                subject: SignalSubject::User(UserId::new()),
            },
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
