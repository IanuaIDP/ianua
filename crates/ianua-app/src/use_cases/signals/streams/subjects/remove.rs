//! Remove subject: make a signal stream stop hearing about a user or agent,
//! as a Shared Signals receiver asks with `remove_subject`.

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

/// Which stream should stop hearing about which subject.
pub struct RemoveSubjectRequest {
    /// The stream to change.
    pub stream_id: SignalStreamId,
    /// The user or agent it should stop hearing about.
    pub subject: SignalSubject,
}

/// The ports [`RemoveSubjectUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RemoveSubjectPorts {
    /// Where streams are kept.
    pub stream_store: Arc<dyn SignalStreamStore>,
    /// Whether the user or agent named is the tenant's.
    pub principals: Arc<dyn PrincipalExistenceChecker>,
    /// Hashes the key a receiver presents.
    pub receiver_keys: Arc<dyn ReceiverKeys>,
    /// What a person holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Makes a signal stream stop hearing about a user or agent.
pub struct RemoveSubjectUseCase {
    ports: RemoveSubjectPorts,
}

impl RemoveSubjectUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RemoveSubjectPorts) -> Self {
        Self { ports }
    }
}

impl Command for RemoveSubjectUseCase {
    type Caller = SignalsCaller;
    type Input = RemoveSubjectRequest;
    type Output = Result<(), AppError>;

    /// Makes the stream stop hearing about `request.subject` and records
    /// `signals.subject_removed`. A subject it already does not hear about
    /// changes and records nothing.
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
        request: RemoveSubjectRequest,
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
            .remove_subject(request.subject, &manager)
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
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::UserId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::signals::{FakeSignalStreamStore, TEST_RECEIVER_KEY, test_stream};
    use crate::test_support::{
        FakeEventDispatcher, FakePrincipalChecker, block_on, test_auditor, test_ctx,
    };
    use crate::use_cases::signals::caller::ReceiverCaller;

    /// The payroll app's stream, hearing about everyone, and its id.
    fn seeded() -> (Arc<FakeSignalStreamStore>, SignalStreamId) {
        let row = test_stream(StreamStatus::Active, StreamVerificationStatus::Verified);
        let id = row.id;
        let store = FakeSignalStreamStore::holding(test_ctx().tenant_id(), row);
        (Arc::new(store), id)
    }

    /// Runs the use case as `caller`, for a person holding `authorities`,
    /// with `principals` saying who the tenant has.
    fn remove_as(
        caller: &SignalsCaller,
        store: Arc<FakeSignalStreamStore>,
        authorities: FakeTenantAuthorities,
        principals: FakePrincipalChecker,
        request: RemoveSubjectRequest,
    ) -> (Result<(), AppError>, Arc<FakeEventDispatcher>) {
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = RemoveSubjectUseCase::new(RemoveSubjectPorts {
            stream_store: store,
            principals: Arc::new(principals),
            tenant_authorities: Arc::new(authorities),
            ..RemoveSubjectPorts::fakes()
        });
        let result = block_on(use_case.execute(caller, &test_auditor(audit.clone()), request));
        (result, audit)
    }

    /// Runs the use case as Ann, holding `authorities`.
    fn remove(
        store: Arc<FakeSignalStreamStore>,
        authorities: FakeTenantAuthorities,
        request: RemoveSubjectRequest,
    ) -> (Result<(), AppError>, Arc<FakeEventDispatcher>) {
        let ann = SignalsCaller::Person(test_ctx());
        let principals = FakePrincipalChecker::accepting();
        remove_as(&ann, store, authorities, principals, request)
    }

    /// Bob leaves the payroll team, and Ann removes him from its stream.
    /// It no longer hears about him, and the change is recorded.
    #[test]
    fn a_removed_user_is_no_longer_heard_about() {
        let (store, id) = seeded();
        let bob = SignalSubject::User(UserId::new());

        let (result, audit) = remove(
            store.clone(),
            FakeTenantAuthorities::holding_everything(),
            RemoveSubjectRequest {
                stream_id: id,
                subject: bob,
            },
        );

        result.unwrap();
        assert!(!store.stored(&id).subjects().covers(&bob));
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["signals.subject_removed"]
        );
    }

    /// The payroll app's receiver removes Bob with the key its stream was
    /// registered with. Its stream no longer hears about him.
    #[test]
    fn the_streams_own_receiver_removes_a_subject_with_its_key() {
        let (store, id) = seeded();
        let bob = SignalSubject::User(UserId::new());
        let receiver = SignalsCaller::Receiver(ReceiverCaller {
            tenant: test_ctx().tenant(),
            stream_id: id,
            key: Secret::new(TEST_RECEIVER_KEY),
        });

        let (result, _) = remove_as(
            &receiver,
            store.clone(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            FakePrincipalChecker::accepting(),
            RemoveSubjectRequest {
                stream_id: id,
                subject: bob,
            },
        );

        result.unwrap();
        assert!(!store.stored(&id).subjects().covers(&bob));
    }

    /// A receiver names a user the tenant never had. It is not found, and
    /// nothing changes or is recorded.
    #[test]
    fn a_subject_the_tenant_does_not_have_is_not_found() {
        let (store, id) = seeded();

        let (result, audit) = remove_as(
            &SignalsCaller::Person(test_ctx()),
            store,
            FakeTenantAuthorities::holding_everything(),
            FakePrincipalChecker::rejecting(),
            RemoveSubjectRequest {
                stream_id: id,
                subject: SignalSubject::User(UserId::new()),
            },
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Ann names a stream the tenant does not have. It is not found.
    #[test]
    fn an_unknown_stream_is_not_found() {
        let (store, _) = seeded();

        let (result, _) = remove(
            store,
            FakeTenantAuthorities::holding_everything(),
            RemoveSubjectRequest {
                stream_id: SignalStreamId::new(),
                subject: SignalSubject::User(UserId::new()),
            },
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Stream viewing rights do not permit removing a subject; the request
    /// is forbidden, the stream still covers them and no event is recorded.
    #[test]
    fn a_viewer_may_not_remove_a_subject() {
        let (store, id) = seeded();
        let sam = SignalSubject::User(UserId::new());

        let (result, audit) = remove(
            store.clone(),
            FakeTenantAuthorities::holding(&[SystemPermission::Signals(SignalsAction::View)]),
            RemoveSubjectRequest {
                stream_id: id,
                subject: sam,
            },
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(store.stored(&id).subjects().covers(&sam));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Removing a subject with a signed-out session returns an
    /// unauthenticated error.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = seeded();

        let (result, _) = remove(
            store,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            RemoveSubjectRequest {
                stream_id: id,
                subject: SignalSubject::User(UserId::new()),
            },
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
