//! Approve impersonation: the person an admin asked to act as agrees, from
//! their own sign-in, and the admin's window starts.

use std::sync::Arc;

use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, SupportImpersonationId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrConflict, OrInternal};
use crate::ports::identity::SupportImpersonationStore;
use crate::use_case::Command;
use crate::use_cases::identity::impersonation::lookup::involving;

/// The ports [`ApproveUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ApprovePorts {
    /// Keeps the requests.
    pub impersonation_store: Arc<dyn SupportImpersonationStore>,
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lets an admin act as the person signed in, as they asked.
pub struct ApproveUseCase {
    ports: ApprovePorts,
}

impl ApproveUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ApprovePorts) -> Self {
        Self { ports }
    }
}

impl Command for ApproveUseCase {
    type Caller = CallerContext;
    type Input = SupportImpersonationId;
    type Output = Result<(), AppError>;

    /// Approves request `id` as the person signed in to `ctx`'s session,
    /// whom it names, and records `identity.support_impersonation_started`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` without a valid tenant session; `NotFound` for no request involving the caller.
    /// - `AppError::Forbidden` unless the caller is the impersonated person, preventing self-approval by the requester.
    /// - `AppError::Conflict` after a day or a concurrent decline/end; `Domain` for a request not awaiting an answer.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        id: SupportImpersonationId,
    ) -> Result<(), AppError> {
        let person = self.ports.tenant_authorities.signed_in(ctx).await?;
        let tenant = ctx.tenant();
        let store = self.ports.impersonation_store.as_ref();
        let mut impersonation = involving(store, &tenant, &id, person.account.id()).await?;
        impersonation
            .approve(&person.signed_in, clock::now())
            .map_err(AppError::from_domain)?;

        store
            .save(&tenant, &impersonation)
            .await
            .or_conflict(message!(
                "identity-the-request-was-answered-or-ended",
                "the request was answered or ended meanwhile"
            ))?;
        auditor
            .dispatch_by(
                &ActorRef::User(*person.account.id()),
                impersonation.take_events(&tenant),
            )
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::impersonation::state::ImpersonationStatus;
    use ianua_domain::types::UserId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::test_caller_id;
    use crate::test_support::identity::{FakeSupportImpersonationStore, impersonation_asked};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn approve(
        store: &Arc<FakeSupportImpersonationStore>,
        id: SupportImpersonationId,
        authorities: FakeTenantAuthorities,
    ) -> (Result<(), AppError>, Arc<FakeEventDispatcher>) {
        let sink = Arc::new(FakeEventDispatcher::new());
        let use_case = ApproveUseCase::new(ApprovePorts {
            impersonation_store: store.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        let result = block_on(use_case.execute(&test_ctx(), &test_auditor(sink.clone()), id));
        (result, sink)
    }

    /// Sam asked to act as Ann. Ann approves from her own sign-in; Sam's
    /// window starts and it is recorded.
    #[test]
    fn the_person_approves_and_the_window_starts() {
        let asked = impersonation_asked(UserId::new(), test_caller_id());
        let id = *asked.id();
        let store = Arc::new(FakeSupportImpersonationStore::holding(&asked));

        let (result, sink) = approve(&store, id, FakeTenantAuthorities::holding_everything());

        result.unwrap();
        assert_eq!(
            store.stored(&id).unwrap().status(),
            ImpersonationStatus::Active
        );
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["identity.support_impersonation_started"]
        );
    }

    /// An administrator cannot approve their own impersonation request.
    /// It stays awaiting consent, and no start event is recorded.
    #[test]
    fn the_admin_cannot_approve_their_own_request() {
        let asked = impersonation_asked(test_caller_id(), UserId::new());
        let id = *asked.id();
        let store = Arc::new(FakeSupportImpersonationStore::holding(&asked));

        let (result, sink) = approve(&store, id, FakeTenantAuthorities::holding_everything());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(
            store.stored(&id).unwrap().status(),
            ImpersonationStatus::AwaitingConsent
        );
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Approving an impersonation request between other people returns not found.
    #[test]
    fn a_request_between_others_is_not_found() {
        let asked = impersonation_asked(UserId::new(), UserId::new());
        let id = *asked.id();
        let store = Arc::new(FakeSupportImpersonationStore::holding(&asked));

        let (result, _) = approve(&store, id, FakeTenantAuthorities::holding_everything());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out person cannot approve a request to impersonate them.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let asked = impersonation_asked(UserId::new(), test_caller_id());
        let id = *asked.id();
        let store = Arc::new(FakeSupportImpersonationStore::holding(&asked));

        let (result, _) = approve(
            &store,
            id,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
