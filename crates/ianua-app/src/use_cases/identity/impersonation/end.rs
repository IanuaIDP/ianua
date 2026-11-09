//! End impersonation: the admin or the person ends an impersonation early,
//! or withdraws a request before it starts.

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

/// The ports [`EndUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct EndPorts {
    /// Keeps the requests.
    pub impersonation_store: Arc<dyn SupportImpersonationStore>,
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Ends an impersonation, by the admin or the person.
pub struct EndUseCase {
    ports: EndPorts,
}

impl EndUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: EndPorts) -> Self {
        Self { ports }
    }
}

impl Command for EndUseCase {
    type Caller = CallerContext;
    type Input = SupportImpersonationId;
    type Output = Result<(), AppError>;

    /// Ends impersonation `id` as the admin or the person signed in to
    /// `ctx`'s session, and records `identity.support_impersonation_ended`.
    /// The admin's next use of it is refused at once.
    ///
    /// Ann sees from her notification that support is acting as her and did
    /// not expect it. She ends it from her own sign-in.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller came with no tenant
    ///   session, or it no longer counts.
    /// - `AppError::NotFound` when there is no such impersonation involving
    ///   them.
    /// - `AppError::Domain` when it was already declined or ended.
    /// - `AppError::Conflict` when it was declined or ended while this
    ///   was under way.
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
            .end(&person.signed_in, clock::now())
            .map_err(AppError::from_domain)?;

        store
            .save(&tenant, &impersonation)
            .await
            .or_conflict(message!(
                "identity-the-impersonation-was-declined-or-ended",
                "the impersonation was declined or ended meanwhile"
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
    use crate::test_support::identity::{
        FakeSupportImpersonationStore, impersonation_active, impersonation_asked,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn end(
        store: &Arc<FakeSupportImpersonationStore>,
        id: SupportImpersonationId,
        authorities: FakeTenantAuthorities,
    ) -> (Result<(), AppError>, Arc<FakeEventDispatcher>) {
        let sink = Arc::new(FakeEventDispatcher::new());
        let use_case = EndUseCase::new(EndPorts {
            impersonation_store: store.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        let result = block_on(use_case.execute(&test_ctx(), &test_auditor(sink.clone()), id));
        (result, sink)
    }

    /// Support is acting as Ann. Ann ends it from her own sign-in; it is
    /// over and recorded.
    #[test]
    fn the_person_ends_it_early() {
        let active = impersonation_active(UserId::new(), test_caller_id());
        let id = *active.id();
        let store = Arc::new(FakeSupportImpersonationStore::holding(&active));

        let (result, sink) = end(&store, id, FakeTenantAuthorities::holding_everything());

        result.unwrap();
        assert_eq!(
            store.stored(&id).unwrap().status(),
            ImpersonationStatus::Ended
        );
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["identity.support_impersonation_ended"]
        );
    }

    /// Ann, the admin, withdraws her request before Bob answers it.
    #[test]
    fn the_admin_withdraws_a_request() {
        let asked = impersonation_asked(test_caller_id(), UserId::new());
        let id = *asked.id();
        let store = Arc::new(FakeSupportImpersonationStore::holding(&asked));

        let (result, _) = end(&store, id, FakeTenantAuthorities::holding_everything());

        result.unwrap();
        assert_eq!(
            store.stored(&id).unwrap().status(),
            ImpersonationStatus::Ended
        );
    }

    /// Ending an impersonation between other people returns not found and
    /// leaves it active.
    #[test]
    fn an_impersonation_between_others_is_not_found() {
        let active = impersonation_active(UserId::new(), UserId::new());
        let id = *active.id();
        let store = Arc::new(FakeSupportImpersonationStore::holding(&active));

        let (result, _) = end(&store, id, FakeTenantAuthorities::holding_everything());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(
            store.stored(&id).unwrap().status(),
            ImpersonationStatus::Active
        );
    }

    /// A signed-out person cannot end an impersonation involving them.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let active = impersonation_active(UserId::new(), test_caller_id());
        let id = *active.id();
        let store = Arc::new(FakeSupportImpersonationStore::holding(&active));

        let (result, _) = end(
            &store,
            id,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
