//! Cancel access request: the person who asked withdraws their request
//! before anyone answers it.

use std::sync::Arc;

use ianua_domain::domains::authorization::access_request::AccessRequest;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::AccessRequestId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrConflict, OrInternal};
use crate::ports::authorization::AccessRequestStore;
use crate::use_case::Command;
use crate::use_cases::authorization::access_requests::lookup::{ANSWERED_MEANWHILE, owned_request};

/// The ports [`CancelUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CancelPorts {
    /// Loads and saves the request.
    pub request_store: Arc<dyn AccessRequestStore>,
    /// Who the caller is in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Withdraws the caller's own access request.
pub struct CancelUseCase {
    ports: CancelPorts,
}

impl CancelUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CancelPorts) -> Self {
        Self { ports }
    }
}

impl Command for CancelUseCase {
    type Caller = CallerContext;
    type Input = AccessRequestId;
    type Output = Result<AccessRequest<ResolvedTenant>, AppError>;

    /// Withdraws request `id` for the caller who asked it, and records it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such request, or the
    ///   caller is not the person who asked: someone else's request cannot
    ///   be told from one that is not there.
    /// - `AppError::Domain` when it was already answered, withdrawn or ran
    ///   out.
    /// - `AppError::Conflict` when it was answered or ran out meanwhile.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        id: AccessRequestId,
    ) -> Result<AccessRequest<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let store = self.ports.request_store.as_ref();
        let mut request = owned_request(store, &tenant, &id, &authority).await?;
        request.cancel(&authority).map_err(AppError::from_domain)?;

        store.save(&tenant, &request).await.or_conflict(message!(
            "authorization-the-request-was-answered-withdrawn-or",
            ANSWERED_MEANWHILE
        ))?;
        auditor
            .dispatch_by(&authority.actor(), request.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::access_request::{AccessRequestStatus, AskedAccess};
    use ianua_domain::shared::clock;
    use ianua_domain::types::RoleId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{FakeAccessRequestStore, pending_request_by};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A store holding a pending request made by `address`.
    fn asked_by(address: &str) -> (Arc<FakeAccessRequestStore>, AccessRequestId) {
        let request = pending_request_by(AskedAccess::Role(RoleId::new()), address, clock::now());
        let id = *request.id();
        let store = FakeAccessRequestStore::holding(test_ctx().tenant_id(), [request]);
        (Arc::new(store), id)
    }

    fn cancel(
        ports: CancelPorts,
        sink: &Arc<FakeEventDispatcher>,
        id: AccessRequestId,
    ) -> Result<AccessRequest<ResolvedTenant>, AppError> {
        block_on(CancelUseCase::new(ports).execute(&test_ctx(), &test_auditor(sink.clone()), id))
    }

    fn ports_over(store: &Arc<FakeAccessRequestStore>) -> CancelPorts {
        CancelPorts {
            request_store: store.clone(),
            ..CancelPorts::fakes()
        }
    }

    /// Ann no longer needs the access she asked for and withdraws it. It is
    /// cancelled and recorded.
    #[test]
    fn the_asker_withdraws_their_request() {
        let (store, id) = asked_by("caller@example.test");
        let sink = Arc::new(FakeEventDispatcher::new());

        cancel(ports_over(&store), &sink, id).unwrap();

        assert_eq!(
            store.status_of(test_ctx().tenant_id(), &id),
            Some(AccessRequestStatus::Cancelled)
        );
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.access_request_cancelled"]
        );
    }

    /// Bob's request is hidden from another caller attempting to withdraw it.
    /// It stays pending and no cancellation is recorded.
    #[test]
    fn someone_else_cannot_withdraw_it() {
        let (store, id) = asked_by("bob@acme.test");
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = cancel(ports_over(&store), &sink, id);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(
            store.status_of(test_ctx().tenant_id(), &id),
            Some(AccessRequestStatus::Pending)
        );
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Ann withdraws a request the tenant does not have. It is not found.
    #[test]
    fn an_unknown_request_is_not_found() {
        let (store, _) = asked_by("caller@example.test");

        let result = cancel(
            ports_over(&store),
            &Arc::new(FakeEventDispatcher::new()),
            AccessRequestId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out session cannot withdraw an access request.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = asked_by("caller@example.test");
        let ports = CancelPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(&store)
        };

        let result = cancel(ports, &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
