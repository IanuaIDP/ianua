//! Deny access request: say no to someone's request for a role or a group.
//!
//! Only someone who could approve it denies it, so Sam, who could not give
//! the role, cannot turn away every request for it either. Nobody answers
//! their own.

use std::sync::Arc;

use ianua_domain::domains::authorization::access_request::{
    AccessRequest, ensure_answers_requests,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::AccessRequestId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrConflict, OrInternal};
use crate::ports::authorization::{AccessRecordStore, AccessRequestStore, GroupStore, RoleStore};
use crate::use_case::Command;
use crate::use_cases::authorization::access_requests::lookup::{
    ANSWERED_MEANWHILE, AskedSources, existing_asked, existing_request,
};

/// The ports [`DenyUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DenyPorts {
    /// Loads and saves the request.
    pub request_store: Arc<dyn AccessRequestStore>,
    /// Loads the role asked for.
    pub role_store: Arc<dyn RoleStore>,
    /// Loads the group asked for.
    pub group_store: Arc<dyn GroupStore>,
    /// Reads who holds what, for what a group brings.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Denies an access request of the caller's tenant.
pub struct DenyUseCase {
    ports: DenyPorts,
}

impl DenyUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DenyPorts) -> Self {
        Self { ports }
    }
}

impl Command for DenyUseCase {
    type Caller = CallerContext;
    type Input = AccessRequestId;
    type Output = Result<AccessRequest<ResolvedTenant>, AppError>;

    /// Denies request `id` for the caller and records it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without role/group assignment rights, before reading the request.
    /// - `AppError::NotFound` for a missing request, role or group; `Forbidden` for deciding one's own request or access the caller could not grant directly.
    /// - `AppError::Conflict` for expiry or a concurrent answer/withdrawal.
    /// - `AppError::Domain` for an already answered/withdrawn request; `Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        id: AccessRequestId,
    ) -> Result<AccessRequest<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        ensure_answers_requests(&authority.standing()).map_err(AppError::from_domain)?;
        let store = self.ports.request_store.as_ref();
        let mut request = existing_request(store, &tenant, &id).await?;
        let sources = AskedSources::of(
            self.ports.role_store.as_ref(),
            self.ports.group_store.as_ref(),
            self.ports.access_records.as_ref(),
        );
        let asked = existing_asked(sources, &tenant, request.asked()).await?;
        request
            .deny(&asked.grant(), &authority)
            .map_err(AppError::from_domain)?;

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
    use crate::test_support::authorization::{
        FakeAccessRequestStore, FakeRoleStore, pending_request_by, stored_role,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A tenant with the "production" role and a request for it by
    /// `address`.
    fn tenant_asked_by(address: &str) -> (DenyPorts, Arc<FakeAccessRequestStore>, AccessRequestId) {
        let tenant = test_ctx().tenant_id();
        let role = stored_role("production", Vec::new(), Vec::new());
        let request = pending_request_by(AskedAccess::Role(*role.id()), address, clock::now());
        let id = *request.id();
        let requests = Arc::new(FakeAccessRequestStore::holding(tenant, [request]));
        let ports = DenyPorts {
            request_store: requests.clone(),
            role_store: Arc::new(FakeRoleStore::holding(tenant, [role])),
            ..DenyPorts::fakes()
        };
        (ports, requests, id)
    }

    fn deny(
        ports: DenyPorts,
        sink: &Arc<FakeEventDispatcher>,
        id: AccessRequestId,
    ) -> Result<AccessRequest<ResolvedTenant>, AppError> {
        block_on(DenyUseCase::new(ports).execute(&test_ctx(), &test_auditor(sink.clone()), id))
    }

    fn status(
        requests: &FakeAccessRequestStore,
        id: &AccessRequestId,
    ) -> Option<AccessRequestStatus> {
        requests.status_of(test_ctx().tenant_id(), id)
    }

    /// Ann denies Bob's request for "production". It is denied and
    /// recorded.
    #[test]
    fn a_request_is_denied_and_recorded() {
        let (ports, requests, id) = tenant_asked_by("bob@acme.test");
        let sink = Arc::new(FakeEventDispatcher::new());

        deny(ports, &sink, id).unwrap();

        assert_eq!(status(&requests, &id), Some(AccessRequestStatus::Denied));
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.access_request_denied"]
        );
    }

    /// Ann denies Bob's request twice. The second time it is no longer
    /// pending, so it is refused.
    #[test]
    fn an_answered_request_is_not_answered_again() {
        let (ports, _, id) = tenant_asked_by("bob@acme.test");
        let use_case = DenyUseCase::new(ports);
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        block_on(use_case.execute(&test_ctx(), &auditor, id)).unwrap();

        let result = block_on(use_case.execute(&test_ctx(), &auditor, id));

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Ann denies a request the tenant does not have. It is not found.
    #[test]
    fn an_unknown_request_is_not_found() {
        let (ports, _, _) = tenant_asked_by("bob@acme.test");

        let unknown = AccessRequestId::new();

        let result = deny(ports, &Arc::new(FakeEventDispatcher::new()), unknown);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A caller without assignment rights cannot deny Bob's production request.
    /// It remains pending and no denial is recorded.
    #[test]
    fn a_caller_who_could_not_approve_does_not_deny() {
        let (ports, requests, id) = tenant_asked_by("bob@acme.test");
        let sink = Arc::new(FakeEventDispatcher::new());
        let ports = DenyPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..ports
        };

        let result = deny(ports, &sink, id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(status(&requests, &id), Some(AccessRequestStatus::Pending));
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Denying one's own access request is forbidden and leaves it pending.
    #[test]
    fn nobody_denies_their_own_request() {
        let (ports, requests, id) = tenant_asked_by("caller@example.test");

        let result = deny(ports, &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(status(&requests, &id), Some(AccessRequestStatus::Pending));
    }

    /// A signed-out session cannot deny Bob's access request.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (ports, _, id) = tenant_asked_by("bob@acme.test");
        let ports = DenyPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports
        };

        let result = deny(ports, &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Bob asked for a role the tenant has since deleted. There is nothing
    /// to answer about, so it is not found.
    #[test]
    fn a_request_for_a_role_since_deleted_is_not_found() {
        let tenant = test_ctx().tenant_id();
        let gone = AskedAccess::Role(RoleId::new());
        let request = pending_request_by(gone, "bob@acme.test", clock::now());
        let id = *request.id();
        let ports = DenyPorts {
            request_store: Arc::new(FakeAccessRequestStore::holding(tenant, [request])),
            ..DenyPorts::fakes()
        };

        let result = deny(ports, &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
