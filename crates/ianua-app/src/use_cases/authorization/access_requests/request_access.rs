//! Request access: ask for a role or a place in a group for a while, with
//! a reason, for someone who could give it to approve.
//!
//! The request is always for the person asking, worked out from who is
//! signed in, never named in the request.

use std::sync::Arc;

use ianua_domain::domains::authorization::access_request::{
    AccessRequest, AskedAccess, NewAccessRequest,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{Lifetime, Text};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{
    AccessRequestPolicyStore, AccessRequestStore, GroupStore, RoleStore,
};
use crate::use_case::Command;
use crate::use_cases::authorization::access_requests::lookup::{asked_label, tenant_policy};

/// The ports [`RequestAccessUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RequestAccessPorts {
    /// Saves the request.
    pub request_store: Arc<dyn AccessRequestStore>,
    /// Loads the role asked for.
    pub role_store: Arc<dyn RoleStore>,
    /// Loads the group asked for.
    pub group_store: Arc<dyn GroupStore>,
    /// Reads the longest the tenant lets its people ask for.
    pub policy_store: Arc<dyn AccessRequestPolicyStore>,
    /// Who the caller is in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// What the caller asks for, why, and for how long.
pub struct RequestAccessRequest {
    /// The role or group.
    pub asked: AskedAccess,
    /// Why they need it.
    pub reason: Text,
    /// How long they need it.
    pub length: Lifetime,
}

/// Asks, for the caller, for a role or a group for a while.
pub struct RequestAccessUseCase {
    ports: RequestAccessPorts,
}

impl RequestAccessUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RequestAccessPorts) -> Self {
        Self { ports }
    }
}

impl Command for RequestAccessUseCase {
    type Caller = CallerContext;
    type Input = RequestAccessRequest;
    type Output = Result<AccessRequest<ResolvedTenant>, AppError>;

    /// Saves the caller's request and records it. Asking gives nothing: the
    /// access comes only once someone else approves it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such role or group.
    /// - `AppError::Domain` when the length is longer than the tenant
    ///   allows.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: RequestAccessRequest,
    ) -> Result<AccessRequest<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let (roles, groups) = (
            self.ports.role_store.as_ref(),
            self.ports.group_store.as_ref(),
        );
        let new = NewAccessRequest {
            asked: request.asked,
            asked_label: asked_label(roles, groups, &tenant, request.asked).await?,
            reason: request.reason,
            length: request.length,
        };
        let policy = tenant_policy(self.ports.policy_store.as_ref(), &tenant).await?;
        let mut asked = AccessRequest::request(new, &authority, policy.limits())
            .map_err(AppError::from_domain)?;

        self.ports
            .request_store
            .save(&tenant, &asked)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), asked.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(asked)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::access_request::AccessRequestStatus;
    use ianua_domain::types::RoleId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{
        FakeAccessRequestPolicyStore, FakeAccessRequestStore, FakeRoleStore, stored_request_policy,
        stored_role,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A tenant with the "production" role, and the request store.
    struct Tenant {
        role_id: RoleId,
        requests: Arc<FakeAccessRequestStore>,
        ports: RequestAccessPorts,
    }

    fn tenant() -> Tenant {
        let production = stored_role("production", Vec::new(), Vec::new());
        let role_id = *production.id();
        let requests = Arc::new(FakeAccessRequestStore::empty());
        Tenant {
            role_id,
            ports: RequestAccessPorts {
                request_store: requests.clone(),
                role_store: Arc::new(FakeRoleStore::holding(test_ctx().tenant_id(), [production])),
                ..RequestAccessPorts::fakes()
            },
            requests,
        }
    }

    fn hours(count: i64) -> Lifetime {
        Lifetime::seconds(count * 3600).unwrap()
    }

    fn asking(asked: AskedAccess, length: Lifetime) -> RequestAccessRequest {
        RequestAccessRequest {
            asked,
            reason: Text::new("reason", "on call tonight").unwrap(),
            length,
        }
    }

    fn request(
        ports: RequestAccessPorts,
        sink: &Arc<FakeEventDispatcher>,
        asked: RequestAccessRequest,
    ) -> Result<AccessRequest<ResolvedTenant>, AppError> {
        block_on(RequestAccessUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            asked,
        ))
    }

    /// Ann is on call and asks for "production" for two hours. The request
    /// is saved pending, for her, and recorded.
    #[test]
    fn a_request_is_saved_pending_and_recorded() {
        let tenant = tenant();
        let sink = Arc::new(FakeEventDispatcher::new());

        let asked = request(
            tenant.ports,
            &sink,
            asking(AskedAccess::Role(tenant.role_id), hours(2)),
        )
        .unwrap();

        assert_eq!(asked.status(), AccessRequestStatus::Pending);
        assert_eq!(
            tenant
                .requests
                .status_of(test_ctx().tenant_id(), asked.id()),
            Some(AccessRequestStatus::Pending)
        );
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.access_requested"]
        );
    }

    /// Ann asks for a role the tenant does not have. It is not found and
    /// nothing is saved.
    #[test]
    fn an_unknown_role_is_not_found() {
        let tenant = tenant();

        let result = request(
            tenant.ports,
            &Arc::new(FakeEventDispatcher::new()),
            asking(AskedAccess::Role(RoleId::new()), hours(2)),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(tenant.requests.count(), 0);
    }

    /// A year-long access request exceeds the allowed duration and is rejected
    /// without saving a request or recording an event.
    #[test]
    fn a_request_longer_than_allowed_is_refused() {
        let tenant = tenant();
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = request(
            tenant.ports,
            &sink,
            asking(AskedAccess::Role(tenant.role_id), hours(24 * 365)),
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(tenant.requests.count(), 0);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// An eight-hour tenant limit rejects a twelve-hour request but accepts
    /// a two-hour request, leaving exactly one request stored.
    #[test]
    fn a_request_longer_than_the_tenant_allows_is_refused() {
        let tenant = tenant();
        let policy = stored_request_policy(hours(8));
        let ports = RequestAccessPorts {
            policy_store: Arc::new(FakeAccessRequestPolicyStore::holding(
                test_ctx().tenant_id(),
                policy,
            )),
            ..tenant.ports
        };
        let sink = Arc::new(FakeEventDispatcher::new());
        let use_case = RequestAccessUseCase::new(ports);
        let ask = |length| {
            block_on(use_case.execute(
                &test_ctx(),
                &test_auditor(sink.clone()),
                asking(AskedAccess::Role(tenant.role_id), length),
            ))
        };

        let twelve = ask(hours(12));
        let two = ask(hours(2));

        assert!(matches!(twelve, Err(AppError::Domain(_))));
        assert!(two.is_ok());
        assert_eq!(tenant.requests.count(), 1);
    }

    /// A signed-out session cannot request production access; nothing is saved.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let tenant = tenant();
        let ports = RequestAccessPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tenant.ports
        };

        let result = request(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            asking(AskedAccess::Role(tenant.role_id), hours(2)),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(tenant.requests.count(), 0);
    }
}
