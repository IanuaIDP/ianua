//! List access requests: the requests of the tenant waiting for an answer,
//! for those who may answer them, and anyone's own.
//!
//! Who asked for what is part of who holds what, so seeing anyone else's
//! needs the right to view roles. Everyone may see their own.

use std::sync::Arc;

use ianua_domain::domains::authorization::access_request::AccessRequest;
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest};
use crate::ports::authorization::{AccessRequestFilter, AccessRequestStore};
use crate::use_case::Query;

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Lists the requests.
    pub request_store: Arc<dyn AccessRequestStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Which requests to list, and which page.
pub struct ListRequest {
    /// Which requests.
    pub filter: AccessRequestFilter,
    /// Which page of them, newest first.
    pub page: PageRequest,
}

/// Lists access requests of the caller's tenant.
pub struct ListUseCase {
    ports: ListPorts,
}

impl ListUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListUseCase {
    type Caller = CallerContext;
    type Input = ListRequest;
    type Output = Result<Page<AccessRequest<ResolvedTenant>>, AppError>;

    /// One page of the requests `request.filter` keeps, newest first.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller asks for others' requests and
    ///   may not view roles.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: ListRequest,
    ) -> Result<Page<AccessRequest<ResolvedTenant>>, AppError> {
        let ListRequest { filter, page } = request;
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        ensure_may_list(&authority, filter)?;
        self.ports
            .request_store
            .list(&ctx.tenant(), filter, &page)
            .await
            .map_err(AppError::from_domain)
    }
}

/// Refuses listing others' requests to a caller who may not view roles.
fn ensure_may_list(
    authority: &TenantAuthority,
    filter: AccessRequestFilter,
) -> Result<(), AppError> {
    if filter == AccessRequestFilter::AskedBy(authority.who().principal()) {
        return Ok(());
    }
    authority
        .ensure_holds(SystemPermission::Roles(RoleAction::View))
        .map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::access_request::AskedAccess;
    use ianua_domain::shared::clock;
    use ianua_domain::types::RoleId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{FakeAccessRequestStore, pending_request_by};
    use crate::test_support::{block_on, test_ctx};

    /// Bob's request and Carol's.
    fn two_requests() -> ListPorts {
        let asked = AskedAccess::Role(RoleId::new());
        let requests = [
            pending_request_by(asked, "bob@acme.test", clock::now()),
            pending_request_by(asked, "carol@acme.test", clock::now()),
        ];
        ListPorts {
            request_store: Arc::new(FakeAccessRequestStore::holding(
                test_ctx().tenant_id(),
                requests,
            )),
            ..ListPorts::fakes()
        }
    }

    fn list(
        ports: ListPorts,
        filter: AccessRequestFilter,
    ) -> Result<Page<AccessRequest<ResolvedTenant>>, AppError> {
        block_on(ListUseCase::new(ports).execute(
            &test_ctx(),
            ListRequest {
                filter,
                page: PageRequest::default(),
            },
        ))
    }

    /// The requests asked through the test caller's own account.
    fn own() -> AccessRequestFilter {
        let caller = FakeTenantAuthorities::holding(&[]);
        let authority = block_on(caller.authority(&test_ctx())).unwrap();
        AccessRequestFilter::AskedBy(authority.who().principal())
    }

    /// Ann, who may view roles, lists the pending requests. She sees Bob's
    /// and Carol's.
    #[test]
    fn pending_requests_are_listed_for_an_approver() {
        let page = list(two_requests(), AccessRequestFilter::Pending).unwrap();

        assert_eq!(page.items.len(), 2);
    }

    /// Dan may view nothing and lists his own requests. He may, and sees
    /// none of Bob's or Carol's.
    #[test]
    fn anyone_lists_their_own_requests() {
        let ports = ListPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..two_requests()
        };

        let page = list(ports, own()).unwrap();

        assert_eq!(page.items.len(), 0);
    }

    /// Listing everyone's access requests is forbidden without role view permission.
    #[test]
    fn others_requests_need_the_right_to_view_roles() {
        let ports = ListPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..two_requests()
        };

        let result = list(ports, AccessRequestFilter::All);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot list pending access requests.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let ports = ListPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..two_requests()
        };

        let result = list(ports, AccessRequestFilter::Pending);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
