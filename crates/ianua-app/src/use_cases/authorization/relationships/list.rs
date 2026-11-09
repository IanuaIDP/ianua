//! List relationships: the relationships of the tenant's app, all of them,
//! those on one object, or those one subject holds.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
use ianua_domain::domains::authorization::relationship::Relationship;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest};
use crate::ports::authorization::{RelationshipFilter, RelationshipStore};
use crate::use_case::Query;

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Lists the relationships.
    pub relationship_store: Arc<dyn RelationshipStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Which relationships to list, and which page.
pub struct ListRequest {
    /// Which relationships.
    pub filter: RelationshipFilter,
    /// Which page of them, newest first.
    pub page: PageRequest,
}

/// Lists the relationships of the caller's tenant's app.
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
    type Output = Result<Page<Relationship<ResolvedTenant>>, AppError>;

    /// One page of the relationships `request.filter` keeps, newest first.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view roles.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: ListRequest,
    ) -> Result<Page<Relationship<ResolvedTenant>>, AppError> {
        let ListRequest { filter, page } = request;
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Roles(RoleAction::View))
            .map_err(AppError::from_domain)?;
        self.ports
            .relationship_store
            .list(&ctx.tenant(), &filter, &page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::PermissionSegment;
    use ianua_domain::domains::authorization::relationship::{
        ObjectKey, ObjectRef, RelationLink, RelationshipRow,
    };
    use ianua_domain::shared::clock;
    use ianua_domain::types::RelationshipId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::FakeRelationshipStore;
    use crate::test_support::{block_on, test_ctx};

    fn object(key: &str) -> ObjectRef {
        let project = PermissionSegment::new("test", "project").unwrap();
        ObjectRef::new(project, ObjectKey::new(key).unwrap())
    }

    /// Project 42 sits under folder 7, and project 43 under folder 8.
    fn two_relationships() -> ListPorts {
        let under = |child: &str, parent: &str| {
            Relationship::reconstitute(RelationshipRow {
                id: RelationshipId::new(),
                object: object(child),
                link: RelationLink::Under(object(parent)),
                created_at: clock::now(),
            })
            .unwrap()
        };
        ListPorts {
            relationship_store: Arc::new(FakeRelationshipStore::holding(
                test_ctx().tenant_id(),
                [under("42", "7"), under("43", "8")],
            )),
            ..ListPorts::fakes()
        }
    }

    fn list(
        ports: ListPorts,
        filter: RelationshipFilter,
    ) -> Result<Page<Relationship<ResolvedTenant>>, AppError> {
        block_on(ListUseCase::new(ports).execute(
            &test_ctx(),
            ListRequest {
                filter,
                page: PageRequest::default(),
            },
        ))
    }

    /// Ann lists what is said about project 42 and sees only its folder.
    #[test]
    fn the_relationships_on_one_object_are_listed() {
        let page = list(
            two_relationships(),
            RelationshipFilter::OnObject(object("42")),
        )
        .unwrap();

        assert_eq!(page.items.len(), 1);
    }

    /// Listing relationships is forbidden without permission to view roles.
    #[test]
    fn a_caller_who_may_not_view_roles_is_refused() {
        let ports = ListPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..two_relationships()
        };

        let result = list(ports, RelationshipFilter::All);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot list the tenant's relationships.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let ports = ListPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..two_relationships()
        };

        let result = list(ports, RelationshipFilter::All);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
