//! Start access review: ask named reviewers, by a due date, whether each
//! holder of a role or member of a group keeps it.
//!
//! Everyone holding what the review covers when it starts is listed, from
//! the tenant's records as they are now; holdings that already ran out are
//! not.

use std::sync::Arc;

use ianua_domain::domains::authorization::access_review::{
    AccessReview, NewAccessReview, ReviewScope, Unanswered,
};
use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{Label, UserId};
use time::OffsetDateTime;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{AccessRecordStore, AccessReviewStore, GroupStore, RoleStore};
use crate::ports::identity::UserStore;
use crate::use_case::Command;
use crate::use_cases::authorization::access_reviews::lookup::{reviewers_named, scope_label};

/// The ports [`StartUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct StartPorts {
    /// Saves the review.
    pub review_store: Arc<dyn AccessReviewStore>,
    /// Reads who holds what now, for the holders listed.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// Loads the role a review covers.
    pub role_store: Arc<dyn RoleStore>,
    /// Loads the group a review covers.
    pub group_store: Arc<dyn GroupStore>,
    /// Loads the reviewers named.
    pub user_store: Arc<dyn UserStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// What a review asks, of whom, and by when.
pub struct StartRequest {
    /// What the review is called, such as "Finance, Q3".
    pub name: Label,
    /// The role or group it covers.
    pub scope: ReviewScope,
    /// The tenant's users who decide.
    pub reviewers: Vec<UserId>,
    /// By when.
    pub due: OffsetDateTime,
    /// What happens to holders nobody decided on.
    pub unanswered: Unanswered,
}

/// Starts an access review in the caller's tenant.
pub struct StartUseCase {
    ports: StartPorts,
}

impl StartUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: StartPorts) -> Self {
        Self { ports }
    }

    /// What starting `request` asks of the domain: the reviewers as people
    /// and the covered role's or group's name.
    async fn new_review(
        &self,
        ctx: &CallerContext,
        request: StartRequest,
    ) -> Result<NewAccessReview, AppError> {
        let tenant = ctx.tenant();
        let users = self.ports.user_store.as_ref();
        let (roles, groups) = (
            self.ports.role_store.as_ref(),
            self.ports.group_store.as_ref(),
        );
        Ok(NewAccessReview {
            name: request.name,
            scope: request.scope,
            scope_label: scope_label(roles, groups, &tenant, request.scope).await?,
            reviewers: reviewers_named(users, &tenant, &request.reviewers).await?,
            due: request.due,
            unanswered: request.unanswered,
        })
    }
}

impl Command for StartUseCase {
    type Caller = CallerContext;
    type Input = StartRequest;
    type Output = Result<AccessReview<ResolvedTenant>, AppError>;

    /// Saves a review of `request.scope` listing everyone who holds it now,
    /// for the caller, and records it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without role assignment rights.
    /// - `AppError::NotFound` for a missing role, group or reviewer.
    /// - `AppError::Domain` for no/excess/duplicate reviewers or a deadline not in the future.
    /// - `AppError::Conflict` when nobody holds the covered access; `Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: StartRequest,
    ) -> Result<AccessReview<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Roles(RoleAction::Assign))
            .map_err(AppError::from_domain)?;
        let new = self.new_review(ctx, request).await?;
        let draft = AccessReview::prepare(new, &authority).map_err(AppError::from_domain)?;
        self.ports
            .access_records
            .hold_grants(&tenant)
            .await
            .or_internal()?;
        let mut review = self
            .ports
            .review_store
            .start(&tenant, draft)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&authority.actor(), review.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(review)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::access_review::AccessReviewVerdict;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{PrincipalRef, RoleId};
    use time::Duration;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{
        AccessSources, FakeAccessRecordStore, FakeAccessReviewStore, FakeRoleAssignmentStore,
        FakeRoleStore, stored_assignment, stored_role,
    };
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A tenant where Bob holds "finance", with Carol to review it.
    struct Tenant {
        role_id: RoleId,
        carol: UserId,
        reviews: Arc<FakeAccessReviewStore>,
        ports: StartPorts,
    }

    fn tenant() -> Tenant {
        let tenant = test_ctx().tenant_id();
        let finance = stored_role("finance", Vec::new(), Vec::new());
        let role_id = *finance.id();
        let bob = stored_assignment(PrincipalRef::User(UserId::new()), role_id);
        let roles = Arc::new(FakeRoleStore::holding(tenant, [finance]));
        let sources = AccessSources {
            roles: roles.clone(),
            assignments: Arc::new(FakeRoleAssignmentStore::holding(tenant, [bob])),
            ..AccessSources::default()
        };
        let carol = UserId::new();
        let reviews = Arc::new(FakeAccessReviewStore::reading(sources.clone()));
        Tenant {
            role_id,
            carol,
            ports: StartPorts {
                review_store: reviews.clone(),
                access_records: Arc::new(FakeAccessRecordStore::reading(sources)),
                role_store: roles,
                user_store: Arc::new(FakeUserStore::with_user(carol, "carol@acme.test")),
                ..StartPorts::fakes()
            },
            reviews,
        }
    }

    fn asking(tenant: &Tenant, scope: ReviewScope, due: OffsetDateTime) -> StartRequest {
        StartRequest {
            name: Label::new("review_name", "Finance, Q3").unwrap(),
            scope,
            reviewers: vec![tenant.carol],
            due,
            unanswered: Unanswered::KeepAccess,
        }
    }

    fn start(
        ports: StartPorts,
        sink: &Arc<FakeEventDispatcher>,
        request: StartRequest,
    ) -> Result<AccessReview<ResolvedTenant>, AppError> {
        block_on(StartUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            request,
        ))
    }

    fn next_week() -> OffsetDateTime {
        clock::now() + Duration::days(7)
    }

    /// Ann starts a review of "finance" with Carol as reviewer. Bob is
    /// listed, undecided, and the start is recorded.
    #[test]
    fn a_review_lists_everyone_holding_what_it_covers() {
        let tenant = tenant();
        let sink = Arc::new(FakeEventDispatcher::new());
        let request = asking(&tenant, ReviewScope::Role(tenant.role_id), next_week());

        let review = start(tenant.ports, &sink, request).unwrap();

        let items = tenant
            .reviews
            .stored_items(test_ctx().tenant_id(), review.id());
        assert_eq!(items.len(), 1);
        assert_eq!(*items[0].verdict(), AccessReviewVerdict::Pending);
        assert!(
            tenant
                .reviews
                .stored(test_ctx().tenant_id(), review.id())
                .is_some()
        );
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.access_review_started"]
        );
    }

    /// Starting uses the scoped snapshot store and grant lock, so it never
    /// materializes the tenant's access records to discover holders.
    #[test]
    fn starting_a_review_does_not_load_tenant_access_records() {
        let mut tenant = tenant();
        let records = Arc::new(FakeAccessRecordStore::empty());
        tenant.ports.access_records = records.clone();
        let request = asking(&tenant, ReviewScope::Role(tenant.role_id), next_week());
        let review = start(tenant.ports, &Arc::new(FakeEventDispatcher::new()), request).unwrap();
        assert_eq!(review.holder_count(), 1);
        assert_eq!(records.whole_reads(), 0);
        assert_eq!(records.holder_reads(), 0);
    }

    /// Ann starts a review due yesterday. It could never be answered, so it
    /// is refused and nothing is saved.
    #[test]
    fn a_review_due_already_is_refused() {
        let tenant = tenant();
        let request = asking(
            &tenant,
            ReviewScope::Role(tenant.role_id),
            clock::now() - Duration::days(1),
        );

        let result = start(tenant.ports, &Arc::new(FakeEventDispatcher::new()), request);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(tenant.reviews.count(), 0);
    }

    /// Ann starts a review of a role the tenant does not have. It is not
    /// found.
    #[test]
    fn an_unknown_role_is_not_found() {
        let tenant = tenant();
        let request = asking(&tenant, ReviewScope::Role(RoleId::new()), next_week());

        let result = start(tenant.ports, &Arc::new(FakeEventDispatcher::new()), request);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Role view permission cannot start a Finance review. No review is saved
    /// and no start is recorded.
    #[test]
    fn a_caller_who_may_not_assign_roles_is_refused() {
        let tenant = tenant();
        let sink = Arc::new(FakeEventDispatcher::new());
        let request = asking(&tenant, ReviewScope::Role(tenant.role_id), next_week());
        let ports = StartPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Roles(RoleAction::View),
            ])),
            ..tenant.ports
        };

        let result = start(ports, &sink, request);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.reviews.count(), 0);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Missing assignment rights return forbidden even for an unknown role
    /// and reviewer, with no review or audit event written.
    #[test]
    fn starting_without_authority_does_not_reveal_scope_or_reviewer_existence() {
        let tenant = tenant();
        let sink = Arc::new(FakeEventDispatcher::new());
        let mut request = asking(&tenant, ReviewScope::Role(RoleId::new()), next_week());
        request.reviewers = vec![UserId::new()];
        let ports = StartPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Roles(RoleAction::View),
            ])),
            ..tenant.ports
        };

        let result = start(ports, &sink, request);

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(tenant.reviews.count(), 0);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot start an access review.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let tenant = tenant();
        let request = asking(&tenant, ReviewScope::Role(tenant.role_id), next_week());
        let ports = StartPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tenant.ports
        };

        let result = start(ports, &Arc::new(FakeEventDispatcher::new()), request);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
