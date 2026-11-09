//! Change policy status: move the tenant's policy through review, activation
//! and archival.
//!
//! Approving puts the policy live, so someone other than the person who
//! sent it to review approves it whenever the tenant has such a person: a
//! user of the tenant, or a member of its organization, who may activate
//! policies. Who those are is read here, from the tenant's records and the
//! organization's, for the domain to decide on.

use std::sync::Arc;

use ianua_domain::domains::authorization::authority::{
    ApproverPool, OutsideHolder, TenantAccess, TenantAuthority,
};
use ianua_domain::domains::authorization::policy::review::PolicyApprover;
use ianua_domain::domains::authorization::policy::set::PolicySet;
use ianua_domain::domains::authorization::policy::version::{PolicyHistory, Replacing};
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::organization::members::tenant_authority::members_holding_in;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{OrganizationId, PrincipalRef, UserId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authorization::{AccessRecordStore, AccessRecords, PolicyStore};
use crate::ports::identity::UserStore;
use crate::ports::organization::{OrganizationStore, TenantMemberRoster};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authorization::lookup::{
    access_records, existing_active_policy, existing_draft, policy_versions,
};

/// Which way a version of the policy moves through its lifecycle.
///
/// The open draft moves through review to live; the live version is only
/// ever taken out of use. The domain refuses the moves that make no sense
/// from where a version is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    /// The open draft to review. Editing stops while it is looked over.
    SubmitForReview,
    /// The draft in review to live, in place of the live version, which
    /// becomes a past one.
    Activate,
    /// The draft in review back to draft, for more work.
    Reject,
    /// The open draft abandoned without going live.
    AbandonDraft,
    /// The live version taken out of use: nothing is enforced until another
    /// is approved.
    TakeOutOfUse,
}

/// The ports [`ChangeStatusUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeStatusPorts {
    /// Loads and saves the policy.
    pub policy_store: Arc<dyn PolicyStore>,
    /// Reads who holds what in the tenant, for who else may approve.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// The tenant's users named by its roles and groups.
    pub users: Arc<dyn UserStore>,
    /// The organization that owns the tenant.
    pub organizations: Arc<dyn OrganizationStore>,
    /// The organization's members who might hold rights in the tenant, with
    /// their grants there.
    pub member_roster: Arc<dyn TenantMemberRoster>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Moves the access policy of the caller's tenant through its lifecycle.
pub struct ChangeStatusUseCase {
    ports: ChangeStatusPorts,
}

impl ChangeStatusUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ChangeStatusPorts) -> Self {
        Self { ports }
    }

    /// The draft in review approved by `authority` and saved live, together
    /// with the live version it replaced, which the approval records.
    async fn activated(
        &self,
        ctx: &CallerContext,
        authority: &TenantAuthority,
    ) -> Result<PolicySet, AppError> {
        let tenant = ctx.tenant();
        let store = self.ports.policy_store.as_ref();
        let versions = policy_versions(store, &tenant).await?;
        let history = PolicyHistory::of(&versions).map_err(AppError::from_domain)?;
        let mut draft = history.open().cloned().or_not_found(message!(
            "authorization-this-tenant-has-no-open-policy",
            "this tenant has no open policy draft"
        ))?;
        let mut live = history.live().cloned();
        let approver = approver(&self.ports, ctx, authority).await?;
        let replacing = match live.as_mut() {
            Some(live) => Replacing::Live(live),
            None => Replacing::NothingLive,
        };
        draft.activate(replacing, &approver).map_err(move_error)?;
        store
            .save_activation(&tenant, &draft, live.as_ref())
            .await
            .or_internal()?;
        Ok(draft)
    }

    /// The open draft after `step`, saved.
    async fn draft_moved(
        &self,
        tenant: &ScopedTenant,
        step: impl FnOnce(&mut PolicySet) -> Result<(), DomainError>,
    ) -> Result<PolicySet, AppError> {
        let store = self.ports.policy_store.as_ref();
        let mut draft = existing_draft(store, tenant).await?;
        step(&mut draft).map_err(move_error)?;
        store.save(tenant, &draft).await.or_internal()?;
        Ok(draft)
    }

    /// The live version taken out of use by `authority`, saved.
    async fn retired(
        &self,
        tenant: &ScopedTenant,
        authority: &TenantAuthority,
    ) -> Result<PolicySet, AppError> {
        let store = self.ports.policy_store.as_ref();
        let mut live = existing_active_policy(store, tenant).await?;
        live.archive(authority).map_err(move_error)?;
        store.save(tenant, &live).await.or_internal()?;
        Ok(live)
    }
}

impl Command for ChangeStatusUseCase {
    type Caller = CallerContext;
    type Input = Transition;
    type Output = Result<PolicySet, AppError>;

    /// Moves a version the way `transition` says, for the caller, and
    /// records the move. Approving saves the new live version and the one
    /// it replaced together.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no open draft to move, or
    ///   no live version to take out of use.
    /// - `AppError::Forbidden` when the caller may not make this move, or
    ///   approves a policy they sent to review while someone else could.
    /// - `AppError::Conflict` when the version cannot move that way from
    ///   where it is.
    /// - `AppError::Internal` when a record cannot be read or written, or
    ///   the tenant's organization is gone.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        transition: Transition,
    ) -> Result<PolicySet, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let mut moved = match transition {
            Transition::Activate => self.activated(ctx, &authority).await?,
            Transition::SubmitForReview => {
                self.draft_moved(&tenant, |draft| draft.submit_for_review(&authority))
                    .await?
            }
            Transition::Reject => {
                self.draft_moved(&tenant, |draft| draft.reject(&authority))
                    .await?
            }
            Transition::AbandonDraft => {
                self.draft_moved(&tenant, |draft| draft.archive(&authority))
                    .await?
            }
            Transition::TakeOutOfUse => self.retired(&tenant, &authority).await?,
        };

        auditor
            .dispatch_by(&authority.actor(), moved.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(moved)
    }
}

/// A move the policy's state does not allow is a conflict; anything else
/// keeps its own meaning.
fn move_error(error: DomainError) -> AppError {
    match error {
        DomainError::InvalidTransition(refusal) => {
            AppError::Conflict(refusal.as_str().to_owned().into())
        }
        other => AppError::from_domain(other),
    }
}

/// `authority` approving the policy, with whether anyone else in the
/// tenant or its organization may approve it worked out by the domain.
async fn approver<'a>(
    ports: &ChangeStatusPorts,
    ctx: &CallerContext,
    authority: &'a TenantAuthority,
) -> Result<PolicyApprover<'a>, AppError> {
    let tenant = ctx.tenant();
    let records = access_records(ports.access_records.as_ref(), &tenant).await?;
    let access = records.access(*tenant);
    let users = users_named(ports.users.as_ref(), &tenant, &records).await?;
    let members = members_holding(ports, ctx.organization_id(), &access).await?;
    let pool = ApproverPool {
        users: &users,
        members: &members,
    };
    access
        .policy_approver(authority, &pool)
        .map_err(AppError::from_domain)
}

/// Every user the tenant's roles and groups are given to, as stored now.
async fn users_named(
    store: &dyn UserStore,
    tenant: &ScopedTenant,
    records: &AccessRecords,
) -> Result<Vec<User<ResolvedTenant>>, AppError> {
    let ids = user_ids_in(records);
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    store.find_by_ids(tenant, &ids).await.or_internal()
}

/// The users `records` give a role to, directly or through a group, each
/// named once.
fn user_ids_in(records: &AccessRecords) -> Vec<UserId> {
    let direct = records.assignments.iter().map(|held| *held.principal());
    let grouped = records.memberships.iter().map(|held| *held.principal());
    let mut ids: Vec<UserId> = Vec::new();
    for principal in direct.chain(grouped) {
        let PrincipalRef::User(id) = principal else {
            continue;
        };
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    ids
}

/// The members of `organization_id` who hold rights in `access`'s tenant
/// now.
async fn members_holding(
    ports: &ChangeStatusPorts,
    organization_id: OrganizationId,
    access: &TenantAccess<'_, ResolvedTenant>,
) -> Result<Vec<OutsideHolder>, AppError> {
    let organization = ports
        .organizations
        .find_by_id(&organization_id)
        .await
        .or_internal()?
        .ok_or_else(|| AppError::internal_msg("the tenant's organization is gone"))?;
    let roster = ports
        .member_roster
        .members_in(&organization_id, &access.tenant)
        .await
        .or_internal()?;
    members_holding_in(access, &organization, &roster.members, &roster.grants)
        .map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{PolicySetAction, SystemPermission};
    use ianua_domain::domains::authorization::policy::status::PolicyStatus;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::test_support::authority::anyone_holding;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{
        AccessSources, FakeAccessRecordStore, FakePolicyStore, FakeRoleAssignmentStore,
        FakeRoleStore, draft_beside, policy_in, stored_assignment, stored_role,
    };
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::organization::{
        FakeTenantMemberRoster, OrgShape, org_shaped, org_store_with, test_org, test_org_user,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The tenant's policy, in `status`, with nobody else who may approve.
    struct Tenant {
        policies: Arc<FakePolicyStore>,
        ports: ChangeStatusPorts,
    }

    impl Tenant {
        fn with_policy_in(status: PolicyStatus) -> Self {
            let tenant = test_ctx().tenant_id();
            let policies = Arc::new(FakePolicyStore::holding(
                tenant,
                policy_in(status, Vec::new()),
            ));
            let organization = test_org(test_ctx().organization_id(), "acme");
            Self {
                ports: ChangeStatusPorts {
                    policy_store: policies.clone(),
                    organizations: org_store_with([organization]),
                    ..ChangeStatusPorts::fakes()
                },
                policies,
            }
        }

        fn with_no_policy() -> Self {
            let mut tenant = Self::with_policy_in(PolicyStatus::Draft);
            tenant.policies = Arc::new(FakePolicyStore::empty());
            tenant.ports.policy_store = tenant.policies.clone();
            tenant
        }

        /// Bob, another user of the tenant, may activate policies too.
        fn with_another_approver(mut self) -> Self {
            let tenant = test_ctx().tenant_id();
            let bob = UserId::new();
            let approvers = stored_role(
                "approvers",
                vec![SystemPermission::ManagePolicy],
                Vec::new(),
            );
            let held = stored_assignment(PrincipalRef::User(bob), *approvers.id());
            let stores = AccessSources {
                roles: Arc::new(FakeRoleStore::holding(tenant, [approvers])),
                assignments: Arc::new(FakeRoleAssignmentStore::holding(tenant, [held])),
                ..AccessSources::default()
            };
            self.ports.access_records = Arc::new(FakeAccessRecordStore::reading(stores));
            self.ports.users = Arc::new(FakeUserStore::with_user(bob, "bob@acme.test"));
            self
        }

        /// Olivia, an owner of Acme's organization, which owns the tenant,
        /// may act in it and so approve too.
        fn with_an_owner_of_the_organization(mut self) -> Self {
            let organization_id = test_ctx().organization_id();
            let owning = OrgShape::owning(&[test_ctx().tenant_id()]);
            let olivia = test_org_user(organization_id, "olivia@acme.test", OrgRole::Owner);
            self.ports.organizations = org_store_with([org_shaped(organization_id, owning)]);
            self.ports.member_roster =
                Arc::new(FakeTenantMemberRoster::holding([olivia], Vec::new()));
            self
        }

        fn holding(mut self, system: &[SystemPermission]) -> Self {
            self.ports.tenant_authorities = Arc::new(FakeTenantAuthorities::holding(system));
            self
        }

        fn status(&self) -> PolicyStatus {
            self.policies
                .stored(test_ctx().tenant_id())
                .unwrap()
                .status()
        }

        fn change(&self, transition: Transition) -> Result<PolicySet, AppError> {
            self.change_recorded(&Arc::new(FakeEventDispatcher::new()), transition)
        }

        fn change_recorded(
            &self,
            sink: &Arc<FakeEventDispatcher>,
            transition: Transition,
        ) -> Result<PolicySet, AppError> {
            let uc = ChangeStatusUseCase::new(ChangeStatusPorts {
                policy_store: self.ports.policy_store.clone(),
                access_records: self.ports.access_records.clone(),
                users: self.ports.users.clone(),
                organizations: self.ports.organizations.clone(),
                member_roster: self.ports.member_roster.clone(),
                tenant_authorities: self.ports.tenant_authorities.clone(),
            });
            block_on(uc.execute(&test_ctx(), &test_auditor(sink.clone()), transition))
        }
    }

    /// Ann sends the draft to review, then approves it. With nobody else in
    /// the tenant who may approve, she approves her own, and it goes live.
    #[test]
    fn a_draft_moves_to_review_and_then_live() {
        let tenant = Tenant::with_policy_in(PolicyStatus::Draft);

        let reviewed = tenant.change(Transition::SubmitForReview).unwrap();
        let live = tenant.change(Transition::Activate).unwrap();

        assert_eq!(reviewed.status(), PolicyStatus::Review);
        assert_eq!(live.status(), PolicyStatus::Active);
        assert_eq!(tenant.status(), PolicyStatus::Active);
    }

    /// Ann sends the draft to review. The move is recorded.
    #[test]
    fn a_move_is_recorded() {
        let tenant = Tenant::with_policy_in(PolicyStatus::Draft);
        let sink = Arc::new(FakeEventDispatcher::new());

        tenant
            .change_recorded(&sink, Transition::SubmitForReview)
            .unwrap();

        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.policy_submitted_for_review"]
        );
    }

    /// Ann sends back a policy under review. It is a draft again, open to
    /// editing.
    #[test]
    fn a_rejected_policy_is_a_draft_again() {
        let tenant = Tenant::with_policy_in(PolicyStatus::Review);

        let rejected = tenant.change(Transition::Reject).unwrap();

        assert!(rejected.status().is_editable());
    }

    /// Ann takes the live policy out of use. It stops deciding requests.
    #[test]
    fn the_live_policy_is_archived() {
        let tenant = Tenant::with_policy_in(PolicyStatus::Active);

        tenant.change(Transition::TakeOutOfUse).unwrap();

        assert_eq!(tenant.status(), PolicyStatus::Archived);
    }

    /// Ann abandons the open draft. It is archived without going live.
    #[test]
    fn an_open_draft_is_abandoned() {
        let tenant = Tenant::with_policy_in(PolicyStatus::Draft);

        tenant.change(Transition::AbandonDraft).unwrap();

        assert_eq!(tenant.status(), PolicyStatus::Archived);
    }

    /// Version 1 is live and Ann's version 2, written beside it, is in
    /// review. Approving it puts version 2 live and makes version 1 a past
    /// version, both saved and both recorded.
    #[test]
    fn approving_a_draft_replaces_the_live_version() {
        let live = policy_in(PolicyStatus::Active, Vec::new());
        let mut draft = draft_beside(&live);
        draft
            .submit_for_review(anyone_holding(&[SystemPermission::ManagePolicy]))
            .unwrap();
        let (first, second) = (live.version(), draft.version());
        let mut tenant = Tenant::with_policy_in(PolicyStatus::Draft);
        tenant.policies = Arc::new(FakePolicyStore::holding_versions(
            test_ctx().tenant_id(),
            [live, draft],
        ));
        tenant.ports.policy_store = tenant.policies.clone();
        let sink = Arc::new(FakeEventDispatcher::new());

        tenant.change_recorded(&sink, Transition::Activate).unwrap();

        let version = |number| tenant.policies.version(test_ctx().tenant_id(), number);
        assert_eq!(version(second).unwrap().status(), PolicyStatus::Active);
        assert_eq!(version(first).unwrap().status(), PolicyStatus::Archived);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            [
                "authorization.policy_archived",
                "authorization.policy_activated"
            ]
        );
    }

    /// Ann sends a draft to review while only the live policy exists.
    /// There is no draft to send, so it is not found and the live policy
    /// stays live.
    #[test]
    fn without_an_open_draft_there_is_nothing_to_submit() {
        let tenant = Tenant::with_policy_in(PolicyStatus::Active);

        let result = tenant.change(Transition::SubmitForReview);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(tenant.status(), PolicyStatus::Active);
    }

    /// Ann approves a draft nobody sent to review. A draft cannot skip
    /// review, so she is refused as a conflict and it stays a draft.
    #[test]
    fn a_draft_cannot_skip_review() {
        let tenant = Tenant::with_policy_in(PolicyStatus::Draft);

        let result = tenant.change(Transition::Activate);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(tenant.status(), PolicyStatus::Draft);
    }

    /// Ann moves the policy of a tenant that never saved one. There is
    /// nothing to move.
    #[test]
    fn a_tenant_without_a_policy_is_not_found() {
        let tenant = Tenant::with_no_policy();

        let result = tenant.change(Transition::Activate);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// The submitter cannot activate a policy when another tenant user may
    /// approve it. The policy stays in review.
    #[test]
    fn the_submitter_does_not_approve_while_someone_else_may() {
        let tenant = Tenant::with_policy_in(PolicyStatus::Draft).with_another_approver();
        tenant.change(Transition::SubmitForReview).unwrap();

        let result = tenant.change(Transition::Activate);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.status(), PolicyStatus::Review);
    }

    /// An organization owner counts as another approver, preventing the
    /// submitter from activating the policy and leaving it in review.
    #[test]
    fn an_owner_of_the_organization_counts_as_another_approver() {
        let tenant =
            Tenant::with_policy_in(PolicyStatus::Draft).with_an_owner_of_the_organization();
        tenant.change(Transition::SubmitForReview).unwrap();

        let result = tenant.change(Transition::Activate);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.status(), PolicyStatus::Review);
    }

    /// Bob may approve, and someone else sent the policy to review. Ann
    /// approves it and it goes live.
    #[test]
    fn someone_other_than_the_submitter_approves() {
        let tenant = Tenant::with_policy_in(PolicyStatus::Review).with_another_approver();

        tenant.change(Transition::Activate).unwrap();

        assert_eq!(tenant.status(), PolicyStatus::Active);
    }

    /// Policy update permission cannot activate a version; it stays in review.
    #[test]
    fn a_caller_who_may_not_activate_is_refused() {
        let tenant = Tenant::with_policy_in(PolicyStatus::Review)
            .holding(&[SystemPermission::PolicySet(PolicySetAction::Update)]);

        let result = tenant.change(Transition::Activate);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.status(), PolicyStatus::Review);
    }

    /// Policy view permission cannot submit a draft for review; it stays a draft.
    #[test]
    fn a_caller_who_may_not_update_the_policy_is_refused() {
        let tenant = Tenant::with_policy_in(PolicyStatus::Draft)
            .holding(&[SystemPermission::PolicySet(PolicySetAction::View)]);

        let result = tenant.change(Transition::SubmitForReview);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.status(), PolicyStatus::Draft);
    }

    /// A signed-out session cannot archive the live policy, which remains active.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let mut tenant = Tenant::with_policy_in(PolicyStatus::Active);
        tenant.ports.tenant_authorities =
            Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = tenant.change(Transition::TakeOutOfUse);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(tenant.status(), PolicyStatus::Active);
    }
}
