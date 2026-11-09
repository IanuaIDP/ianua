//! What the person an execution acts for holds right now.
//!
//! A workflow keeps running for its person after they start it. A schedule
//! fires for whoever published it. An approval resumes it days later. So
//! every step that acts for them asks again what they hold, as an agent run
//! asks again before every step. When a person leaves, is suspended or
//! loses a grant, their workflows stop at the next such step.

use crate::domains::agents::authority::capability::{CapabilitySet, ResourceCapability};
use crate::domains::agents::authority::delegation::HeldResources;
use crate::domains::authorization::authority::{TenantAccess, TenantAuthority};
use crate::domains::authorization::permission::{SystemPermission, WorkflowAction};
use crate::domains::authorization::run_authority::RunCharter;
use crate::domains::identity::sealed::Sealed;
use crate::domains::notifications::category::VisibleTo;
use crate::domains::organization::members::account_now::AccountNow;
use crate::domains::workflows::account::IntegrationAccount;
use crate::domains::workflows::design::workflow::{Publication, Workflow};
use crate::domains::workflows::evaluation::run::Evaluation;
use crate::domains::workflows::execution::{ExecutionStatus, WorkflowExecution};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{EventType, EventVisibility, Human, ModelProviderId};

/// What one person holds right now: their built-in permissions, as the
/// tenant's records give them, and the resources the relationship graph
/// says they were given use of.
///
/// Nobody writes it by hand. Sam starts a workflow. If the request carried
/// what he holds, it would name "manage users" and every step would act
/// with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActingAuthority {
    person: Human,
    held: CapabilitySet,
}

impl ActingAuthority {
    /// What the person signed in as `authority` holds, with the resources
    /// `resources` says they hold.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `resources` was answered for
    ///   someone else.
    pub fn of_signed_in(
        authority: &TenantAuthority,
        resources: &HeldResources,
    ) -> Result<Self, DomainError> {
        let person = authority.who().clone();
        let held = held_from(&person, authority.standing().system().to_vec(), resources)?;
        Ok(Self { person, held })
    }

    /// Resolves the publisher's current rights for schedule, webhook and event starts.
    /// Uses current tenant roles or organization membership; departed or barred publishers cannot act.
    ///
    /// # Errors
    /// [`DomainError::Conflict`] if never published.
    /// [`DomainError::Forbidden`] for another person's account/resources, inability to act,
    /// or an organization that does not own the tenant, is closed, or is suspended for a non-owner.
    /// [`DomainError::Infrastructure`] for missing role or group records.
    pub fn of_publisher<T: TenantScope>(
        workflow: &Workflow<T>,
        account: &AccountNow<'_, T>,
        access: &TenantAccess<'_, T>,
        resources: &HeldResources,
    ) -> Result<Self, DomainError> {
        let Publication::PublishedBy(person) = workflow.publication() else {
            return Err(DomainError::conflict(message!(
                "workflows-the-workflow-was-never-published",
                "the workflow was never published"
            )));
        };
        Self::of_person(person, account, access, resources)
    }

    /// Resolves current rights for the person an execution acts for before each later step.
    /// Resuming a paused execution cannot retain rights its actor has lost.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] for another person's account/resources, inability to act,
    /// or an organization that does not own the tenant, is closed, or is suspended for a non-owner.
    /// [`DomainError::Infrastructure`] for missing role or group records.
    pub fn of_acting_for<T: TenantScope>(
        execution: &WorkflowExecution<T>,
        account: &AccountNow<'_, T>,
        access: &TenantAccess<'_, T>,
        resources: &HeldResources,
    ) -> Result<Self, DomainError> {
        Self::of_person(execution.acting_for(), account, access, resources)
    }

    /// What the person who started `evaluation` holds now, for the test
    /// run of each case it starts after they asked.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `account` is not theirs, may not
    ///   act now, or `resources` was answered for someone else.
    /// - [`DomainError::Forbidden`] when a member's organization does not
    ///   own the tenant, is closed, or is suspended and they are no owner.
    /// - [`DomainError::Infrastructure`] when the records name a role or
    ///   group that is not there.
    pub fn of_evaluator<T: TenantScope>(
        evaluation: &Evaluation<T>,
        account: &AccountNow<'_, T>,
        access: &TenantAccess<'_, T>,
        resources: &HeldResources,
    ) -> Result<Self, DomainError> {
        Self::of_person(evaluation.started_by(), account, access, resources)
    }

    /// What the owner of `shared` holds now, as the tenant's records say,
    /// for [`IntegrationAccount::grant_use`] to ask whether they may still
    /// lend it. It carries no resources, since lending needs none.
    ///
    /// Ann shares her account with the tenant. Bob's workflow uses it while
    /// Ann is signed out, so what she holds is worked out from her account
    /// as it is now. Once she leaves, her account acts for nobody.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `owner` is not the account that
    ///   connected `shared`, or may not act now.
    /// - [`DomainError::Forbidden`] when a member's organization does not
    ///   own the tenant, is closed, or is suspended and they are no owner.
    /// - [`DomainError::Infrastructure`] when the records name a role or
    ///   group that is not there.
    pub fn of_account_owner<T: TenantScope>(
        shared: &IntegrationAccount<T>,
        owner: &AccountNow<'_, T>,
        access: &TenantAccess<'_, T>,
    ) -> Result<Self, DomainError> {
        let person = shared.owner();
        ensure_account_of(person, owner)?;
        let standing = owner.standing_in(access)?;
        Ok(Self {
            person: person.clone(),
            held: CapabilitySet::new(standing.system().to_vec(), Vec::new()),
        })
    }

    /// What `person` holds now through `account`, with `resources`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `account` is not `person`'s, or may
    ///   not act now.
    /// - [`DomainError::Forbidden`] when `resources` was answered for
    ///   someone else.
    /// - [`DomainError::Forbidden`] when a member's organization does not
    ///   own the tenant, is closed, or is suspended and they are no owner.
    /// - [`DomainError::Infrastructure`] when the records name a role or
    ///   group that is not there.
    fn of_person<T: TenantScope>(
        person: &Human,
        account: &AccountNow<'_, T>,
        access: &TenantAccess<'_, T>,
        resources: &HeldResources,
    ) -> Result<Self, DomainError> {
        ensure_account_of(person, account)?;
        let standing = account.standing_in(access)?;
        let held = held_from(person, standing.system().to_vec(), resources)?;
        Ok(Self {
            person: person.clone(),
            held,
        })
    }

    /// `person` holding `held`, as a test says, without the records behind
    /// it.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn assumed(person: Human, held: CapabilitySet) -> Self {
        Self { person, held }
    }

    /// Whose authority this is.
    #[must_use]
    pub fn person(&self) -> &Human {
        &self.person
    }

    /// Whether `person` may have workflows run for them.
    ///
    /// This must be their authority, and they must hold the permission to
    /// run workflows.
    pub(super) fn may_run_for(&self, person: &Human) -> bool {
        self.person == *person && self.covers(&run_permission())
    }

    /// Whether `person` may have an agent run on `provider` under a
    /// delegation granting `granted`.
    ///
    /// They must be able to run workflows and use the provider. They must
    /// still hold everything the delegation grants.
    pub(super) fn may_run_agent_for(
        &self,
        person: &Human,
        provider: &ModelProviderId,
        granted: &CapabilitySet,
    ) -> bool {
        let provider_use = CapabilitySet::empty()
            .with_resources(vec![ResourceCapability::use_of_provider(provider)]);
        self.may_run_for(person) && self.covers(&provider_use) && self.covers(granted)
    }

    /// Whether this is `owner`'s authority and they may still lend the
    /// integration accounts they connected.
    pub(crate) fn may_lend_accounts(&self, owner: &Human) -> bool {
        let lending = CapabilitySet::new(
            vec![SystemPermission::Workflows(WorkflowAction::ConnectAccounts)],
            Vec::new(),
        );
        self.person == *owner && self.covers(&lending)
    }

    /// Whether they may test workflows: edit them and have them run.
    pub(super) fn may_test(&self) -> bool {
        let testing = CapabilitySet::new(
            vec![
                SystemPermission::Workflows(WorkflowAction::Update),
                SystemPermission::Workflows(WorkflowAction::Run),
            ],
            Vec::new(),
        );
        self.covers(&testing)
    }

    fn covers(&self, needed: &CapabilitySet) -> bool {
        needed.subset_of(&self.held)
    }
}

/// The events the person may see now, by the same rule as their
/// notification feed.
impl EventVisibility for ActingAuthority {
    fn may_see(&self, event_type: &EventType) -> bool {
        VisibleTo(self.held.http()).may_see(event_type)
    }
}

/// Refuses `account` unless it is the one `person` acts through.
fn ensure_account_of<T: TenantScope>(
    person: &Human,
    account: &AccountNow<'_, T>,
) -> Result<(), DomainError> {
    if person.principal() != account.principal() {
        return Err(may_not_act());
    }
    Ok(())
}

fn may_not_act() -> DomainError {
    DomainError::forbidden(message!(
        "workflows-the-person-the-workflow-acts-for",
        "the person the workflow acts for may not act now"
    ))
}

/// `system` with the resources `resources` says `person` holds.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] when `resources` was answered for someone
///   else.
fn held_from(
    person: &Human,
    system: Vec<SystemPermission>,
    resources: &HeldResources,
) -> Result<CapabilitySet, DomainError> {
    if *resources.subject() != person.principal() {
        return Err(DomainError::forbidden(message!(
            "workflows-the-resources-were-looked-up-for",
            "the resources were looked up for someone else"
        )));
    }
    Ok(CapabilitySet::new(system, Vec::new()).with_resources(resources.resources().to_vec()))
}

fn run_permission() -> CapabilitySet {
    CapabilitySet::new(
        vec![SystemPermission::Workflows(WorkflowAction::Run)],
        Vec::new(),
    )
}

/// A run tells authorization who it acts for and whether it still runs,
/// so a company step calls a feature as its person, and only while it runs.
impl<T: TenantScope> Sealed for WorkflowExecution<T> {}

impl<T: TenantScope> RunCharter for WorkflowExecution<T> {
    fn acting_for(&self) -> &Human {
        WorkflowExecution::acting_for(self)
    }

    fn is_running(&self) -> bool {
        matches!(self.status(), ExecutionStatus::Running)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::group::{Group, GroupMembership};
    use crate::domains::authorization::role::{DefaultAssignment, NewRole, Role, RoleAssignment};
    use crate::domains::authorization::stewardship::TenantGrants;
    use crate::domains::data_classification::level::DataClassLevel;
    use crate::domains::identity::account::user::User;
    use crate::domains::identity::account::user::tests::control_over;
    use crate::domains::organization::access::session::tests::{acme_with, plain_member};
    use crate::domains::organization::lifecycle::Organization;
    use crate::domains::organization::members::account_now::MemberNow;
    use crate::domains::organization::members::org_user::OrgUser;
    use crate::domains::organization::members::tenant_grant::{OrgTenantGrant, OrgTenantGrantRow};
    use crate::domains::organization::status::OrganizationStatus;
    use crate::domains::workflows::execution::tests::fixtures::{
        SeesAll, acting, ann, append, approval, bob, by_hand, draft, publish_as, published,
        sheet_account, start_as,
    };
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::builders::{label, user};
    use crate::types::{ActedBy, HumanAccount, PersonKey, PrincipalRef, RoleId, TenantId};

    const RUN: SystemPermission = SystemPermission::Workflows(WorkflowAction::Run);
    const LEND: SystemPermission = SystemPermission::Workflows(WorkflowAction::ConnectAccounts);

    /// One tenant's roles and who holds them, owned so a test can lend them
    /// out.
    struct Records {
        tenant: TenantId,
        roles: Vec<Role<ResolvedTenant>>,
        assignments: Vec<RoleAssignment<ResolvedTenant>>,
    }

    impl Records {
        /// `tenant`, with one role granting `system`, held by `holders`.
        fn of(tenant: TenantId, system: &[SystemPermission], holders: &[PrincipalRef]) -> Self {
            let role = Role::provisioned(NewRole {
                id: RoleId::new(),
                name: label("automation"),
                system_permissions: system.to_vec(),
                custom_permissions: Vec::new(),
                assignment: DefaultAssignment::Manual,
            });
            let everything = anyone_holding(SystemPermission::all());
            let assignments = holders
                .iter()
                .map(|holder| RoleAssignment::create(*holder, &role, everything).unwrap())
                .collect();
            Self {
                tenant,
                roles: vec![role],
                assignments,
            }
        }

        fn role(&self) -> RoleId {
            *self.roles[0].id()
        }

        fn access(&self) -> TenantAccess<'_, ResolvedTenant> {
            TenantAccess {
                tenant: self.tenant,
                grants: TenantGrants {
                    roles: &self.roles,
                    assignments: &self.assignments,
                    groups: &[] as &[Group<ResolvedTenant>],
                    memberships: &[] as &[GroupMembership<ResolvedTenant>],
                },
                catalogue: &[],
                break_glass: &[],
            }
        }
    }

    /// The active tenant account `person` acts through.
    fn account_of(person: &Human) -> User<ResolvedTenant> {
        let HumanAccount::User(id) = person.account() else {
            unreachable!("the test people act through tenant accounts")
        };
        let mut account = user(id, person.person().as_str());
        account.activate(&control_over(&account)).unwrap();
        account
    }

    fn shut_out(account: &mut User<ResolvedTenant>) {
        account.deactivate(&control_over(account)).unwrap();
    }

    fn nothing_for(person: &Human) -> HeldResources {
        HeldResources::answered(person.principal(), Vec::new())
    }

    /// Ann published the weekly report and may run workflows. Its schedule
    /// acts for her with what the records give her now.
    #[test]
    fn a_publisher_acts_with_what_the_records_give_them_now() {
        let workflow = published(vec![approval("check")], Vec::new());
        let records = Records::of(TenantId::new(), &[RUN], &[ann().principal()]);
        let account = account_of(&ann());

        let authority = ActingAuthority::of_publisher(
            &workflow,
            &AccountNow::User(&account),
            &records.access(),
            &nothing_for(&ann()),
        )
        .unwrap();

        assert_eq!(authority.person(), &ann());
        assert!(authority.may_run_for(&ann()));
    }

    /// Publisher authority cannot be resolved from Ann's deactivated
    /// account or from Bob's account substituted for hers. Both are forbidden.
    #[test]
    fn a_shut_out_publisher_or_someone_elses_account_starts_nothing() {
        let workflow = published(vec![approval("check")], Vec::new());
        let records = Records::of(TenantId::new(), &[RUN], &[ann().principal()]);
        let mut account = account_of(&ann());
        shut_out(&mut account);
        let bobs = account_of(&bob());

        let for_ann = ActingAuthority::of_publisher(
            &workflow,
            &AccountNow::User(&account),
            &records.access(),
            &nothing_for(&ann()),
        );
        let for_bob = ActingAuthority::of_publisher(
            &workflow,
            &AccountNow::User(&bobs),
            &records.access(),
            &nothing_for(&ann()),
        );

        assert!(matches!(for_ann, Err(DomainError::Forbidden(_))));
        assert!(matches!(for_bob, Err(DomainError::Forbidden(_))));
    }

    /// Acme's production tenant and its organization, where Sam is a plain
    /// member granted a role that runs workflows, with a workflow Sam
    /// published there.
    struct MemberPublished {
        records: Records,
        organization: Organization,
        sam: OrgUser,
        grants: Vec<OrgTenantGrant>,
        workflow: Workflow<ResolvedTenant>,
    }

    impl MemberPublished {
        fn new() -> Self {
            let production = TenantId::new();
            let (organization, founder) = acme_with(production);
            let sam = plain_member(&organization, &founder);
            let records = Records::of(production, &[RUN], &[]);
            let grants = vec![
                OrgTenantGrant::reconstitute(OrgTenantGrantRow {
                    org_user_id: *sam.id(),
                    tenant_id: production,
                    role_id: records.role(),
                    granted_by: ActedBy::Platform,
                    granted_at: crate::shared::clock::now(),
                })
                .unwrap(),
            ];
            let mut workflow = draft(vec![approval("check")], Vec::new());
            publish_as(&mut workflow, &human(&sam), &[], &SeesAll).unwrap();
            Self {
                records,
                organization,
                sam,
                grants,
                workflow,
            }
        }

        fn publisher(&self) -> Result<ActingAuthority, DomainError> {
            let member = AccountNow::Member(MemberNow {
                member: &self.sam,
                organization: &self.organization,
                grants: &self.grants,
            });
            ActingAuthority::of_publisher(
                &self.workflow,
                &member,
                &self.records.access(),
                &nothing_for(&human(&self.sam)),
            )
        }
    }

    fn human(member: &OrgUser) -> Human {
        Human::new(
            HumanAccount::OrgUser(*member.id()),
            PersonKey::of(member.email()),
        )
    }

    /// Sam, a plain member of Acme's organization, published a workflow in
    /// production, where his grant lets him run workflows. Its trigger
    /// starts it for him.
    #[test]
    fn a_member_publisher_holds_what_their_tenant_grant_gives() {
        let published = MemberPublished::new();

        let authority = published.publisher().unwrap();

        assert!(authority.may_run_for(&human(&published.sam)));
    }

    /// Suspending Acme prevents resolving publisher authority for its plain
    /// member Sam and returns a forbidden error.
    #[test]
    fn a_suspended_organizations_member_starts_nothing() {
        let mut published = MemberPublished::new();
        published
            .organization
            .change_status(OrganizationStatus::Suspended, ActedBy::Platform)
            .unwrap();

        assert!(matches!(
            published.publisher(),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// Bob starts Ann's workflow by hand and is shut out before its next
    /// step. The step acts for Bob with what he holds now, so it is refused.
    /// Ann's account does not stand in for him.
    #[test]
    fn a_later_step_acts_for_the_person_the_execution_was_started_for() {
        let workflow = published(vec![approval("check")], Vec::new());
        let (execution, _) = start_as(&workflow, &bob(), by_hand(DataClassLevel::Public)).unwrap();
        let records = Records::of(TenantId::new(), &[RUN], &[bob().principal()]);
        let mut bobs = account_of(&bob());
        let anns = account_of(&ann());
        let step = |account: &User<ResolvedTenant>| {
            ActingAuthority::of_acting_for(
                &execution,
                &AccountNow::User(account),
                &records.access(),
                &nothing_for(&bob()),
            )
        };

        let while_active = step(&bobs).map(|authority| authority.may_run_for(&bob()));
        let through_ann = step(&anns);
        shut_out(&mut bobs);
        let after = step(&bobs);

        assert!(matches!(while_active, Ok(true)));
        assert!(matches!(through_ann, Err(DomainError::Forbidden(_))));
        assert!(matches!(after, Err(DomainError::Forbidden(_))));
    }

    /// Ann shares her sheets account with the tenant and may still lend it.
    /// Bob's workflow uses it while she is signed out.
    #[test]
    fn a_shared_account_is_lent_with_its_owners_rights_now() {
        let shared = sheet_account(&ann(), "google-sheets");
        let records = Records::of(TenantId::new(), &[LEND], &[ann().principal()]);
        let owner = account_of(&ann());

        let lender = ActingAuthority::of_account_owner(
            &shared,
            &AccountNow::User(&owner),
            &records.access(),
        )
        .unwrap();

        assert!(
            shared
                .grant_use(&acting(&bob()), &append(), &lender)
                .is_ok()
        );
    }

    /// Bob cannot borrow Ann's shared account after she loses lending
    /// rights. Deactivating Ann also prevents resolving her lender authority.
    #[test]
    fn a_shared_account_whose_owner_may_no_longer_lend_it_acts_for_nobody() {
        let shared = sheet_account(&ann(), "google-sheets");
        let without_the_right = Records::of(TenantId::new(), &[RUN], &[ann().principal()]);
        let mut owner = account_of(&ann());

        let lender = ActingAuthority::of_account_owner(
            &shared,
            &AccountNow::User(&owner),
            &without_the_right.access(),
        )
        .unwrap();
        let lent = shared.grant_use(&acting(&bob()), &append(), &lender);
        shut_out(&mut owner);
        let after_leaving = ActingAuthority::of_account_owner(
            &shared,
            &AccountNow::User(&owner),
            &without_the_right.access(),
        );

        assert!(matches!(lent, Err(DomainError::Forbidden(_))));
        assert!(matches!(after_leaving, Err(DomainError::Forbidden(_))));
    }
}
