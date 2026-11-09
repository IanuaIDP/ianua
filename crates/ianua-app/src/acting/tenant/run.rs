//! A workflow run's company step, acting as the person the run is for.

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::run_authority::authority_of_run;
use ianua_domain::domains::organization::members::tenant_authority::{
    RunMember, authority_of_member_run,
};
use ianua_domain::domains::workflows::execution::WorkflowExecution;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{OrgUserId, UserId, WorkflowExecutionId};

use crate::acting::tenant::{Resolving, TenantActing, credential_refusal};
use crate::context::CallerIdentity;
use crate::error::AppError;
use crate::ports::authorization::Holder;

impl TenantActing {
    /// The run `execution`, acting for the person `identity` names. Only a
    /// person can be acted for: a tenant user or an organization member.
    pub(in crate::acting::tenant) async fn through_run(
        &self,
        at: &Resolving<'_>,
        identity: &CallerIdentity,
        execution: &WorkflowExecutionId,
    ) -> Result<TenantAuthority, AppError> {
        match identity {
            CallerIdentity::TenantUser(user) => self.of_run(at, user, execution).await,
            CallerIdentity::OrgUser(member) => self.of_member_run(at, member, execution).await,
            CallerIdentity::Operator(_) => Err(credential_refusal(at.caller.credential())),
        }
    }

    /// The run `execution`, acting for the tenant user `user`, for what they
    /// hold now and only while the run runs.
    async fn of_run(
        &self,
        at: &Resolving<'_>,
        user: &UserId,
        execution: &WorkflowExecutionId,
    ) -> Result<TenantAuthority, AppError> {
        let tenant = at.caller.tenant();
        let run = self.run(at, execution).await?;
        let records = self.held_by(at.caller, Holder::user(*user)).await?;
        let person = self.user(&tenant, user).await?;
        authority_of_run(&records.access(at.caller.tenant_id()), &run, &person)
            .map_err(AppError::from_domain)
    }

    /// The run `execution`, acting for the organization member `member`,
    /// for what they hold in the tenant now and only while the run runs.
    async fn of_member_run(
        &self,
        at: &Resolving<'_>,
        member_id: &OrgUserId,
        execution: &WorkflowExecutionId,
    ) -> Result<TenantAuthority, AppError> {
        let run = self.run(at, execution).await?;
        let member = self.member(member_id).await?;
        let organization = self.organization(at.caller).await?;
        let grants = self.grants(member_id, at.caller).await?;
        let records = self.granted_to(at, member_id, &grants).await?;
        let person = RunMember {
            member: &member,
            organization: &organization,
            grants: &grants,
        };
        authority_of_member_run(&records.access(at.caller.tenant_id()), &run, person)
            .map_err(AppError::from_domain)
    }

    /// The run, read afresh, or an unauthenticated caller when it is gone.
    async fn run(
        &self,
        at: &Resolving<'_>,
        execution: &WorkflowExecutionId,
    ) -> Result<WorkflowExecution<ResolvedTenant>, AppError> {
        self.ports
            .executions
            .find_by_id(&at.caller.tenant(), execution)
            .await
            .map_err(AppError::from_domain)?
            .ok_or(AppError::Unauthenticated)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
    use ianua_domain::domains::organization::billing::plan::OrganizationPlan;
    use ianua_domain::types::{ActionClass, Human, HumanAccount, PersonKey, PrincipalRef};

    use super::*;
    use crate::acting::TenantAuthorities;
    use crate::acting::tenant::{TenantActingPorts, TenantCredentialPorts};
    use crate::context::{CallerContext, CallerIdentity, Credential};
    use crate::ports::authorization::AccessRecords;
    use crate::test_support::authorization::{
        FakeAccessRecordStore, stored_assignment, stored_role,
    };
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::workflows::{FakeWorkflowExecutionStore, awaiting_approval, managing};
    use crate::test_support::{block_on, test_ctx};

    const MANAGE_ROLES: SystemPermission = SystemPermission::Roles(RoleAction::Manage);

    fn ann_of(user: UserId) -> Human {
        Human::new(
            HumanAccount::User(user),
            PersonKey::new("ann@acme.test").expect("an address"),
        )
    }

    /// A run Ann started, still running: it waits for an approval.
    fn running_for(ann: &Human) -> WorkflowExecution<ResolvedTenant> {
        awaiting_approval(ann, ann, ActionClass::Write)
    }

    /// Acme, where Ann may manage roles, keeping `runs`.
    fn acme(ann: UserId, runs: FakeWorkflowExecutionStore) -> TenantActing {
        let manager = stored_role("manager", vec![MANAGE_ROLES], Vec::new());
        let records = AccessRecords {
            assignments: vec![stored_assignment(PrincipalRef::User(ann), *manager.id())],
            roles: vec![manager],
            ..AccessRecords::default()
        };
        TenantActing::new(TenantActingPorts {
            access: Arc::new(FakeAccessRecordStore::holding(
                test_ctx().tenant_id(),
                records,
            )),
            tenants: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
            executions: Arc::new(runs),
            tenant: TenantCredentialPorts {
                users: Arc::new(FakeUserStore::with_user(ann, "ann@acme.test")),
                ..TenantCredentialPorts::fakes()
            },
            ..TenantActingPorts::fakes()
        })
    }

    /// `user`, coming through the run `execution`.
    fn through_run(user: UserId, execution: WorkflowExecutionId) -> CallerContext {
        CallerContext::new(
            CallerIdentity::TenantUser(user),
            Credential::WorkflowRun(execution),
            test_ctx().organization_id(),
            test_ctx().tenant_id(),
            OrganizationPlan::Free.default_limits(),
        )
        .expect("a run fits a tenant user")
    }

    /// Ann's running workflow signs Lee out. Its step holds what Ann holds
    /// now, as Ann.
    #[test]
    fn a_running_run_acts_with_its_persons_rights() {
        let ann = UserId::new();
        let run = running_for(&ann_of(ann));
        let acting = acme(ann, FakeWorkflowExecutionStore::holding(&run));

        let authority = block_on(acting.authority(&through_run(ann, *run.id()))).unwrap();

        assert!(authority.holds(MANAGE_ROLES));
        assert_eq!(authority.who().account(), HumanAccount::User(ann));
    }

    /// Cancelling Ann's run prevents later authority resolution through
    /// that run, which returns forbidden.
    #[test]
    fn an_ended_run_is_refused() {
        let ann = UserId::new();
        let mut run = running_for(&ann_of(ann));
        run.cancel(&managing(&ann_of(ann))).unwrap();
        let acting = acme(ann, FakeWorkflowExecutionStore::holding(&run));

        let result = block_on(acting.authority(&through_run(ann, *run.id())));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Mallory cannot use Ann's workflow run as her own credential;
    /// resolving that caller returns forbidden.
    #[test]
    fn someone_elses_run_is_refused() {
        let ann = UserId::new();
        let mallory = UserId::new();
        let run = running_for(&ann_of(ann));
        let acting = acme(mallory, FakeWorkflowExecutionStore::holding(&run));

        let result = block_on(acting.authority(&through_run(mallory, *run.id())));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A workflow run missing from storage is unauthenticated, even when
    /// the named user has tenant permissions.
    #[test]
    fn a_run_that_is_not_there_is_refused() {
        let ann = UserId::new();
        let run = running_for(&ann_of(ann));
        let acting = acme(ann, FakeWorkflowExecutionStore::holding(&run));

        let missing = block_on(acting.authority(&through_run(ann, WorkflowExecutionId::new())));

        assert!(matches!(missing, Err(AppError::Unauthenticated)));
    }
}
