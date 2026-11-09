//! The approval request a paused run raises, so the call it holds appears
//! where people look for decisions.
//!
//! The request names the run and the exact call it holds, so a decision
//! cannot land on a different call. It names the agent's owner and the
//! people behind the delegation the call uses, none of whom may approve it.

use ianua_domain::domains::agents::execution::run::AgentRun;
use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::oversight::approval::{
    ActionParties, ApprovalAction, ApprovalOrigin, ApprovalRequest, RequestApprovalParams,
    RunOrigin,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{DeclaredAction, Human, PrincipalRef};

use crate::error::AppError;
use crate::use_cases::agents::people::{PeopleSources, people_behind_all};
use crate::use_cases::agents::runs::driving::drive::Driving;
use crate::use_cases::agents::runs::driving::toolbox::Toolbox;

/// A run paused on a call, with its agent and the action it holds.
pub(in crate::use_cases::agents::runs) struct PausedRun<'a> {
    /// The execution holding the call awaiting a decision.
    pub(in crate::use_cases::agents::runs) run: &'a AgentRun<ResolvedTenant>,
    /// The run's agent.
    pub(in crate::use_cases::agents::runs) agent: &'a AgentIdentity<ResolvedTenant>,
    /// The action the call takes.
    pub(in crate::use_cases::agents::runs) action: ApprovalAction,
}

/// The approval request `paused` raises, lasting the worker's approval
/// window.
///
/// # Errors
///
/// - `AppError::Conflict` when the run is not paused.
/// - `AppError::Domain` when a person behind the delegation is no longer
///   stored, or the request does not fit the run.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::agents::runs) async fn raised_approval(
    driving: &Driving<'_>,
    toolbox: &Toolbox,
    paused: PausedRun<'_>,
) -> Result<ApprovalRequest<ResolvedTenant>, AppError> {
    let origin = RunOrigin::of(paused.run).ok_or_else(|| {
        AppError::Conflict(message!(
            "agents-the-run-is-not-paused-on",
            "the run is not paused on a call"
        ))
    })?;
    let people = people_behind(driving, &toolbox.delegators()).await?;
    let parties = ActionParties::behind(paused.agent, &toolbox.action_authority(), &people)
        .map_err(AppError::from_domain)?;
    ApprovalRequest::request(RequestApprovalParams {
        agent_id: *paused.run.agent_id(),
        delegation_id: *paused.run.delegation_id(),
        action_class: DeclaredAction::Declared(origin.class()),
        origin: ApprovalOrigin::Run(origin),
        parties,
        action: paused.action,
        ttl_seconds: driving.approval_ttl,
    })
    .map_err(AppError::from_domain)
}

/// The person behind each of `principals` that is a person and still
/// stored.
async fn people_behind(
    driving: &Driving<'_>,
    principals: &[PrincipalRef],
) -> Result<Vec<Human>, AppError> {
    let sources = PeopleSources {
        users: driving.ports.people.user_store.as_ref(),
        members: driving.ports.people.org_user_store.as_ref(),
    };
    people_behind_all(sources, driving.tenant, principals).await
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::{AgentId, HumanAccount, OrganizationId, Seconds, UserId};

    use super::*;
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::organization::{FakeOrgUserStore, org_user_store_with, test_org_user};
    use crate::test_support::{block_on, test_ctx};
    use crate::use_cases::agents::runs::driving::drive::{DrivePorts, RunPeople};

    /// Mixed repeated accounts keep their original order and omit missing
    /// people without repeating either account store read.
    #[test]
    fn paused_run_people_share_one_account_read_per_kind() {
        let ann = UserId::new();
        let bob = UserId::new();
        let users = Arc::new(FakeUserStore::with_user(ann, "ann@example.test"));
        users.add_active_user(bob, "bob@example.test");
        let carol = test_org_user(OrganizationId::new(), "ann@example.test", OrgRole::Member);
        let dan = test_org_user(OrganizationId::new(), "dan@example.test", OrgRole::Member);
        let carol_id = *carol.id();
        let dan_id = *dan.id();
        let members = Arc::new(org_user_store_with([carol, dan]));
        let principals = vec![
            PrincipalRef::User(ann),
            PrincipalRef::OrgUser(carol_id),
            PrincipalRef::User(bob),
            PrincipalRef::OrgUser(dan_id),
            PrincipalRef::User(ann),
            PrincipalRef::Agent(AgentId::new()),
            PrincipalRef::User(UserId::new()),
        ];

        let people = resolve_people(&users, &members, &principals);

        assert_eq!(
            people.iter().map(Human::account).collect::<Vec<_>>(),
            vec![
                HumanAccount::User(ann),
                HumanAccount::OrgUser(carol_id),
                HumanAccount::User(bob),
                HumanAccount::OrgUser(dan_id),
                HumanAccount::User(ann)
            ]
        );
        assert_reads(&people, &users, &members);
    }

    /// Resolves these accounts through the stores a paused run uses.
    fn resolve_people(
        users: &Arc<FakeUserStore>,
        members: &Arc<FakeOrgUserStore>,
        principals: &[PrincipalRef],
    ) -> Vec<Human> {
        let ports = DrivePorts {
            people: RunPeople {
                user_store: users.clone(),
                org_user_store: members.clone(),
                ..RunPeople::fakes()
            },
            ..DrivePorts::fakes()
        };
        let tenant = test_ctx().tenant();
        let driving = Driving {
            ports: &ports,
            tenant: &tenant,
            approval_ttl: Seconds::new(900),
        };
        block_on(people_behind(&driving, principals)).unwrap()
    }

    /// The shared mailbox resolves to one person and each account store is read once.
    fn assert_reads(people: &[Human], users: &FakeUserStore, members: &FakeOrgUserStore) {
        assert_eq!(people[0].person(), people[1].person());
        assert_eq!(
            users.id_reads().len(),
            1,
            "tenant people must share one read"
        );
        assert_eq!(
            members.id_reads().len(),
            1,
            "organization people must share one read"
        );
    }
}
