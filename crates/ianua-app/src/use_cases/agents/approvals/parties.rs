//! The people answerable for an agent's action: its owner and the people
//! behind the delegation it uses, none of whom may approve it.
//!
//! A delegation names accounts. Two-person rules compare people, so each
//! account the chain names is read back to the person behind it, from the
//! account's own record.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::oversight::approval::ActionParties;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::error::AppError;
use crate::ports::identity::UserStore;
use crate::ports::organization::OrgUserStore;
use crate::tenancy::ScopedTenant;
use crate::use_cases::agents::approvals::action_authority::LoadedAuthority;
use crate::use_cases::agents::people::{PeopleSources, people_behind_all};

/// Where the people behind an account are read.
#[derive(Clone, ianua_macros::Fakes)]
pub struct PeoplePorts {
    /// The tenant's users.
    pub user_store: Arc<dyn UserStore>,
    /// The organization's members.
    pub org_user_store: Arc<dyn OrgUserStore>,
}

impl PeoplePorts {
    /// The stores as the people service reads them.
    pub(in crate::use_cases::agents) fn sources(&self) -> PeopleSources<'_> {
        PeopleSources {
            users: self.user_store.as_ref(),
            members: self.org_user_store.as_ref(),
        }
    }
}

/// The people answerable for an action of `agent` on `loaded`.
///
/// # Errors
///
/// - `AppError::Forbidden` when the delegation was granted to another agent.
/// - `AppError::Domain` when a person behind the delegation can no longer
///   be read.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::agents) async fn parties_behind(
    people: &PeoplePorts,
    tenant: &ScopedTenant,
    agent: &AgentIdentity<ResolvedTenant>,
    loaded: &LoadedAuthority,
) -> Result<ActionParties, AppError> {
    let named = people_behind_all(people.sources(), tenant, &loaded.grantors()).await?;
    ActionParties::behind(agent, &loaded.authority(), &named).map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::CapabilitySet;
    use ianua_domain::domains::agents::authority::delegation::{
        Delegation, DelegationRow, Lineage,
    };
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::{
        AgentCredentialId, AgentId, HumanAccount, OrganizationId, PrincipalRef, UserId,
    };

    use super::*;
    use crate::ports::agents::DelegationStore as _;
    use crate::test_support::agents::{
        FakeDelegationStore, agent_owned_by, caller_person, child_delegation, delegation_row,
        root_delegation,
    };
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::organization::{FakeOrgUserStore, org_user_store_with, test_org_user};
    use crate::test_support::{block_on, test_ctx};
    use crate::use_cases::agents::approvals::action_authority::loaded_from;

    /// A minted grant keeps all four human roots answerable while their two
    /// account kinds are each read once.
    #[test]
    fn approval_parties_share_one_account_read_per_kind() {
        let ann = UserId::new();
        let bob = UserId::new();
        let users = Arc::new(FakeUserStore::with_user(ann, "ann@example.test"));
        users.add_active_user(bob, "bob@example.test");
        let carol = test_org_user(OrganizationId::new(), "carol@example.test", OrgRole::Member);
        let dan = test_org_user(OrganizationId::new(), "dan@example.test", OrgRole::Member);
        let accounts = [
            HumanAccount::User(ann),
            HumanAccount::User(bob),
            HumanAccount::OrgUser(*carol.id()),
            HumanAccount::OrgUser(*dan.id()),
        ];
        let members = Arc::new(org_user_store_with([carol, dan]));
        let people = PeoplePorts {
            user_store: users.clone(),
            org_user_store: members.clone(),
        };
        let agent = agent_owned_by(AgentId::new(), caller_person());
        let loaded = authority_from(&agent, &accounts);

        let parties = block_on(parties_behind(
            &people,
            &test_ctx().tenant(),
            &agent,
            &loaded,
        ))
        .unwrap();

        assert_parties(&parties, &agent, &accounts);
        assert_account_reads(&users, &members);
    }

    /// Resolving all parties reads each account store once.
    fn assert_account_reads(users: &FakeUserStore, members: &FakeOrgUserStore) {
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

    /// Every source account and the agent's owner remain answerable for the action.
    fn assert_parties(
        parties: &ActionParties,
        agent: &AgentIdentity<ResolvedTenant>,
        accounts: &[HumanAccount],
    ) {
        assert_eq!(parties.owner(), agent.owner());
        assert_eq!(parties.delegators().len(), accounts.len());
        for account in accounts {
            assert!(
                parties
                    .delegators()
                    .iter()
                    .any(|person| person.account() == *account)
            );
        }
    }

    /// An unreadable person at the delegation root prevents resolving the
    /// approval parties and returns a validation error.
    #[test]
    fn a_missing_root_person_still_refuses_approval_parties() {
        let agent = agent_owned_by(AgentId::new(), caller_person());
        let loaded = authority_from(&agent, &[HumanAccount::User(UserId::new())]);

        let result = block_on(parties_behind(
            &PeoplePorts::fakes(),
            &test_ctx().tenant(),
            &agent,
            &loaded,
        ));

        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::Validation(_)))
        ));
    }

    /// Human roots pass through one agent to the acting agent, which
    /// mints their combined authority and retains every source.
    fn authority_from(
        agent: &AgentIdentity<ResolvedTenant>,
        accounts: &[HumanAccount],
    ) -> LoadedAuthority {
        let tenant = test_ctx().tenant();
        let store = FakeDelegationStore::empty();
        let intermediary = AgentId::new();
        let mut sources = Vec::new();
        for account in accounts {
            let principal = match account {
                HumanAccount::User(id) => PrincipalRef::User(*id),
                HumanAccount::OrgUser(id) => PrincipalRef::OrgUser(*id),
            };
            let root = root_delegation(principal, intermediary, CapabilitySet::empty());
            let child = child_delegation(&root, *agent.id(), CapabilitySet::empty());
            sources.push(*child.id());
            block_on(store.save(&tenant, &root)).unwrap();
            block_on(store.save(&tenant, &child)).unwrap();
        }
        let minted = Delegation::reconstitute(DelegationRow {
            lineage: Lineage::Minted {
                from: sources,
                delegator: PrincipalRef::Agent(intermediary),
                signed_in_with: AgentCredentialId::new(),
            },
            depth: 1,
            ..delegation_row(*agent.id(), PrincipalRef::Agent(*agent.id()))
        })
        .unwrap();
        block_on(loaded_from(&store, &tenant, minted)).unwrap()
    }
}
