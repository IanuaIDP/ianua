//! Who may decide an approval request, and who may not.

use crate::domains::agents::authority::delegation::{ActingUnder, people_behind};
use crate::domains::agents::identity::agent::AgentIdentity;
use crate::domains::agents::identity::control::AgentControl;
use crate::domains::agents::oversight::approval::ActionAuthority;
use crate::domains::authentication::mfa::enrollment::AnsweredCode;
use crate::domains::authentication::sessions::fresh_sign_in::FreshSignIn;
use crate::domains::authorization::permission::AgentAction;
use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::identity::account::control::RecentProof;
use crate::domains::tenant::control::principal_of;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{Human, PrincipalRef};

/// The people answerable for the action a request is about: the agent's
/// owner, and the people at the root of the delegation the action uses.
///
/// None of them may approve it. An approval exists so someone else looks at
/// what the agent does. Bob's schedule starts a run of Ann's agent, and it
/// pauses on a payment. Without this, Ann approves her own agent's payment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionParties {
    owner: Human,
    delegators: Vec<Human>,
}

impl ActionParties {
    /// The people answerable for an action of `agent` on `authority`: its
    /// owner, and the person at the top of every chain the delegation was
    /// cut from, through parents and the delegations a task token was minted
    /// from.
    ///
    /// `people` gives the person behind each account the chain names. Each
    /// one is matched by account, so naming someone else changes nothing.
    /// Ann's delegation reaches the agent through a token it minted. Without
    /// following the token to her delegation, Ann would not be named and
    /// could approve her own delegation's payment.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the delegation was granted to an
    ///   agent other than `agent`.
    /// - [`DomainError::Validation`] when `people` leaves out a person the
    ///   chain names.
    pub fn behind<T: TenantScope>(
        agent: &AgentIdentity<T>,
        authority: &ActionAuthority<'_, T>,
        people: &[Human],
    ) -> Result<Self, DomainError> {
        let named = match authority {
            ActionAuthority::NoDelegation => Vec::new(),
            ActionAuthority::Delegation { delegation, above } => {
                if delegation.delegate() != agent.id() {
                    return Err(DomainError::forbidden(message!(
                        "agents-the-delegation-was-granted-to-another",
                        "the delegation was granted to another agent"
                    )));
                }
                people_behind(delegation, above)
            }
        };
        let delegators = named
            .iter()
            .map(|principal| person_named(principal, people))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            owner: agent.owner().clone(),
            delegators,
        })
    }

    /// The parties as a stored request keeps them.
    #[must_use]
    pub fn from_stored(owner: Human, delegators: Vec<Human>) -> Self {
        Self { owner, delegators }
    }

    /// The agent's owner.
    #[must_use]
    pub fn owner(&self) -> &Human {
        &self.owner
    }

    /// The people at the root of the delegation the action uses. It is
    /// empty exactly when the action uses none.
    #[must_use]
    pub fn delegators(&self) -> &[Human] {
        &self.delegators
    }

    /// Whether `by` is one of them, through any of their accounts.
    #[must_use]
    pub(crate) fn include(&self, by: &Human) -> bool {
        self.owner.is_same_person_as(by)
            || self
                .delegators
                .iter()
                .any(|delegator| delegator.is_same_person_as(by))
    }

    /// Whether they name delegators exactly when the action uses a
    /// delegation.
    #[must_use]
    pub fn fit(&self, under: &ActingUnder) -> bool {
        match under {
            ActingUnder::NoDelegation => self.delegators.is_empty(),
            ActingUnder::Delegation(_) => !self.delegators.is_empty(),
        }
    }
}

/// The person in `people` acting through `principal`.
fn person_named(principal: &PrincipalRef, people: &[Human]) -> Result<Human, DomainError> {
    people
        .iter()
        .find(|person| person.principal() == *principal)
        .cloned()
        .ok_or_else(|| {
            DomainError::invalid(message!(
                "agents-a-person-behind-the-delegation-is",
                "a person behind the delegation is not named"
            ))
        })
}

/// Whether a person deciding proved they are present just now, with a fresh
/// second factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// They proved it just now.
    Proven,
    /// They did not.
    NotProven,
}

/// How a person deciding proves they are present just now.
#[derive(Debug, Clone, Copy)]
pub enum PresenceProof<'p> {
    /// A right code from their own second factor, its time step already
    /// claimed as used.
    Code(&'p AnsweredCode),
    /// They signed in again a moment ago.
    SignIn(&'p FreshSignIn),
}

impl PresenceProof<'_> {
    /// Whether this proves the holder of `by`'s account. A workflow's
    /// approver proves their presence the same ways.
    pub(crate) fn proves(&self, by: &Human) -> bool {
        let account = principal_of(by.account());
        match self {
            Self::Code(answer) => answer.subject() == account,
            Self::SignIn(fresh) => RecentProof::proves_recently(*fresh, &account),
        }
    }
}

/// A person deciding a request, with what they hold, the most sensitive
/// data they are cleared to see, and whether they proved they are present.
///
/// Its fields are private. The clearance comes from what the tenant's
/// records say the person holds, and presence only from a proof of their
/// own account. Sam, cleared for internal data, would otherwise say he is
/// cleared for restricted data and read the salaries a paused call quotes.
#[derive(Debug, Clone, Copy)]
pub struct Approver<'a> {
    control: AgentControl<'a>,
    clearance: DataClassLevel,
    presence: Presence,
}

impl<'a> Approver<'a> {
    /// The person `control` names, deciding without having proved they are
    /// present just now. They may decide only what is not high risk.
    #[must_use]
    pub fn of(control: AgentControl<'a>) -> Self {
        Self {
            control,
            clearance: control.authority().data_clearance(),
            presence: Presence::NotProven,
        }
    }

    /// The person `control` names, who proved they are present with
    /// `proof`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `proof` is for another account, or
    ///   a sign-in no longer fresh.
    pub fn present(
        control: AgentControl<'a>,
        proof: PresenceProof<'_>,
    ) -> Result<Self, DomainError> {
        if !proof.proves(control.by()) {
            return Err(DomainError::forbidden(message!(
                "agents-the-proof-of-presence-is-not",
                "the proof of presence is not the approver's own, or not fresh"
            )));
        }
        Ok(Self {
            presence: Presence::Proven,
            ..Self::of(control)
        })
    }

    /// `control`'s person, cleared for `clearance` and with `presence`, as a
    /// test says, without the records and proofs behind them.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn assumed(
        control: AgentControl<'a>,
        clearance: DataClassLevel,
        presence: Presence,
    ) -> Self {
        Self {
            control,
            clearance,
            presence,
        }
    }

    /// The person deciding.
    #[must_use]
    pub fn by(&self) -> &'a Human {
        self.control.by()
    }

    /// The most sensitive data they may see.
    #[must_use]
    pub fn clearance(&self) -> DataClassLevel {
        self.clearance
    }

    /// Whether they proved they are present just now.
    #[must_use]
    pub fn presence(&self) -> Presence {
        self.presence
    }

    /// Refuses an approver who may not approve agent actions, or who is
    /// cleared below `exposure`, what the request shows them.
    ///
    /// A run at confidential pauses on a call quoting salaries. Without the
    /// clearance check, Sam, cleared for public data, reads them in the
    /// request.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when they do not hold the permission to
    ///   approve agent actions.
    /// - [`DomainError::Forbidden`] when their clearance is below `exposure`.
    pub(super) fn ensure_entitled(&self, exposure: DataClassLevel) -> Result<(), DomainError> {
        if !self.control.holds_agent(AgentAction::Approve) {
            return Err(DomainError::forbidden(message!(
                "agents-approving-an-agent-s-action-needs",
                "approving an agent's action needs the permission to approve agent actions"
            )));
        }
        if self.clearance < exposure {
            return Err(DomainError::forbidden(message!(
                "agents-the-approver-is-not-cleared-for",
                "the approver is not cleared for the data the request shows"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::authority::capability::{CapabilitySet, DelegationConstraints};
    use crate::domains::agents::authority::delegation::{
        Delegate, Delegation, GrantDelegationParams, HeldBy, HeldResources, OwnedTokenRequest,
        ReviewDuty,
    };
    use crate::domains::agents::identity::acting::ActingAgent;
    use crate::domains::authentication::mfa::enrollment::answer_for;
    use crate::domains::authentication::sessions::fresh_sign_in::fresh_proof_of;
    use crate::domains::authorization::permission::SystemPermission;
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::authority::assumed_authority;
    use crate::types::{EventLabel, HumanAccount, Lifetime, PersonKey, Seconds, TenantId, UserId};

    const APPROVES: [SystemPermission; 1] = [SystemPermission::Agents(AgentAction::Approve)];

    fn person(address: &str) -> Human {
        Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new(address).unwrap(),
        )
    }

    /// `by`, allowed to approve agent actions.
    fn control(by: &Human) -> AgentControl<'_> {
        AgentControl::new(assumed_authority(by, TenantId::new(), &APPROVES, &[]))
    }

    /// Bob proves he is present with a code from his own factor, or by
    /// signing in again. Either way he decides as present. With no proof he
    /// does not.
    #[test]
    fn presence_comes_only_from_a_proof_of_the_approvers_own_account() {
        let bob = person("bob@corp.test");
        let code = answer_for(principal_of(bob.account()));
        let fresh = fresh_proof_of(principal_of(bob.account()));

        let by_code = Approver::present(control(&bob), PresenceProof::Code(&code)).unwrap();
        let by_sign_in = Approver::present(control(&bob), PresenceProof::SignIn(&fresh)).unwrap();

        assert_eq!(by_code.presence(), Presence::Proven);
        assert_eq!(by_sign_in.presence(), Presence::Proven);
        assert_eq!(Approver::of(control(&bob)).presence(), Presence::NotProven);
    }

    /// A factor answer or fresh sign-in from another account cannot prove
    /// an approver's presence; both attempts are forbidden.
    #[test]
    fn a_proof_of_someone_elses_account_is_refused() {
        let bob = person("bob@corp.test");
        let mallory = person("mallory@corp.test");
        let code = answer_for(principal_of(mallory.account()));
        let fresh = fresh_proof_of(principal_of(mallory.account()));

        let by_code = Approver::present(control(&bob), PresenceProof::Code(&code));
        let by_sign_in = Approver::present(control(&bob), PresenceProof::SignIn(&fresh));

        assert!(matches!(by_code, Err(DomainError::Forbidden(_))));
        assert!(matches!(by_sign_in, Err(DomainError::Forbidden(_))));
    }

    /// An approver's clearance is what the tenant's records say they may
    /// see, never a value the caller picks.
    #[test]
    fn the_clearance_is_the_one_the_records_give() {
        let bob = person("bob@corp.test");
        let authority = control(&bob).authority();

        assert_eq!(
            Approver::of(control(&bob)).clearance(),
            authority.data_clearance()
        );
    }

    /// Ann's delegation to Owen's agent, and the task token the agent minted
    /// from it.
    fn minted_under(
        ann: &Human,
        agent: &AgentIdentity<ResolvedTenant>,
    ) -> (Delegation<ResolvedTenant>, Delegation<ResolvedTenant>) {
        let nothing = CapabilitySet::empty();
        let constraints = DelegationConstraints::new(Seconds::new(600), 1).unwrap();
        let source = source_from(ann, agent, &nothing, &constraints);
        let minted = Delegation::grant_owned_within(
            OwnedTokenRequest {
                agent: &ActingAgent::assumed(*agent.id()),
                agent_label: EventLabel::of("agent"),
                granted: nothing,
                requested: constraints,
                max_ttl: Lifetime::seconds(60).unwrap(),
            },
            std::slice::from_ref(&source),
        )
        .unwrap();
        (source, minted)
    }

    /// Grants an agent an empty source delegation within Ann's current rights.
    fn source_from(
        ann: &Human,
        agent: &AgentIdentity<ResolvedTenant>,
        nothing: &CapabilitySet,
        constraints: &DelegationConstraints,
    ) -> Delegation<ResolvedTenant> {
        let held = HeldBy::worked_out::<ResolvedTenant>(
            &AgentControl::new(assumed_authority(ann, TenantId::new(), &[], &[])),
            nothing,
            &HeldResources::answered(ann.principal(), Vec::new()),
            &[],
        )
        .unwrap();
        Delegation::grant(
            GrantDelegationParams {
                granted: nothing.clone(),
                constraints: constraints.clone(),
                name: None,
            },
            &held,
            &Delegate {
                agent,
                duty: ReviewDuty::NotReviewing,
            },
        )
        .unwrap()
    }

    /// An action's parties include the person behind the source delegation
    /// of its minted token. Omitting that person prevents constructing the parties.
    #[test]
    fn the_people_behind_a_minted_token_are_named() {
        let (ann, owen) = (person("ann@corp.test"), person("owen@corp.test"));
        let agent = crate::domains::agents::identity::agent::tests::fixtures::agent_of(&owen);
        let (source, minted) = minted_under(&ann, &agent);
        let authority = ActionAuthority::Delegation {
            delegation: &minted,
            above: std::slice::from_ref(&source),
        };

        let parties =
            ActionParties::behind(&agent, &authority, std::slice::from_ref(&ann)).unwrap();
        let unnamed = ActionParties::behind(&agent, &authority, &[]);

        assert!(parties.include(&ann));
        assert_eq!(parties.delegators(), [ann]);
        assert!(matches!(unnamed, Err(DomainError::Validation(_))));
    }

    /// Owen owns the agent and no delegation is used. The parties name Owen
    /// and nobody behind a delegation.
    #[test]
    fn an_action_on_no_delegation_names_only_the_owner() {
        let owen = person("owen@corp.test");
        let agent = crate::domains::agents::identity::agent::tests::fixtures::agent_of(&owen);

        let parties = ActionParties::behind(&agent, &ActionAuthority::NoDelegation, &[]).unwrap();

        assert!(parties.owner().is_same_person_as(&owen));
        assert!(parties.delegators().is_empty());
    }
}
