//! Who starts a run, as the domain proved it.

use crate::domains::agents::identity::acting::ActingAgent;
use crate::domains::authorization::authority::TenantAuthority;
use crate::types::{Human, Initiator, PrincipalRef};

/// The person or agent starting a run, proven rather than named.
///
/// The run records its starter, and the starter may not approve its paused
/// calls. A delegation backs only the runs its delegator starts. If the
/// request named the starter, Sam would start a run under Ann's delegation
/// named as hers, or name Bob as starter and approve the run's paused
/// write himself.
#[derive(Debug, Clone, Copy)]
pub struct RunStarter<'a> {
    who: Who<'a>,
}

#[derive(Debug, Clone, Copy)]
enum Who<'a> {
    Person(&'a Human),
    Agent(&'a ActingAgent),
}

impl<'a> RunStarter<'a> {
    /// The person `authority` names, as the authorizer worked it out from
    /// their sign-in.
    #[must_use]
    pub fn person(authority: &'a TenantAuthority) -> Self {
        Self {
            who: Who::Person(authority.who()),
        }
    }

    /// The agent that signed in with its own key.
    #[must_use]
    pub fn agent(agent: &'a ActingAgent) -> Self {
        Self {
            who: Who::Agent(agent),
        }
    }

    /// The person a workflow execution acts for, which the engine starts
    /// the run for.
    pub(crate) fn acting_for(person: &'a Human) -> Self {
        Self {
            who: Who::Person(person),
        }
    }

    /// The starter, as the run records it.
    pub(super) fn initiator(&self) -> Initiator {
        match self.who {
            Who::Person(person) => Initiator::Human(person.clone()),
            Who::Agent(agent) => Initiator::Agent(*agent.agent()),
        }
    }

    /// The starter, as a principal a delegation names.
    pub(super) fn principal(&self) -> PrincipalRef {
        match self.who {
            Who::Person(person) => person.principal(),
            Who::Agent(agent) => PrincipalRef::Agent(*agent.agent()),
        }
    }
}
