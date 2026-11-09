//! An AI agent's identity inside one tenant.
//!
//! It belongs to a tenant, like [`Service`]. Stores read and write it only
//! for the resolved tenant. [`AgentStatus`] decides which status moves are
//! allowed.
//!
//! Its owner is the person who created it, until ownership is handed on.
//! Every change to the agent needs that owner, or someone allowed to manage
//! agents, through [`AgentControl`].
//!
//! [`Service`]: crate::domains::routing::service::Service

mod attesting;
mod ownership;

use std::marker::PhantomData;

pub use attesting::{AgentProof, Containment};
pub use ownership::{AgentRecipient, Handover, OFFER_LIFETIME, OwnershipOffer};
use time::OffsetDateTime;

use crate::domains::agents::events::identity::{
    AgentContained, AgentIdentityCreated, AgentIdentityDeleted, AgentIdentityResumed,
    AgentIdentityRevoked, AgentIdentitySuspended, AgentIdentityUpdated,
};
use crate::domains::agents::identity::control::AgentControl;
use crate::domains::agents::identity::standing::AgentStanding;
use crate::domains::agents::identity::status::AgentStatus;
use crate::domains::authorization::permission::AgentAction;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::types::event_type::AgentsEvent;
use crate::types::{AgentId, EventLabel, Human, Label};

/// Parameters for creating a new agent identity.
pub struct CreateAgentParams {
    /// Display name, such as `"nightly-report"`.
    pub name: Label,
    /// Optional description.
    pub description: Option<Label>,
}

/// Who suspends an agent.
#[derive(Debug, Clone, Copy)]
pub enum SuspendedBy<'a> {
    /// A person. They must own the agent or be allowed to update agents.
    Person(AgentControl<'a>),
    /// One of the platform's own monitors, which caught the agent out.
    ///
    /// Stopping an agent is the safe direction, so a monitor needs no
    /// person. Resuming always does.
    Monitor,
}

/// Persisted state for reconstitution.
pub struct AgentIdentityRow {
    /// Unique identifier.
    pub id: AgentId,
    /// Display name.
    pub name: Label,
    /// Optional description.
    pub description: Option<Label>,
    /// The person who owns the agent, with the account they created it from.
    pub owner: Human,
    /// Whether the agent waits for someone it was offered to.
    pub offer: OwnershipOffer,
    /// Current status.
    pub status: AgentStatus,
    /// How the agent proves it is itself.
    pub proof: AgentProof,
    /// Whether the agent is held until it re-attests.
    pub containment: Containment,
    /// When the agent last proved what it is.
    pub last_attested_at: Option<OffsetDateTime>,
    /// When created.
    pub created_at: OffsetDateTime,
    /// When last modified.
    pub updated_at: OffsetDateTime,
}

/// An AI agent that holds authority of its own inside one tenant.
#[derive(Debug, Clone)]
pub struct AgentIdentity<T: TenantScope> {
    id: AgentId,
    name: Label,
    description: Option<Label>,
    owner: Human,
    offer: OwnershipOffer,
    status: AgentStatus,
    proof: AgentProof,
    containment: Containment,
    last_attested_at: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> AgentIdentity<T> {
    /// Creates an active agent owned by the person `control` names, who is
    /// creating it. It proves itself with an enrolled key.
    ///
    /// The owner is always a person, and always the creator. Sam cannot
    /// create an agent that reads as Ann's, nor one owned by another agent.
    /// And Sam may only view agents. Without the right check, he registers
    /// agents the tenant never allowed him to.
    ///
    /// Raises `agents.agent_created`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not create agents.
    pub fn create(
        control: &AgentControl<'_>,
        params: CreateAgentParams,
    ) -> Result<Self, DomainError> {
        if !control.holds_agent(AgentAction::Create) {
            return Err(DomainError::forbidden(message!(
                "agents-creating-an-agent-needs-the-right",
                "creating an agent needs the right to create agents"
            )));
        }
        let now = crate::shared::clock::now();
        let mut agent = Self {
            id: AgentId::new(),
            name: params.name,
            description: params.description,
            owner: control.by().clone(),
            offer: OwnershipOffer::Unoffered,
            status: AgentStatus::Active,
            proof: AgentProof::EnrolledKey,
            containment: Containment::Free,
            last_attested_at: None,
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        agent.raised.raise(AgentIdentityCreated {
            agent_id: agent.id,
            agent_label: agent.label(),
            occurred_at: now,
        });
        Ok(agent)
    }

    /// Rebuilds an agent from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says the agent changed,
    ///   attested, was held or was offered before it was registered.
    /// - [`DomainError::Infrastructure`] when its offer lapses before it was
    ///   made, or names the account that owns the agent.
    pub fn reconstitute(row: AgentIdentityRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            name: row.name,
            description: row.description,
            owner: row.owner,
            offer: row.offer,
            status: row.status,
            proof: row.proof,
            containment: row.containment,
            last_attested_at: row.last_attested_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &AgentIdentityRow) -> Result<(), DomainError> {
        RowCheck::of("agent")
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was registered",
            )
            .in_order_if(
                row.created_at,
                row.last_attested_at,
                "attested before it was registered",
            )
            .in_order_if(
                row.created_at,
                row.containment.since(),
                "contained before it was registered",
            )
            .finish()?;
        Self::ensure_offer_consistent(row)
    }

    /// Refuses a stored offer made before the agent was registered, one
    /// that lapses before it was made, or one naming the owner.
    fn ensure_offer_consistent(row: &AgentIdentityRow) -> Result<(), DomainError> {
        RowCheck::of("agent")
            .in_order_if(
                row.created_at,
                row.offer.offered_at(),
                "offered before it was registered",
            )
            .holds(
                row.offer.lapses_after_it_began(),
                "offer lapsed before it was made",
            )
            .holds(
                row.offer
                    .recipient()
                    .is_none_or(|recipient| !recipient.is_same_account_as(&row.owner)),
                "offered to its own owner",
            )
            .finish()
    }

    /// Unique identifier.
    #[must_use]
    pub fn id(&self) -> &AgentId {
        &self.id
    }

    /// Display name.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// Optional description.
    #[must_use]
    pub fn description(&self) -> Option<&Label> {
        self.description.as_ref()
    }

    /// The person who owns the agent.
    #[must_use]
    pub fn owner(&self) -> &Human {
        &self.owner
    }

    /// Current status.
    #[must_use]
    pub fn status(&self) -> AgentStatus {
        self.status
    }

    /// Whether this agent is active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status.is_active()
    }

    /// Whether it may act at `now`, and if not, why.
    ///
    /// It combines its status with whether it owes a re-attestation. An
    /// agent owes one when someone required it, or when its last attestation
    /// is older than its policy's interval. An agent with an hourly policy
    /// that stops attesting must re-attest an hour later, with no one asking.
    #[must_use]
    pub fn standing(&self, now: OffsetDateTime) -> AgentStanding {
        AgentStanding::of(self.status, self.reattestation_at(now))
    }

    /// Whether it may act at `now`.
    #[must_use]
    pub fn may_act_at(&self, now: OffsetDateTime) -> bool {
        self.standing(now).permits_requests()
    }

    /// Updates the display name and description.
    ///
    /// Raises `agents.agent_updated`, once for an edit that also changes the
    /// agent's proof, naming the agent as it stands at the end.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person is neither the owner nor
    ///   allowed to update agents.
    pub fn update_details(
        &mut self,
        control: &AgentControl<'_>,
        name: Label,
        description: Option<Label>,
    ) -> Result<(), DomainError> {
        self.ensure_may(control, AgentAction::Update)?;
        self.name = name;
        self.description = description;
        self.touch();
        self.raise_updated();
        Ok(())
    }

    /// Suspends an active agent. A resume undoes it.
    ///
    /// Raises `agents.agent_suspended`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when a person suspends it who is neither
    ///   the owner nor allowed to update agents.
    /// - [`DomainError::InvalidTransition`] when the agent is revoked or
    ///   already suspended.
    pub fn suspend(&mut self, by: SuspendedBy<'_>) -> Result<(), DomainError> {
        if let SuspendedBy::Person(control) = by {
            self.ensure_may(&control, AgentAction::Update)?;
        }
        self.move_to(AgentStatus::Suspended)?;
        self.raised.raise(AgentIdentitySuspended {
            agent_id: self.id,
            agent_label: self.label(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Resumes a suspended agent.
    ///
    /// An agent is often suspended during an incident. Sam may only view
    /// agents. Without this check, Sam resumes Ann's agent while it is still
    /// being looked at.
    ///
    /// Raises `agents.agent_resumed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person is neither the owner nor
    ///   allowed to update agents.
    /// - [`DomainError::InvalidTransition`] when the agent is revoked or
    ///   already active.
    pub fn resume(&mut self, control: &AgentControl<'_>) -> Result<(), DomainError> {
        self.ensure_may(control, AgentAction::Update)?;
        self.move_to(AgentStatus::Active)?;
        self.raised.raise(AgentIdentityResumed {
            agent_id: self.id,
            agent_label: self.label(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Revokes the agent for good.
    ///
    /// Raises `agents.agent_revoked`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person is neither the owner nor
    ///   allowed to delete agents.
    /// - [`DomainError::InvalidTransition`] when it is already revoked.
    pub fn revoke(&mut self, control: &AgentControl<'_>) -> Result<(), DomainError> {
        self.ensure_may(control, AgentAction::Delete)?;
        self.move_to(AgentStatus::Revoked)?;
        self.raised.raise(AgentIdentityRevoked {
            agent_id: self.id,
            agent_label: self.label(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Revokes the agent as the first step of containing it, unless it is
    /// revoked already, so containing it again is safe.
    ///
    /// It raises nothing. Containment is one record, made by
    /// [`record_containment`](Self::record_containment) once the agent's
    /// delegations have fallen, not a revocation of its own.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person is neither the owner nor
    ///   allowed to delete agents, even when the agent is revoked already.
    pub fn contain(&mut self, control: &AgentControl<'_>) -> Result<(), DomainError> {
        self.ensure_may(control, AgentAction::Delete)?;
        if self.status.is_revoked() {
            return Ok(());
        }
        self.move_to(AgentStatus::Revoked)
    }

    /// Records that the agent was contained and `revoked_count` delegations
    /// fell with it, its own and every one passed on from them.
    ///
    /// Raises `agents.agent_contained`. Containing an agent contained before
    /// is recorded too, with what fell this time.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person is neither the owner nor
    ///   allowed to delete agents.
    pub fn record_containment(
        &mut self,
        control: &AgentControl<'_>,
        revoked_count: u32,
    ) -> Result<(), DomainError> {
        self.ensure_may(control, AgentAction::Delete)?;
        self.raised.raise(AgentContained {
            agent_id: self.id,
            agent_label: self.label(),
            revoked_count,
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Deletes this agent, once the person owns it or may delete agents,
    /// and it is revoked. The store removes its record.
    ///
    /// An agent is revoked first, so every key and delegation it held is
    /// already dead when its record goes. Sam may only view agents. Without
    /// this check, he deletes Ann's agent and the trail of what it did
    /// loses its name.
    ///
    /// Raises `agents.agent_deleted`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person is neither the owner nor
    ///   allowed to delete agents.
    /// - [`DomainError::InvalidTransition`] while the agent is not revoked.
    pub fn delete(&mut self, control: &AgentControl<'_>) -> Result<(), DomainError> {
        self.ensure_may(control, AgentAction::Delete)?;
        if !self.status.is_revoked() {
            return Err(DomainError::invalid_transition(message!(
                "agents-an-agent-is-revoked-before-it",
                "an agent is revoked before it is deleted"
            )));
        }
        self.raised.raise(AgentIdentityDeleted {
            agent_id: self.id,
            agent_label: self.label(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Refuses `action` unless the person owns the agent or holds the agent
    /// permission for it.
    fn ensure_may(
        &self,
        control: &AgentControl<'_>,
        action: AgentAction,
    ) -> Result<(), DomainError> {
        control.ensure_may(&self.owner, action)
    }

    fn move_to(&mut self, to: AgentStatus) -> Result<(), DomainError> {
        self.status = self.status.try_transition(to).map_err(|e| {
            DomainError::invalid_transition(message!(
                "agents-cannot-transition-agent-from-to",
                format!("cannot transition agent from {:?} to {:?}", e.from, e.to)
            ))
        })?;
        self.touch();
        Ok(())
    }

    fn touch(&mut self) {
        self.updated_at = crate::shared::clock::now();
    }

    /// The name the records about the agent show.
    pub(in crate::domains::agents) fn label(&self) -> EventLabel {
        EventLabel::of(self.name.as_str())
    }

    /// Records a change to the agent's details or proof, as the agent stands
    /// now. An edit that changes several is one record. An agent created in
    /// the same edit gets none: its creation already describes it.
    fn raise_updated(&mut self) {
        if self.raised.holds(AgentsEvent::AgentCreated.into()) {
            return;
        }
        let updated = AgentIdentityUpdated {
            agent_id: self.id,
            agent_label: self.label(),
            occurred_at: self.updated_at,
        };
        self.raised.raise_latest(updated);
    }
}

impl<T: TenantScope> Raises for AgentIdentity<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

impl<T: TenantScope> Aggregate for AgentIdentity<T> {
    type Id = AgentId;

    fn id(&self) -> &Self::Id {
        &self.id
    }

    fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

#[cfg(test)]
pub(crate) mod tests {
    /// People, controls and agents shared by the identity tests.
    pub(crate) mod fixtures {
        use super::*;
        use crate::domains::authorization::permission::SystemPermission;
        use crate::isolation::scope::ResolvedTenant;
        use crate::test_support::authority::assumed_authority;
        use crate::types::{HumanAccount, PersonKey, TenantId, UserId};

        static VIEW_AGENTS: [SystemPermission; 1] = [SystemPermission::Agents(AgentAction::View)];
        static MANAGE_AGENTS: [SystemPermission; 1] = [SystemPermission::ManageAgents];
        static CREATE_AGENTS: [SystemPermission; 1] =
            [SystemPermission::Agents(AgentAction::Create)];

        /// A person signed in through a fresh user account.
        pub(crate) fn person(address: &str) -> Human {
            Human::new(
                HumanAccount::User(UserId::new()),
                PersonKey::new(address).unwrap(),
            )
        }

        /// Ann, who owns the agents in these tests.
        pub(crate) fn ann() -> Human {
            person("ann@corp.test")
        }

        /// Sam, who may only view agents.
        pub(crate) fn sam() -> Human {
            person("sam@corp.test")
        }

        /// `by` acting with no permission at all.
        pub(crate) fn acting(by: &Human) -> AgentControl<'_> {
            AgentControl::new(assumed_authority(by, TenantId::new(), &[], &[]))
        }

        /// `by` acting while allowed only to view agents.
        pub(crate) fn viewing(by: &Human) -> AgentControl<'_> {
            AgentControl::new(assumed_authority(by, TenantId::new(), &VIEW_AGENTS, &[]))
        }

        /// `by` acting while allowed to manage every agent.
        pub(crate) fn managing(by: &Human) -> AgentControl<'_> {
            AgentControl::new(assumed_authority(by, TenantId::new(), &MANAGE_AGENTS, &[]))
        }

        /// `by` acting while allowed only to create agents.
        pub(crate) fn creating(by: &Human) -> AgentControl<'_> {
            AgentControl::new(assumed_authority(by, TenantId::new(), &CREATE_AGENTS, &[]))
        }

        /// A new agent created by `owner`.
        pub(crate) fn agent_of(owner: &Human) -> AgentIdentity<ResolvedTenant> {
            AgentIdentity::create(
                &creating(owner),
                CreateAgentParams {
                    name: Label::new("name", "nightly-report").unwrap(),
                    description: None,
                },
            )
            .unwrap()
        }
    }

    use self::fixtures::{acting, agent_of, ann, managing, person, sam, viewing};
    use super::*;
    use crate::domains::agents::identity::attestation::{
        AttestationMethod, AttestationPolicy, AttestedOrigin,
    };
    use crate::domains::agents::identity::challenge::AttestationNonce;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{Lifetime, Seconds};

    /// Ann creates an agent. It is active, and Ann is its owner.
    #[test]
    fn create_produces_an_active_agent_owned_by_its_creator() {
        let ann = ann();

        let agent = agent_of(&ann);

        assert!(agent.is_active());
        assert!(agent.owner().is_same_person_as(&ann));
    }

    /// Permission to view agents does not authorize creating one; creation
    /// is refused for a caller who holds only viewing rights.
    #[test]
    fn a_person_who_may_not_create_agents_creates_none() {
        let sam = sam();

        let created = AgentIdentity::<ResolvedTenant>::create(
            &viewing(&sam),
            CreateAgentParams {
                name: Label::new("name", "side-project").unwrap(),
                description: None,
            },
        );

        assert!(matches!(created, Err(DomainError::Forbidden(_))));
    }

    /// Ann suspends her agent and then resumes it. It is suspended in between
    /// and active again at the end.
    #[test]
    fn suspend_then_resume() {
        let ann = ann();
        let mut a = agent_of(&ann);

        a.suspend(SuspendedBy::Person(acting(&ann))).unwrap();
        assert_eq!(a.status(), AgentStatus::Suspended);
        a.resume(&acting(&ann)).unwrap();
        assert!(a.is_active());
    }

    /// A viewer cannot resume another person's agent after a monitor
    /// suspends it. The refusal leaves the agent suspended.
    #[test]
    fn a_person_with_no_say_cannot_resume_someone_elses_agent() {
        let ann = ann();
        let sam = sam();
        let mut a = agent_of(&ann);
        a.suspend(SuspendedBy::Monitor).unwrap();

        let result = a.resume(&viewing(&sam));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(a.status(), AgentStatus::Suspended);
    }

    /// A viewer cannot suspend another person's agent, which stays active
    /// after the refusal. A manager can then suspend it.
    #[test]
    fn a_person_with_no_say_cannot_suspend_someone_elses_agent() {
        let ann = ann();
        let sam = sam();
        let bob = person("bob@corp.test");
        let mut a = agent_of(&ann);

        let refused = a.suspend(SuspendedBy::Person(viewing(&sam)));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert!(a.is_active());
        a.suspend(SuspendedBy::Person(managing(&bob))).unwrap();
        assert_eq!(a.status(), AgentStatus::Suspended);
    }

    /// The drift monitor catches Ann's agent out and suspends it with no
    /// person involved. It is suspended.
    #[test]
    fn a_monitor_may_suspend_an_agent_on_its_own() {
        let mut a = agent_of(&ann());

        a.suspend(SuspendedBy::Monitor).unwrap();

        assert_eq!(a.status(), AgentStatus::Suspended);
    }

    /// A viewer cannot revoke another person's agent; the refusal leaves
    /// the agent active.
    #[test]
    fn a_person_with_no_say_cannot_revoke_someone_elses_agent() {
        let ann = ann();
        let mut a = agent_of(&ann);

        let result = a.revoke(&viewing(&sam()));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(a.is_active());
    }

    /// A revoked agent cannot be suspended, resumed or revoked again.
    #[test]
    fn revoke_is_terminal() {
        let ann = ann();
        let mut a = agent_of(&ann);
        a.revoke(&acting(&ann)).unwrap();
        assert!(a.suspend(SuspendedBy::Person(acting(&ann))).is_err());
        assert!(a.resume(&acting(&ann)).is_err());
        assert!(a.revoke(&acting(&ann)).is_err());
    }

    /// An agent is renamed and given a description, then the description is
    /// cleared. Each change shows, so the dashboard never keeps an old name.
    #[test]
    fn updating_the_details_replaces_the_name_and_description() {
        let ann = ann();
        let mut a = agent_of(&ann);
        assert_eq!(a.description(), None);

        a.update_details(
            &acting(&ann),
            Label::new("name", "quarterly-report").unwrap(),
            Some(Label::new("name", "reads the ledger").unwrap()),
        )
        .unwrap();

        assert_eq!(a.name().as_str(), "quarterly-report");
        assert_eq!(a.description().map(Label::as_str), Some("reads the ledger"));

        a.update_details(
            &acting(&ann),
            Label::new("name", "quarterly-report").unwrap(),
            None,
        )
        .unwrap();
        assert_eq!(a.description(), None, "a description can be cleared");
    }

    /// A viewer cannot rename another person's agent. The attempt is
    /// forbidden and the original name remains.
    #[test]
    fn a_person_with_no_say_cannot_rename_someone_elses_agent() {
        let mut a = agent_of(&ann());

        let result = a.update_details(
            &viewing(&sam()),
            Label::new("name", "approved-by-security").unwrap(),
            None,
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(a.name().as_str(), "nightly-report");
    }

    /// Ann renames her agent five seconds after she created it. Its update
    /// time moves forward, so the change shows.
    #[test]
    fn editing_an_agent_moves_its_updated_stamp() {
        let ann = ann();
        let mut a = agent_of(&ann);
        let before = a.updated_at();
        let frozen = crate::shared::clock::freeze(before + time::Duration::seconds(5));

        a.update_details(&acting(&ann), Label::new("name", "renamed").unwrap(), None)
            .unwrap();

        assert!(a.updated_at() > before);
        assert_eq!(Aggregate::id(&a), a.id());
        drop(frozen);
    }

    /// A stored agent attested one second before it was created. The row is
    /// refused as corrupt.
    #[test]
    fn a_stored_agent_attested_before_it_was_registered_is_refused() {
        let agent = agent_of(&ann());
        let row = AgentIdentityRow {
            id: agent.id,
            name: agent.name.clone(),
            description: agent.description.clone(),
            owner: agent.owner.clone(),
            offer: OwnershipOffer::Unoffered,
            status: agent.status,
            proof: agent.proof.clone(),
            containment: agent.containment,
            last_attested_at: Some(agent.created_at - time::Duration::SECOND),
            created_at: agent.created_at,
            updated_at: agent.updated_at,
        };

        assert!(refused_as_corrupt(
            &AgentIdentity::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// Deletion is refused while an agent is active and to a viewer after
    /// revocation. Its owner and a manager can delete it once revoked.
    #[test]
    fn only_the_owner_or_a_manager_deletes_a_revoked_agent() {
        let ann = ann();
        let mut agent = agent_of(&ann);

        let while_active = agent.delete(&acting(&ann));
        agent.revoke(&acting(&ann)).unwrap();

        assert!(matches!(
            while_active,
            Err(DomainError::InvalidTransition(_))
        ));
        assert!(matches!(
            agent.delete(&viewing(&sam())),
            Err(DomainError::Forbidden(_))
        ));
        let bob = person("bob@corp.test");
        assert!(agent.delete(&acting(&ann)).is_ok());
        assert!(agent.delete(&managing(&bob)).is_ok());
    }

    /// The name the record gives the agent it is about.
    fn agent_named(event: &DomainEvent) -> String {
        match event.payload().value("agent") {
            Some(FieldValue::Reference(reference)) => reference.label().to_owned(),
            other => panic!("agent is not an entity reference: {other:?}"),
        }
    }

    /// Ann's agent, with its creation already taken.
    fn settled_agent_of(owner: &Human) -> AgentIdentity<ResolvedTenant> {
        let mut agent = agent_of(owner);
        raised_names(&mut agent);
        agent
    }

    fn spiffe_policy() -> AttestationPolicy {
        AttestationPolicy::new(
            vec![AttestationMethod::Spiffe],
            Seconds::new(3600),
            vec![AttestedOrigin::new("spiffe://cluster").unwrap()],
        )
        .unwrap()
    }

    /// Ann creates the agent "nightly-report". Its creation is raised,
    /// naming it.
    #[test]
    fn creating_an_agent_raises_its_creation() {
        let mut agent = agent_of(&ann());

        let events = raised(&mut agent);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type().to_string(), "agents.agent_created");
        assert_eq!(agent_named(&events[0]), "nightly-report");
    }

    /// Ann suspends her agent, resumes it and revokes it. Each move is
    /// raised, in the order it happened.
    #[test]
    fn each_status_move_raises_its_event() {
        let ann = ann();
        let mut agent = settled_agent_of(&ann);

        agent.suspend(SuspendedBy::Person(acting(&ann))).unwrap();
        agent.resume(&acting(&ann)).unwrap();
        agent.revoke(&acting(&ann)).unwrap();

        assert_eq!(
            raised_names(&mut agent),
            [
                "agents.agent_suspended",
                "agents.agent_resumed",
                "agents.agent_revoked"
            ]
        );
    }

    /// Ann renames her agent and gives it an attestation policy in one
    /// edit. One update is raised, naming the agent by its new name.
    #[test]
    fn an_edit_of_details_and_proof_raises_one_update_with_the_new_name() {
        let ann = ann();
        let mut agent = settled_agent_of(&ann);

        agent
            .update_details(&acting(&ann), Label::new("name", "renamed").unwrap(), None)
            .unwrap();
        agent
            .trust_attestation(&acting(&ann), spiffe_policy())
            .unwrap();

        let events = raised(&mut agent);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type().to_string(), "agents.agent_updated");
        assert_eq!(agent_named(&events[0]), "renamed");
    }

    /// Ann creates an agent that proves itself by attesting. Only its
    /// creation is raised: setting the policy is part of making it.
    #[test]
    fn a_policy_set_while_creating_raises_only_the_creation() {
        let ann = ann();
        let mut agent = agent_of(&ann);

        agent
            .trust_attestation(&acting(&ann), spiffe_policy())
            .unwrap();

        assert_eq!(raised_names(&mut agent), ["agents.agent_created"]);
    }

    /// Ann clears her agent's attestation policy. The change is raised as
    /// an update.
    #[test]
    fn clearing_the_attestation_policy_raises_an_update() {
        let ann = ann();
        let mut agent = settled_agent_of(&ann);

        agent.clear_attestation_policy(&acting(&ann)).unwrap();

        assert_eq!(raised_names(&mut agent), ["agents.agent_updated"]);
    }

    /// Ann requires her agent to re-attest. The requirement is raised.
    #[test]
    fn requiring_reattestation_raises_it() {
        let ann = ann();
        let mut agent = settled_agent_of(&ann);

        agent.require_reattestation(&acting(&ann)).unwrap();

        assert_eq!(raised_names(&mut agent), ["agents.reattestation_required"]);
    }

    /// The agent asks for a challenge to bootstrap with. The challenge is
    /// for this agent, and its issue is raised.
    #[test]
    fn issuing_a_challenge_raises_its_issue() {
        let mut agent = settled_agent_of(&ann());

        let challenge = agent.issue_attestation_challenge(
            AttestationNonce::new("n".repeat(32)).unwrap(),
            Lifetime::new(time::Duration::minutes(2)).unwrap(),
        );

        assert_eq!(challenge.agent_id(), agent.id());
        assert_eq!(
            raised_names(&mut agent),
            ["agents.attestation_challenge_issued"]
        );
    }

    /// Ann contains her agent. Revoking it raises nothing of its own; the
    /// containment is raised once with how many delegations fell.
    #[test]
    fn containment_raises_one_record_with_what_fell() {
        let ann = ann();
        let mut agent = settled_agent_of(&ann);

        agent.contain(&acting(&ann)).unwrap();
        let after_revoking = raised_names(&mut agent);
        agent.record_containment(&acting(&ann), 12).unwrap();

        assert!(after_revoking.is_empty());
        assert_eq!(agent.status(), AgentStatus::Revoked);
        let events = raised(&mut agent);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type().to_string(), "agents.agent_contained");
        assert!(matches!(
            events[0].payload().value("revoked_count"),
            Some(FieldValue::Text(count)) if count == "12"
        ));
    }

    /// A viewer can neither contain another person's agent nor record its
    /// containment. Both refusals leave it active without raising events.
    #[test]
    fn a_refused_containment_raises_nothing() {
        let mut agent = settled_agent_of(&ann());

        let contained = agent.contain(&viewing(&sam()));
        let recorded = agent.record_containment(&viewing(&sam()), 3);

        assert!(matches!(contained, Err(DomainError::Forbidden(_))));
        assert!(matches!(recorded, Err(DomainError::Forbidden(_))));
        assert!(agent.is_active());
        assert!(raised_names(&mut agent).is_empty());
    }

    /// Ann deletes her revoked agent. The deletion is raised.
    #[test]
    fn deleting_a_revoked_agent_raises_its_deletion() {
        let ann = ann();
        let mut agent = settled_agent_of(&ann);
        agent.revoke(&acting(&ann)).unwrap();
        raised_names(&mut agent);

        agent.delete(&acting(&ann)).unwrap();

        assert_eq!(raised_names(&mut agent), ["agents.agent_deleted"]);
    }

    /// A viewer's attempts to rename and suspend another person's agent
    /// both fail without raising any events.
    #[test]
    fn a_refused_change_raises_nothing() {
        let mut agent = settled_agent_of(&ann());

        let renamed = agent.update_details(
            &viewing(&sam()),
            Label::new("name", "approved-by-security").unwrap(),
            None,
        );
        let suspended = agent.suspend(SuspendedBy::Person(viewing(&sam())));

        assert!(renamed.is_err());
        assert!(suspended.is_err());
        assert!(raised_names(&mut agent).is_empty());
    }

    /// An agent read back from storage has raised nothing, so loading it
    /// records nothing.
    #[test]
    fn an_agent_read_back_from_storage_has_raised_nothing() {
        let agent = agent_of(&ann());
        let mut read_back = AgentIdentity::<ResolvedTenant>::reconstitute(stored(&agent)).unwrap();

        assert!(raised_names(&mut read_back).is_empty());
    }

    /// The row `agent` would be stored as, with no offer.
    fn stored(agent: &AgentIdentity<ResolvedTenant>) -> AgentIdentityRow {
        AgentIdentityRow {
            id: agent.id,
            name: agent.name.clone(),
            description: None,
            owner: agent.owner.clone(),
            offer: OwnershipOffer::Unoffered,
            status: agent.status,
            proof: agent.proof.clone(),
            containment: agent.containment,
            last_attested_at: None,
            created_at: agent.created_at,
            updated_at: agent.updated_at,
        }
    }

    /// A stored agent offered to the account that owns it. Accepting moves
    /// an agent and ends its offer, so the row is refused as corrupt.
    #[test]
    fn a_stored_agent_offered_to_its_own_owner_is_refused() {
        let agent = agent_of(&ann());
        let row = AgentIdentityRow {
            offer: OwnershipOffer::Open {
                recipient: agent.owner.clone(),
                offered_at: agent.created_at,
                expires_at: agent.created_at.saturating_add(OFFER_LIFETIME),
            },
            ..stored(&agent)
        };

        assert!(refused_as_corrupt(
            &AgentIdentity::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored offer that lapses before it was made. The row is refused as
    /// corrupt.
    #[test]
    fn a_stored_offer_that_lapses_before_it_was_made_is_refused() {
        let agent = agent_of(&ann());
        let row = AgentIdentityRow {
            offer: OwnershipOffer::Open {
                recipient: person("bob@corp.test"),
                offered_at: agent.created_at,
                expires_at: agent.created_at - time::Duration::SECOND,
            },
            ..stored(&agent)
        };

        assert!(refused_as_corrupt(
            &AgentIdentity::<ResolvedTenant>::reconstitute(row)
        ));
    }
}
