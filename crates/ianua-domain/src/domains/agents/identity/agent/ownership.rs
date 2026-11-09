//! How an agent's ownership moves to another person.
//!
//! An agent always has a person answerable for it. When that person moves
//! on, the agent goes to someone else rather than staying with nobody to
//! answer for what it does.
//!
//! An owner gives an agent to a named person by offering it. The offer
//! checks that person may own an agent from what the tenant's records say
//! they hold, since they are not the one signed in. Nothing moves until
//! they accept, signed in themselves, so nobody is made answerable for an
//! agent without agreeing to it.

use time::{Duration, OffsetDateTime};

use crate::domains::agents::events::identity::{
    AgentOwnershipOfferWithdrawn, AgentOwnershipOffered, AgentOwnershipTransferred,
};
use crate::domains::agents::identity::agent::AgentIdentity;
use crate::domains::agents::identity::control::AgentControl;
use crate::domains::authorization::authority::TenantAccess;
use crate::domains::authorization::permission::{AgentAction, SystemPermission};
use crate::domains::identity::account::user::User;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::clock;
use crate::shared::errors::DomainError;
use crate::types::{Human, HumanAccount, PersonKey, PrincipalRef};

/// How long an offer of an agent waits for an answer before it lapses.
pub const OFFER_LIFETIME: Duration = Duration::days(7);

/// The right a person needs to own an agent.
const OWNS_AGENTS: SystemPermission = SystemPermission::Agents(AgentAction::Create);

/// Why an agent's ownership moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handover {
    /// Its owner, or someone allowed to manage agents, gives it to another
    /// person.
    Given,
    /// Its owner left, and someone allowed to manage agents hands it on.
    OwnerLeft,
}

impl Handover {
    /// The name the records show.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Given => "given",
            Self::OwnerLeft => "owner_left",
        }
    }
}

/// Whether an agent waits for a person it was offered to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnershipOffer {
    /// Nobody was offered the agent.
    Unoffered,
    /// It was offered to `recipient`, who may accept it until `expires_at`.
    Open {
        /// The person it was offered to, through the account named.
        recipient: Human,
        /// When it was offered.
        offered_at: OffsetDateTime,
        /// When the offer lapses unanswered.
        expires_at: OffsetDateTime,
    },
}

impl OwnershipOffer {
    /// The person the agent was offered to, while an offer stands at `now`.
    #[must_use]
    pub fn open_to(&self, now: OffsetDateTime) -> Option<&Human> {
        match self {
            Self::Open {
                recipient,
                expires_at,
                ..
            } if now < *expires_at => Some(recipient),
            Self::Open { .. } | Self::Unoffered => None,
        }
    }

    /// When the offer was made, if one was.
    #[must_use]
    pub fn offered_at(&self) -> Option<OffsetDateTime> {
        match self {
            Self::Open { offered_at, .. } => Some(*offered_at),
            Self::Unoffered => None,
        }
    }

    /// When the offer lapses, if one was made.
    #[must_use]
    pub fn expires_at(&self) -> Option<OffsetDateTime> {
        match self {
            Self::Open { expires_at, .. } => Some(*expires_at),
            Self::Unoffered => None,
        }
    }

    /// The person an offer was made to, open or lapsed.
    pub(crate) fn recipient(&self) -> Option<&Human> {
        match self {
            Self::Open { recipient, .. } => Some(recipient),
            Self::Unoffered => None,
        }
    }

    /// Whether an offer lapses after it was made, as every offer does.
    pub(crate) fn lapses_after_it_began(&self) -> bool {
        match self {
            Self::Open {
                offered_at,
                expires_at,
                ..
            } => offered_at < expires_at,
            Self::Unoffered => true,
        }
    }
}

/// A tenant user an agent may be offered to, because the tenant's records
/// say they may create agents and so may own one.
///
/// Its field is private. Only [`AgentRecipient::worked_out`] makes one,
/// from the records, so an offer never rests on the offerer's word about
/// what the other person holds.
#[derive(Debug, Clone)]
pub struct AgentRecipient {
    who: Human,
}

impl AgentRecipient {
    /// `account`, as one who may own an agent, from what `access` says they
    /// hold through their roles and groups.
    ///
    /// A break-glass grant is left out: it is given for an emergency, not
    /// to make someone answerable for an agent for good.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the account may not sign in now.
    /// - [`DomainError::Forbidden`] when the records do not let them create
    ///   agents.
    /// - The cases
    ///   [`TenantGrants::administrators`](crate::domains::authorization::stewardship::TenantGrants::administrators)
    ///   lists, for records that name a role or group that is not there.
    pub fn worked_out<T: TenantScope>(
        access: &TenantAccess<'_, T>,
        account: &User<T>,
    ) -> Result<Self, DomainError> {
        if !account.can_authenticate() {
            return Err(DomainError::forbidden(message!(
                "agents-an-agent-goes-only-to-someone-2",
                "an agent goes only to someone who may sign in"
            )));
        }
        let standing = access.standing_of(PrincipalRef::User(*account.id()))?;
        if !standing
            .system()
            .iter()
            .any(|held| held.implies(&OWNS_AGENTS))
        {
            return Err(may_not_own());
        }
        Ok(Self {
            who: Human::new(
                HumanAccount::User(*account.id()),
                PersonKey::of(account.email()),
            ),
        })
    }

    /// The person, through the account the offer names.
    #[must_use]
    pub fn who(&self) -> &Human {
        &self.who
    }
}

impl<T: TenantScope> AgentIdentity<T> {
    /// Whether the agent waits for someone it was offered to.
    #[must_use]
    pub fn offer(&self) -> &OwnershipOffer {
        &self.offer
    }

    /// Transfers the agent for `handover`'s reason and closes any open ownership offer.
    /// Status, proof and delegations stay intact, including each delegation's grantor.
    /// Raises `agents.agent_ownership_transferred`.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] unless the actor owns or manages the agent, or if the
    /// recipient may not create agents. Only an agent manager can act for a departed owner.
    /// [`DomainError::Conflict`] if the recipient's account already owns the agent.
    pub fn transfer_ownership(
        &mut self,
        control: &AgentControl<'_>,
        recipient: &AgentControl<'_>,
        handover: Handover,
    ) -> Result<(), DomainError> {
        self.ensure_may_hand_over(control, handover)?;
        ensure_may_own(recipient)?;
        self.ensure_not_owner(recipient.by())?;
        self.hand_to(recipient.by(), handover);
        Ok(())
    }

    /// Offers the agent to the person `recipient` names, who may accept it
    /// for [`OFFER_LIFETIME`]. An earlier offer still open is replaced.
    ///
    /// Only the owner, or someone allowed to manage agents, offers it. The
    /// recipient was worked out from the tenant's records, so Ann cannot
    /// offer her agent to Sam, who may only view agents, for him to accept
    /// later.
    ///
    /// Raises `agents.agent_ownership_offered`, naming the recipient so they
    /// hear of it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `control` neither owns the agent
    ///   nor may manage agents.
    /// - [`DomainError::Conflict`] when the recipient owns it already,
    ///   through the same account.
    pub fn offer_ownership(
        &mut self,
        control: &AgentControl<'_>,
        recipient: &AgentRecipient,
    ) -> Result<(), DomainError> {
        self.ensure_may_hand_over(control, Handover::Given)?;
        self.ensure_not_owner(recipient.who())?;
        let now = clock::now();
        let expires_at = now.saturating_add(OFFER_LIFETIME);
        self.offer = OwnershipOffer::Open {
            recipient: recipient.who().clone(),
            offered_at: now,
            expires_at,
        };
        self.updated_at = now;
        self.raised.raise(AgentOwnershipOffered {
            agent_id: self.id,
            agent_label: self.label(),
            owner: self.owner.principal(),
            recipient: recipient.who().principal(),
            expires_at,
            occurred_at: now,
        });
        Ok(())
    }

    /// The person the agent was offered to takes it, signed in themselves.
    ///
    /// They must still be allowed to create agents now, since what they
    /// held when it was offered may have been taken away since.
    ///
    /// Raises `agents.agent_ownership_transferred`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when no offer stands: none was made, it
    ///   lapsed, or it was withdrawn.
    /// - [`DomainError::Forbidden`] when the offer was made to someone else.
    /// - [`DomainError::Forbidden`] when they may no longer create agents.
    pub fn accept_ownership(&mut self, recipient: &AgentControl<'_>) -> Result<(), DomainError> {
        let Some(offered) = self.offer.open_to(clock::now()) else {
            return Err(DomainError::conflict(message!(
                "agents-the-agent-is-not-on-offer",
                "the agent is not on offer"
            )));
        };
        if !offered.is_same_account_as(recipient.by()) {
            return Err(DomainError::forbidden(message!(
                "agents-the-agent-was-offered-to-someone",
                "the agent was offered to someone else"
            )));
        }
        ensure_may_own(recipient)?;
        self.hand_to(recipient.by(), Handover::Given);
        Ok(())
    }

    /// Ends an offer still open without moving the agent: its owner, or
    /// someone allowed to manage agents, withdraws it, or the person it was
    /// made to declines it.
    ///
    /// Raises `agents.agent_ownership_offer_withdrawn`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when no offer stands.
    /// - [`DomainError::Forbidden`] when `control` is neither the
    ///   recipient, the owner, nor allowed to manage agents.
    pub fn withdraw_offer(&mut self, control: &AgentControl<'_>) -> Result<(), DomainError> {
        let now = clock::now();
        let Some(offered) = self.offer.open_to(now) else {
            return Err(DomainError::conflict(message!(
                "agents-the-agent-is-not-on-offer",
                "the agent is not on offer"
            )));
        };
        let recipient = offered.principal();
        if !offered.is_same_account_as(control.by()) {
            self.ensure_may_hand_over(control, Handover::Given)?;
        }
        self.offer = OwnershipOffer::Unoffered;
        self.updated_at = now;
        self.raised.raise(AgentOwnershipOfferWithdrawn {
            agent_id: self.id,
            agent_label: self.label(),
            recipient,
            occurred_at: now,
        });
        Ok(())
    }

    /// Makes `to` the owner, ending any offer, and records the move.
    fn hand_to(&mut self, to: &Human, handover: Handover) {
        let from = self.owner.principal();
        self.owner = to.clone();
        self.offer = OwnershipOffer::Unoffered;
        self.touch();
        self.raised.raise(AgentOwnershipTransferred {
            agent_id: self.id,
            agent_label: self.label(),
            from,
            to: self.owner.principal(),
            handover,
            occurred_at: self.updated_at,
        });
    }

    /// Refuses a person who may not move the agent for `handover`.
    fn ensure_may_hand_over(
        &self,
        control: &AgentControl<'_>,
        handover: Handover,
    ) -> Result<(), DomainError> {
        if control.holds_agent(AgentAction::Manage) {
            return Ok(());
        }
        match handover {
            Handover::Given if control.by().is_same_person_as(&self.owner) => Ok(()),
            Handover::Given => Err(DomainError::forbidden(message!(
                "agents-only-the-agent-s-owner-or",
                "only the agent's owner, or someone allowed to manage agents, gives it away"
            ))),
            Handover::OwnerLeft => Err(DomainError::forbidden(message!(
                "agents-only-someone-allowed-to-manage-agents-5",
                "only someone allowed to manage agents hands on the agent of an owner who left"
            ))),
        }
    }

    /// Refuses moving the agent to the account that owns it already.
    fn ensure_not_owner(&self, to: &Human) -> Result<(), DomainError> {
        if to.is_same_account_as(&self.owner) {
            return Err(DomainError::conflict(message!(
                "agents-the-agent-is-already-theirs",
                "the agent is already theirs"
            )));
        }
        Ok(())
    }
}

/// Refuses a new owner who may not create agents.
fn ensure_may_own(recipient: &AgentControl<'_>) -> Result<(), DomainError> {
    if recipient.holds_agent(AgentAction::Create) {
        return Ok(());
    }
    Err(may_not_own())
}

/// The refusal of a new owner who may not create agents.
fn may_not_own() -> DomainError {
    DomainError::forbidden(message!(
        "agents-an-agent-goes-only-to-someone",
        "an agent goes only to someone allowed to create agents"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::identity::agent::tests::fixtures::{
        acting, agent_of, ann, creating, managing, person, sam, viewing,
    };
    use crate::domains::authorization::fixtures::{Records, role};
    use crate::domains::authorization::role::RoleAssignment;
    use crate::domains::identity::account::verified_email::proof_of;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::builders::user;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::UserId;

    /// `who` as an agent may be offered to them, as the records would say.
    fn recipient(who: &Human) -> AgentRecipient {
        AgentRecipient { who: who.clone() }
    }

    /// A tenant user who may sign in.
    fn active(address: &str) -> User<ResolvedTenant> {
        let mut account = user(UserId::new(), address);
        account.verify_email(&proof_of(account.email())).unwrap();
        account
    }

    /// Records giving `account` one role holding `system`.
    fn records_giving(account: &User<ResolvedTenant>, system: &[SystemPermission]) -> Records {
        let role = role("team", system, &[]);
        let assignment = RoleAssignment::create(
            PrincipalRef::User(*account.id()),
            &role,
            anyone_holding(SystemPermission::all()),
        )
        .unwrap();
        Records {
            roles: vec![role],
            assignments: vec![assignment],
            ..Records::default()
        }
    }

    /// Bob's roles let him create agents. The records make him someone an
    /// agent may be offered to, through his own account.
    #[test]
    fn a_user_whose_roles_create_agents_may_be_offered_one() {
        let bob = active("bob@corp.test");
        let records = records_giving(&bob, &[OWNS_AGENTS]);

        let offered = AgentRecipient::worked_out(&records.access(), &bob).unwrap();

        assert_eq!(offered.who().account(), HumanAccount::User(*bob.id()));
    }

    /// A user whose roles only permit viewing agents cannot qualify as
    /// an ownership-offer recipient.
    #[test]
    fn a_user_whose_roles_do_not_create_agents_is_offered_none() {
        let sam = active("sam@corp.test");
        let records = records_giving(&sam, &[SystemPermission::Agents(AgentAction::View)]);

        let offered = AgentRecipient::worked_out(&records.access(), &sam);

        assert!(matches!(offered, Err(DomainError::Forbidden(_))));
    }

    /// Ann gives her agent to Bob, who may create agents. Bob owns it now,
    /// and the move is raised naming both of them and why it moved.
    #[test]
    fn an_owner_gives_her_agent_to_someone_who_may_create_agents() {
        let (ann, bob) = (ann(), person("bob@corp.test"));
        let mut agent = agent_of(&ann);
        raised_names(&mut agent);

        agent
            .transfer_ownership(&acting(&ann), &creating(&bob), Handover::Given)
            .unwrap();

        assert!(agent.owner().is_same_account_as(&bob));
        let events = raised(&mut agent);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().to_string(),
            "agents.agent_ownership_transferred"
        );
        assert_eq!(
            events[0].payload().value("handover"),
            Some(&FieldValue::Text("given".to_owned()))
        );
    }

    /// A viewer cannot transfer another person's agent to an eligible
    /// recipient. The refusal leaves ownership with the original owner.
    #[test]
    fn a_person_with_no_say_cannot_give_someone_elses_agent_away() {
        let ann = ann();
        let bob = person("bob@corp.test");
        let mut agent = agent_of(&ann);

        let given = agent.transfer_ownership(&viewing(&sam()), &creating(&bob), Handover::Given);

        assert!(matches!(given, Err(DomainError::Forbidden(_))));
        assert!(agent.owner().is_same_account_as(&ann));
    }

    /// An owner cannot transfer an agent to a recipient who may only view
    /// agents. The refusal leaves ownership unchanged.
    #[test]
    fn an_agent_goes_only_to_someone_allowed_to_create_agents() {
        let ann = ann();
        let mut agent = agent_of(&ann);

        let given = agent.transfer_ownership(&acting(&ann), &viewing(&sam()), Handover::Given);

        assert!(matches!(given, Err(DomainError::Forbidden(_))));
        assert!(agent.owner().is_same_account_as(&ann));
    }

    /// Ann left the company. Bob, who manages agents, hands her agent on to
    /// Carl. Ann herself, still signed in somewhere, may not use that path.
    #[test]
    fn only_a_manager_hands_on_the_agent_of_an_owner_who_left() {
        let ann = ann();
        let (bob, carl) = (person("bob@corp.test"), person("carl@corp.test"));
        let mut agent = agent_of(&ann);

        let by_ann = agent.transfer_ownership(&acting(&ann), &creating(&carl), Handover::OwnerLeft);
        agent
            .transfer_ownership(&managing(&bob), &creating(&carl), Handover::OwnerLeft)
            .unwrap();

        assert!(matches!(by_ann, Err(DomainError::Forbidden(_))));
        assert!(agent.owner().is_same_account_as(&carl));
    }

    /// Ann gives her agent to herself, through the account that already
    /// owns it. It is refused as a conflict, and nothing is raised.
    #[test]
    fn giving_an_agent_to_its_owner_is_a_conflict() {
        let ann = ann();
        let mut agent = agent_of(&ann);
        raised_names(&mut agent);

        let given = agent.transfer_ownership(&acting(&ann), &creating(&ann), Handover::Given);

        assert!(matches!(given, Err(DomainError::Conflict(_))));
        assert!(raised_names(&mut agent).is_empty());
    }

    /// Every reason an agent moves has its own stored name.
    #[test]
    fn each_handover_has_its_own_name() {
        assert_eq!(Handover::Given.as_str(), "given");
        assert_eq!(Handover::OwnerLeft.as_str(), "owner_left");
    }

    /// Ann offers her agent to Bob. It stays hers, waits for Bob for a
    /// week, and the offer is raised naming him.
    #[test]
    fn an_offer_names_the_recipient_and_moves_nothing() {
        let (ann, bob) = (ann(), person("bob@corp.test"));
        let mut agent = agent_of(&ann);
        raised_names(&mut agent);

        agent
            .offer_ownership(&acting(&ann), &recipient(&bob))
            .unwrap();

        assert!(agent.owner().is_same_account_as(&ann));
        let now = clock::now();
        assert_eq!(agent.offer().open_to(now), Some(&bob));
        assert_eq!(raised_names(&mut agent), ["agents.agent_ownership_offered"]);
    }

    /// Bob accepts the agent Ann offered him. He owns it now, the offer is
    /// over, and the move is raised.
    #[test]
    fn the_recipient_accepts_and_owns_the_agent() {
        let (ann, bob) = (ann(), person("bob@corp.test"));
        let mut agent = agent_of(&ann);
        agent
            .offer_ownership(&acting(&ann), &recipient(&bob))
            .unwrap();
        raised_names(&mut agent);

        agent.accept_ownership(&creating(&bob)).unwrap();

        assert!(agent.owner().is_same_account_as(&bob));
        assert_eq!(agent.offer(), &OwnershipOffer::Unoffered);
        assert_eq!(
            raised_names(&mut agent),
            ["agents.agent_ownership_transferred"]
        );
    }

    /// A person other than the offer's recipient cannot accept the agent,
    /// even with creation rights. The original owner keeps it.
    #[test]
    fn only_the_person_offered_the_agent_accepts_it() {
        let (ann, bob, sam) = (ann(), person("bob@corp.test"), sam());
        let mut agent = agent_of(&ann);
        agent
            .offer_ownership(&acting(&ann), &recipient(&bob))
            .unwrap();

        let by_sam = agent.accept_ownership(&creating(&sam));

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert!(agent.owner().is_same_account_as(&ann));
    }

    /// An offer's recipient cannot accept with only viewing rights;
    /// acceptance is refused and the original owner keeps the agent.
    #[test]
    fn a_recipient_who_lost_the_right_to_own_agents_cannot_accept() {
        let (ann, bob) = (ann(), person("bob@corp.test"));
        let mut agent = agent_of(&ann);
        agent
            .offer_ownership(&acting(&ann), &recipient(&bob))
            .unwrap();

        let accepted = agent.accept_ownership(&viewing(&bob));

        assert!(matches!(accepted, Err(DomainError::Forbidden(_))));
        assert!(agent.owner().is_same_account_as(&ann));
    }

    /// A viewer cannot offer another person's agent to a new owner;
    /// the refusal leaves the agent without an ownership offer.
    #[test]
    fn a_person_with_no_say_cannot_offer_someone_elses_agent() {
        let ann = ann();
        let mut agent = agent_of(&ann);

        let offered =
            agent.offer_ownership(&viewing(&sam()), &recipient(&person("carl@corp.test")));

        assert!(matches!(offered, Err(DomainError::Forbidden(_))));
        assert_eq!(agent.offer(), &OwnershipOffer::Unoffered);
    }

    /// Bob accepts an agent nobody offered him. It is a conflict.
    #[test]
    fn accepting_an_agent_not_on_offer_is_a_conflict() {
        let mut agent = agent_of(&ann());

        let accepted = agent.accept_ownership(&creating(&person("bob@corp.test")));

        assert!(matches!(accepted, Err(DomainError::Conflict(_))));
    }

    /// Bob declines the agent Ann offered him. The offer ends, the agent
    /// stays Ann's, and the end is raised. Accepting afterwards is a
    /// conflict.
    #[test]
    fn the_recipient_declines_an_offer() {
        let (ann, bob) = (ann(), person("bob@corp.test"));
        let mut agent = agent_of(&ann);
        agent
            .offer_ownership(&acting(&ann), &recipient(&bob))
            .unwrap();
        raised_names(&mut agent);

        agent.withdraw_offer(&acting(&bob)).unwrap();

        assert_eq!(
            raised_names(&mut agent),
            ["agents.agent_ownership_offer_withdrawn"]
        );
        assert!(matches!(
            agent.accept_ownership(&creating(&bob)),
            Err(DomainError::Conflict(_))
        ));
    }

    /// A viewer who is neither owner nor recipient cannot withdraw an
    /// ownership offer. It remains open to the named recipient.
    #[test]
    fn only_the_owner_a_manager_or_the_recipient_ends_an_offer() {
        let (ann, bob) = (ann(), person("bob@corp.test"));
        let mut agent = agent_of(&ann);
        agent
            .offer_ownership(&acting(&ann), &recipient(&bob))
            .unwrap();

        let by_sam = agent.withdraw_offer(&viewing(&sam()));

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert_eq!(agent.offer().open_to(clock::now()), Some(&bob));
    }

    /// Ann offers her agent to Bob, then Carl, who manages agents, takes it
    /// over. Bob's offer ends with the move, so he cannot take it from
    /// Carl later.
    #[test]
    fn a_transfer_ends_an_open_offer() {
        let (ann, bob, carl) = (ann(), person("bob@corp.test"), person("carl@corp.test"));
        let mut agent = agent_of(&ann);
        agent
            .offer_ownership(&acting(&ann), &recipient(&bob))
            .unwrap();

        agent
            .transfer_ownership(&managing(&carl), &creating(&carl), Handover::Given)
            .unwrap();

        assert!(matches!(
            agent.accept_ownership(&creating(&bob)),
            Err(DomainError::Conflict(_))
        ));
    }

    /// An offer is open until it lapses, and not after.
    #[test]
    fn an_offer_lapses_after_its_lifetime() {
        let bob = person("bob@corp.test");
        let at = OffsetDateTime::UNIX_EPOCH;
        let offer = OwnershipOffer::Open {
            recipient: bob.clone(),
            offered_at: at,
            expires_at: at.saturating_add(OFFER_LIFETIME),
        };

        assert_eq!(offer.open_to(at), Some(&bob));
        assert_eq!(offer.open_to(at.saturating_add(OFFER_LIFETIME)), None);
    }
}
