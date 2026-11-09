//! A [`Delegation`] hands part of someone's authority to an agent.
//!
//! The agent gets a [`CapabilitySet`] from a delegator, inside one tenant.
//! The stores are opened for one resolved tenant, and that keeps delegator,
//! delegate and delegation in the same tenant. The type itself does not.
//!
//! The rules a delegation keeps:
//!
//! - **It only shrinks.** It grants no more than the delegator holds
//!   ([`CapabilitySet::subset_of`]). A sub-delegation grants no more than its
//!   parent.
//! - **Its chain is bounded.** A chain never grows past its `max_depth`.
//! - **Its children share its budget.** Each child's request cap counts
//!   against the parent's, see [`Delegation::budget_fits_beside`].
//!
//! A delegation keeps a copy of what it was given. It does not change when
//! the delegator loses a right, or when a delegation above it is revoked.
//! So whoever uses one asks two questions as well:
//! [`still_allowed`](Delegation::still_allowed), given what the delegator
//! holds now, and [`live_under`](Delegation::live_under), given the chain
//! above it. A task token's delegation records what it was minted from, so
//! the second question reaches it too.

mod acting_under;
mod budget_share;
mod ceiling;
mod held;
mod held_by;
mod held_now;
mod lineage;
mod narrowing;
mod record;
mod recorded;
mod renewal;
mod resources;
mod token_key;

use std::marker::PhantomData;

pub use acting_under::*;
pub use ceiling::{Attenuator, ResourceCeiling};
pub use held_by::*;
pub use held_now::HeldNow;
pub use lineage::Lineage;
pub(crate) use lineage::people_behind;
pub(crate) use narrowing::attenuate_constraints;
pub use record::*;
use time::{Duration, OffsetDateTime};
pub use token_key::TokenKey;

use crate::domains::agents::authority::capability::{
    AgentBudget, CapabilitySet, DelegationConstraints,
};
use crate::domains::agents::authority::delegation::budget_share::fits_beside;
use crate::domains::agents::authority::delegation::held::ensure_owned_and_held;
use crate::domains::agents::authority::delegation::lineage::live_within;
use crate::domains::agents::authority::delegation::narrowing::narrowed_by_all;
use crate::domains::agents::authority::delegation::record::ensure_consistent;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::raised::Raised;
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::restriction::Restriction;
use crate::types::{AgentId, DelegationId, Label, Lifetime, PrincipalRef};

/// Authority one principal hands to one agent, no wider than what the giver
/// holds.
#[derive(Debug, Clone)]
pub struct Delegation<T: TenantScope> {
    id: DelegationId,
    delegator: PrincipalRef,
    delegate: AgentId,
    granted: CapabilitySet,
    constraints: DelegationConstraints,
    lineage: Lineage,
    depth: u8,
    status: DelegationStatus,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    renewed: DelegationRenewal,
    updated_at: OffsetDateTime,
    name: Option<Label>,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> Delegation<T> {
    /// Starts a new chain: a person hands an agent part of what they hold.
    ///
    /// Only a person starts a chain. An agent passes authority on through
    /// [`attenuate`](Self::attenuate), which keeps its own limits on the
    /// child. Agent A may act only on the Q1 books. If A could start a fresh
    /// chain, it would hand agent B the same rights with no task limit. The
    /// delegator is the person `held` was made for, so an agent never starts
    /// one.
    ///
    /// Raises `agents.delegation_granted` and `agents.token_issued`, naming
    /// the agent by its name.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the agent receiving it is reviewing
    ///   another agent, or may not act now.
    /// - [`DomainError::Forbidden`] when it asks for anything the delegator
    ///   does not hold.
    pub fn grant(
        params: GrantDelegationParams,
        held: &HeldBy,
        delegate: &Delegate<'_, T>,
    ) -> Result<Self, DomainError> {
        delegate.ensure_may_receive()?;
        if !params.granted.subset_of(held.caps()) {
            return Err(DomainError::forbidden(message!(
                "agents-delegation-exceeds-delegator-authority",
                "delegation exceeds delegator authority"
            )));
        }
        let now = crate::shared::clock::now();
        let expires_at = lifetime_end(now, &params.constraints);
        let granted = Self {
            id: DelegationId::new(),
            delegator: held.holder(),
            delegate: delegate.id(),
            granted: params.granted,
            constraints: params.constraints,
            lineage: Lineage::Root,
            depth: 0,
            status: DelegationStatus::Active,
            issued_at: now,
            expires_at,
            renewed: DelegationRenewal::NotRenewed,
            updated_at: now,
            name: params.name,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        Ok(recorded::handed_over(granted, &delegate.label()))
    }

    /// Gives an agent `granted` as its own authority, with no limit from
    /// anyone above it. For tests only.
    ///
    /// The agent is both delegator and delegate, so it acts for no one but
    /// itself. Nothing checks `granted` against anyone's rights. Outside
    /// tests, an agent makes its own delegation only through
    /// [`grant_owned_within`](Self::grant_owned_within), which holds it inside
    /// what the agent was given.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn grant_owned(
        agent_id: AgentId,
        granted: CapabilitySet,
        constraints: DelegationConstraints,
    ) -> Self {
        let now = crate::shared::clock::now();
        let expires_at = lifetime_end(now, &constraints);
        Self {
            id: DelegationId::new(),
            delegator: PrincipalRef::Agent(agent_id),
            delegate: agent_id,
            granted,
            constraints,
            lineage: Lineage::Root,
            depth: 0,
            status: DelegationStatus::Active,
            issued_at: now,
            expires_at,
            renewed: DelegationRenewal::NotRenewed,
            updated_at: now,
            name: None,
            raised: Raised::default(),
            _scope: PhantomData,
        }
    }

    /// Makes the delegation behind a task token: the agent grants itself
    /// part of what it was given.
    ///
    /// The agent asks for the limits itself, so none of them is trusted.
    /// Each one is held inside every delegation in `ceiling`. Ann's agent may
    /// act only with her approval. Without this, the agent asks for a token
    /// with no approval rule and acts without asking her.
    ///
    /// `ceiling` holds the live delegations someone else granted this agent.
    /// A revoked or expired one gives nothing. Another agent's is not this
    /// agent's to use. One the agent made itself would let it widen its own
    /// rights at the next exchange. When two delegations in `ceiling` set
    /// limits nothing can meet together, such as two purposes with no class
    /// in common, the request is refused.
    ///
    /// The token lives no longer than `max_ttl` and no longer than the
    /// soonest expiry in `ceiling`. A task token covers one unit of work, so
    /// a stolen one stays useful only briefly.
    ///
    /// The result sits as deep as the deepest delegation in `ceiling`. So an
    /// agent at the end of its chain cannot pass authority on by exchanging a
    /// token.
    ///
    /// It records the delegations in `ceiling` and who granted them. Ann
    /// revokes her agent's delegation a minute after it exchanged a token.
    /// Without the record, nothing would tie the token to what she revoked,
    /// and an approval for it could not name her.
    ///
    /// It records the credential whose key signed the agent in, too. A bound
    /// token is bound to that key, see [`token_key`](Self::token_key), and
    /// revoking that credential ends the token. The agent holds k2 and k3
    /// and signs in with k3. Without the record, its token could be bound to
    /// k2, and revoking k3 after a leak would leave the token working.
    ///
    /// Raises `agents.delegation_granted` and `agents.token_issued`, naming
    /// the agent as `request` names it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `ceiling` is empty.
    /// - [`DomainError::Forbidden`] when a delegation in `ceiling` is revoked,
    ///   expired, made by the agent itself, or granted to another agent.
    /// - [`DomainError::Forbidden`] when the delegations in `ceiling` come
    ///   from more than one delegator. A token carries one party's
    ///   authority, never Ann's and Bob's rights added together.
    /// - [`DomainError::Forbidden`] when `granted` asks for anything the
    ///   delegations in `ceiling` do not give between them.
    /// - [`DomainError::Forbidden`] when `requested` asks for a wider limit
    ///   than any delegation in `ceiling` has.
    pub fn grant_owned_within(
        request: OwnedTokenRequest<'_>,
        ceiling: &[Self],
    ) -> Result<Self, DomainError> {
        let (earliest_expiry, first) = Self::earliest_and_first(ceiling)?;
        let now = crate::shared::clock::now();
        let agent = *request.agent.agent();
        ensure_owned_and_held(agent, &request.granted, ceiling, now)?;
        let constraints = narrowed_by_all(ceiling, request.requested)?;
        let expires_at = token_expiry(now, &constraints, request.max_ttl).min(earliest_expiry);
        let minted = Self {
            id: DelegationId::new(),
            delegator: PrincipalRef::Agent(agent),
            delegate: agent,
            granted: request.granted,
            constraints,
            lineage: lineage::minted_from(ceiling, first, *request.agent.credential()),
            depth: ceiling.iter().map(Self::depth).max().unwrap_or(0),
            status: DelegationStatus::Active,
            issued_at: now,
            expires_at,
            renewed: DelegationRenewal::NotRenewed,
            updated_at: now,
            name: None,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        Ok(recorded::handed_over(minted, &request.agent_label))
    }

    /// When the first delegation of `ceiling` runs out, and its first
    /// delegation; an empty ceiling grants nothing to mint from.
    fn earliest_and_first(ceiling: &[Self]) -> Result<(OffsetDateTime, &Self), DomainError> {
        let (Some(earliest_expiry), Some(first)) =
            (ceiling.iter().map(Self::expires_at).min(), ceiling.first())
        else {
            return Err(DomainError::forbidden(message!(
                "agents-an-agent-with-no-granted-authority",
                "an agent with no granted authority cannot mint a token"
            )));
        };
        Ok((earliest_expiry, first))
    }

    /// Grants another agent a child delegation with narrower rights, limits and expiry.
    /// The holding agent, its owner or an authorized steward may act. The child names
    /// that agent as delegator, sits one link deeper and is revoked with its parent.
    /// Raises `agents.delegation_granted` and `agents.token_issued`, naming the recipient.
    ///
    /// # Errors
    /// [`DomainError::InvalidTransition`] if the parent is revoked or expired.
    /// [`DomainError::Forbidden`] for an unauthorized actor, a steward exceeding their rights,
    /// a recipient that is the holder, reviewing or unable to act, or a child exceeding
    /// parent capabilities, limits or chain depth, or naming a different task.
    pub fn attenuate(
        &self,
        by: &Attenuator<'_, T>,
        delegate: &Delegate<'_, T>,
        params: AttenuateParams,
    ) -> Result<Self, DomainError> {
        by.ensure_speaks_for(self)?;
        by.ensure_may_pass_on(&params.granted)?;
        if delegate.id() == self.delegate {
            return Err(DomainError::forbidden(message!(
                "agents-an-agent-does-not-pass-a",
                "an agent does not pass a delegation on to itself"
            )));
        }
        delegate.ensure_may_receive()?;
        let child = self.narrowed(delegate.id(), params)?;
        Ok(recorded::handed_over(child, &delegate.label()))
    }

    /// The child for `delegate` that `params` asks for, narrowed from this
    /// delegation.
    fn narrowed(&self, delegate: AgentId, params: AttenuateParams) -> Result<Self, DomainError> {
        let now = crate::shared::clock::now();
        let child_depth = self.ensure_can_attenuate(&params, now)?;
        let expires_at = lifetime_end(now, &params.constraints).min(self.expires_at);
        let constraints = attenuate_constraints(&self.constraints, params.constraints)?
            .deep_enough_for(child_depth);
        Ok(Self {
            id: DelegationId::new(),
            delegator: PrincipalRef::Agent(self.delegate),
            delegate,
            granted: params.granted,
            constraints,
            lineage: Lineage::Under(self.id),
            depth: child_depth,
            status: DelegationStatus::Active,
            issued_at: now,
            expires_at,
            renewed: DelegationRenewal::NotRenewed,
            updated_at: now,
            name: params.name,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// The depth a child of this delegation would sit at.
    ///
    /// It is refused unless this delegation is live at `now`, `params` asks
    /// for no more than it grants, and the chain has room for one more link.
    fn ensure_can_attenuate(
        &self,
        params: &AttenuateParams,
        now: OffsetDateTime,
    ) -> Result<u8, DomainError> {
        if !self.is_valid(now) {
            return Err(DomainError::invalid_transition(message!(
                "agents-cannot-attenuate-a-revoked-or-expired",
                "cannot attenuate a revoked or expired delegation"
            )));
        }
        if !params.granted.subset_of(&self.granted) {
            return Err(DomainError::forbidden(message!(
                "agents-sub-delegation-exceeds-parent-authority",
                "sub-delegation exceeds parent authority"
            )));
        }
        self.depth
            .checked_add(1)
            .filter(|child_depth| *child_depth <= self.constraints.max_depth())
            .ok_or_else(|| {
                DomainError::forbidden(message!(
                    "agents-maximum-delegation-depth-exceeded",
                    "maximum delegation depth exceeded"
                ))
            })
    }

    /// Rebuilds a delegation from storage, after checking the row.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row's lineage and depth
    ///   disagree. Examples are a sub-delegation at depth zero, one under
    ///   itself, or a root an agent granted to another agent.
    /// - [`DomainError::Infrastructure`] when the row says it expires, or
    ///   changed, before it was issued.
    pub fn reconstitute(row: DelegationRow) -> Result<Self, DomainError> {
        ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            delegator: row.delegator,
            delegate: row.delegate,
            granted: row.granted,
            constraints: row.constraints,
            lineage: row.lineage,
            depth: row.depth,
            status: row.status,
            issued_at: row.issued_at,
            expires_at: row.expires_at,
            renewed: row.renewed,
            updated_at: row.updated_at,
            name: row.name,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// The delegation's id.
    #[must_use]
    pub fn id(&self) -> &DelegationId {
        &self.id
    }

    /// Who handed over the authority.
    #[must_use]
    pub fn delegator(&self) -> &PrincipalRef {
        &self.delegator
    }

    /// The agent receiving authority.
    #[must_use]
    pub fn delegate(&self) -> &AgentId {
        &self.delegate
    }

    /// The capabilities it grants.
    #[must_use]
    pub fn granted(&self) -> &CapabilitySet {
        &self.granted
    }

    /// The limits on it, such as its lifetime, depth, task and budget.
    #[must_use]
    pub fn constraints(&self) -> &DelegationConstraints {
        &self.constraints
    }

    /// Where this delegation sits: at the top of its chain, under a parent,
    /// or minted for a task token from the delegations its agent holds.
    #[must_use]
    pub fn lineage(&self) -> &Lineage {
        &self.lineage
    }

    /// The parent delegation, when this is a sub-delegation.
    #[must_use]
    pub fn parent(&self) -> Option<DelegationId> {
        let Lineage::Under(parent) = self.lineage else {
            return None;
        };
        Some(parent)
    }

    /// How many links it sits below the top of its chain. A root is 0.
    #[must_use]
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// The title people see, given when the delegation is made. `None` when
    /// it has none.
    #[must_use]
    pub fn name(&self) -> Option<&Label> {
        self.name.as_ref()
    }

    /// When this delegation expires.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// Whether this delegation is revoked.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.status == DelegationStatus::Revoked
    }

    /// Whether the agent granted this to itself.
    ///
    /// These come from the token exchange, where the agent is both delegator
    /// and delegate. They add nothing the agent was not given. So counting
    /// what an agent holds must leave them out. If they counted, each
    /// exchange could widen what the next one may ask for.
    #[must_use]
    pub fn is_self_rooted(&self) -> bool {
        matches!(self.delegator, PrincipalRef::Agent(id) if id == self.delegate)
    }

    /// What a task token minted for this delegation is bound to.
    ///
    /// A delegation that asks for no proof of possession gives a bearer
    /// token. One the agent minted in a token exchange binds the key that
    /// signed the agent in, never another of its keys. Any other bound
    /// delegation binds the agent's one active key.
    #[must_use]
    pub fn token_key(&self) -> TokenKey {
        if !self.constraints.is_sender_constrained() {
            return TokenKey::Bearer;
        }
        match &self.lineage {
            Lineage::Minted { signed_in_with, .. } => TokenKey::SignedInWith(*signed_in_with),
            Lineage::Root | Lineage::Under(_) => TokenKey::AgentsActiveKey,
        }
    }

    /// Whether this delegation is usable at `now`: not revoked and not
    /// expired.
    ///
    /// It checks only this delegation. [`live_under`](Self::live_under)
    /// checks the ones above it too.
    #[must_use]
    pub fn is_valid(&self, now: OffsetDateTime) -> bool {
        !self.is_revoked() && now < self.expires_at
    }

    /// Whether what this delegation grants is still inside what its
    /// delegator holds today, as `delegator_now` worked it out from records.
    ///
    /// The delegation keeps a copy of what it was given. Ann loses "view
    /// reports". Her agent's delegation still lists it, and this answers no
    /// from then on. Holdings worked out for someone other than its
    /// delegator answer no too. A delegation an agent passed on or minted
    /// is held to what it was cut from by [`live_under`](Self::live_under).
    #[must_use]
    pub fn still_allowed(&self, delegator_now: &HeldNow) -> bool {
        delegator_now.holder() == self.delegator && self.granted.subset_of(delegator_now.caps())
    }

    /// Whether this delegation and every delegation above it are usable at
    /// `now`.
    ///
    /// `above` holds the delegations its chain runs through, in any order:
    /// the parents of a sub-delegation and the delegations a task token was
    /// minted from. Each link must be live and grant no more than what it
    /// was cut from grants now. A link missing from `above` makes the answer
    /// no. Ann revokes her agent's delegation. Without this, the child her
    /// agent passed on, and the token it minted, still read as usable.
    #[must_use]
    pub fn live_under(&self, above: &[Self], now: OffsetDateTime) -> bool {
        live_within(self, above, now, above.len())
    }

    /// Whether a child asking for the budget `asked` fits beside `siblings`,
    /// the children already passed on from this delegation.
    ///
    /// Children share their parent's budget. The request caps of the live
    /// children add up to no more than the parent's cap. A child naming no
    /// budget takes the whole cap. Ann's agent may make 100 requests an hour.
    /// Without this, it passes ten children 100 each, and they make 1,000.
    /// Delegations in `siblings` under another parent are left out.
    #[must_use]
    pub fn budget_fits_beside(
        &self,
        asked: &Restriction<AgentBudget>,
        siblings: &[Self],
        now: OffsetDateTime,
    ) -> bool {
        fits_beside(self, asked, siblings, now)
    }

    /// Revokes this delegation. Revoking one already revoked changes
    /// nothing, so it keeps the time of the first revoke.
    ///
    /// Sam, with no say over Ann's agent, cannot take back what she gave it.
    ///
    /// Raises `agents.delegation_revoked` whenever the revoke is allowed,
    /// also for a delegation already revoked: each time someone takes
    /// authority back is on record.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when a person who neither granted it nor
    ///   has a say over its agent revokes it.
    pub fn revoke(&mut self, by: Revoker<'_>) -> Result<(), DomainError> {
        by.ensure_may_revoke(&self.delegator)?;
        if let Ok(revoked) = self.status.try_transition(DelegationStatus::Revoked) {
            self.status = revoked;
            self.updated_at = crate::shared::clock::now();
        }
        recorded::raise_revocation(self);
        Ok(())
    }

    /// Records that an action under this delegation left the intent it
    /// binds, as the platform's drift monitor judged it. Nothing about the
    /// delegation changes; the monitor answers the drift apart.
    ///
    /// Raises `agents.intent_drift`.
    pub fn record_drift(&mut self) {
        recorded::raise_drift(self);
    }
}

impl<T: TenantScope> Aggregate for Delegation<T> {
    type Id = DelegationId;

    fn id(&self) -> &Self::Id {
        &self.id
    }

    fn created_at(&self) -> OffsetDateTime {
        self.issued_at
    }

    fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

/// When a delegation made at `now` under `constraints` ends by its own
/// lifetime.
fn lifetime_end(now: OffsetDateTime, constraints: &DelegationConstraints) -> OffsetDateTime {
    now.saturating_add(Duration::seconds(i64::from(
        constraints.ttl_seconds().get(),
    )))
}

/// When a task token made at `now` under `constraints` ends: its own
/// lifetime, never past `max_ttl`.
fn token_expiry(
    now: OffsetDateTime,
    constraints: &DelegationConstraints,
    max_ttl: Lifetime,
) -> OffsetDateTime {
    let requested = Duration::seconds(i64::from(constraints.ttl_seconds().get()));
    now.saturating_add(requested.min(max_ttl.duration()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::authority::capability::{
        AgentBudget, AppAccess, AppReach, McpGrant, McpTool, McpToolPattern, PubSub, Relation,
        ResourceCapability, ResourceRef, ResourceScope, TaskBinding, TopicCapability, TopicPattern,
    };
    use crate::domains::agents::authority::intent::{
        DriftPolicy, DriftThreshold, IntentBinding, IntentDigest, IntentEnvelope, IntentStatement,
    };
    use crate::domains::agents::identity::acting::ActingAgent;
    use crate::domains::agents::identity::agent::{
        AgentIdentity, AgentIdentityRow, AgentProof, Containment, OwnershipOffer,
    };
    use crate::domains::agents::identity::control::AgentControl;
    use crate::domains::agents::identity::status::AgentStatus;
    use crate::domains::authorization::permission::{
        AgentAction, MessagingAction, RoutingAction, SystemPermission,
    };
    use crate::domains::data_classification::level::DataClassLevel;
    use crate::domains::organization::members::account_now::AccountNow;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEvent;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::assumed_authority;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{
        ActionClass, AgentCredentialId, EventLabel, Human, HumanAccount, Lifetime, PersonKey,
        Seconds, ServiceId, TaskTemplateId, TenantId, UserId,
    };

    const TASK_TOKEN_MAX: Lifetime = Lifetime::from_secs(std::num::NonZeroU32::new(3600).unwrap());

    fn caps(action: RoutingAction, topic: &str, rights: PubSub) -> CapabilitySet {
        CapabilitySet::new(
            vec![SystemPermission::Routing(action)],
            vec![TopicCapability::new(
                TopicPattern::new(topic).unwrap(),
                rights,
            )],
        )
    }

    fn constraints(max_depth: u8) -> DelegationConstraints {
        DelegationConstraints::new(Seconds::new(600), max_depth).unwrap()
    }

    /// `by` granting from `caps`: their standing rights are its built-in
    /// permissions, plus a messaging one when it names topics, and the graph
    /// says they hold its resources.
    fn held_by(by: &Human, caps: &CapabilitySet) -> HeldBy {
        let mut standing = caps.http().to_vec();
        if !caps.messaging().is_empty() {
            standing.push(SystemPermission::Messaging(MessagingAction::Publish));
        }
        let control = AgentControl::new(assumed_authority(by, TenantId::new(), &standing, &[]));
        let answer = HeldResources::answered(by.principal(), caps.resources().to_vec());
        HeldBy::worked_out::<ResolvedTenant>(&control, caps, &answer, &[]).unwrap()
    }

    /// A person of their own granting from `caps`.
    fn held(caps: &CapabilitySet) -> HeldBy {
        held_by(
            &Human::new(
                HumanAccount::User(UserId::new()),
                PersonKey::new("ann@corp.test").unwrap(),
            ),
            caps,
        )
    }

    /// The tenant user `delegator` names granting from `caps`.
    fn held_as(delegator: &PrincipalRef, caps: &CapabilitySet) -> HeldBy {
        let PrincipalRef::User(id) = delegator else {
            panic!("a root in these tests is granted by a tenant user");
        };
        held_by(
            &Human::new(
                HumanAccount::User(*id),
                PersonKey::new("ann@corp.test").unwrap(),
            ),
            caps,
        )
    }

    /// Claiming route-management capability does not add it to a viewer's
    /// holdings, so granting that capability to an agent is forbidden.
    #[test]
    fn a_ceiling_holds_only_the_permissions_its_holder_has() {
        let sam = Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new("sam@corp.test").unwrap(),
        );
        let views = [SystemPermission::Routing(RoutingAction::View)];
        let control = AgentControl::new(assumed_authority(&sam, TenantId::new(), &views, &[]));
        let manages = vec![SystemPermission::Routing(RoutingAction::Manage)];
        let claimed = CapabilitySet::new(manages, Vec::new());
        let answer = HeldResources::answered(sam.principal(), Vec::new());
        let held = HeldBy::worked_out::<ResolvedTenant>(&control, &claimed, &answer, &[]).unwrap();

        let result = Delegation::<ResolvedTenant>::grant(
            GrantDelegationParams {
                granted: claimed,
                constraints: constraints(1),
                name: None,
            },
            &held,
            &to(&live(AgentId::new())),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    fn root() -> Delegation<ResolvedTenant> {
        let delegator_caps = caps(RoutingAction::Manage, "ianua.msg.t1.>", PubSub::Both);
        Delegation::grant(
            GrantDelegationParams {
                granted: caps(
                    RoutingAction::View,
                    "ianua.msg.t1.agents.a1",
                    PubSub::Publish,
                ),
                constraints: constraints(1),
                name: None,
            },
            &held(&delegator_caps),
            &to(&live(AgentId::new())),
        )
        .unwrap()
    }

    /// A delegation carrying every limit a person can set on it.
    fn confined_root() -> Delegation<ResolvedTenant> {
        let delegator_caps = caps(RoutingAction::Manage, "ianua.msg.t1.>", PubSub::Both);
        let constraints = DelegationConstraints::new(Seconds::new(600), 1)
            .unwrap()
            .with_budget(
                AgentBudget::new(Seconds::new(3600))
                    .unwrap()
                    .with_max_requests(100),
            )
            .with_resource_scope(ResourceScope::new(vec!["/reports/".to_owned()]).unwrap())
            .with_max_data_class(DataClassLevel::Internal)
            .under_template(TaskTemplateId::new())
            .sender_constrained()
            .requiring_approval();

        Delegation::grant(
            GrantDelegationParams {
                granted: caps(
                    RoutingAction::View,
                    "ianua.msg.t1.agents.a1",
                    PubSub::Publish,
                ),
                constraints,
                name: None,
            },
            &held(&delegator_caps),
            &to(&live(AgentId::new())),
        )
        .unwrap()
    }

    /// Minting with bare constraints retains the source's sender constraint,
    /// approval, budget, resource scope, data class and template restrictions.
    #[test]
    fn grant_owned_within_carries_every_confinement_into_the_minted_delegation() {
        let ceiling = confined_root();
        let agent = *ceiling.delegate();
        let bare = DelegationConstraints::new(Seconds::new(600), 0).unwrap();

        let minted = Delegation::<ResolvedTenant>::grant_owned_within(
            OwnedTokenRequest {
                agent: &ActingAgent::assumed(agent),
                agent_label: EventLabel::of("agent"),
                granted: ceiling.granted().clone(),
                requested: bare,
                max_ttl: TASK_TOKEN_MAX,
            },
            std::slice::from_ref(&ceiling),
        )
        .unwrap();

        let c = minted.constraints();
        assert!(c.is_sender_constrained(), "proof of possession was dropped");
        assert!(c.requires_approval(), "approval requirement was dropped");
        assert!(c.budget().is_restricted(), "budget was dropped");
        assert!(
            c.resource_scope().is_restricted(),
            "resource scope was dropped"
        );
        assert_eq!(
            c.max_data_class(),
            crate::shared::model::restriction::Restriction::To(DataClassLevel::Internal)
        );
        assert_eq!(c.template(), ceiling.constraints().template());
    }

    mod apps {
        use super::*;

        fn reaching(apps: &[ServiceId]) -> Delegation<ResolvedTenant> {
            let delegator_caps = caps(RoutingAction::Manage, "ianua.msg.t1.>", PubSub::Both);
            Delegation::grant(
                GrantDelegationParams {
                    granted: caps(
                        RoutingAction::View,
                        "ianua.msg.t1.agents.a1",
                        PubSub::Publish,
                    ),
                    constraints: constraints(2)
                        .with_apps(AppReach::new(apps.iter().copied()).unwrap()),
                    name: None,
                },
                &held(&delegator_caps),
                &to(&live(AgentId::new())),
            )
            .unwrap()
        }

        fn child_of(
            parent: &Delegation<ResolvedTenant>,
            apps: Option<&[ServiceId]>,
        ) -> Result<Delegation<ResolvedTenant>, DomainError> {
            let mut constraints = constraints(1);
            if let Some(apps) = apps {
                constraints = constraints.with_apps(AppReach::new(apps.iter().copied()).unwrap());
            }
            parent.narrowed(
                AgentId::new(),
                AttenuateParams {
                    granted: parent.granted().clone(),
                    constraints,
                    name: None,
                },
            )
        }

        /// A parent reaches one app and its child names no apps. The child
        /// reaches no app at all, not every app the parent reaches.
        #[test]
        fn a_child_naming_no_apps_reaches_none() {
            let parent = reaching(&[ServiceId::new()]);

            let child = child_of(&parent, None).unwrap();

            assert_eq!(child.constraints().apps(), &AppAccess::NoApps);
        }

        /// A parent reaches the shop and the reports app. A child naming only
        /// the shop is made and reaches only the shop.
        #[test]
        fn a_child_may_drop_apps() {
            let (shop, reports) = (ServiceId::new(), ServiceId::new());
            let parent = reaching(&[shop, reports]);

            let child = child_of(&parent, Some(&[shop])).unwrap();

            assert!(
                matches!(child.constraints().apps(), AppAccess::Listed(apps) if apps.services() == [shop])
            );
        }

        /// A child delegation cannot name an app outside its parent's app list.
        #[test]
        fn a_child_may_never_add_an_app() {
            let parent = reaching(&[ServiceId::new()]);

            assert!(child_of(&parent, Some(&[ServiceId::new()])).is_err());
        }

        /// A parent reaches no app. A child naming an app is refused, and a
        /// child naming none is made and reaches none.
        #[test]
        fn a_child_of_a_parent_reaching_no_app_reaches_none() {
            let parent = root();

            assert!(child_of(&parent, Some(&[ServiceId::new()])).is_err());
            assert!(child_of(&parent, None).unwrap().constraints().apps() == &AppAccess::NoApps);
        }

        /// An app list naming no app, or one more than `AppReach::MAX_APPS`,
        /// is refused. "No apps" is said with `AppAccess::NoApps` instead.
        #[test]
        fn an_empty_or_oversized_list_is_refused() {
            assert!(AppReach::new([]).is_err());
            let too_many = (0..=AppReach::MAX_APPS).map(|_| ServiceId::new());
            assert!(AppReach::new(too_many).is_err());
        }
    }

    /// A token requested with the maximum delegation lifetime still expires
    /// no later than the authority it was minted from.
    #[test]
    fn grant_owned_within_cannot_outlive_the_authority_it_derives_from() {
        let ceiling = confined_root();
        let agent = *ceiling.delegate();
        let forever = DelegationConstraints::new(
            Seconds::new(crate::domains::agents::authority::capability::MAX_DELEGATION_SECONDS),
            0,
        )
        .unwrap();

        let minted = Delegation::<ResolvedTenant>::grant_owned_within(
            OwnedTokenRequest {
                agent: &ActingAgent::assumed(agent),
                agent_label: EventLabel::of("agent"),
                granted: ceiling.granted().clone(),
                requested: forever,
                max_ttl: TASK_TOKEN_MAX,
            },
            std::slice::from_ref(&ceiling),
        )
        .unwrap();

        assert!(minted.expires_at() <= ceiling.expires_at());
    }

    /// An agent asks for a token that lives for years while the task token
    /// limit is 30 seconds. The token ends within those 30 seconds, so a
    /// stolen one is useful only briefly.
    #[test]
    fn grant_owned_within_never_outlives_the_task_token_ceiling() {
        let ceiling = confined_root();
        let agent = *ceiling.delegate();
        let forever = DelegationConstraints::new(
            Seconds::new(crate::domains::agents::authority::capability::MAX_DELEGATION_SECONDS),
            0,
        )
        .unwrap();
        let short = Lifetime::seconds(30).unwrap();

        let minted = Delegation::<ResolvedTenant>::grant_owned_within(
            OwnedTokenRequest {
                agent: &ActingAgent::assumed(agent),
                agent_label: EventLabel::of("agent"),
                granted: ceiling.granted().clone(),
                requested: forever,
                max_ttl: short,
            },
            std::slice::from_ref(&ceiling),
        )
        .unwrap();

        assert!(minted.expires_at() <= crate::shared::clock::now() + short.duration());
    }

    /// A token minted at the chain's depth limit retains that depth and
    /// cannot be narrowed into another child delegation.
    #[test]
    fn a_minted_delegation_keeps_the_depth_it_derives_from() {
        let root = root();
        let child = root
            .narrowed(AgentId::new(), child_of(constraints(1)))
            .unwrap();
        let agent = *child.delegate();

        let minted = Delegation::<ResolvedTenant>::grant_owned_within(
            OwnedTokenRequest {
                agent: &ActingAgent::assumed(agent),
                agent_label: EventLabel::of("agent"),
                granted: child.granted().clone(),
                requested: constraints(1),
                max_ttl: TASK_TOKEN_MAX,
            },
            std::slice::from_ref(&child),
        )
        .unwrap();
        let spawned = minted.narrowed(
            AgentId::new(),
            AttenuateParams {
                granted: child.granted().clone(),
                constraints: constraints(1),
                name: None,
            },
        );

        assert_eq!(minted.depth(), child.depth());
        assert!(matches!(spawned, Err(DomainError::Forbidden(_))));
    }

    /// Minting is forbidden when the requested routing and messaging
    /// capabilities exceed the agent's source delegation.
    #[test]
    fn grant_owned_within_refuses_capabilities_the_agent_was_not_given() {
        let ceiling = root();

        let result = Delegation::<ResolvedTenant>::grant_owned_within(
            OwnedTokenRequest {
                agent: &ActingAgent::assumed(*ceiling.delegate()),
                agent_label: EventLabel::of("agent"),
                granted: caps(RoutingAction::Manage, "ianua.msg.t1.>", PubSub::Both),
                requested: constraints(0),
                max_ttl: TASK_TOKEN_MAX,
            },
            std::slice::from_ref(&ceiling),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// An agent with no source delegations cannot mint a token delegation.
    #[test]
    fn grant_owned_within_refuses_an_agent_holding_no_authority() {
        let result = Delegation::<ResolvedTenant>::grant_owned_within(
            OwnedTokenRequest {
                agent: &ActingAgent::assumed(AgentId::new()),
                agent_label: EventLabel::of("agent"),
                granted: caps(RoutingAction::Manage, "ianua.msg.t1.>", PubSub::Both),
                requested: constraints(0),
                max_ttl: TASK_TOKEN_MAX,
            },
            &[],
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A child cannot raise its parent's chain-depth limit from one to 255.
    #[test]
    fn attenuate_rejects_a_child_reopening_the_delegation_chain() {
        let parent = root();
        let result = parent.narrowed(
            AgentId::new(),
            AttenuateParams {
                granted: caps(
                    RoutingAction::View,
                    "ianua.msg.t1.agents.a1",
                    PubSub::Publish,
                ),
                constraints: constraints(255),
                name: None,
            },
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A child omitting sender and approval constraints inherits both from
    /// its parent.
    #[test]
    fn attenuate_keeps_a_sender_constrained_parent_sender_constrained() {
        let parent = confined_root();
        let child = parent
            .narrowed(
                AgentId::new(),
                AttenuateParams {
                    granted: caps(
                        RoutingAction::View,
                        "ianua.msg.t1.agents.a1",
                        PubSub::Publish,
                    ),
                    constraints: DelegationConstraints::new(Seconds::new(300), 0).unwrap(),
                    name: None,
                },
            )
            .unwrap();

        assert!(child.constraints().is_sender_constrained());
        assert!(child.constraints().requires_approval());
    }

    /// A parent limited to internal data cannot grant a child access to
    /// restricted data.
    #[test]
    fn attenuate_refuses_a_child_reaching_more_sensitive_data() {
        let parent = confined_root();

        let result = parent.narrowed(
            AgentId::new(),
            AttenuateParams {
                granted: caps(
                    RoutingAction::View,
                    "ianua.msg.t1.agents.a1",
                    PubSub::Publish,
                ),
                constraints: DelegationConstraints::new(Seconds::new(300), 0)
                    .unwrap()
                    .with_max_data_class(DataClassLevel::Restricted),
                name: None,
            },
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A grant exceeding the delegator's routing permission and messaging
    /// scope is forbidden.
    #[test]
    fn grant_rejects_escalation() {
        let weak = caps(
            RoutingAction::View,
            "ianua.msg.t1.agents.a1",
            PubSub::Publish,
        );
        let result = Delegation::<ResolvedTenant>::grant(
            GrantDelegationParams {
                granted: caps(RoutingAction::Manage, "ianua.msg.t1.>", PubSub::Both),
                constraints: constraints(1),
                name: None,
            },
            &held(&weak),
            &to(&live(AgentId::new())),
        );
        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A person grants an agent a delegation. It starts a chain at depth
    /// zero, has no parent and is active.
    #[test]
    fn grant_produces_root_at_depth_zero() {
        let d = root();
        assert_eq!(d.depth(), 0);
        assert!(d.parent().is_none());
        assert!(!d.is_revoked());
    }

    /// A grant given no title has none. One titled "Q1 reconciliation
    /// delegation" reports that exact title.
    #[test]
    fn a_grant_with_no_name_has_none_and_one_with_a_name_round_trips() {
        assert!(root().name().is_none());

        let delegator_caps = caps(RoutingAction::Manage, "ianua.msg.t1.>", PubSub::Both);
        let named = Delegation::<ResolvedTenant>::grant(
            GrantDelegationParams {
                granted: caps(
                    RoutingAction::View,
                    "ianua.msg.t1.agents.a1",
                    PubSub::Publish,
                ),
                constraints: constraints(1),
                name: Some(Label::new("name", "Q1 reconciliation delegation").unwrap()),
            },
            &held(&delegator_caps),
            &to(&live(AgentId::new())),
        )
        .unwrap();
        assert_eq!(
            named.name().map(Label::as_str),
            Some("Q1 reconciliation delegation")
        );
    }

    /// An untitled delegation is passed on to a child titled "sub-task". The
    /// child has that title and the parent stays untitled.
    #[test]
    fn a_sub_delegation_can_carry_its_own_name_independent_of_the_parent() {
        let parent = root();
        let child = parent
            .narrowed(
                AgentId::new(),
                AttenuateParams {
                    granted: caps(
                        RoutingAction::View,
                        "ianua.msg.t1.agents.a1",
                        PubSub::Publish,
                    ),
                    constraints: constraints(1),
                    name: Some(Label::new("name", "sub-task").unwrap()),
                },
            )
            .unwrap();
        assert!(parent.name().is_none());
        assert_eq!(child.name().map(Label::as_str), Some("sub-task"));
    }

    /// An agent is given its own authority. It is both delegator and
    /// delegate, at depth zero with no parent, and active.
    #[test]
    fn grant_owned_is_self_rooted() {
        let agent = AgentId::new();
        let d = Delegation::<ResolvedTenant>::grant_owned(
            agent,
            caps(
                RoutingAction::View,
                "ianua.msg.t1.agents.a1",
                PubSub::Publish,
            ),
            constraints(1),
        );
        assert_eq!(d.depth(), 0);
        assert!(d.parent().is_none());
        assert_eq!(*d.delegate(), agent);
        assert!(matches!(d.delegator(), PrincipalRef::Agent(a) if *a == agent));
        assert!(!d.is_revoked());
        assert!(d.is_self_rooted());
    }

    /// A delegation from a person, and one passed on by another agent, are
    /// not self-rooted. The token exchange counts both as authority the
    /// agent holds.
    #[test]
    fn only_a_delegation_to_oneself_is_self_rooted() {
        assert!(!root().is_self_rooted());

        let from_another_agent = root()
            .narrowed(
                AgentId::new(),
                AttenuateParams {
                    granted: caps(
                        RoutingAction::View,
                        "ianua.msg.t1.agents.a1",
                        PubSub::Publish,
                    ),
                    constraints: constraints(1),
                    name: None,
                },
            )
            .unwrap();

        assert!(!from_another_agent.is_self_rooted());
    }

    /// A root grant names the person whose holdings authorize it as its delegator.
    #[test]
    fn a_root_names_the_person_acting_as_its_delegator() {
        let ann = Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new("ann@corp.test").unwrap(),
        );
        let anns = caps(RoutingAction::Manage, "ianua.msg.t1.>", PubSub::Both);

        let granted = Delegation::<ResolvedTenant>::grant(
            GrantDelegationParams {
                granted: caps(
                    RoutingAction::View,
                    "ianua.msg.t1.agents.a1",
                    PubSub::Publish,
                ),
                constraints: constraints(1),
                name: None,
            },
            &held_by(&ann, &anns),
            &to(&live(AgentId::new())),
        )
        .unwrap();

        assert_eq!(*granted.delegator(), ann.principal());
    }

    /// An agent passes part of its delegation on. The child sits at depth
    /// one under its parent, and the agent is its delegator.
    #[test]
    fn attenuate_shrinks_and_increments_depth() {
        let parent = root();
        let child = parent
            .narrowed(
                AgentId::new(),
                AttenuateParams {
                    granted: caps(
                        RoutingAction::View,
                        "ianua.msg.t1.agents.a1",
                        PubSub::Publish,
                    ),
                    constraints: constraints(1),
                    name: None,
                },
            )
            .unwrap();
        assert_eq!(child.depth(), 1);
        assert_eq!(child.parent(), Some(*parent.id()));
        assert!(matches!(child.delegator(), PrincipalRef::Agent(_)));
    }

    /// A child requesting broader routing and messaging capabilities than
    /// its parent is forbidden.
    #[test]
    fn attenuate_rejects_escalation() {
        let parent = root();
        let result = parent.narrowed(
            AgentId::new(),
            AttenuateParams {
                granted: caps(RoutingAction::Manage, "ianua.msg.t1.>", PubSub::Both),
                constraints: constraints(1),
                name: None,
            },
        );
        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A delegation at depth 255 cannot create a child even when its depth
    /// limit is 255, preventing depth overflow from admitting another link.
    #[test]
    fn a_chain_at_the_last_depth_there_is_cannot_grow() {
        let deepest = deepest_delegation();
        let child = deepest.narrowed(AgentId::new(), child_of(constraints(u8::MAX)));

        assert!(matches!(child, Err(DomainError::Forbidden(_))));
    }

    /// Restores a valid delegation at the largest representable chain depth.
    fn deepest_delegation() -> Delegation<ResolvedTenant> {
        let now = crate::shared::clock::now();
        Delegation::reconstitute(DelegationRow {
            id: DelegationId::new(),
            delegator: PrincipalRef::Agent(AgentId::new()),
            delegate: AgentId::new(),
            granted: caps(
                RoutingAction::View,
                "ianua.msg.t1.agents.a1",
                PubSub::Publish,
            ),
            constraints: constraints(u8::MAX),
            lineage: Lineage::Under(DelegationId::new()),
            depth: u8::MAX,
            status: DelegationStatus::Active,
            issued_at: now,
            expires_at: now + time::Duration::minutes(10),
            renewed: DelegationRenewal::NotRenewed,
            updated_at: now,
            name: None,
        })
        .unwrap()
    }

    /// Ann allows a chain one link deep. Her agent passes a child on, and the
    /// child tries to pass a grandchild on. The grandchild is refused.
    #[test]
    fn attenuate_enforces_max_depth() {
        let parent = root();
        let child = parent
            .narrowed(
                AgentId::new(),
                AttenuateParams {
                    granted: caps(
                        RoutingAction::View,
                        "ianua.msg.t1.agents.a1",
                        PubSub::Publish,
                    ),
                    constraints: constraints(1),
                    name: None,
                },
            )
            .unwrap();
        let grandchild = child.narrowed(
            AgentId::new(),
            AttenuateParams {
                granted: caps(
                    RoutingAction::View,
                    "ianua.msg.t1.agents.a1",
                    PubSub::Publish,
                ),
                constraints: constraints(1),
                name: None,
            },
        );
        assert!(matches!(grandchild, Err(DomainError::Forbidden(_))));
    }

    /// Ann's agent hands a task on one link down, asking for no further
    /// links. The child's limit stays at its own depth, so it reads back
    /// whole, and it can hand nothing further on.
    #[test]
    fn a_child_asking_for_less_depth_than_it_sits_at_stays_consistent() {
        let child = root()
            .narrowed(
                AgentId::new(),
                AttenuateParams {
                    granted: caps(
                        RoutingAction::View,
                        "ianua.msg.t1.agents.a1",
                        PubSub::Publish,
                    ),
                    constraints: constraints(0),
                    name: None,
                },
            )
            .unwrap();

        assert_eq!(child.depth, 1);
        assert_eq!(child.constraints().max_depth(), 1);
    }

    /// A revoked delegation is invalid before its expiry and cannot create
    /// a child delegation.
    #[test]
    fn revoked_delegation_is_invalid_and_cannot_attenuate() {
        let mut d = root();
        d.revoke(Revoker::Platform).unwrap();
        assert!(!d.is_valid(d.expires_at() - Duration::seconds(1)));
        let result = d.narrowed(
            AgentId::new(),
            AttenuateParams {
                granted: caps(
                    RoutingAction::View,
                    "ianua.msg.t1.agents.a1",
                    PubSub::Publish,
                ),
                constraints: constraints(1),
                name: None,
            },
        );
        assert!(matches!(result, Err(DomainError::InvalidTransition(_))));
    }

    /// A delegation is usable one second before it expires. At the expiry
    /// time itself it is not.
    #[test]
    fn expiry_bounds_validity() {
        let d = root();
        assert!(d.is_valid(d.expires_at() - Duration::seconds(1)));
        assert!(!d.is_valid(d.expires_at()));
    }

    fn enforce_intent(
        env: crate::domains::agents::authority::intent::IntentEnvelope,
    ) -> crate::domains::agents::authority::intent::IntentBinding {
        IntentBinding::new(
            IntentStatement::new("read the ledger").unwrap(),
            IntentDigest::new([1u8; 32]),
            DriftPolicy::Enforce(DriftThreshold::from_basis_points(0).unwrap()),
            env,
        )
    }

    fn intent_root(
        env: crate::domains::agents::authority::intent::IntentEnvelope,
    ) -> Delegation<ResolvedTenant> {
        root_with(constraints(2).with_intent(enforce_intent(env)))
    }

    fn root_with(constraints: DelegationConstraints) -> Delegation<ResolvedTenant> {
        let delegator_caps = caps(RoutingAction::Manage, "ianua.msg.t1.>", PubSub::Both);
        Delegation::grant(
            GrantDelegationParams {
                granted: caps(
                    RoutingAction::View,
                    "ianua.msg.t1.agents.a1",
                    PubSub::Publish,
                ),
                constraints,
                name: None,
            },
            &held(&delegator_caps),
            &to(&live(AgentId::new())),
        )
        .unwrap()
    }

    /// A child inherits the parent's task when it names none, while a child
    /// naming a different task is forbidden.
    #[test]
    fn a_child_stays_bound_to_its_parents_task() {
        let books = TaskBinding::new("close the Q1 books").unwrap();
        let parent = root_with(constraints(2).with_task(books.clone()));

        let silent = parent
            .narrowed(AgentId::new(), child_of(constraints(2)))
            .unwrap();
        let elsewhere = parent.narrowed(
            AgentId::new(),
            child_of(constraints(2).with_task(TaskBinding::new("pay the vendors").unwrap())),
        );

        assert_eq!(silent.constraints().task(), Some(&books));
        assert!(matches!(elsewhere, Err(DomainError::Forbidden(_))));
    }

    /// The agent holding `delegation`, signed in as itself.
    fn holder_of(delegation: &Delegation<ResolvedTenant>) -> ActingAgent {
        ActingAgent::assumed(*delegation.delegate())
    }

    /// An unrelated agent cannot pass on a delegation using its own proof;
    /// the agent holding the delegation can.
    #[test]
    fn attenuate_by_another_agents_proof_is_refused() {
        let parent = root();
        let agent_b = ActingAgent::assumed(AgentId::new());

        let by_another = parent.attenuate(
            &Attenuator::Agent(&agent_b),
            &to(&live(AgentId::new())),
            child_of(constraints(1)),
        );
        let by_its_agent = parent.attenuate(
            &Attenuator::Agent(&holder_of(&parent)),
            &to(&live(AgentId::new())),
            child_of(constraints(1)),
        );

        assert!(matches!(by_another, Err(DomainError::Forbidden(_))));
        assert!(by_its_agent.is_ok());
    }

    /// Someone at `address`.
    fn person(address: &str) -> Human {
        Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new(address).unwrap(),
        )
    }

    /// `by`, holding nothing, speaking for `holder` as its owner.
    fn owner_for<'a>(
        by: &'a Human,
        holder: &'a AgentIdentity<ResolvedTenant>,
    ) -> Attenuator<'a, ResolvedTenant> {
        Attenuator::Owner {
            control: AgentControl::new(assumed_authority(by, TenantId::new(), &[], &[])),
            holder,
        }
    }

    /// `by`, holding `system` and `held`, speaking for `holder` without
    /// owning it.
    fn steward_for<'a>(
        by: &'a Human,
        system: &'a [SystemPermission],
        holder: &'a AgentIdentity<ResolvedTenant>,
        held: &'a HeldBy,
    ) -> Attenuator<'a, ResolvedTenant> {
        Attenuator::Steward {
            control: AgentControl::new(assumed_authority(by, TenantId::new(), system, &[])),
            holder,
            held,
        }
    }

    /// The root fixture, given to `holder`.
    fn root_to(holder: &AgentIdentity<ResolvedTenant>) -> Delegation<ResolvedTenant> {
        Delegation::grant(
            GrantDelegationParams {
                granted: caps(
                    RoutingAction::View,
                    "ianua.msg.t1.agents.a1",
                    PubSub::Publish,
                ),
                constraints: constraints(1),
                name: None,
            },
            &held(&caps(RoutingAction::Manage, "ianua.msg.t1.>", PubSub::Both)),
            &to(holder),
        )
        .unwrap()
    }

    /// Ann owns the agent holding a delegation and passes part of it on to
    /// another agent herself. The child is made, its delegator is her agent,
    /// not Ann, and it sits under the delegation it came from.
    #[test]
    fn the_holding_agents_owner_passes_a_delegation_on_in_its_name() {
        let holder = live(AgentId::new());
        let parent = root_to(&holder);

        let child = parent
            .attenuate(
                &owner_for(holder.owner(), &holder),
                &to(&live(AgentId::new())),
                child_of(constraints(1)),
            )
            .unwrap();

        assert_eq!(*child.delegator(), PrincipalRef::Agent(*holder.id()));
        assert_eq!(child.parent(), Some(*parent.id()));
    }

    /// A nonowner without delegation rights is refused as owner and steward.
    /// A steward with the rights and holdings succeeds only for the correct holder.
    #[test]
    fn only_a_person_with_a_say_over_the_holder_passes_its_delegation_on() {
        let holder = live(AgentId::new());
        let parent = root_to(&holder);
        let elsewhere = live(AgentId::new());
        let (sam, bob) = (person("sam@corp.test"), person("bob@corp.test"));
        let delegates = [SystemPermission::Agents(AgentAction::Delegate)];
        let (sam_holds, bob_holds) = (
            held_by(&sam, parent.granted()),
            held_by(&bob, parent.granted()),
        );
        let pass = |by: &Attenuator<'_, ResolvedTenant>| {
            parent.attenuate(by, &to(&live(AgentId::new())), child_of(constraints(1)))
        };

        let sam_as_owner = pass(&owner_for(&sam, &holder));
        let sam_as_steward = pass(&steward_for(&sam, &[], &holder, &sam_holds));
        let wrong_holder = pass(&steward_for(&bob, &delegates, &elsewhere, &bob_holds));
        let by_bob = pass(&steward_for(&bob, &delegates, &holder, &bob_holds));

        assert!(matches!(sam_as_owner, Err(DomainError::Forbidden(_))));
        assert!(matches!(sam_as_steward, Err(DomainError::Forbidden(_))));
        assert!(matches!(wrong_holder, Err(DomainError::Forbidden(_))));
        assert!(by_bob.is_ok());
    }

    /// Delegation rights do not let a steward pass on capabilities they lack,
    /// while the holding agent's owner may pass on its delegation.
    #[test]
    fn a_steward_passes_on_only_what_they_hold_themselves() {
        let holder = live(AgentId::new());
        let parent = root_to(&holder);
        let mallory = person("mallory@corp.test");
        let delegates = [SystemPermission::Agents(AgentAction::Delegate)];
        let holds_nothing = held_by(&mallory, &CapabilitySet::default());
        let pass = |by: &Attenuator<'_, ResolvedTenant>| {
            parent.attenuate(by, &to(&live(AgentId::new())), child_of(constraints(1)))
        };

        let by_mallory = pass(&steward_for(&mallory, &delegates, &holder, &holds_nothing));
        let by_owner = pass(&owner_for(holder.owner(), &holder));

        assert!(matches!(by_mallory, Err(DomainError::Forbidden(_))));
        assert!(by_owner.is_ok());
    }

    /// A steward cannot authorize attenuation using holdings resolved for
    /// another person.
    #[test]
    fn a_steward_brings_their_own_holdings() {
        let holder = live(AgentId::new());
        let parent = root_to(&holder);
        let (mallory, bob) = (person("mallory@corp.test"), person("bob@corp.test"));
        let delegates = [SystemPermission::Agents(AgentAction::Delegate)];
        let bobs = held_by(&bob, parent.granted());

        let result = parent.attenuate(
            &steward_for(&mallory, &delegates, &holder, &bobs),
            &to(&live(AgentId::new())),
            child_of(constraints(1)),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// An owner can add ledger access to a child only after its parent has
    /// that access; the child continues to name the holding agent as delegator.
    #[test]
    fn a_person_widens_a_child_only_within_its_parent() {
        let holder = live(AgentId::new());
        let mut parent = root_to(&holder);
        let mut child = passed_on_by_owner(&parent, &holder);
        let owner = holder.owner().clone();

        let past_parent = child.grant_resource(
            &ledger_read(),
            &ResourceCeiling::Parent {
                parent: &parent,
                by: owner_for(&owner, &holder),
            },
        );
        let holder_principal = *parent.delegator();
        parent
            .grant_resource(
                &ledger_read(),
                &ResourceCeiling::Delegator(held_as(&holder_principal, &ceiling())),
            )
            .unwrap();
        let within = child.grant_resource(
            &ledger_read(),
            &ResourceCeiling::Parent {
                parent: &parent,
                by: owner_for(&owner, &holder),
            },
        );

        assert!(matches!(past_parent, Err(DomainError::Forbidden(_))));
        assert!(within.is_ok());
        assert_eq!(*child.delegator(), PrincipalRef::Agent(*holder.id()));
    }

    /// Has the holding agent's owner pass its authority to another active agent.
    fn passed_on_by_owner(
        parent: &Delegation<ResolvedTenant>,
        holder: &AgentIdentity<ResolvedTenant>,
    ) -> Delegation<ResolvedTenant> {
        parent
            .attenuate(
                &owner_for(holder.owner(), holder),
                &to(&live(AgentId::new())),
                child_of(constraints(1)),
            )
            .unwrap()
    }

    /// A reviewing agent cannot receive either a root grant or an attenuated
    /// child delegation.
    #[test]
    fn a_reviewing_agent_is_given_no_delegation() {
        let delegator_caps = caps(RoutingAction::Manage, "ianua.msg.t1.>", PubSub::Both);
        let granted = Delegation::<ResolvedTenant>::grant(
            GrantDelegationParams {
                granted: caps(
                    RoutingAction::View,
                    "ianua.msg.t1.agents.a1",
                    PubSub::Publish,
                ),
                constraints: constraints(1),
                name: None,
            },
            &held(&delegator_caps),
            &Delegate {
                agent: &live(AgentId::new()),
                duty: ReviewDuty::Reviewing,
            },
        );
        let parent = root();
        let passed_on = parent.attenuate(
            &Attenuator::Agent(&holder_of(&parent)),
            &Delegate {
                agent: &live(AgentId::new()),
                duty: ReviewDuty::Reviewing,
            },
            child_of(constraints(1)),
        );

        assert!(matches!(granted, Err(DomainError::Forbidden(_))));
        assert!(matches!(passed_on, Err(DomainError::Forbidden(_))));
    }

    /// A reviewing agent cannot receive a delegation with an app audience
    /// even when its capability set is empty.
    #[test]
    fn a_reviewing_agent_is_given_no_delegation_that_grants_nothing() {
        let billing = AppReach::new([ServiceId::new()]).unwrap();
        let granted = Delegation::<ResolvedTenant>::grant(
            GrantDelegationParams {
                granted: CapabilitySet::empty(),
                constraints: constraints(1).with_apps(billing),
                name: None,
            },
            &held(&CapabilitySet::empty()),
            &Delegate {
                agent: &live(AgentId::new()),
                duty: ReviewDuty::Reviewing,
            },
        );

        assert!(matches!(granted, Err(DomainError::Forbidden(_))));
    }

    /// Suspended and revoked agents are each refused both root grants and
    /// child delegations.
    #[test]
    fn an_agent_that_may_not_act_is_given_no_delegation() {
        let parent = root();
        for status in [AgentStatus::Suspended, AgentStatus::Revoked] {
            let contained = agent_in(AgentId::new(), status);

            let granted = Delegation::<ResolvedTenant>::grant(
                GrantDelegationParams {
                    granted: parent.granted().clone(),
                    constraints: constraints(1),
                    name: None,
                },
                &held(&caps(RoutingAction::Manage, "ianua.msg.t1.>", PubSub::Both)),
                &to(&contained),
            );
            let passed_on = parent.attenuate(
                &Attenuator::Agent(&holder_of(&parent)),
                &to(&contained),
                child_of(constraints(1)),
            );

            assert!(
                matches!(granted, Err(DomainError::Forbidden(_))),
                "{status:?}"
            );
            assert!(
                matches!(passed_on, Err(DomainError::Forbidden(_))),
                "{status:?}"
            );
        }
    }

    /// The holding agent cannot attenuate its delegation to itself.
    #[test]
    fn an_agent_cannot_pass_a_delegation_on_to_itself() {
        let parent = root();

        let result = parent.attenuate(
            &Attenuator::Agent(&holder_of(&parent)),
            &to(&live(*parent.delegate())),
            child_of(constraints(1)),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A minted delegation is live while its source is live. Revoking or
    /// omitting that source makes the lineage check fail even though the
    /// minted delegation remains individually valid.
    #[test]
    fn revoking_what_a_token_was_minted_from_ends_the_token() {
        let mut source = root();
        let minted = mint_from(
            *source.delegate(),
            source.granted(),
            std::slice::from_ref(&source),
        )
        .unwrap();
        let now = crate::shared::clock::now();
        assert!(minted.live_under(std::slice::from_ref(&source), now));

        source.revoke(Revoker::Platform).unwrap();

        assert!(minted.is_valid(now));
        assert!(!minted.live_under(std::slice::from_ref(&source), now));
        assert!(!minted.live_under(&[], now), "its source must be named");
    }

    /// A token is minted from Ann's delegation by her agent signed in with
    /// its key k3. It records that delegation, Ann as who granted it and k3,
    /// and the people behind it name Ann alone.
    #[test]
    fn a_minted_delegation_names_what_it_was_cut_from_and_its_people() {
        let source = root();
        let k3 = AgentCredentialId::new();
        let minted = mint_signed_in(
            &ActingAgent::assumed_with(*source.delegate(), k3),
            source.granted(),
            constraints(1),
            std::slice::from_ref(&source),
        )
        .unwrap();

        assert_eq!(
            minted.lineage(),
            &Lineage::Minted {
                from: vec![*source.id()],
                delegator: *source.delegator(),
                signed_in_with: k3,
            }
        );
        assert_eq!(
            people_behind(&minted, std::slice::from_ref(&source)),
            [*source.delegator()]
        );
    }

    /// A sender-constrained minted delegation binds to the credential that
    /// signed the agent in.
    #[test]
    fn a_bound_token_minted_by_an_agent_binds_the_key_that_signed_it_in() {
        let source = root();
        let k3 = AgentCredentialId::new();
        let minted = mint_signed_in(
            &ActingAgent::assumed_with(*source.delegate(), k3),
            source.granted(),
            constraints(1).sender_constrained(),
            std::slice::from_ref(&source),
        )
        .unwrap();

        assert_eq!(minted.token_key(), TokenKey::SignedInWith(k3));
    }

    /// A delegation asking for no proof of possession gives a bearer token;
    /// a bound one a person granted binds the agent's one active key, as no
    /// key of the agent's signed anything for it.
    #[test]
    fn a_token_is_bound_only_when_its_delegation_asks_for_it() {
        let source = root();
        let minted = mint_from(
            *source.delegate(),
            source.granted(),
            std::slice::from_ref(&source),
        )
        .unwrap();
        let mut row = stored(&source);
        row.constraints = row.constraints.clone().sender_constrained();
        let bound_root = Delegation::<ResolvedTenant>::reconstitute(row).unwrap();

        assert_eq!(source.token_key(), TokenKey::Bearer);
        assert_eq!(minted.token_key(), TokenKey::Bearer);
        assert_eq!(bound_root.token_key(), TokenKey::AgentsActiveKey);
    }

    /// A child passed on by Ann's agent names Ann as the person behind it,
    /// following its parent, never the agent that passed it on.
    #[test]
    fn the_people_behind_a_child_are_its_roots_delegators() {
        let parent = root();
        let child = parent
            .narrowed(AgentId::new(), child_of(constraints(1)))
            .unwrap();

        assert_eq!(
            people_behind(&child, std::slice::from_ref(&parent)),
            [*parent.delegator()]
        );
    }

    /// A valid minted delegation reconstitutes, while empty, self-referential
    /// or duplicate sources and a self-granting delegator are corrupt rows.
    #[test]
    fn a_stored_minted_delegation_names_real_sources() {
        let source = root();
        let minted = mint_from(
            *source.delegate(),
            source.granted(),
            std::slice::from_ref(&source),
        )
        .unwrap();
        assert!(Delegation::<ResolvedTenant>::reconstitute(stored(&minted)).is_ok());
        for lineage in invalid_minted_lineages(&source, &minted) {
            let mut row = stored(&minted);
            row.lineage = lineage.clone();
            assert!(
                refused_as_corrupt(&Delegation::<ResolvedTenant>::reconstitute(row)),
                "{lineage:?}"
            );
        }
    }

    /// Supplies missing, circular, duplicate and self-granting token sources.
    fn invalid_minted_lineages(
        source: &Delegation<ResolvedTenant>,
        minted: &Delegation<ResolvedTenant>,
    ) -> [Lineage; 4] {
        let key = AgentCredentialId::new();
        [
            (Vec::new(), *source.delegator()),
            (vec![*minted.id()], *source.delegator()),
            (vec![*source.id(), *source.id()], *source.delegator()),
            (vec![*source.id()], PrincipalRef::Agent(*minted.delegate())),
        ]
        .map(|(from, delegator)| Lineage::Minted {
            from,
            delegator,
            signed_in_with: key,
        })
    }

    /// Widening another person's root requires agent-management authority;
    /// delegation rights alone fail even when both people hold the resource.
    /// With management authority, the ledger grant is added.
    #[test]
    fn only_an_agent_administrator_widens_a_root_someone_else_granted() {
        let ann = person("ann@corp.test");
        let bob = person("bob@corp.test");
        let mut d = empty_grant(&ann);
        let anns_now = current_ledger_rights(&ann, vec![ledger_read()]);

        let by_delegate_right = d.grant_resource(
            &ledger_read(),
            &ResourceCeiling::Administrator {
                admin: ledger_holding(&bob, &[SystemPermission::Agents(AgentAction::Delegate)]),
                delegator: anns_now.clone(),
            },
        );
        assert!(matches!(by_delegate_right, Err(DomainError::Forbidden(_))));

        let by_admin = d.grant_resource(
            &ledger_read(),
            &ResourceCeiling::Administrator {
                admin: ledger_holding(&bob, &[SystemPermission::ManageAgents]),
                delegator: anns_now,
            },
        );
        assert!(by_admin.is_ok());
        assert_eq!(d.granted().resources(), &[ledger_read()]);
    }

    /// An administrator cannot add a resource the root's delegator does
    /// not currently hold, leaving the delegation's resources empty.
    #[test]
    fn an_administrator_widens_a_root_only_within_its_delegator_now() {
        let ann = person("ann@corp.test");
        let admin = person("admin@corp.test");
        let mut d = empty_grant(&ann);
        let admins = ledger_holding(&admin, &[SystemPermission::ManageAgents]);
        let anns_now = current_ledger_rights(&ann, Vec::new());

        let result = d.grant_resource(
            &ledger_read(),
            &ResourceCeiling::Administrator {
                admin: admins,
                delegator: anns_now,
            },
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(d.granted().resources().is_empty());
    }

    /// Grants an active agent no capabilities on behalf of this person.
    fn empty_grant(by: &Human) -> Delegation<ResolvedTenant> {
        Delegation::grant(
            GrantDelegationParams {
                granted: CapabilitySet::empty(),
                constraints: constraints(1),
                name: None,
            },
            &held_by(by, &CapabilitySet::empty()),
            &to(&live(AgentId::new())),
        )
        .unwrap()
    }

    /// Resolves ledger-read authority alongside the caller's supplied system rights.
    fn ledger_holding(by: &Human, rights: &[SystemPermission]) -> HeldBy {
        let control = AgentControl::new(assumed_authority(by, TenantId::new(), rights, &[]));
        let ledger = CapabilitySet::empty().with_resources(vec![ledger_read()]);
        HeldBy::worked_out::<ResolvedTenant>(
            &control,
            &ledger,
            &HeldResources::answered(by.principal(), vec![ledger_read()]),
            &[],
        )
        .unwrap()
    }

    /// Resolves current ledger authority from an active account and resource answer.
    fn current_ledger_rights(by: &Human, resources: Vec<ResourceCapability>) -> HeldNow {
        let records = crate::domains::consumers::fixtures::ConsumerRecords::empty();
        let account = held_now::tests::account_of(by);
        let ledger = CapabilitySet::empty().with_resources(vec![ledger_read()]);
        HeldNow::worked_out::<ResolvedTenant>(
            &records.access(),
            &AccountNow::User(&account),
            &ledger,
            &HeldResources::answered(by.principal(), resources),
            &[],
        )
        .unwrap()
    }

    /// Revoking a parent makes its child's lineage check fail even though
    /// the child remains individually valid.
    #[test]
    fn revoking_a_parent_ends_its_children() {
        let mut parent = root();
        let child = parent
            .narrowed(AgentId::new(), child_of(constraints(1)))
            .unwrap();
        let now = crate::shared::clock::now();
        assert!(child.live_under(std::slice::from_ref(&parent), now));

        parent.revoke(Revoker::Platform).unwrap();

        assert!(child.is_valid(now));
        assert!(!child.live_under(std::slice::from_ref(&parent), now));
    }

    /// A child whose parent is missing from the chain it is asked with is
    /// not live, since nobody can say its parent still stands. A root asked
    /// with no chain is live.
    #[test]
    fn a_child_with_no_known_parent_is_not_live() {
        let parent = root();
        let child = parent
            .narrowed(AgentId::new(), child_of(constraints(1)))
            .unwrap();
        let now = crate::shared::clock::now();

        assert!(!child.live_under(&[], now));
        assert!(parent.live_under(&[], now));
    }

    /// Removing ledger access from a parent makes a child still granting
    /// that access fail its lineage check.
    #[test]
    fn a_child_granting_more_than_its_parent_now_does_is_not_live() {
        let mut parent = root();
        let holder = *parent.delegator();
        parent
            .grant_resource(
                &ledger_read(),
                &ResourceCeiling::Delegator(held_as(&holder, &ceiling())),
            )
            .unwrap();
        let mut child = parent
            .narrowed(AgentId::new(), child_of(constraints(1)))
            .unwrap();
        let anns_agent = holder_of(&parent);
        child
            .grant_resource(
                &ledger_read(),
                &ResourceCeiling::Parent {
                    parent: &parent,
                    by: Attenuator::Agent(&anns_agent),
                },
            )
            .unwrap();

        parent
            .revoke_resource(
                Revoker::Platform,
                ledger_read().relation(),
                ledger_read().resource_ref(),
            )
            .unwrap();

        assert!(!child.live_under(&[parent], crate::shared::clock::now()));
    }

    /// With 60 of a parent's 100 hourly requests allocated, a child budget
    /// of 40 fits; 50 or an omitted budget does not.
    #[test]
    fn children_share_their_parents_budget() {
        let hourly = |requests| {
            AgentBudget::new(Seconds::new(3600))
                .unwrap()
                .with_max_requests(requests)
        };
        let parent = root_with(constraints(2).with_budget(hourly(100)));
        let first = parent
            .narrowed(
                AgentId::new(),
                child_of(constraints(2).with_budget(hourly(60))),
            )
            .unwrap();
        let siblings = [first];
        let now = crate::shared::clock::now();

        assert!(!parent.budget_fits_beside(&Restriction::To(hourly(50)), &siblings, now));
        assert!(!parent.budget_fits_beside(&Restriction::Unrestricted, &siblings, now));
        assert!(parent.budget_fits_beside(&Restriction::To(hourly(40)), &siblings, now));
    }

    /// A parent's child of 60 requests is revoked. It takes nothing from the
    /// budget any more, so a new child may ask for the whole 100.
    #[test]
    fn a_revoked_child_frees_its_share_of_the_budget() {
        let hourly = |requests| {
            AgentBudget::new(Seconds::new(3600))
                .unwrap()
                .with_max_requests(requests)
        };
        let parent = root_with(constraints(2).with_budget(hourly(100)));
        let mut first = parent
            .narrowed(
                AgentId::new(),
                child_of(constraints(2).with_budget(hourly(60))),
            )
            .unwrap();
        first.revoke(Revoker::Platform).unwrap();

        assert!(parent.budget_fits_beside(
            &Restriction::To(hourly(100)),
            &[first],
            crate::shared::clock::now()
        ));
    }

    /// The agent with `id`, in `status`, owned by Ann.
    fn agent_in(id: AgentId, status: AgentStatus) -> AgentIdentity<ResolvedTenant> {
        let now = crate::shared::clock::now();
        AgentIdentity::reconstitute(AgentIdentityRow {
            id,
            name: Label::new("name", "ledger-bot").unwrap(),
            description: None,
            owner: Human::new(
                HumanAccount::User(UserId::new()),
                PersonKey::new("ann@corp.test").unwrap(),
            ),
            offer: OwnershipOffer::Unoffered,
            status,
            proof: AgentProof::EnrolledKey,
            containment: Containment::Free,
            last_attested_at: None,
            created_at: now,
            updated_at: now,
        })
        .unwrap()
    }

    /// The active agent with `id`.
    fn live(id: AgentId) -> AgentIdentity<ResolvedTenant> {
        agent_in(id, AgentStatus::Active)
    }

    /// An unrelated person cannot revoke a delegation, which remains valid
    /// after refusal; the agent's owner can revoke it.
    #[test]
    fn only_the_delegator_or_someone_with_a_say_revokes() {
        let mut d = root();
        let owner = Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new("owner@corp.test").unwrap(),
        );
        let sam = Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new("sam@corp.test").unwrap(),
        );
        let by = |person| Revoker::Person {
            control: AgentControl::new(assumed_authority(person, TenantId::new(), &[], &[])),
            agent_owner: &owner,
        };

        let by_sam = d.revoke(by(&sam));

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert!(d.is_valid(crate::shared::clock::now()));
        assert!(d.revoke(by(&owner)).is_ok());
    }

    /// A root cannot be widened against holdings belonging to someone
    /// other than its delegator.
    #[test]
    fn a_root_is_widened_only_against_its_own_delegators_rights() {
        let mut d = root();
        let anns = ceiling();

        let result = d.grant_resource(&ledger_read(), &ResourceCeiling::Delegator(held(&anns)));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// `agent` as a delegate that reviews nobody.
    fn to(agent: &AgentIdentity<ResolvedTenant>) -> Delegate<'_, ResolvedTenant> {
        Delegate {
            agent,
            duty: ReviewDuty::NotReviewing,
        }
    }

    fn child_of(constraints: DelegationConstraints) -> AttenuateParams {
        AttenuateParams {
            granted: caps(
                RoutingAction::View,
                "ianua.msg.t1.agents.a1",
                PubSub::Publish,
            ),
            constraints,
            name: None,
        }
    }

    /// A parent may only read. A child that names no purpose gets the
    /// parent's, so it may read and may not delete.
    #[test]
    fn child_inherits_parent_intent_when_it_declares_none() {
        let parent = intent_root(IntentEnvelope::new([ActionClass::Read]));
        let child = parent
            .narrowed(AgentId::new(), child_of(constraints(2)))
            .unwrap();
        let env = child.constraints().intent().limit().unwrap().envelope();
        assert!(env.permits(ActionClass::Read));
        assert!(!env.permits(ActionClass::Delete));
    }

    /// A parent may read and write. A child whose purpose only reads is
    /// made.
    #[test]
    fn child_may_narrow_within_parent_intent() {
        let parent = intent_root(IntentEnvelope::new([ActionClass::Read, ActionClass::Write]));
        let narrowed =
            constraints(2).with_intent(enforce_intent(IntentEnvelope::new([ActionClass::Read])));
        assert!(parent.narrowed(AgentId::new(), child_of(narrowed)).is_ok());
    }

    /// A child cannot add deletion to its parent's read-only intent envelope.
    #[test]
    fn child_intent_exceeding_parent_is_forbidden() {
        let parent = intent_root(IntentEnvelope::new([ActionClass::Read]));
        let wider = constraints(2).with_intent(enforce_intent(IntentEnvelope::new([
            ActionClass::Read,
            ActionClass::Delete,
        ])));
        let result = parent.narrowed(AgentId::new(), child_of(wider));
        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    fn ledger_read() -> ResourceCapability {
        ResourceCapability::new(
            Relation::new("reader").unwrap(),
            ResourceRef::new("ledger:2026-q1").unwrap(),
        )
    }

    /// The root fixture's delegator, holding both ledger tuples.
    fn ceiling() -> CapabilitySet {
        caps(RoutingAction::Manage, "ianua.msg.t1.>", PubSub::Both).with_resources(vec![
            ledger_read(),
            ResourceCapability::new(
                Relation::new("writer").unwrap(),
                ResourceRef::new("ledger:2026-q1").unwrap(),
            ),
        ])
    }

    /// A child cannot gain ledger access absent from its parent and retains
    /// an empty resource set after refusal.
    #[test]
    fn a_sub_delegation_is_not_widened_past_its_parent() {
        let parent = root();
        let mut child = parent
            .narrowed(AgentId::new(), child_of(constraints(1)))
            .unwrap();

        let anns_agent = holder_of(&parent);

        let result = child.grant_resource(
            &ledger_read(),
            &ResourceCeiling::Parent {
                parent: &parent,
                by: Attenuator::Agent(&anns_agent),
            },
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(child.granted().resources().is_empty());
    }

    /// An unrelated agent cannot widen a child using its parent's resources,
    /// leaving the resource set empty; the agent holding the parent can widen it.
    #[test]
    fn a_forged_parent_widening_is_refused() {
        let mut parent = root();
        let holder = *parent.delegator();
        parent
            .grant_resource(
                &ledger_read(),
                &ResourceCeiling::Delegator(held_as(&holder, &ceiling())),
            )
            .unwrap();
        let mut child = parent
            .narrowed(AgentId::new(), child_of(constraints(1)))
            .unwrap();
        let mallorys_agent = ActingAgent::assumed(AgentId::new());
        let anns_agent = holder_of(&parent);

        let forged = child.grant_resource(
            &ledger_read(),
            &ResourceCeiling::Parent {
                parent: &parent,
                by: Attenuator::Agent(&mallorys_agent),
            },
        );
        assert!(matches!(forged, Err(DomainError::Forbidden(_))));
        assert!(child.granted().resources().is_empty());

        let by_its_holder = child.grant_resource(
            &ledger_read(),
            &ResourceCeiling::Parent {
                parent: &parent,
                by: Attenuator::Agent(&anns_agent),
            },
        );
        assert!(by_its_holder.is_ok());
    }

    /// A root cannot gain ledger access that its delegator does not hold.
    #[test]
    fn a_root_is_not_widened_past_its_delegator() {
        let mut d = root();
        let sams = caps(RoutingAction::Manage, "ianua.msg.t1.>", PubSub::Both);

        let result = d.grant_resource(
            &ledger_read(),
            &ResourceCeiling::Delegator(held_as(d.delegator(), &sams)),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A child cannot use a person's holdings as its resource ceiling in
    /// place of its parent delegation.
    #[test]
    fn a_ceiling_from_elsewhere_in_the_chain_is_refused() {
        let parent = root();
        let mut child = parent
            .narrowed(AgentId::new(), child_of(constraints(1)))
            .unwrap();

        let result = child.grant_resource(
            &ledger_read(),
            &ResourceCeiling::Delegator(held(&ceiling())),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Read access to the Q1 ledger is added to a delegation twice. It
    /// grants that access once, not twice.
    #[test]
    fn grant_resource_adds_a_tuple_and_is_idempotent() {
        let mut d = root();
        assert!(d.granted().resources().is_empty());

        d.grant_resource(
            &ledger_read(),
            &ResourceCeiling::Delegator(held_as(d.delegator(), &ceiling())),
        )
        .unwrap();
        assert_eq!(d.granted().resources(), &[ledger_read()]);

        d.grant_resource(
            &ledger_read(),
            &ResourceCeiling::Delegator(held_as(d.delegator(), &ceiling())),
        )
        .unwrap();
        assert_eq!(d.granted().resources(), &[ledger_read()]);
    }

    /// Read access to the Q1 ledger is added to a delegation. Its route
    /// access stays the same, and its change time moves forward.
    #[test]
    fn grant_resource_leaves_the_rest_of_the_delegation_untouched() {
        let mut d = root();
        let before_http = d.granted().http().to_vec();
        let before_updated = d.updated_at();

        d.grant_resource(
            &ledger_read(),
            &ResourceCeiling::Delegator(held_as(d.delegator(), &ceiling())),
        )
        .unwrap();

        assert_eq!(d.granted().http(), before_http.as_slice());
        assert!(d.updated_at() >= before_updated);
    }

    /// Adding ledger access to a revoked delegation fails as an invalid transition.
    #[test]
    fn grant_resource_on_a_revoked_delegation_is_rejected() {
        let mut d = root();
        d.revoke(Revoker::Platform).unwrap();
        assert!(matches!(
            d.grant_resource(
                &ledger_read(),
                &ResourceCeiling::Delegator(held_as(d.delegator(), &ceiling())),
            ),
            Err(DomainError::InvalidTransition(_))
        ));
    }

    /// A delegation grants read and write on the Q1 ledger. Removing read
    /// leaves write in place.
    #[test]
    fn revoke_resource_removes_only_the_matching_tuple() {
        let mut d = root();
        let other = ResourceCapability::new(
            Relation::new("writer").unwrap(),
            ResourceRef::new("ledger:2026-q1").unwrap(),
        );
        d.grant_resource(
            &ledger_read(),
            &ResourceCeiling::Delegator(held_as(d.delegator(), &ceiling())),
        )
        .unwrap();
        d.grant_resource(
            &other,
            &ResourceCeiling::Delegator(held_as(d.delegator(), &ceiling())),
        )
        .unwrap();

        d.revoke_resource(
            Revoker::Platform,
            ledger_read().relation(),
            ledger_read().resource_ref(),
        )
        .unwrap();

        assert_eq!(d.granted().resources(), &[other]);
    }

    /// A delegation grants read on the Q1 ledger. Removing owner on a
    /// calendar it never granted succeeds and leaves the ledger read.
    #[test]
    fn revoke_resource_not_present_is_a_no_op() {
        let mut d = root();
        d.grant_resource(
            &ledger_read(),
            &ResourceCeiling::Delegator(held_as(d.delegator(), &ceiling())),
        )
        .unwrap();

        let unrelated = ResourceCapability::new(
            Relation::new("owner").unwrap(),
            ResourceRef::new("calendar:abc").unwrap(),
        );
        d.revoke_resource(
            Revoker::Platform,
            unrelated.relation(),
            unrelated.resource_ref(),
        )
        .unwrap();

        assert_eq!(d.granted().resources(), &[ledger_read()]);
    }

    /// A delegation is revoked. Removing a resource from it is refused,
    /// because a revoked delegation is not changed.
    #[test]
    fn revoke_resource_on_a_revoked_delegation_is_rejected() {
        let mut d = root();
        d.revoke(Revoker::Platform).unwrap();
        assert!(matches!(
            d.revoke_resource(
                Revoker::Platform,
                ledger_read().relation(),
                ledger_read().resource_ref()
            ),
            Err(DomainError::InvalidTransition(_))
        ));
    }

    /// A delegation someone granted to `agent`, holding `granted`.
    fn granted_to(agent: AgentId, granted: &CapabilitySet) -> Delegation<ResolvedTenant> {
        Delegation::grant(
            GrantDelegationParams {
                granted: granted.clone(),
                constraints: constraints(1),
                name: None,
            },
            &held(&caps(RoutingAction::Manage, "ianua.msg.t1.>", PubSub::Both)),
            &to(&live(agent)),
        )
        .unwrap()
    }

    fn mint_from(
        agent: AgentId,
        granted: &CapabilitySet,
        ceiling: &[Delegation<ResolvedTenant>],
    ) -> Result<Delegation<ResolvedTenant>, DomainError> {
        mint_signed_in(
            &ActingAgent::assumed(agent),
            granted,
            constraints(1),
            ceiling,
        )
    }

    /// The token `acting` mints from `ceiling`, asking for `granted` under
    /// `requested`.
    fn mint_signed_in(
        acting: &ActingAgent,
        granted: &CapabilitySet,
        requested: DelegationConstraints,
        ceiling: &[Delegation<ResolvedTenant>],
    ) -> Result<Delegation<ResolvedTenant>, DomainError> {
        Delegation::grant_owned_within(
            OwnedTokenRequest {
                agent: acting,
                agent_label: EventLabel::of("agent"),
                granted: granted.clone(),
                requested,
                max_ttl: TASK_TOKEN_MAX,
            },
            ceiling,
        )
    }

    /// A revoked source delegation cannot authorize minting a token delegation.
    #[test]
    fn a_token_is_not_minted_from_a_revoked_delegation() {
        let agent = AgentId::new();
        let granted = caps(
            RoutingAction::View,
            "ianua.msg.t1.agents.a1",
            PubSub::Publish,
        );
        let mut revoked = granted_to(agent, &granted);
        revoked.revoke(Revoker::Platform).unwrap();

        assert!(matches!(
            mint_from(agent, &granted, &[revoked]),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// An agent cannot mint a token from a delegation granted to another agent.
    #[test]
    fn a_token_is_not_minted_from_another_agents_delegation() {
        let agent = AgentId::new();
        let granted = caps(
            RoutingAction::View,
            "ianua.msg.t1.agents.a1",
            PubSub::Publish,
        );
        let theirs = granted_to(AgentId::new(), &granted);

        assert!(matches!(
            mint_from(agent, &granted, &[theirs]),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// A self-rooted delegation cannot supply authority for another token exchange.
    #[test]
    fn a_token_is_not_minted_from_a_self_rooted_delegation() {
        let agent = AgentId::new();
        let granted = caps(
            RoutingAction::View,
            "ianua.msg.t1.agents.a1",
            PubSub::Publish,
        );
        let own = Delegation::<ResolvedTenant>::grant_owned(agent, granted.clone(), constraints(1));

        assert!(matches!(
            mint_from(agent, &granted, &[own]),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// A delegation is granted by a person, made by an agent for itself,
    /// minted for a token, and passed on. Each one expires its ten minute
    /// lifetime after it was issued, never before.
    #[test]
    fn every_way_of_granting_expires_a_ttl_after_it_was_issued() {
        let ttl = time::Duration::seconds(600);
        let agent = AgentId::new();
        let granted = caps(
            RoutingAction::View,
            "ianua.msg.t1.agents.a1",
            PubSub::Publish,
        );

        let by_someone = granted_to(agent, &granted);
        let own: Delegation<ResolvedTenant> =
            Delegation::grant_owned(agent, granted.clone(), constraints(1));
        let within = mint_from(agent, &granted, std::slice::from_ref(&by_someone)).unwrap();
        let child = by_someone
            .narrowed(AgentId::new(), child_of(constraints(1)))
            .unwrap();

        for delegation in [&by_someone, &own, &within, &child] {
            let lifetime = delegation.expires_at() - delegation.created_at();
            assert!(
                (lifetime - ttl).abs() < time::Duration::seconds(2),
                "granted for {lifetime} rather than {ttl}"
            );
            assert!(delegation.expires_at() > delegation.created_at());
        }
    }

    /// Revoking a valid delegation makes it report revoked and invalid.
    #[test]
    fn a_revoked_delegation_says_so() {
        let mut d = root();

        assert!(!d.is_revoked());
        assert!(d.is_valid(crate::shared::clock::now()));

        d.revoke(Revoker::Platform).unwrap();

        assert!(d.is_revoked());
        assert!(!d.is_valid(crate::shared::clock::now()));
        assert_eq!(Aggregate::id(&d), d.id());
    }

    /// Children inherit sender constraints and approval requirements when
    /// either is set alone or both are set on the parent.
    #[test]
    fn a_child_inherits_each_of_its_parents_confinements_on_its_own() {
        let parents = [
            ("sender constraint", constraints(1).sender_constrained()),
            ("approval gate", constraints(1).requiring_approval()),
            (
                "both",
                constraints(1).sender_constrained().requiring_approval(),
            ),
        ];

        for (what, parent_constraints) in parents {
            let parent = root_with(parent_constraints.clone());
            let child = parent
                .narrowed(AgentId::new(), child_of(constraints(1)))
                .unwrap();

            assert_eq!(
                child.constraints().is_sender_constrained(),
                parent_constraints.is_sender_constrained(),
                "{what}: the sender constraint was not carried down"
            );
            assert_eq!(
                child.constraints().requires_approval(),
                parent_constraints.requires_approval(),
                "{what}: the approval gate was not carried down"
            );
        }
    }

    /// A child inherits the parent's 100-request budget when none is named,
    /// may narrow it to ten, and cannot raise it to 101.
    #[test]
    fn a_child_that_declares_no_budget_inherits_its_parents() {
        let parent = root_with(request_budget(100));
        assert_inherited_budget(&parent);
        let narrower = parent
            .narrowed(AgentId::new(), child_of(request_budget(10)))
            .unwrap();
        assert_eq!(
            narrower
                .constraints()
                .budget()
                .limit()
                .map(AgentBudget::max_requests),
            Some(crate::shared::model::restriction::Restriction::To(10))
        );

        let wider = parent.narrowed(AgentId::new(), child_of(request_budget(101)));
        assert!(
            matches!(wider, Err(DomainError::Forbidden(_))),
            "a child may not spend more than its parent"
        );
    }

    /// Limits a ten-minute delegation to the requested number of calls.
    fn request_budget(requests: u32) -> DelegationConstraints {
        constraints(1).with_budget(
            AgentBudget::new(Seconds::new(600))
                .unwrap()
                .with_max_requests(requests),
        )
    }

    /// Proves that omitting a child budget retains the parent's 100 requests.
    fn assert_inherited_budget(parent: &Delegation<ResolvedTenant>) {
        let silent = parent
            .narrowed(AgentId::new(), child_of(constraints(1)))
            .unwrap();
        assert_eq!(
            silent
                .constraints()
                .budget()
                .limit()
                .map(AgentBudget::max_requests),
            Some(crate::shared::model::restriction::Restriction::To(100)),
            "a child that names no budget is held to its parent's"
        );
    }

    /// An admin revokes a delegation twice. The second revoke keeps the
    /// first one's time, so the record shows when access really ended.
    #[test]
    fn revoking_twice_keeps_the_first_revocation() {
        let mut d = root();
        d.revoke(Revoker::Platform).unwrap();
        let first = d.updated_at();

        d.revoke(Revoker::Platform).unwrap();

        assert!(d.is_revoked());
        assert_eq!(d.updated_at(), first);
    }

    /// Revoked delegation status cannot transition back to active.
    #[test]
    fn a_revoked_delegation_cannot_become_active_again() {
        assert!(
            DelegationStatus::Revoked
                .try_transition(DelegationStatus::Active)
                .is_err()
        );
    }

    fn stored(delegation: &Delegation<ResolvedTenant>) -> DelegationRow {
        DelegationRow {
            id: delegation.id,
            delegator: delegation.delegator,
            delegate: delegation.delegate,
            granted: delegation.granted.clone(),
            constraints: delegation.constraints.clone(),
            lineage: delegation.lineage.clone(),
            depth: delegation.depth,
            status: delegation.status,
            issued_at: delegation.issued_at,
            expires_at: delegation.expires_at,
            renewed: delegation.renewed,
            updated_at: delegation.updated_at,
            name: delegation.name.clone(),
        }
    }

    /// A root and a sub-delegation are stored as they are. Both read back
    /// without being refused.
    #[test]
    fn a_stored_delegation_reads_back() {
        let child = root()
            .narrowed(AgentId::new(), child_of(constraints(1)))
            .unwrap();

        assert!(Delegation::<ResolvedTenant>::reconstitute(stored(&root())).is_ok());
        assert!(Delegation::<ResolvedTenant>::reconstitute(stored(&child)).is_ok());
    }

    /// A stored child delegation at depth zero is rejected as corrupt.
    #[test]
    fn a_stored_sub_delegation_at_depth_zero_is_refused() {
        let mut row = stored(
            &root()
                .narrowed(AgentId::new(), child_of(constraints(1)))
                .unwrap(),
        );
        row.depth = 0;

        assert!(refused_as_corrupt(
            &Delegation::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored delegation names itself as its own parent. No real chain
    /// looks like that, so it is refused as corrupt.
    #[test]
    fn a_stored_delegation_under_itself_is_refused() {
        let mut row = stored(&root());
        row.lineage = Lineage::Under(row.id);
        row.depth = 1;

        assert!(refused_as_corrupt(
            &Delegation::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored root that a person granted to an agent says it sits at
    /// depth two. A root sits at the top of its chain, so it is refused as
    /// corrupt.
    #[test]
    fn a_stored_root_granted_by_another_below_depth_zero_is_refused() {
        let mut row = stored(&root());
        row.depth = 2;

        assert!(refused_as_corrupt(
            &Delegation::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored root granted by one agent to another is rejected as corrupt.
    #[test]
    fn a_stored_root_an_agent_granted_to_another_is_refused() {
        let mut row = stored(&root());
        row.delegator = PrincipalRef::Agent(AgentId::new());

        assert!(refused_as_corrupt(
            &Delegation::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored delegation expires at the moment it was issued. That
    /// delegation never worked, so it is refused as corrupt.
    #[test]
    fn a_stored_delegation_that_expires_before_it_was_issued_is_refused() {
        let mut row = stored(&root());
        row.expires_at = row.issued_at;

        assert!(refused_as_corrupt(
            &Delegation::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// An expired delegation cannot be narrowed into a child delegation.
    #[test]
    fn an_expired_delegation_cannot_be_attenuated() {
        let mut row = stored(&root());
        row.issued_at -= Duration::hours(2);
        row.updated_at = row.issued_at;
        row.expires_at = row.issued_at + Duration::minutes(1);
        let expired = Delegation::<ResolvedTenant>::reconstitute(row).unwrap();

        assert!(matches!(
            expired.narrowed(AgentId::new(), child_of(constraints(3))),
            Err(DomainError::InvalidTransition(_))
        ));
    }

    /// A child requesting the maximum lifetime expires no later than its
    /// ten-minute parent.
    #[test]
    fn a_child_never_outlives_its_parent() {
        let parent = root();
        let thirty_days = DelegationConstraints::new(
            Seconds::new(crate::domains::agents::authority::capability::MAX_DELEGATION_SECONDS),
            1,
        )
        .unwrap();

        let child = parent
            .narrowed(AgentId::new(), child_of(thirty_days))
            .unwrap();

        assert!(child.expires_at() <= parent.expires_at());
    }

    /// A parent limited to `github_*` tools admits a child using
    /// `github_create_issue` and rejects one requesting every tool.
    #[test]
    fn a_child_calls_no_tool_its_parent_does_not() {
        let mcp = |pattern: &str| {
            let tool = McpTool::new(McpToolPattern::new(pattern).unwrap(), ActionClass::Write);
            McpGrant::new(vec![tool], Vec::new(), Vec::new())
        };
        let mut row = stored(&root());
        row.granted = row.granted.with_mcp(mcp("github_*"));
        let parent = Delegation::<ResolvedTenant>::reconstitute(row).unwrap();
        let asking = |pattern: &str| AttenuateParams {
            granted: parent.granted().clone().with_mcp(mcp(pattern)),
            constraints: constraints(1),
            name: None,
        };

        let every_tool = parent.narrowed(AgentId::new(), asking("*"));
        let one_tool = parent.narrowed(AgentId::new(), asking("github_create_issue"));

        assert!(matches!(every_tool, Err(DomainError::Forbidden(_))));
        assert!(one_tool.is_ok());
    }

    /// A child cannot widen `/reports/` access to every path, and inherits
    /// `/reports/` when it supplies no resource scope.
    #[test]
    fn a_child_reaches_no_path_its_parent_does_not() {
        let reports = ResourceScope::new(vec!["/reports/".to_owned()]).unwrap();
        let parent = root_with(constraints(2).with_resource_scope(reports.clone()));
        let everything = ResourceScope::new(vec!["/".to_owned()]).unwrap();

        let wider = parent.narrowed(
            AgentId::new(),
            child_of(constraints(2).with_resource_scope(everything)),
        );
        let silent = parent
            .narrowed(AgentId::new(), child_of(constraints(2)))
            .unwrap();

        assert!(matches!(wider, Err(DomainError::Forbidden(_))));
        assert_eq!(
            silent.constraints().resource_scope().limit(),
            Some(&reports)
        );
    }

    /// The reference a raised event's payload holds under `key`: the id and
    /// the name it carried.
    fn named_in(event: &DomainEvent, key: &str) -> (String, String) {
        match event.payload().value(key) {
            Some(FieldValue::Reference(reference)) => {
                (reference.id().to_owned(), reference.label().to_owned())
            }
            other => panic!("{key} is not a reference: {other:?}"),
        }
    }

    /// Ann gives the agent "ledger-bot" a delegation with no title. The
    /// grant and the issue of its token are raised, naming the agent by its
    /// name and the delegation by its id.
    #[test]
    fn granting_raises_the_grant_and_its_token() {
        let mut d = root();

        let events = raised(&mut d);

        let names: Vec<String> = events.iter().map(|e| e.event_type().to_string()).collect();
        assert_eq!(names, ["agents.delegation_granted", "agents.token_issued"]);
        for event in &events {
            assert_eq!(
                named_in(event, "delegation"),
                (d.id().to_string(), d.id().to_string())
            );
            assert_eq!(named_in(event, "delegate").1, "ledger-bot");
        }
    }

    /// Ann passes part of her agent's delegation on to another agent. The
    /// child raises its own grant and token; the parent raises nothing.
    #[test]
    fn passing_on_raises_the_childs_grant_and_token() {
        let holder = live(AgentId::new());
        let mut parent = root_to(&holder);
        raised_names(&mut parent);

        let mut child = parent
            .attenuate(
                &owner_for(holder.owner(), &holder),
                &to(&live(AgentId::new())),
                child_of(constraints(1)),
            )
            .unwrap();

        assert_eq!(
            raised_names(&mut child),
            ["agents.delegation_granted", "agents.token_issued"]
        );
        assert!(raised_names(&mut parent).is_empty());
    }

    /// The agent mints itself the delegation behind a task token. Its grant
    /// and token are raised, naming the agent as the request named it.
    #[test]
    fn minting_raises_the_grant_and_its_token() {
        let agent = AgentId::new();
        let ceiling = granted_to(
            agent,
            &caps(RoutingAction::View, "ianua.msg.t1.>", PubSub::Both),
        );

        let mut minted =
            mint_from(agent, ceiling.granted(), std::slice::from_ref(&ceiling)).unwrap();

        let events = raised(&mut minted);
        assert_eq!(events.len(), 2);
        assert_eq!(named_in(&events[0], "delegate").1, "agent");
    }

    /// Ann revokes her agent's delegation, and revokes it again. Each revoke
    /// is raised, so every time someone took the authority back is on record.
    #[test]
    fn revoking_raises_each_revoke() {
        let mut d = root();
        raised_names(&mut d);

        d.revoke(Revoker::Platform).unwrap();
        d.revoke(Revoker::Platform).unwrap();

        assert_eq!(
            raised_names(&mut d),
            ["agents.delegation_revoked", "agents.delegation_revoked"]
        );
    }

    /// Ledger read is added to a delegation and taken away again. Each
    /// raises its change, naming the relation and the object.
    #[test]
    fn adding_and_removing_a_resource_raises_each_change() {
        let mut d = root();
        raised_names(&mut d);

        d.grant_resource(
            &ledger_read(),
            &ResourceCeiling::Delegator(held_as(d.delegator(), &ceiling())),
        )
        .unwrap();
        d.revoke_resource(
            Revoker::Platform,
            ledger_read().relation(),
            ledger_read().resource_ref(),
        )
        .unwrap();

        let events = raised(&mut d);
        let names: Vec<String> = events.iter().map(|e| e.event_type().to_string()).collect();
        assert_eq!(
            names,
            [
                "agents.delegation_resource_granted",
                "agents.delegation_resource_revoked"
            ]
        );
        assert!(matches!(
            events[0].payload().value("resource"),
            Some(FieldValue::Text(object)) if object == "ledger:2026-q1"
        ));
    }

    /// The drift monitor catches an action outside the delegation's intent.
    /// The drift is raised and the delegation is otherwise as it was.
    #[test]
    fn recording_a_drift_raises_it_and_changes_nothing() {
        let mut d = root();
        raised_names(&mut d);

        d.record_drift();

        assert_eq!(raised_names(&mut d), ["agents.intent_drift"]);
        assert!(d.is_valid(crate::shared::clock::now()));
    }

    /// Unauthorized revocation and widening against an unrelated person's
    /// holdings both fail without raising events.
    #[test]
    fn a_refused_change_raises_nothing() {
        let mut d = root();
        raised_names(&mut d);
        let sam = person("sam@corp.test");
        let owner = person("owner@corp.test");

        let revoked = d.revoke(Revoker::Person {
            control: AgentControl::new(assumed_authority(&sam, TenantId::new(), &[], &[])),
            agent_owner: &owner,
        });
        let widened = d.grant_resource(
            &ledger_read(),
            &ResourceCeiling::Delegator(held(&ceiling())),
        );

        assert!(revoked.is_err());
        assert!(widened.is_err());
        assert!(raised_names(&mut d).is_empty());
    }

    /// A delegation is read back from storage. It has raised nothing, so
    /// loading it records nothing.
    #[test]
    fn read_back_from_storage_has_raised_nothing() {
        let mut d = Delegation::<ResolvedTenant>::reconstitute(stored(&root())).unwrap();

        assert!(raised_names(&mut d).is_empty());
    }
}
