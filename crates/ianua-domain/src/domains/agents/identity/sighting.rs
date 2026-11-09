//! An agent seen at work that nobody registered.
//!
//! An agent that calls the tenant's routes with a person's key, a client
//! nobody tied to an agent, or a workload a cloud scan found, holds
//! authority no delegation records. A sighting keeps what was seen, so
//! someone allowed to manage agents registers it as an agent, which puts it
//! under delegations, or dismisses it as no agent at all. A sighting grants
//! nothing: what it saw is still refused or allowed by the usual rules.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::agents::events::discovery::{AgentSightingChanged, SightingChange};
use crate::domains::agents::identity::agent::AgentIdentity;
use crate::domains::agents::identity::control::AgentControl;
use crate::domains::authorization::permission::AgentAction;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::clock;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::{AgentId, AgentSightingId, UntrustedText};

/// Where an unregistered agent was seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SightingSource {
    /// The gateway saw it call a route the way agents do.
    Gateway,
    /// An OAuth client acted with no agent behind it.
    OAuthClient,
    /// A scan of the tenant's cloud found a workload holding credentials.
    CloudScan,
}

impl SightingSource {
    /// The stored name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gateway => "gateway",
            Self::OAuthClient => "oauth_client",
            Self::CloudScan => "cloud_scan",
        }
    }

    /// Reads a stored name.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the name is unknown. The row
    ///   is corrupt.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        match value {
            "gateway" => Ok(Self::Gateway),
            "oauth_client" => Ok(Self::OAuthClient),
            "cloud_scan" => Ok(Self::CloudScan),
            _ => Err(DomainError::corrupt_row(
                "agent sighting",
                "an unknown source",
            )),
        }
    }
}

text_value! {
    /// What tells one unregistered caller apart from another, such as an
    /// OAuth client id, a workload's subject, or a user agent with the
    /// network it came from. One sighting is kept per fingerprint.
    pub struct SightingFingerprint;
}

impl TextValue for SightingFingerprint {
    const FIELD: &'static str = "fingerprint";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.not_empty().char_length(1..=256).no_control_chars()
    }
}

/// Whether a person has dealt with a sighting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SightingState {
    /// Nobody has looked at it yet.
    Unreviewed,
    /// It was registered as this agent.
    Registered {
        /// The agent it became.
        agent_id: AgentId,
        /// When it was registered.
        at: OffsetDateTime,
    },
    /// It was judged no agent at all.
    Dismissed {
        /// When it was dismissed.
        at: OffsetDateTime,
    },
}

impl SightingState {
    /// When a person dealt with it, once they have.
    #[must_use]
    pub fn decided_at(self) -> Option<OffsetDateTime> {
        match self {
            Self::Unreviewed => None,
            Self::Registered { at, .. } | Self::Dismissed { at } => Some(at),
        }
    }
}

/// Persisted state for reconstitution.
pub struct AgentSightingRow {
    /// Unique identifier.
    pub id: AgentSightingId,
    /// Where it was seen.
    pub source: SightingSource,
    /// What tells it apart.
    pub fingerprint: SightingFingerprint,
    /// What it called itself, as seen.
    pub calls_itself: UntrustedText,
    /// How many times it was seen.
    pub seen_count: u32,
    /// When it was first seen.
    pub first_seen_at: OffsetDateTime,
    /// When it was last seen.
    pub last_seen_at: OffsetDateTime,
    /// Whether a person dealt with it.
    pub state: SightingState,
    /// When it last changed.
    pub updated_at: OffsetDateTime,
}

/// An agent seen at work that nobody registered.
#[derive(Debug, Clone)]
pub struct AgentSighting<T: TenantScope> {
    id: AgentSightingId,
    source: SightingSource,
    fingerprint: SightingFingerprint,
    calls_itself: UntrustedText,
    seen_count: u32,
    first_seen_at: OffsetDateTime,
    last_seen_at: OffsetDateTime,
    state: SightingState,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> AgentSighting<T> {
    /// Records the first sighting of the caller `fingerprint` names, seen by
    /// `source`, calling itself `calls_itself`.
    ///
    /// The platform sees it in traffic or a scan, so no person makes it.
    /// What it calls itself is the caller's own word, kept short and on one
    /// line.
    ///
    /// Raises `agents.agent_sighted`, so the people who manage agents hear
    /// of it.
    #[must_use]
    pub fn observe(
        source: SightingSource,
        fingerprint: SightingFingerprint,
        calls_itself: &str,
    ) -> Self {
        let now = clock::now();
        let mut sighting = Self {
            id: AgentSightingId::new(),
            source,
            fingerprint,
            calls_itself: UntrustedText::record(calls_itself),
            seen_count: 1,
            first_seen_at: now,
            last_seen_at: now,
            state: SightingState::Unreviewed,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        sighting.raise(SightingChange::Sighted);
        sighting
    }

    /// Rebuilds a sighting from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row was seen no times, or
    ///   last seen before it was first seen.
    /// - [`DomainError::Infrastructure`] when it changed, or was decided,
    ///   before it was first seen.
    pub fn reconstitute(row: AgentSightingRow) -> Result<Self, DomainError> {
        ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            source: row.source,
            fingerprint: row.fingerprint,
            calls_itself: row.calls_itself,
            seen_count: row.seen_count,
            first_seen_at: row.first_seen_at,
            last_seen_at: row.last_seen_at,
            state: row.state,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Unique identifier.
    #[must_use]
    pub fn id(&self) -> &AgentSightingId {
        &self.id
    }

    /// Where it was seen.
    #[must_use]
    pub fn source(&self) -> SightingSource {
        self.source
    }

    /// What tells it apart.
    #[must_use]
    pub fn fingerprint(&self) -> &SightingFingerprint {
        &self.fingerprint
    }

    /// What it called itself, as seen. Never trusted.
    #[must_use]
    pub fn calls_itself(&self) -> &UntrustedText {
        &self.calls_itself
    }

    /// How many times it was seen.
    #[must_use]
    pub fn seen_count(&self) -> u32 {
        self.seen_count
    }

    /// When it was first seen.
    #[must_use]
    pub fn first_seen_at(&self) -> OffsetDateTime {
        self.first_seen_at
    }

    /// When it was last seen.
    #[must_use]
    pub fn last_seen_at(&self) -> OffsetDateTime {
        self.last_seen_at
    }

    /// Whether a person dealt with it.
    #[must_use]
    pub fn state(&self) -> SightingState {
        self.state
    }

    /// Counts one more sighting, now.
    ///
    /// It raises nothing: the first sighting told the people who manage
    /// agents, and one record per call would flood their feeds. A sighting
    /// dealt with stays as it was decided.
    pub fn record_sighting(&mut self) {
        let now = clock::now();
        self.seen_count = self.seen_count.saturating_add(1);
        self.last_seen_at = now;
        self.updated_at = now;
    }

    /// Records that the caller is `agent`, which the person `control` names
    /// registered for it.
    ///
    /// Only someone allowed to manage agents deals with a sighting. Sam may
    /// create agents. Without this check, he marks a rogue agent Mallory
    /// runs as one of his own, and it drops out of the list that shows it.
    ///
    /// Raises `agents.agent_sighting_registered`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not manage agents.
    /// - [`DomainError::InvalidTransition`] when it is registered already.
    pub fn register(
        &mut self,
        control: &AgentControl<'_>,
        agent: &AgentIdentity<T>,
    ) -> Result<(), DomainError> {
        ensure_manages(control)?;
        if matches!(self.state, SightingState::Registered { .. }) {
            return Err(DomainError::invalid_transition(message!(
                "agents-the-sighting-is-registered-already",
                "the sighting is registered already"
            )));
        }
        let now = clock::now();
        self.state = SightingState::Registered {
            agent_id: *agent.id(),
            at: now,
        };
        self.updated_at = now;
        self.raise(SightingChange::Registered);
        Ok(())
    }

    /// Dismisses the sighting as no agent at all.
    ///
    /// Raises `agents.agent_sighting_dismissed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not manage agents.
    /// - [`DomainError::InvalidTransition`] when a person dealt with it
    ///   already.
    pub fn dismiss(&mut self, control: &AgentControl<'_>) -> Result<(), DomainError> {
        ensure_manages(control)?;
        if self.state != SightingState::Unreviewed {
            return Err(DomainError::invalid_transition(message!(
                "agents-only-a-sighting-nobody-dealt-with",
                "only a sighting nobody dealt with is dismissed"
            )));
        }
        let now = clock::now();
        self.state = SightingState::Dismissed { at: now };
        self.updated_at = now;
        self.raise(SightingChange::Dismissed);
        Ok(())
    }

    /// Raises `change` to this sighting.
    fn raise(&mut self, change: SightingChange) {
        self.raised.raise(AgentSightingChanged {
            sighting_id: self.id,
            source: self.source,
            change,
            occurred_at: self.updated_at,
        });
    }
}

/// Refuses a person who may not manage agents.
fn ensure_manages(control: &AgentControl<'_>) -> Result<(), DomainError> {
    if control.holds_agent(AgentAction::Manage) {
        return Ok(());
    }
    Err(DomainError::forbidden(message!(
        "agents-only-someone-allowed-to-manage-agents-4",
        "only someone allowed to manage agents deals with a sighting"
    )))
}

impl<T: TenantScope> Raises for AgentSighting<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

impl<T: TenantScope> Aggregate for AgentSighting<T> {
    type Id = AgentSightingId;

    fn id(&self) -> &Self::Id {
        &self.id
    }

    fn created_at(&self) -> OffsetDateTime {
        self.first_seen_at
    }

    fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

/// Refuses a stored sighting seen no times, last seen before it was first
/// seen, or changed or decided before it was first seen.
fn ensure_consistent(row: &AgentSightingRow) -> Result<(), DomainError> {
    RowCheck::of("agent sighting")
        .holds(row.seen_count >= 1, "seen no times")
        .in_order(
            row.first_seen_at,
            row.last_seen_at,
            "last seen before it was first seen",
        )
        .in_order(
            row.last_seen_at,
            row.updated_at,
            "seen after it last changed",
        )
        .in_order_if(
            row.first_seen_at,
            row.state.decided_at(),
            "decided before it was seen",
        )
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::identity::agent::tests::fixtures::{
        agent_of, ann, creating, managing, person,
    };
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::raised_names;

    /// A sighting of a LangChain client calling the orders route.
    fn sighting() -> AgentSighting<ResolvedTenant> {
        AgentSighting::observe(
            SightingSource::Gateway,
            SightingFingerprint::new("ua:LangChain/0.2 net:10.0.4.0/24").unwrap(),
            "LangChain/0.2",
        )
    }

    fn row_of(sighting: &AgentSighting<ResolvedTenant>) -> AgentSightingRow {
        AgentSightingRow {
            id: sighting.id,
            source: sighting.source,
            fingerprint: sighting.fingerprint.clone(),
            calls_itself: sighting.calls_itself.clone(),
            seen_count: sighting.seen_count,
            first_seen_at: sighting.first_seen_at,
            last_seen_at: sighting.last_seen_at,
            state: sighting.state,
            updated_at: sighting.updated_at,
        }
    }

    /// The gateway sees an unregistered agent for the first time. It is
    /// unreviewed, seen once, and its sighting is raised.
    #[test]
    fn a_first_sighting_is_unreviewed_and_raised() {
        let mut seen = sighting();

        assert_eq!(seen.state(), SightingState::Unreviewed);
        assert_eq!(seen.seen_count(), 1);
        assert_eq!(raised_names(&mut seen), ["agents.agent_sighted"]);
    }

    /// The same caller is seen again a minute later. The count and time
    /// move, and nothing more is raised.
    #[test]
    fn seeing_it_again_counts_without_raising() {
        let mut seen = sighting();
        raised_names(&mut seen);
        let later = clock::freeze(seen.last_seen_at() + time::Duration::minutes(1));

        seen.record_sighting();

        assert_eq!(seen.seen_count(), 2);
        assert!(seen.last_seen_at() > seen.first_seen_at());
        assert!(raised_names(&mut seen).is_empty());
        drop(later);
    }

    /// A caller-supplied name containing a newline is recorded without it,
    /// keeping the sighting's untrusted display name on one line.
    #[test]
    fn what_it_calls_itself_is_kept_on_one_line() {
        let seen = AgentSighting::<ResolvedTenant>::observe(
            SightingSource::OAuthClient,
            SightingFingerprint::new("client:abc").unwrap(),
            "bot\nadmin ok",
        );

        assert!(!seen.calls_itself().as_str().contains('\n'));
    }

    /// Bob, who manages agents, registers the sighting as Ann's new agent.
    /// It names that agent, and the registration is raised.
    #[test]
    fn a_manager_registers_a_sighting_as_an_agent() {
        let bob = person("bob@corp.test");
        let agent = agent_of(&ann());
        let mut seen = sighting();
        raised_names(&mut seen);

        seen.register(&managing(&bob), &agent).unwrap();

        assert!(matches!(
            seen.state(),
            SightingState::Registered { agent_id, .. } if agent_id == *agent.id()
        ));
        assert_eq!(
            raised_names(&mut seen),
            ["agents.agent_sighting_registered"]
        );
    }

    /// Permission to create agents does not allow registering or dismissing
    /// a sighting. Both attempts are refused and the sighting stays unreviewed.
    #[test]
    fn only_a_manager_deals_with_a_sighting() {
        let sam = person("sam@corp.test");
        let agent = agent_of(&sam);
        let mut seen = sighting();

        let registered = seen.register(&creating(&sam), &agent);
        let dismissed = seen.dismiss(&creating(&sam));

        assert!(matches!(registered, Err(DomainError::Forbidden(_))));
        assert!(matches!(dismissed, Err(DomainError::Forbidden(_))));
        assert_eq!(seen.state(), SightingState::Unreviewed);
    }

    /// Bob dismisses a sighting, then dismisses it again. The second is
    /// refused. He may still register it later, once it proves to be an
    /// agent, but not register it twice.
    #[test]
    fn a_sighting_is_dismissed_once_and_registered_once() {
        let bob = person("bob@corp.test");
        let agent = agent_of(&ann());
        let mut seen = sighting();

        seen.dismiss(&managing(&bob)).unwrap();
        let again = seen.dismiss(&managing(&bob));
        seen.register(&managing(&bob), &agent).unwrap();
        let twice = seen.register(&managing(&bob), &agent);

        assert!(matches!(again, Err(DomainError::InvalidTransition(_))));
        assert!(matches!(twice, Err(DomainError::InvalidTransition(_))));
    }

    /// A stored sighting seen no times, or decided before it was first
    /// seen, is refused as corrupt.
    #[test]
    fn a_stored_sighting_that_breaks_its_rules_is_refused() {
        let seen = sighting();
        let never_seen = AgentSightingRow {
            seen_count: 0,
            ..row_of(&seen)
        };
        let decided_early = AgentSightingRow {
            state: SightingState::Dismissed {
                at: seen.first_seen_at - time::Duration::SECOND,
            },
            ..row_of(&seen)
        };

        assert!(refused_as_corrupt(
            &AgentSighting::<ResolvedTenant>::reconstitute(never_seen)
        ));
        assert!(refused_as_corrupt(
            &AgentSighting::<ResolvedTenant>::reconstitute(decided_early)
        ));
    }

    /// Every source reads back from its stored name, and an unknown one is
    /// refused as corrupt.
    #[test]
    fn each_source_reads_back_from_its_stored_name() {
        for source in [
            SightingSource::Gateway,
            SightingSource::OAuthClient,
            SightingSource::CloudScan,
        ] {
            assert_eq!(
                SightingSource::from_stored(source.as_str()).unwrap(),
                source
            );
        }
        assert!(matches!(
            SightingSource::from_stored("rumour"),
            Err(DomainError::Infrastructure(_))
        ));
    }
}
