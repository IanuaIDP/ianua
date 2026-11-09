//! Egress policies: where a service that agents can reach may itself go.
//!
//! An agent may be kept off the internet, yet call a service that fetches
//! whatever it is asked to. The request then leaves from the service, not
//! the agent. So each such service sends its outbound traffic through the
//! ianua egress gateway. The gateway lets a connection out only to a host
//! and port the service's policy lists by exact name. A service with no
//! policy reaches nothing.
//!
//! The outbound call may carry the signed assertion the data plane gave the
//! agent's request. Then the gateway also knows which agent caused it. The
//! agent's data mark must not be above what the policy lets out, and a
//! refusal is held against that agent. A call without the assertion could
//! be any agent's. It leaves only under a policy that lets out the most
//! sensitive data.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::routing::control::{RoutingControl, RoutingRight};
use crate::domains::routing::events::{EgressPolicyChange, EgressPolicyChanged};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::shared::security::acting_person::is_person;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;
use crate::types::{EgressPolicyId, Label, PrincipalRef};

mod endpoints;

pub use endpoints::{EgressDestination, EgressTarget, ServiceIdentity};

/// The most destinations one policy may list. A policy is meant to stay
/// short enough to review.
pub(crate) const MAX_DESTINATIONS: usize = 32;

/// What a person asks for when making an egress policy.
pub struct CreateEgressPolicyParams {
    /// A name people recognise the service by.
    pub name: Label,
    /// The service the policy is for.
    pub service: ServiceIdentity,
    /// Where it may go.
    pub destinations: Vec<EgressDestination>,
    /// The most sensitive data an agent may have touched for a call it
    /// caused to be let out.
    pub max_data_class: DataClassLevel,
}

/// An [`EgressPolicy`] as storage holds it, read back through
/// [`EgressPolicy::reconstitute`].
pub struct EgressPolicyRow {
    /// The policy's id.
    pub id: EgressPolicyId,
    /// The name people recognise the service by.
    pub name: Label,
    /// The service the policy is for.
    pub service: ServiceIdentity,
    /// Where it may go.
    pub destinations: Vec<EgressDestination>,
    /// The most sensitive data an agent's call may carry out.
    pub max_data_class: DataClassLevel,
    /// Who made it.
    pub created_by: PrincipalRef,
    /// When it was made.
    pub created_at: OffsetDateTime,
    /// When it last changed.
    pub updated_at: OffsetDateTime,
}

/// Where one service may send traffic.
///
/// Every change needs the routing right, held by a person signed in to the
/// tenant, so an agent never makes one. Sam's agent reads customer records
/// and calls a fetch service. Without this rule, Sam adds his own server to
/// the list and the agent sends the records there.
#[derive(Debug, Clone)]
pub struct EgressPolicy<T: TenantScope> {
    id: EgressPolicyId,
    name: Label,
    service: ServiceIdentity,
    destinations: Vec<EgressDestination>,
    max_data_class: DataClassLevel,
    created_by: PrincipalRef,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> EgressPolicy<T> {
    /// Creates a policy, made by `by`. Raises `routing.egress_policy_created`
    /// with where the service may go.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not create routing.
    /// - [`DomainError::Validation`] when the destination list is empty, or
    ///   longer than `MAX_DESTINATIONS`.
    /// - [`DomainError::Validation`] when a destination is listed twice.
    pub fn create(
        params: CreateEgressPolicyParams,
        by: &RoutingControl<'_>,
    ) -> Result<Self, DomainError> {
        by.ensure_may(RoutingRight::Create)?;
        let destinations = checked(params.destinations)?;
        let now = crate::shared::clock::now();
        let mut policy = Self {
            id: EgressPolicyId::new(),
            name: params.name,
            service: params.service,
            destinations,
            max_data_class: params.max_data_class,
            created_by: by.by().principal(),
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        policy.raise_change(EgressPolicyChange::Created);
        Ok(policy)
    }

    /// Rebuilds an egress policy from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says an agent or a
    ///   consumer made it.
    /// - [`DomainError::Infrastructure`] when it lists no destination, too
    ///   many, or one twice.
    /// - [`DomainError::Infrastructure`] when it changed before it was created.
    pub fn reconstitute(row: EgressPolicyRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            name: row.name,
            service: row.service,
            destinations: row.destinations,
            max_data_class: row.max_data_class,
            created_by: row.created_by,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &EgressPolicyRow) -> Result<(), DomainError> {
        RowCheck::of("egress policy")
            .holds(is_person(&row.created_by), "made by someone not a person")
            .holds(
                checked(row.destinations.clone()).is_ok(),
                "destinations none, too many, or listed twice",
            )
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was created",
            )
            .finish()
    }

    /// The policy's id.
    #[must_use]
    pub fn id(&self) -> &EgressPolicyId {
        &self.id
    }

    /// The name people recognise the service by.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// The service the policy is for.
    #[must_use]
    pub fn service(&self) -> &ServiceIdentity {
        &self.service
    }

    /// Where it may go.
    #[must_use]
    pub fn destinations(&self) -> &[EgressDestination] {
        &self.destinations
    }

    /// The most sensitive data an agent's call may carry out.
    #[must_use]
    pub fn max_data_class(&self) -> DataClassLevel {
        self.max_data_class
    }

    /// Who made it.
    #[must_use]
    pub fn created_by(&self) -> &PrincipalRef {
        &self.created_by
    }

    /// When it was made.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When it last changed.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// Replaces where the service may go, on behalf of `by`.
    ///
    /// Raises `routing.egress_policy_updated`, once for all the changes made
    /// before a save.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    /// - [`DomainError::Validation`] for a destination list
    ///   [`create`](Self::create) refuses.
    pub fn replace_destinations(
        &mut self,
        destinations: Vec<EgressDestination>,
        by: &RoutingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        self.destinations = checked(destinations)?;
        self.record_update();
        Ok(())
    }

    /// Renames the policy to `name`, on behalf of `by`. The service it is
    /// for and where it may go stay as they are.
    ///
    /// Raises `routing.egress_policy_updated`, once for all the changes made
    /// before a save.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    pub fn rename(&mut self, name: Label, by: &RoutingControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        self.name = name;
        self.record_update();
        Ok(())
    }

    /// Changes the most sensitive data an agent's call may carry out, on
    /// behalf of `by`.
    ///
    /// Raises `routing.egress_policy_updated`, once for all the changes made
    /// before a save.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    pub fn change_max_data_class(
        &mut self,
        class: DataClassLevel,
        by: &RoutingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        self.max_data_class = class;
        self.record_update();
        Ok(())
    }

    /// Deletes this policy once `by` may delete routing. Raises
    /// `routing.egress_policy_deleted`, taken once the policy is removed from
    /// storage.
    ///
    /// A service without a policy reaches nothing. So deleting the one that
    /// lets the billing service reach its payment provider stops billing,
    /// which is more than an edit to it can do.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not delete routing.
    pub fn delete(&mut self, by: &RoutingControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Delete)?;
        self.raise_change(EgressPolicyChange::Deleted);
        Ok(())
    }

    /// Whether this policy lets `request` out.
    ///
    /// The host and port must be listed. A call an agent caused is also
    /// refused when the agent's data mark is above the policy's class.
    ///
    /// A call with no assertion could come from any agent, so it counts as
    /// carrying the most sensitive data. Ann lets a service send out public
    /// data only. Sam's agent has read restricted records and has the
    /// service call out without the assertion. That call is refused.
    #[must_use]
    pub fn decide(&self, request: &EgressRequest<'_>) -> EgressDecision {
        if !self
            .destinations
            .iter()
            .any(|d| d.is(request.host, request.port))
        {
            return EgressDecision::Deny(EgressDenial::DestinationNotListed);
        }
        match request.agent_mark {
            AgentMark::Unattributed if self.max_data_class < DataClassLevel::Restricted => {
                EgressDecision::Deny(EgressDenial::Unattributed)
            }
            AgentMark::Marked(mark) if mark > self.max_data_class => {
                EgressDecision::Deny(EgressDenial::DataTooSensitive)
            }
            AgentMark::Unattributed | AgentMark::Marked(_) => EgressDecision::Allow,
        }
    }

    /// Marks a change to where the service may go or what it may carry
    /// out, raising `routing.egress_policy_updated` with the policy as it
    /// now is.
    fn record_update(&mut self) {
        self.updated_at = crate::shared::clock::now();
        let event = self.change_event(EgressPolicyChange::Updated);
        self.raised.raise_latest(event);
    }

    /// Raises `change` with the policy as it now is.
    fn raise_change(&mut self, change: EgressPolicyChange) {
        let event = self.change_event(change);
        self.raised.raise(event);
    }

    /// The record of `change`. A deleted policy lets the service go
    /// nowhere, so it lists no destination.
    fn change_event(&self, change: EgressPolicyChange) -> EgressPolicyChanged {
        let (destinations, occurred_at) = match change {
            EgressPolicyChange::Deleted => (Vec::new(), crate::shared::clock::now()),
            EgressPolicyChange::Created | EgressPolicyChange::Updated => {
                (self.destinations.clone(), self.updated_at)
            }
        };
        EgressPolicyChanged {
            policy_id: self.id,
            name: self.name.clone(),
            service: self.service.clone(),
            destinations,
            max_data_class: self.max_data_class,
            change,
            occurred_at,
        }
    }
}

impl<T: TenantScope> Raises for EgressPolicy<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

fn checked(destinations: Vec<EgressDestination>) -> Result<Vec<EgressDestination>, DomainError> {
    validate_count("destinations", destinations.len(), 1..=MAX_DESTINATIONS)?;
    if first_repeat(&destinations).is_some() {
        return Err(DomainError::invalid(message!(
            "routing-an-egress-destination-is-listed-twice",
            "an egress destination is listed twice"
        )));
    }
    Ok(destinations)
}

impl<T: TenantScope> Aggregate for EgressPolicy<T> {
    type Id = EgressPolicyId;

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

/// One outbound connection a service asks the gateway for.
#[derive(Debug, Clone, Copy)]
pub struct EgressRequest<'a> {
    /// The host it asks for.
    pub host: &'a str,
    /// The port it asks for.
    pub port: u16,
    /// The data mark of the agent whose request caused it, when the call
    /// says.
    pub agent_mark: AgentMark,
}

/// Whether an outbound call carries an agent's data mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentMark {
    /// No assertion came with the call. Nobody knows whether an agent caused
    /// it, so it is let out only where the policy allows the most sensitive
    /// data.
    Unattributed,
    /// The call carries the assertion of an agent that has read data up to
    /// this class.
    Marked(DataClassLevel),
}

/// Why an outbound connection was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressDenial {
    /// The service has no egress policy.
    NoPolicy,
    /// The destination is not on the service's list.
    DestinationNotListed,
    /// The agent behind the call touched data more sensitive than the
    /// policy lets out.
    DataTooSensitive,
    /// The call carries no assertion, and the policy does not let out the
    /// most sensitive data.
    Unattributed,
    /// The request does not name a host and port the gateway can judge.
    MalformedTarget,
}

impl EgressDenial {
    /// A short, stable reason for the audit record.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoPolicy => "no_policy",
            Self::DestinationNotListed => "destination_not_listed",
            Self::DataTooSensitive => "data_too_sensitive",
            Self::Unattributed => "unattributed",
            Self::MalformedTarget => "malformed_target",
        }
    }
}

/// The verdict on one outbound connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressDecision {
    /// Let it out.
    Allow,
    /// Refuse it, for this reason.
    Deny(EgressDenial),
}

/// The one claim among `claims`, or `None` when there is none or more than
/// one.
///
/// A service is named by its certificate, and two tenants may each write a
/// policy for the same name. Which tenant's list would then apply is a
/// guess, and a guess is not a decision, so the service reaches nothing
/// until one of them takes its policy back.
#[must_use]
pub fn sole_claim<C>(mut claims: Vec<C>) -> Option<C> {
    match claims.len() {
        1 => claims.pop(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::routing::fixtures::{routing_admin, routing_editor, routing_viewer};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{AgentId, DomainName};

    fn dest(host: &str, port: u16) -> EgressDestination {
        EgressDestination::new(DomainName::new(host).unwrap(), port).unwrap()
    }

    fn params(destinations: Vec<EgressDestination>) -> CreateEgressPolicyParams {
        CreateEgressPolicyParams {
            name: Label::new("name", "fetcher").unwrap(),
            service: ServiceIdentity::new("spiffe://ianua.test/ns/svc/sa/fetcher").unwrap(),
            destinations,
            max_data_class: DataClassLevel::Internal,
        }
    }

    fn policy(destinations: Vec<EgressDestination>) -> EgressPolicy<ResolvedTenant> {
        EgressPolicy::create(params(destinations), &routing_admin()).unwrap()
    }

    fn to(host: &str, port: u16) -> EgressRequest<'_> {
        EgressRequest {
            host,
            port,
            agent_mark: AgentMark::Marked(DataClassLevel::Public),
        }
    }

    fn unattributed(host: &str, port: u16) -> EgressRequest<'_> {
        EgressRequest {
            host,
            port,
            agent_mark: AgentMark::Unattributed,
        }
    }

    /// A policy lists `api.github.com:443`. The same host in other case is let
    /// out, while port 80, another host and a subdomain of it are refused.
    #[test]
    fn only_a_listed_host_and_port_is_let_out() {
        let p = policy(vec![dest("api.github.com", 443)]);

        assert_eq!(p.decide(&to("API.GitHub.com", 443)), EgressDecision::Allow);
        assert_eq!(
            p.decide(&to("api.github.com", 80)),
            EgressDecision::Deny(EgressDenial::DestinationNotListed)
        );
        assert_eq!(
            p.decide(&to("www.gov.example", 443)),
            EgressDecision::Deny(EgressDenial::DestinationNotListed)
        );
        assert_eq!(
            p.decide(&to("evil.api.github.com", 443)),
            EgressDecision::Deny(EgressDenial::DestinationNotListed)
        );
    }

    /// A request marked restricted is denied as too sensitive under an
    /// internal-data policy, even for a listed destination.
    #[test]
    fn a_call_caused_by_an_agent_holding_sensitive_data_is_refused() {
        let p = policy(vec![dest("api.github.com", 443)]);
        let request = EgressRequest {
            host: "api.github.com",
            port: 443,
            agent_mark: AgentMark::Marked(DataClassLevel::Restricted),
        };

        assert_eq!(
            p.decide(&request),
            EgressDecision::Deny(EgressDenial::DataTooSensitive)
        );
    }

    /// A public-data policy denies an unattributed request to a listed host.
    #[test]
    fn an_unattributed_call_is_refused_under_a_policy_below_the_top_class() {
        let mut p = policy(vec![dest("api.github.com", 443)]);
        p.change_max_data_class(DataClassLevel::Public, &routing_admin())
            .unwrap();

        assert_eq!(
            p.decide(&unattributed("api.github.com", 443)),
            EgressDecision::Deny(EgressDenial::Unattributed)
        );
    }

    /// A policy lets restricted data out. An unattributed call to a listed
    /// host is let out, since no mark could be above that.
    #[test]
    fn an_unattributed_call_is_let_out_when_the_policy_allows_every_class() {
        let mut p = policy(vec![dest("api.github.com", 443)]);
        p.change_max_data_class(DataClassLevel::Restricted, &routing_admin())
            .unwrap();

        assert_eq!(
            p.decide(&unattributed("api.github.com", 443)),
            EgressDecision::Allow
        );
    }

    /// Routing update permission alone cannot create an egress policy.
    #[test]
    fn making_a_way_out_needs_the_create_right() {
        let result = EgressPolicy::<ResolvedTenant>::create(
            params(vec![dest("example.com", 443)]),
            &routing_editor(),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// An editor cannot delete an egress policy, while a routing
    /// administrator can.
    #[test]
    fn deleting_a_way_out_needs_the_delete_right() {
        let mut policy = policy(vec![dest("payments.example.com", 443)]);

        let by_editor = policy.delete(&routing_editor());

        assert!(matches!(by_editor, Err(DomainError::Forbidden(_))));
        assert!(policy.delete(&routing_admin()).is_ok());
    }

    /// An admin makes a policy. It records the admin as the one who made it,
    /// not anyone the request names.
    #[test]
    fn a_policy_records_who_made_it() {
        let admin = routing_admin();

        let p =
            EgressPolicy::<ResolvedTenant>::create(params(vec![dest("example.com", 443)]), &admin)
                .unwrap();

        assert_eq!(*p.created_by(), admin.by().principal());
    }

    /// A destination of `*.example.com` or port zero is refused. So is
    /// replacing a policy's list with nothing, or with one host twice.
    #[test]
    fn wildcards_empty_or_repeated_lists_are_refused() {
        assert!(EgressDestination::new(DomainName::new("*.example.com").unwrap(), 443).is_err());
        assert!(EgressDestination::new(DomainName::new("example.com").unwrap(), 0).is_err());
        let mut p = policy(vec![dest("a.example.com", 443)]);
        let admin = routing_admin();
        assert!(p.replace_destinations(vec![], &admin).is_err());
        assert!(
            p.replace_destinations(
                vec![dest("a.example.com", 443), dest("a.example.com", 443)],
                &admin
            )
            .is_err()
        );
    }

    /// A viewer cannot replace the allowed destination or raise the data
    /// ceiling. The original host and internal ceiling remain.
    #[test]
    fn a_viewer_cannot_widen_a_way_out() {
        let mut p = policy(vec![dest("api.partner.com", 443)]);
        let sam = routing_viewer();

        let destinations = p.replace_destinations(vec![dest("attacker.example", 443)], &sam);
        let ceiling = p.change_max_data_class(DataClassLevel::Restricted, &sam);

        assert!(matches!(destinations, Err(DomainError::Forbidden(_))));
        assert!(matches!(ceiling, Err(DomainError::Forbidden(_))));
        assert_eq!(p.destinations(), [dest("api.partner.com", 443)]);
        assert_eq!(p.max_data_class(), DataClassLevel::Internal);
    }

    fn stored(policy: &EgressPolicy<ResolvedTenant>) -> EgressPolicyRow {
        EgressPolicyRow {
            id: policy.id,
            name: policy.name.clone(),
            service: policy.service.clone(),
            destinations: policy.destinations.clone(),
            max_data_class: policy.max_data_class,
            created_by: policy.created_by,
            created_at: policy.created_at,
            updated_at: policy.updated_at,
        }
    }

    /// One stored policy says an agent made it, and another lists a host
    /// twice. Both are refused as corrupt rows.
    #[test]
    fn a_stored_policy_made_by_an_agent_or_listing_a_destination_twice_is_refused() {
        let mut by_an_agent = stored(&policy(vec![dest("api.example.com", 443)]));
        by_an_agent.created_by = PrincipalRef::Agent(AgentId::new());
        let mut twice = stored(&policy(vec![dest("api.example.com", 443)]));
        twice.destinations.push(dest("api.example.com", 443));

        for row in [by_an_agent, twice] {
            assert!(refused_as_corrupt(
                &EgressPolicy::<ResolvedTenant>::reconstitute(row)
            ));
        }
    }

    /// The "fetcher" policy as it was saved, its creation taken out.
    fn saved_policy() -> EgressPolicy<ResolvedTenant> {
        let mut policy = policy(vec![dest("payments.example.com", 443)]);
        raised_names(&mut policy);
        policy
    }

    fn text(event: &DomainEvent, key: &str) -> String {
        match event.payload().value(key) {
            Some(FieldValue::Text(value)) => value.clone(),
            other => panic!("{key} is not a scalar: {other:?}"),
        }
    }

    /// Ann lets "fetcher" reach the payments provider. The creation is
    /// raised with that destination.
    #[test]
    fn creating_raises_routing_egress_policy_created_with_its_destinations() {
        let mut policy = policy(vec![dest("payments.example.com", 443)]);

        let events = raised(&mut policy);

        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().to_string(),
            "routing.egress_policy_created"
        );
        assert_eq!(text(&events[0], "destinations"), "payments.example.com:443");
    }

    /// The policy is read back from storage. Loading it is no change, so it
    /// has raised nothing.
    #[test]
    fn a_policy_read_back_from_storage_has_raised_nothing() {
        let mut stored =
            EgressPolicy::<ResolvedTenant>::reconstitute(stored(&saved_policy())).unwrap();

        assert!(raised_names(&mut stored).is_empty());
    }

    /// Replacing destinations and raising the data ceiling before taking
    /// events raises one update containing both hosts and the final class.
    #[test]
    fn several_edits_before_a_save_raise_one_update_as_the_policy_ends() {
        let mut policy = saved_policy();

        policy
            .replace_destinations(
                vec![
                    dest("payments.example.com", 443),
                    dest("api.partner.com", 443),
                ],
                &routing_admin(),
            )
            .unwrap();
        policy
            .change_max_data_class(DataClassLevel::Restricted, &routing_admin())
            .unwrap();

        let events = raised(&mut policy);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().to_string(),
            "routing.egress_policy_updated"
        );
        assert_eq!(
            text(&events[0], "max_data_class"),
            DataClassLevel::Restricted.as_str()
        );
        assert_eq!(
            text(&events[0], "destinations"),
            "payments.example.com:443,api.partner.com:443"
        );
    }

    /// Fay deletes "fetcher". The deletion is raised, listing no
    /// destination, since the service now reaches nothing.
    #[test]
    fn deleting_raises_routing_egress_policy_deleted_with_no_destination() {
        let mut policy = saved_policy();

        policy.delete(&routing_admin()).unwrap();

        let events = raised(&mut policy);
        assert_eq!(
            events[0].event_type().to_string(),
            "routing.egress_policy_deleted"
        );
        assert_eq!(text(&events[0], "destinations"), "");
    }

    /// A viewer's destination replacement and delete both fail and raise
    /// no events.
    #[test]
    fn a_refused_change_raises_nothing() {
        let mut policy = saved_policy();

        let widened =
            policy.replace_destinations(vec![dest("sam.example.com", 443)], &routing_viewer());
        let deleted = policy.delete(&routing_viewer());

        assert!(widened.is_err());
        assert!(deleted.is_err());
        assert!(raised_names(&mut policy).is_empty());
    }

    /// Fay renames "fetcher" to "partner-fetcher". The record carries the
    /// new name, and the service and its ways out stay as they were.
    #[test]
    fn a_renamed_policy_is_recorded_under_its_new_name() {
        let mut policy = saved_policy();
        let destinations = policy.destinations().to_vec();

        policy
            .rename(
                Label::new("name", "partner-fetcher").unwrap(),
                &routing_admin(),
            )
            .unwrap();

        assert_eq!(policy.name().as_str(), "partner-fetcher");
        assert_eq!(policy.destinations(), destinations.as_slice());
        let events = raised(&mut policy);
        assert_eq!(text(&events[0], "name"), "partner-fetcher");
    }

    /// A viewer cannot rename an egress policy. Its original name remains.
    #[test]
    fn a_viewer_cannot_rename_a_policy() {
        let mut policy = saved_policy();

        let renamed = policy.rename(Label::new("name", "billing").unwrap(), &routing_viewer());

        assert!(matches!(renamed, Err(DomainError::Forbidden(_))));
        assert_eq!(policy.name().as_str(), "fetcher");
    }

    /// One tenant's policy for a service is the one that applies.
    #[test]
    fn a_service_claimed_once_has_its_claim() {
        assert_eq!(sole_claim(vec!["acme"]), Some("acme"));
    }

    /// Selecting a sole service claim returns none for either two claims
    /// or no claims.
    #[test]
    fn a_service_claimed_twice_or_never_has_no_claim() {
        assert_eq!(sole_claim(vec!["acme", "mallory"]), None);
        assert_eq!(sole_claim(Vec::<&str>::new()), None);
    }

    /// A `CONNECT API.GitHub.com:443` reads as `api.github.com:443`, and the
    /// policy listing that host lets it out.
    #[test]
    fn a_target_reads_as_the_host_and_port_it_names() {
        let target = EgressTarget::new("API.GitHub.com", 443).unwrap();
        let p = policy(vec![dest("api.github.com", 443)]);

        assert_eq!(target.to_string(), "api.github.com:443");
        assert_eq!(
            p.decide(&target.request(AgentMark::Marked(DataClassLevel::Public))),
            EgressDecision::Allow
        );
    }

    /// Egress targets reject internal addresses, wildcard and userinfo
    /// hostnames, port zero and an empty host.
    #[test]
    fn a_target_that_is_no_plain_host_is_refused() {
        for (host, port) in [
            ("169.254.169.254", 80),
            ("10.0.0.1", 443),
            ("*.github.com", 443),
            ("user@api.github.com", 443),
            ("api.github.com", 0),
            ("", 443),
        ] {
            assert!(
                matches!(
                    EgressTarget::new(host, port),
                    Err(DomainError::Validation(_))
                ),
                "{host}:{port}"
            );
        }
    }
}
