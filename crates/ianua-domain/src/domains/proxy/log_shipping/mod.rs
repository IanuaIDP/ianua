//! Log shipping: sending a tenant's request records to a place of its own.
//!
//! The gateway already keeps every request's record in its own log. A
//! tenant with a security team wants them in its own tools too, a SIEM, a
//! bucket or Datadog, without polling the dashboard. Each target names one
//! such place, what is sent there and in which shape.
//!
//! A record says who asked for what and what was decided, so it is worth
//! stealing. Pointing a target somewhere new sends every later record
//! there, so every change names who made it and needs the routing right.

mod destination;

use std::marker::PhantomData;

pub use destination::{
    BucketName, BucketRegion, LogDestination, LogFormat, SamplePercent, ShippedRecords,
    ShippingCredential,
};
use time::OffsetDateTime;

use crate::domains::proxy::events::{
    LogTargetChanged, LogTargetCreated, LogTargetDeleted, LogTargetPaused, LogTargetResumed,
};
use crate::domains::proxy::observation::RequestObservation;
use crate::domains::routing::control::{RoutingControl, RoutingRight};
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::shared::model::transition::{InvalidTransition, checked};
use crate::types::event_type::ProxyEvent;
use crate::types::{Label, LogShippingTargetId};

/// Whether a target is being shipped to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum LogTargetStatus {
    /// Records are sent to it.
    Active,
    /// Nothing is sent to it until it is resumed.
    Paused,
}

impl LogTargetStatus {
    /// Moves to `to`. Active and paused swap.
    ///
    /// # Errors
    ///
    /// - [`InvalidTransition`] when the target is already in `to`.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidTransition<Self>> {
        checked(self, to, |from, to| from != to)
    }
}

/// Where and what a target ships.
pub struct LogTargetSettings {
    /// Where records go.
    pub destination: LogDestination,
    /// What the gateway signs in to it with.
    pub credential: ShippingCredential,
    /// Which records are sent.
    pub records: ShippedRecords,
    /// The shape each record is written in.
    pub format: LogFormat,
}

/// A [`LogShippingTarget`] as storage holds it, read back through
/// [`LogShippingTarget::reconstitute`].
pub struct LogShippingTargetRow {
    /// The target's id.
    pub id: LogShippingTargetId,
    /// Name, unique within the tenant.
    pub name: Label,
    /// Where and what it ships.
    pub settings: LogTargetSettings,
    /// Whether it is being shipped to.
    pub status: LogTargetStatus,
    /// When it was created.
    pub created_at: OffsetDateTime,
    /// When it last changed.
    pub updated_at: OffsetDateTime,
}

/// A place a tenant's request records are shipped to.
///
/// Tenant-scoped: read and written only through stores opened for the
/// resolved tenant (see [`crate::isolation`]).
///
/// Every change needs the routing right, held by a person signed in to the
/// tenant. Without this rule, Sam points the target at his own server and
/// reads who called what for as long as nobody looks.
#[derive(Debug, Clone)]
pub struct LogShippingTarget<T: TenantScope> {
    id: LogShippingTargetId,
    name: Label,
    destination: LogDestination,
    credential: ShippingCredential,
    records: ShippedRecords,
    format: LogFormat,
    status: LogTargetStatus,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> LogShippingTarget<T> {
    /// Creates an active target `id` named `name`, on behalf of `by`. The
    /// id is chosen before, so the credential can be sealed for it. Raises
    /// `proxy.log_target_created`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not create routing.
    /// - [`DomainError::Validation`] when the destination needs a credential
    ///   and none is given.
    pub fn create(
        id: LogShippingTargetId,
        name: Label,
        settings: LogTargetSettings,
        by: &RoutingControl<'_>,
    ) -> Result<Self, DomainError> {
        by.ensure_may(RoutingRight::Create)?;
        settings
            .destination
            .ensure_reachable_with(&settings.credential)?;
        let now = crate::shared::clock::now();
        let mut target = Self {
            id,
            name,
            destination: settings.destination,
            credential: settings.credential,
            records: settings.records,
            format: settings.format,
            status: LogTargetStatus::Active,
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        target.raised.raise(LogTargetCreated {
            target_id: target.id,
            name: target.name.clone(),
            destination: target.destination.kind(),
            occurred_at: now,
        });
        Ok(target)
    }

    /// Rebuilds a target from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row's destination needs a
    ///   credential and it holds none.
    /// - [`DomainError::Infrastructure`] when it changed before it was
    ///   created.
    pub fn reconstitute(row: LogShippingTargetRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            name: row.name,
            destination: row.settings.destination,
            credential: row.settings.credential,
            records: row.settings.records,
            format: row.settings.format,
            status: row.status,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &LogShippingTargetRow) -> Result<(), DomainError> {
        RowCheck::of("log shipping target")
            .holds(
                row.settings
                    .destination
                    .ensure_reachable_with(&row.settings.credential)
                    .is_ok(),
                "a destination that needs a credential, with none",
            )
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was created",
            )
            .finish()
    }

    /// The target's id.
    #[must_use]
    pub fn id(&self) -> &LogShippingTargetId {
        &self.id
    }

    /// Name, unique within the tenant.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// Where records go.
    #[must_use]
    pub fn destination(&self) -> &LogDestination {
        &self.destination
    }

    /// What the gateway signs in to the destination with.
    #[must_use]
    pub fn credential(&self) -> &ShippingCredential {
        &self.credential
    }

    /// Which records are sent.
    #[must_use]
    pub fn records(&self) -> ShippedRecords {
        self.records
    }

    /// The shape each record is written in.
    #[must_use]
    pub fn format(&self) -> LogFormat {
        self.format
    }

    /// Whether it is being shipped to.
    #[must_use]
    pub fn status(&self) -> LogTargetStatus {
        self.status
    }

    /// When it was created.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When it last changed.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// Whether the record of `observed` is sent to this target: it is
    /// active and its selection takes the record.
    #[must_use]
    pub fn ships(&self, observed: &RequestObservation) -> bool {
        self.status == LogTargetStatus::Active && self.records.selects(observed)
    }

    /// Replaces where and what the target ships. Raises
    /// `proxy.log_target_changed`, once for all the changes made before a
    /// save.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    /// - [`DomainError::Validation`] when the destination needs a credential
    ///   and none is given.
    pub fn change_settings(
        &mut self,
        settings: LogTargetSettings,
        by: &RoutingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        settings
            .destination
            .ensure_reachable_with(&settings.credential)?;
        self.destination = settings.destination;
        self.credential = settings.credential;
        self.records = settings.records;
        self.format = settings.format;
        self.record_update();
        Ok(())
    }

    /// Renames the target. Raises `proxy.log_target_changed`, once for all
    /// the changes made before a save.
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

    /// Stops shipping to the target until it is resumed. Raises
    /// `proxy.log_target_paused`.
    ///
    /// A security team watching its SIEM stops seeing traffic, so this needs
    /// the update right and is recorded like any other change.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    /// - [`DomainError::InvalidTransition`] when it is already paused.
    pub fn pause(&mut self, by: &RoutingControl<'_>) -> Result<(), DomainError> {
        self.move_to(LogTargetStatus::Paused, by)?;
        self.raised.raise(LogTargetPaused {
            target_id: self.id,
            name: self.name.clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Starts shipping to a paused target again. Raises
    /// `proxy.log_target_resumed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    /// - [`DomainError::InvalidTransition`] when it is already active.
    pub fn resume(&mut self, by: &RoutingControl<'_>) -> Result<(), DomainError> {
        self.move_to(LogTargetStatus::Active, by)?;
        self.raised.raise(LogTargetResumed {
            target_id: self.id,
            name: self.name.clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Deletes this target once `by` may delete routing. Raises
    /// `proxy.log_target_deleted`, taken once it is removed from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not delete routing.
    pub fn delete(&mut self, by: &RoutingControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Delete)?;
        self.raised.raise(LogTargetDeleted {
            target_id: self.id,
            name: self.name.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Moves to `to`, once `by` may update routing.
    fn move_to(&mut self, to: LogTargetStatus, by: &RoutingControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        self.status = self.status.try_transition(to)?;
        self.updated_at = crate::shared::clock::now();
        Ok(())
    }

    /// Marks a change to the name or settings, raising
    /// `proxy.log_target_changed` unless the target is not yet saved, whose
    /// setup is part of its creation.
    fn record_update(&mut self) {
        self.updated_at = crate::shared::clock::now();
        if self.raised.holds(ProxyEvent::LogTargetCreated.into()) {
            return;
        }
        self.raised.raise_latest(LogTargetChanged {
            target_id: self.id,
            name: self.name.clone(),
            destination: self.destination.kind(),
            records: self.records.as_str(),
            occurred_at: self.updated_at,
        });
    }
}

impl<T: TenantScope> Raises for LogShippingTarget<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

impl<T: TenantScope> Aggregate for LogShippingTarget<T> {
    type Id = LogShippingTargetId;

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
mod tests {
    use std::net::IpAddr;

    use time::Duration;

    use super::*;
    use crate::domains::audit::streaming::DatadogSite;
    use crate::domains::proxy::observation::{
        DecidingRule, DecidingStage, GatewayCheck, ObservedPath, ObservedPrincipal, RequestOutcome,
        RouteMatch, Traced,
    };
    use crate::domains::routing::fixtures::{routing_admin, routing_editor, routing_viewer};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::raised_names;
    use crate::types::{
        CorrelationId, Fact, PublicHttpsUrl, SealedSecret, TenantId, UntrustedText,
    };

    /// Ann's SIEM collector, taking every record as JSON lines.
    fn siem() -> LogTargetSettings {
        LogTargetSettings {
            destination: LogDestination::Https(
                PublicHttpsUrl::new("https://siem.example.com/ingest").unwrap(),
            ),
            credential: ShippingCredential::Sealed(SealedSecret::new("v1.AAECAwQF").unwrap()),
            records: ShippedRecords::All,
            format: LogFormat::JsonLines,
        }
    }

    /// Datadog in the EU with no credential, which it would refuse.
    fn datadog_without_key() -> LogTargetSettings {
        LogTargetSettings {
            destination: LogDestination::Datadog(DatadogSite::Eu1),
            credential: ShippingCredential::None,
            records: ShippedRecords::All,
            format: LogFormat::JsonLines,
        }
    }

    /// The name "siem".
    fn name() -> Label {
        Label::new("name", "siem").unwrap()
    }

    /// A new target shipping to Ann's SIEM.
    fn target() -> LogShippingTarget<ResolvedTenant> {
        LogShippingTarget::create(LogShippingTargetId::new(), name(), siem(), &routing_admin())
            .unwrap()
    }

    /// The target as it was saved, its creation taken out.
    fn saved() -> LogShippingTarget<ResolvedTenant> {
        let mut target = target();
        raised_names(&mut target);
        target
    }

    /// A finished request with `outcome`.
    fn observed(outcome: RequestOutcome) -> RequestObservation {
        RequestObservation {
            correlation_id: CorrelationId::new(),
            tenant_id: Fact::Known(TenantId::new()),
            route: RouteMatch::NoRoute,
            method: UntrustedText::record("GET"),
            path: ObservedPath::record("/reports"),
            client: IpAddr::from([203, 0, 113, 1]),
            principal: ObservedPrincipal::Anonymous,
            outcome,
            trace: Traced::NotTraced,
            latency: Duration::milliseconds(5),
            classification: Vec::new(),
            policy: Default::default(),
            occurred_at: crate::shared::clock::now(),
        }
    }

    /// A request the gateway refused for want of a route.
    fn denied() -> RequestObservation {
        observed(RequestOutcome::Denied {
            status: 404,
            reason: "no route".to_owned(),
            decided_by: DecidingStage::Gateway(GatewayCheck::Route),
            rule: DecidingRule::Unnamed,
        })
    }

    /// A request forwarded and answered with 200.
    fn allowed() -> RequestObservation {
        observed(RequestOutcome::Allowed {
            upstream_status: 200,
        })
    }

    /// Creating a SIEM target with only routing-view permission returns
    /// `Forbidden`.
    #[test]
    fn creating_a_target_needs_the_create_right() {
        let created = LogShippingTarget::<ResolvedTenant>::create(
            LogShippingTargetId::new(),
            name(),
            siem(),
            &routing_viewer(),
        );

        assert!(matches!(created, Err(DomainError::Forbidden(_))));
    }

    /// A Datadog target with no API key would have every batch refused. It
    /// is refused when created.
    #[test]
    fn a_destination_needing_a_credential_is_refused_without_one() {
        let created = LogShippingTarget::<ResolvedTenant>::create(
            LogShippingTargetId::new(),
            name(),
            datadog_without_key(),
            &routing_admin(),
        );

        assert!(matches!(created, Err(DomainError::Validation(_))));
    }

    /// Ann creates a target and renames it before its first save. Only the
    /// creation is raised.
    #[test]
    fn creating_raises_only_the_creation() {
        let mut target = target();

        target
            .rename(Label::new("name", "siem-eu").unwrap(), &routing_admin())
            .unwrap();

        assert_eq!(raised_names(&mut target), ["proxy.log_target_created"]);
    }

    /// Ann narrows a saved target to refusals and renames it in one edit.
    /// One change is raised.
    #[test]
    fn several_changes_before_a_save_raise_one_change() {
        let mut target = saved();

        target
            .change_settings(
                LogTargetSettings {
                    records: ShippedRecords::DeniedOnly,
                    ..siem()
                },
                &routing_admin(),
            )
            .unwrap();
        target
            .rename(Label::new("name", "siem-eu").unwrap(), &routing_admin())
            .unwrap();

        assert_eq!(raised_names(&mut target), ["proxy.log_target_changed"]);
        assert_eq!(target.records(), ShippedRecords::DeniedOnly);
    }

    /// A routing viewer's attempts to repoint and pause a saved target both
    /// return `Forbidden`, and the target remains active.
    #[test]
    fn a_viewer_cannot_repoint_or_pause_a_target() {
        let mut target = saved();
        let elsewhere = LogTargetSettings {
            destination: LogDestination::Https(
                PublicHttpsUrl::new("https://sam.example.net/collect").unwrap(),
            ),
            ..siem()
        };

        let repointed = target.change_settings(elsewhere, &routing_viewer());
        let paused = target.pause(&routing_viewer());

        assert!(matches!(repointed, Err(DomainError::Forbidden(_))));
        assert!(matches!(paused, Err(DomainError::Forbidden(_))));
        assert_eq!(target.status(), LogTargetStatus::Active);
    }

    /// Ann pauses a target and resumes it. Each is raised, and a paused
    /// target ships nothing.
    #[test]
    fn a_paused_target_ships_nothing_until_resumed() {
        let mut target = saved();

        target.pause(&routing_admin()).unwrap();
        assert!(!target.ships(&denied()));
        target.resume(&routing_admin()).unwrap();

        assert!(target.ships(&denied()));
        assert_eq!(
            raised_names(&mut target),
            ["proxy.log_target_paused", "proxy.log_target_resumed"]
        );
    }

    /// Pausing a target that is already paused is refused.
    #[test]
    fn a_paused_target_cannot_be_paused_again() {
        let mut target = saved();
        target.pause(&routing_admin()).unwrap();

        let again = target.pause(&routing_admin());

        assert!(matches!(again, Err(DomainError::InvalidTransition(_))));
    }

    /// A routing editor's deletion is forbidden; an administrator can then
    /// delete the target, raising exactly one deletion event.
    #[test]
    fn deleting_a_target_needs_the_delete_right() {
        let mut target = saved();

        assert!(matches!(
            target.delete(&routing_editor()),
            Err(DomainError::Forbidden(_))
        ));
        target.delete(&routing_admin()).unwrap();
        assert_eq!(raised_names(&mut target), ["proxy.log_target_deleted"]);
    }

    /// A target shipping refusals only ships the refused request and not
    /// the allowed one.
    #[test]
    fn a_denied_only_target_ships_only_refusals() {
        let records = ShippedRecords::DeniedOnly;

        assert!(records.selects(&denied()));
        assert!(!records.selects(&allowed()));
    }

    /// A one-percent sampling selection includes each of 50 denied
    /// request observations.
    #[test]
    fn sampling_never_drops_a_refusal() {
        let records = ShippedRecords::Sampled(SamplePercent::new(1).unwrap());

        for _ in 0..50 {
            assert!(records.selects(&denied()));
        }
    }

    /// A target sampling 100 percent ships every allowed request.
    #[test]
    fn a_full_sample_ships_every_request() {
        let records = ShippedRecords::Sampled(SamplePercent::new(100).unwrap());

        assert!(records.selects(&allowed()));
    }

    /// A stored Datadog target with no credential is refused as corrupt. A
    /// valid stored target reads back.
    #[test]
    fn a_stored_target_missing_its_credential_is_refused() {
        let now = crate::shared::clock::now();
        let row = |settings| LogShippingTargetRow {
            id: LogShippingTargetId::new(),
            name: name(),
            settings,
            status: LogTargetStatus::Active,
            created_at: now,
            updated_at: now,
        };

        assert!(LogShippingTarget::<ResolvedTenant>::reconstitute(row(siem())).is_ok());
        assert!(refused_as_corrupt(
            &LogShippingTarget::<ResolvedTenant>::reconstitute(row(datadog_without_key()))
        ));
    }
}
