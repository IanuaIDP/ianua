//! Streaming a tenant's audit records to the SIEM it runs.
//!
//! Ann's security team keeps every record in Splunk. She adds a stream to
//! Acme's tenant that names the collector and its token, and a worker sends
//! each new record there. A collector that keeps refusing records pauses
//! the stream on its own after [`FAILURES_BEFORE_PAUSE`] tries in a row, so
//! a dead endpoint is not called forever; Ann resumes it once it is fixed.
//!
//! A stream sends every record out of the platform. So adding one, or
//! pointing one somewhere else, needs the compliance right and a fresh
//! proof of the person: Mallory, holding a stolen admin session, cannot
//! quietly copy the tenant's whole history to a server of her own.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::audit::streaming::{StreamDestination, StreamFilter};
use crate::domains::identity::account::control::RecentProof;
use crate::domains::tenant::control::{TenantArea, TenantControl};
use crate::domains::tenant::events::audit_streams::{
    AuditStreamChanged, AuditStreamCreated, AuditStreamPaused, AuditStreamRemoved,
    AuditStreamResumed,
};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::types::{AuditStreamId, Label};

/// The most audit streams one tenant keeps.
pub const MAX_AUDIT_STREAMS: usize = 5;

/// How many failed sends in a row pause a stream on its own.
pub const FAILURES_BEFORE_PAUSE: u32 = 10;

/// Why a stream stopped sending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauseReason {
    /// An administrator paused it.
    ByAdministrator,
    /// Its destination refused [`FAILURES_BEFORE_PAUSE`] sends in a row.
    AfterFailures,
}

impl PauseReason {
    /// The stable name storage and records use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ByAdministrator => "by_administrator",
            Self::AfterFailures => "after_failures",
        }
    }
}

/// Whether a stream is sending, and how it is going.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Records are sent, and the last send worked.
    Active,
    /// Records are sent, but the destination has refused the last ones.
    Failing {
        /// When the first of these failures happened.
        since: OffsetDateTime,
        /// How many sends in a row failed.
        failures: u32,
    },
    /// Nothing is sent.
    Paused {
        /// Why.
        reason: PauseReason,
        /// Since when.
        at: OffsetDateTime,
    },
}

/// What adding a stream asks for.
#[derive(Debug, Clone)]
pub struct NewAuditStream {
    /// The id the stream is kept under, chosen before it is made so its
    /// credentials can be sealed for it.
    pub id: AuditStreamId,
    /// What it is called, such as "Splunk production".
    pub name: Label,
    /// Where records go.
    pub destination: StreamDestination,
    /// Which records go.
    pub filter: StreamFilter,
    /// How many streams the tenant has already.
    pub existing_streams: usize,
}

/// What reconfiguring a stream sets: all three parts at once, as a form
/// saves them.
#[derive(Debug, Clone)]
pub struct StreamSettings {
    /// What it is called.
    pub name: Label,
    /// Where records go.
    pub destination: StreamDestination,
    /// Which records go.
    pub filter: StreamFilter,
}

/// An [`AuditStream`] as storage holds it, read back through
/// [`AuditStream::reconstitute`].
pub struct AuditStreamRow {
    /// The stream.
    pub id: AuditStreamId,
    /// What it is called.
    pub name: Label,
    /// Where records go.
    pub destination: StreamDestination,
    /// Which records go.
    pub filter: StreamFilter,
    /// Whether it is sending.
    pub state: StreamState,
    /// When it was created.
    pub created_at: OffsetDateTime,
    /// When it last changed.
    pub updated_at: OffsetDateTime,
}

/// One stream of a tenant's audit records to a SIEM.
#[derive(Debug)]
pub struct AuditStream<T: TenantScope> {
    id: AuditStreamId,
    name: Label,
    destination: StreamDestination,
    filter: StreamFilter,
    state: StreamState,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> AuditStream<T> {
    /// Adds a stream to the tenant `scope` stands for, as `by` decides with
    /// `proof` that they proved who they are just now. It starts sending at
    /// once. Raises `tenant.audit_stream_created`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change the tenant's
    ///   compliance settings, or did not prove who they are just now.
    /// - [`DomainError::Conflict`] when the tenant already has
    ///   [`MAX_AUDIT_STREAMS`] streams.
    pub fn create(
        new: NewAuditStream,
        scope: &T,
        by: TenantControl<'_>,
        proof: &impl RecentProof,
    ) -> Result<Self, DomainError> {
        ensure_trusted(scope, by, proof)?;
        if new.existing_streams >= MAX_AUDIT_STREAMS {
            return Err(DomainError::conflict(message!(
                "tenant-a-tenant-keeps-at-most-audit",
                format!("a tenant keeps at most {MAX_AUDIT_STREAMS} audit streams")
            )));
        }
        let now = crate::shared::clock::now();
        let mut stream = Self {
            id: new.id,
            name: new.name,
            destination: new.destination,
            filter: new.filter,
            state: StreamState::Active,
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        stream.raised.raise(AuditStreamCreated {
            stream_id: stream.id,
            name: stream.name.clone(),
            kind: stream.destination.kind(),
            occurred_at: now,
        });
        Ok(stream)
    }

    /// Rebuilds a stream from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row changed before it was
    ///   created, or is failing with no failure counted or with enough
    ///   failures counted to have paused.
    pub fn reconstitute(row: AuditStreamRow) -> Result<Self, DomainError> {
        check_row(&row)?;
        Ok(Self {
            id: row.id,
            name: row.name,
            destination: row.destination,
            filter: row.filter,
            state: row.state,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// The stream.
    #[must_use]
    pub fn id(&self) -> &AuditStreamId {
        &self.id
    }

    /// What it is called.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// Where records go.
    #[must_use]
    pub fn destination(&self) -> &StreamDestination {
        &self.destination
    }

    /// Which records go.
    #[must_use]
    pub fn filter(&self) -> &StreamFilter {
        &self.filter
    }

    /// Whether it is sending, and how it is going.
    #[must_use]
    pub fn state(&self) -> StreamState {
        self.state
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

    /// Whether records are sent now.
    #[must_use]
    pub fn is_sending(&self) -> bool {
        !matches!(self.state, StreamState::Paused { .. })
    }

    /// Replaces the stream's name, destination and filter, as `by` decides
    /// with `proof` that they proved who they are just now. A failing
    /// stream starts counting again, since the destination may be new.
    /// Raises `tenant.audit_stream_changed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change the tenant's
    ///   compliance settings, or did not prove who they are just now.
    pub fn reconfigure(
        &mut self,
        settings: StreamSettings,
        scope: &T,
        by: TenantControl<'_>,
        proof: &impl RecentProof,
    ) -> Result<(), DomainError> {
        ensure_trusted(scope, by, proof)?;
        let old_kind = self.destination.kind();
        self.name = settings.name;
        self.destination = settings.destination;
        self.filter = settings.filter;
        if matches!(self.state, StreamState::Failing { .. }) {
            self.state = StreamState::Active;
        }
        self.touch();
        self.raised.raise(AuditStreamChanged {
            stream_id: self.id,
            name: self.name.clone(),
            old_kind,
            new_kind: self.destination.kind(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Stops sending, as `by` decides. Raises `tenant.audit_stream_paused`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change the tenant's
    ///   compliance settings.
    /// - [`DomainError::Conflict`] when the stream is already paused.
    pub fn pause(&mut self, scope: &T, by: TenantControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(scope.tenant_id(), TenantArea::AuditStreaming)?;
        self.ensure_sending()?;
        self.pause_for(PauseReason::ByAdministrator);
        Ok(())
    }

    /// Starts sending again, as `by` decides. Raises
    /// `tenant.audit_stream_resumed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change the tenant's
    ///   compliance settings.
    /// - [`DomainError::Conflict`] when the stream is not paused.
    pub fn resume(&mut self, scope: &T, by: TenantControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(scope.tenant_id(), TenantArea::AuditStreaming)?;
        if self.is_sending() {
            return Err(DomainError::conflict(message!(
                "tenant-the-stream-is-not-paused",
                "the stream is not paused"
            )));
        }
        self.state = StreamState::Active;
        self.touch();
        self.raised.raise(AuditStreamResumed {
            stream_id: self.id,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Removes the stream, as `by` decides. Raises
    /// `tenant.audit_stream_removed`; the caller takes it once the stream
    /// is deleted.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change the tenant's
    ///   compliance settings.
    pub fn remove(&mut self, scope: &T, by: TenantControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(scope.tenant_id(), TenantArea::AuditStreaming)?;
        self.raised.raise(AuditStreamRemoved {
            stream_id: self.id,
            name: self.name.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Records that a send worked. A failing stream is active again.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when the stream is paused, so nothing
    ///   was sent.
    pub fn record_delivered(&mut self) -> Result<(), DomainError> {
        self.ensure_sending()?;
        if self.state != StreamState::Active {
            self.state = StreamState::Active;
            self.touch();
        }
        Ok(())
    }

    /// Records that a send failed. After [`FAILURES_BEFORE_PAUSE`] in a row
    /// the stream pauses itself and raises `tenant.audit_stream_paused`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when the stream is paused, so nothing
    ///   was sent.
    pub fn record_failed(&mut self) -> Result<(), DomainError> {
        self.ensure_sending()?;
        let now = crate::shared::clock::now();
        let (since, failures) = match self.state {
            StreamState::Failing { since, failures } => (since, failures.saturating_add(1)),
            StreamState::Active | StreamState::Paused { .. } => (now, 1),
        };
        if failures >= FAILURES_BEFORE_PAUSE {
            self.pause_for(PauseReason::AfterFailures);
            return Ok(());
        }
        self.state = StreamState::Failing { since, failures };
        self.touch();
        Ok(())
    }

    /// Pauses the stream for `reason` and raises it.
    fn pause_for(&mut self, reason: PauseReason) {
        self.touch();
        self.state = StreamState::Paused {
            reason,
            at: self.updated_at,
        };
        self.raised.raise(AuditStreamPaused {
            stream_id: self.id,
            reason,
            occurred_at: self.updated_at,
        });
    }

    /// Refuses a step that needs the stream to be sending.
    fn ensure_sending(&self) -> Result<(), DomainError> {
        if !self.is_sending() {
            return Err(DomainError::conflict(message!(
                "tenant-the-stream-is-paused",
                "the stream is paused"
            )));
        }
        Ok(())
    }

    /// Bumps the `updated_at` timestamp.
    fn touch(&mut self) {
        self.updated_at = crate::shared::clock::now();
    }
}

impl<T: TenantScope> Raises for AuditStream<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// Refuses `by` sending the tenant's records somewhere new unless they may
/// change its compliance settings and proved who they are just now.
fn ensure_trusted<T: TenantScope>(
    scope: &T,
    by: TenantControl<'_>,
    proof: &impl RecentProof,
) -> Result<(), DomainError> {
    by.ensure_may(scope.tenant_id(), TenantArea::AuditStreaming)?;
    by.ensure_proved_recently(proof)
}

/// Refuses a stored stream that breaks a rule the stream keeps.
fn check_row(row: &AuditStreamRow) -> Result<(), DomainError> {
    let counted = match row.state {
        StreamState::Failing { failures, .. } => (1..FAILURES_BEFORE_PAUSE).contains(&failures),
        StreamState::Active | StreamState::Paused { .. } => true,
    };
    RowCheck::of("audit_stream")
        .in_order(
            row.created_at,
            row.updated_at,
            "changed before it was created",
        )
        .holds(
            counted,
            "a failure count that is none, or enough to have paused",
        )
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::audit::streaming::{DatadogSite, DatadogTarget, SplunkIndex, SplunkTarget};
    use crate::domains::authorization::permission::{ComplianceAction, SystemPermission};
    use crate::domains::tenant::fixtures::{ADMIN, ProvedJustNow, active, holding, person};
    use crate::domains::tenant::lifecycle::Tenant;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::clock::freeze;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::builders::label;
    use crate::test_support::events::raised_names;
    use crate::types::{PublicHttpsUrl, SealedSecret};

    type Stream = AuditStream<ResolvedTenant>;

    const VIEW_ONLY: &[SystemPermission] = &[SystemPermission::Compliance(ComplianceAction::View)];

    fn scope_of(tenant: &Tenant) -> ResolvedTenant {
        ResolvedTenant::new(*tenant.id(), tenant.slug().clone())
    }

    fn splunk() -> StreamDestination {
        StreamDestination::Splunk(SplunkTarget::new(
            PublicHttpsUrl::new("https://splunk.acme.com:8088/services/collector").unwrap(),
            SealedSecret::new("v1.c3BsdW5r").unwrap(),
            SplunkIndex::TokenDefault,
        ))
    }

    fn datadog() -> StreamDestination {
        StreamDestination::Datadog(DatadogTarget::new(
            DatadogSite::Eu1,
            SealedSecret::new("v1.ZGF0YWRvZw").unwrap(),
        ))
    }

    fn new_stream(existing_streams: usize) -> NewAuditStream {
        NewAuditStream {
            id: AuditStreamId::new(),
            name: label("Splunk production"),
            destination: splunk(),
            filter: StreamFilter::everything(),
            existing_streams,
        }
    }

    /// Ann, an admin who just signed in again, streams Acme's records to
    /// Splunk.
    fn anns_stream(tenant: &Tenant) -> Stream {
        let ann = person("ann@acme.test");
        Stream::create(
            new_stream(0),
            &scope_of(tenant),
            holding(&ann, tenant, ADMIN),
            &ProvedJustNow::by(&ann),
        )
        .unwrap()
    }

    /// Ann adds a Splunk stream. It sends at once and raises
    /// `tenant.audit_stream_created`, which names Splunk and no token.
    #[test]
    fn an_admin_adds_a_stream() {
        let acme = active();

        let mut stream = anns_stream(&acme);

        assert_eq!(stream.state(), StreamState::Active);
        let events = crate::test_support::events::raised(&mut stream);
        assert_eq!(events[0].payload().get("destination"), Some("splunk"));
        assert!(
            !format!("{:?}", events[0].payload()).contains("c3BsdW5r"),
            "the record carries the token"
        );
    }

    /// A compliance viewer cannot create an audit stream, even with fresh proof.
    #[test]
    fn a_viewer_cannot_add_a_stream() {
        let acme = active();
        let sam = person("sam@acme.test");

        let refused = Stream::create(
            new_stream(0),
            &scope_of(&acme),
            holding(&sam, &acme, VIEW_ONLY),
            &ProvedJustNow::by(&sam),
        );

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Proof from another person cannot authorize creating or redirecting an
    /// audit stream. The existing stream keeps its Splunk destination.
    #[test]
    fn a_stream_needs_a_fresh_proof_of_the_person() {
        let acme = active();
        let ann = person("ann@acme.test");
        let mallory = person("mallory@evil.test");
        let mut stream = anns_stream(&acme);

        let added = Stream::create(
            new_stream(0),
            &scope_of(&acme),
            holding(&ann, &acme, ADMIN),
            &ProvedJustNow::by(&mallory),
        );
        let moved = stream.reconfigure(
            StreamSettings {
                name: label("Splunk production"),
                destination: datadog(),
                filter: StreamFilter::everything(),
            },
            &scope_of(&acme),
            holding(&ann, &acme, ADMIN),
            &ProvedJustNow::by(&mallory),
        );

        assert!(matches!(added, Err(DomainError::Forbidden(_))));
        assert!(matches!(moved, Err(DomainError::Forbidden(_))));
        assert_eq!(stream.destination(), &splunk());
    }

    /// Administrative rights in another tenant cannot pause this tenant's stream.
    #[test]
    fn what_someone_holds_elsewhere_moves_no_stream() {
        let acme = active();
        let theirs = active();
        let eve = person("eve@other.test");
        let mut stream = anns_stream(&acme);

        let refused = stream.pause(&scope_of(&acme), holding(&eve, &theirs, ADMIN));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// A tenant with five streams adds a sixth. It is refused.
    #[test]
    fn a_tenant_keeps_a_bounded_number_of_streams() {
        let acme = active();
        let ann = person("ann@acme.test");

        let refused = Stream::create(
            new_stream(MAX_AUDIT_STREAMS),
            &scope_of(&acme),
            holding(&ann, &acme, ADMIN),
            &ProvedJustNow::by(&ann),
        );

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
    }

    /// Ann moves her stream to Datadog. The record shows the move from
    /// Splunk to Datadog.
    #[test]
    fn an_admin_moves_a_stream_to_another_destination() {
        let acme = active();
        let ann = person("ann@acme.test");
        let mut stream = anns_stream(&acme);
        let _ = raised_names(&mut stream);

        stream
            .reconfigure(
                StreamSettings {
                    name: label("Datadog EU"),
                    destination: datadog(),
                    filter: StreamFilter::everything(),
                },
                &scope_of(&acme),
                holding(&ann, &acme, ADMIN),
                &ProvedJustNow::by(&ann),
            )
            .unwrap();

        assert_eq!(stream.destination(), &datadog());
        assert_eq!(
            raised_names(&mut stream),
            vec!["tenant.audit_stream_changed"]
        );
    }

    /// The collector refuses one send, then takes the next. The stream is
    /// failing in between and active again after.
    #[test]
    fn a_send_that_works_clears_the_failures() {
        let acme = active();
        let mut stream = anns_stream(&acme);

        stream.record_failed().unwrap();
        assert!(matches!(
            stream.state(),
            StreamState::Failing { failures: 1, .. }
        ));
        stream.record_delivered().unwrap();

        assert_eq!(stream.state(), StreamState::Active);
    }

    /// The collector is down and refuses ten sends in a row. The stream
    /// pauses itself and raises `tenant.audit_stream_paused`, so the dead
    /// endpoint is not called forever.
    #[test]
    fn a_stream_failing_again_and_again_pauses_itself() {
        let _clock = freeze(crate::shared::clock::now());
        let acme = active();
        let mut stream = anns_stream(&acme);
        let _ = raised_names(&mut stream);

        for _ in 0..FAILURES_BEFORE_PAUSE {
            stream.record_failed().unwrap();
        }

        assert!(matches!(
            stream.state(),
            StreamState::Paused {
                reason: PauseReason::AfterFailures,
                ..
            }
        ));
        assert_eq!(
            raised_names(&mut stream),
            vec!["tenant.audit_stream_paused"]
        );
        assert!(matches!(
            stream.record_failed(),
            Err(DomainError::Conflict(_))
        ));
    }

    /// Ann pauses her stream and resumes it. Pausing twice and resuming a
    /// stream that sends are refused.
    #[test]
    fn an_admin_pauses_and_resumes_a_stream() {
        let acme = active();
        let ann = person("ann@acme.test");
        let mut stream = anns_stream(&acme);
        let scope = scope_of(&acme);

        stream.pause(&scope, holding(&ann, &acme, ADMIN)).unwrap();
        assert!(!stream.is_sending());
        assert!(matches!(
            stream.pause(&scope, holding(&ann, &acme, ADMIN)),
            Err(DomainError::Conflict(_))
        ));
        stream.resume(&scope, holding(&ann, &acme, ADMIN)).unwrap();

        assert!(stream.is_sending());
        assert!(matches!(
            stream.resume(&scope, holding(&ann, &acme, ADMIN)),
            Err(DomainError::Conflict(_))
        ));
    }

    /// A compliance viewer cannot remove an audit stream, and the refusal
    /// raises no event.
    #[test]
    fn a_viewer_cannot_remove_a_stream() {
        let acme = active();
        let sam = person("sam@acme.test");
        let mut stream = anns_stream(&acme);
        let _ = raised_names(&mut stream);

        let refused = stream.remove(&scope_of(&acme), holding(&sam, &acme, VIEW_ONLY));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert!(raised_names(&mut stream).is_empty());
    }

    fn row_of(stream: &Stream) -> AuditStreamRow {
        AuditStreamRow {
            id: stream.id,
            name: stream.name.clone(),
            destination: stream.destination.clone(),
            filter: stream.filter.clone(),
            state: stream.state,
            created_at: stream.created_at,
            updated_at: stream.updated_at,
        }
    }

    /// A stream is stored and read back as it was, with nothing raised.
    #[test]
    fn a_stored_stream_reads_back() {
        let acme = active();
        let stream = anns_stream(&acme);

        let mut read = Stream::reconstitute(row_of(&stream)).unwrap();

        assert_eq!(read.destination(), stream.destination());
        assert!(raised_names(&mut read).is_empty());
    }

    /// Failing stream rows with zero failures or enough failures to require a
    /// pause are rejected as corrupt.
    #[test]
    fn a_stored_stream_breaking_its_rules_is_refused() {
        let acme = active();
        let stream = anns_stream(&acme);
        let since = stream.created_at;
        let no_failure = AuditStreamRow {
            state: StreamState::Failing { since, failures: 0 },
            ..row_of(&stream)
        };
        let past_pausing = AuditStreamRow {
            state: StreamState::Failing {
                since,
                failures: FAILURES_BEFORE_PAUSE,
            },
            ..row_of(&stream)
        };

        assert!(refused_as_corrupt(&Stream::reconstitute(no_failure)));
        assert!(refused_as_corrupt(&Stream::reconstitute(past_pausing)));
    }
}
