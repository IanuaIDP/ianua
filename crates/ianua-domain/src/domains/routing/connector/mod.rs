//! Private-network connectors: how the gateway reaches upstreams that have
//! no public address.
//!
//! A tenant runs a small agent inside its own network. It dials out to the
//! gateway and holds a link open, so nothing in the network has to accept
//! connections from the internet. Requests for an upstream reached through
//! it travel down that link, and the connector dials the backend from
//! inside.
//!
//! An admin creates the connector with a one-time enrollment code. The
//! agent presents the code once, with a signing request for the key it
//! holds its link with from then on (see [`enrollment`]). The code is
//! spent on use and expires within the hour.

pub mod certificate;
pub mod enrollment;
pub mod scope;
pub mod sighting;
pub mod tunnel;

use std::marker::PhantomData;

pub use enrollment::ConnectorEnrollment;
pub use sighting::LastSeen;
use time::OffsetDateTime;

use crate::domains::routing::connector::certificate::ConnectorCertificate;
use crate::domains::routing::connector::enrollment::{
    ENROLLMENT_WINDOW, enrollment_refused, renewal_refused,
};
use crate::domains::routing::connector::scope::ConnectorScope;
use crate::domains::routing::control::{RoutingControl, RoutingRight};
use crate::domains::routing::events::{ConnectorChange, ConnectorChanged};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::shared::model::transition::{InvalidTransition, checked};
use crate::types::{ConnectorId, Label, PublicKeyPin, TokenHash};

/// Whether a connector may carry traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ConnectorStatus {
    /// It carries traffic once enrolled.
    Active,
    /// Its link is refused and every upstream reached through it is
    /// unreachable. For good: a connector whose key may have leaked is
    /// replaced, not trusted again.
    Revoked,
}

impl ConnectorStatus {
    /// Moves to `to`. Only an active connector is revoked, and a revoked
    /// one stays revoked.
    ///
    /// # Errors
    ///
    /// - [`InvalidTransition`] for any other move.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidTransition<Self>> {
        checked(self, to, |from, to| {
            matches!((from, to), (Self::Active, Self::Revoked))
        })
    }
}

/// What a new connector is created with.
pub struct CreateConnectorParams {
    /// Name, shown in the dashboard and unique within the tenant.
    pub name: Label,
    /// What it may be asked to dial.
    pub scope: ConnectorScope,
    /// The digest of the one-time enrollment code shown to the admin.
    pub code_hash: TokenHash,
}

/// A [`PrivateConnector`] as storage holds it, read back through
/// [`PrivateConnector::reconstitute`].
pub struct PrivateConnectorRow {
    /// The connector's id.
    pub id: ConnectorId,
    /// Name, unique within the tenant.
    pub name: Label,
    /// What it may be asked to dial.
    pub scope: ConnectorScope,
    /// Where its enrollment stands.
    pub enrollment: ConnectorEnrollment,
    /// Whether it may carry traffic.
    pub status: ConnectorStatus,
    /// When the gateway last saw its link.
    pub last_seen: LastSeen,
    /// When it was created.
    pub created_at: OffsetDateTime,
    /// When it last changed.
    pub updated_at: OffsetDateTime,
}

/// An agent inside a tenant's network that the gateway reaches private
/// upstreams through.
///
/// Tenant-scoped: read and written only through stores opened for the
/// resolved tenant (see [`crate::isolation`]).
///
/// Every change an admin makes needs the routing right, held by a person
/// signed in to the tenant. Without this rule, Sam widens the scope of a
/// connector in the payroll network and points a route at the database
/// behind it.
#[derive(Debug, Clone)]
pub struct PrivateConnector<T: TenantScope> {
    id: ConnectorId,
    name: Label,
    scope: ConnectorScope,
    enrollment: ConnectorEnrollment,
    status: ConnectorStatus,
    last_seen: LastSeen,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> PrivateConnector<T> {
    /// Creates a connector awaiting enrollment, on behalf of `by`. Its code
    /// is good for an hour. Raises `routing.connector_created`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not create routing.
    pub fn create(
        params: CreateConnectorParams,
        by: &RoutingControl<'_>,
    ) -> Result<Self, DomainError> {
        by.ensure_may(RoutingRight::Create)?;
        let now = crate::shared::clock::now();
        let mut connector = Self {
            id: ConnectorId::new(),
            name: params.name,
            scope: params.scope,
            enrollment: ConnectorEnrollment::Awaiting {
                code_hash: params.code_hash,
                expires_at: now.saturating_add(ENROLLMENT_WINDOW),
            },
            status: ConnectorStatus::Active,
            last_seen: LastSeen::Never,
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        connector.record_change(ConnectorChange::Created);
        Ok(connector)
    }

    /// Rebuilds a connector from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when its code was good for longer
    ///   than an hour after it was made.
    /// - [`DomainError::Infrastructure`] when it enrolled before it was
    ///   created, or its certificate ends before the enrollment or more
    ///   than a day after the connector last changed.
    /// - [`DomainError::Infrastructure`] when it was seen before it
    ///   enrolled, or without enrolling.
    /// - [`DomainError::Infrastructure`] when it changed before it was
    ///   created.
    pub fn reconstitute(row: PrivateConnectorRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            name: row.name,
            scope: row.scope,
            enrollment: row.enrollment,
            status: row.status,
            last_seen: row.last_seen,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &PrivateConnectorRow) -> Result<(), DomainError> {
        RowCheck::of("connector")
            .holds(
                row.enrollment.fits(row.created_at, row.updated_at),
                "an enrollment outside its window",
            )
            .holds(
                row.last_seen.fits(&row.enrollment),
                "seen before it enrolled",
            )
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was created",
            )
            .finish()
    }

    /// The connector's id.
    #[must_use]
    pub fn id(&self) -> &ConnectorId {
        &self.id
    }

    /// Name, unique within the tenant.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// What it may be asked to dial.
    #[must_use]
    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    /// Where its enrollment stands.
    #[must_use]
    pub fn enrollment(&self) -> &ConnectorEnrollment {
        &self.enrollment
    }

    /// The certificate it holds now, once enrolled.
    #[must_use]
    pub fn certificate(&self) -> Option<ConnectorCertificate> {
        self.enrollment.certificate()
    }

    /// Whether it may carry traffic.
    #[must_use]
    pub fn status(&self) -> ConnectorStatus {
        self.status
    }

    /// When the gateway last saw its link.
    #[must_use]
    pub fn last_seen(&self) -> LastSeen {
        self.last_seen
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

    /// Whether a link held with a certificate for `key` is this
    /// connector's, enrolled and not revoked.
    #[must_use]
    pub fn admits_tunnel(&self, key: &PublicKeyPin) -> bool {
        let ConnectorEnrollment::Enrolled { key: enrolled, .. } = &self.enrollment else {
            return false;
        };
        self.status == ConnectorStatus::Active && enrolled == key
    }

    /// Enrolls the agent that presented `code`, the digest of the one-time
    /// code, with the key `key` its signing request names. Raises
    /// `routing.connector_enrolled`.
    ///
    /// Answers the certificate the authority is to sign: for `key`, good
    /// for a day from now.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the connector is revoked, already
    ///   enrolled, its code has expired, or `code` is not its code. The
    ///   refusal says no more, so a guesser learns nothing.
    pub fn enroll(
        &mut self,
        code: &TokenHash,
        key: PublicKeyPin,
    ) -> Result<ConnectorCertificate, DomainError> {
        let now = crate::shared::clock::now();
        let ConnectorEnrollment::Awaiting {
            code_hash,
            expires_at,
        } = &self.enrollment
        else {
            return Err(enrollment_refused());
        };
        if self.status != ConnectorStatus::Active || now >= *expires_at || code_hash != code {
            return Err(enrollment_refused());
        }
        let certificate = ConnectorCertificate::issued(key, now);
        self.enrollment = ConnectorEnrollment::Enrolled {
            key,
            certificate_expires_at: certificate.expires_at(),
            enrolled_at: now,
        };
        self.updated_at = now;
        self.record_change(ConnectorChange::Enrolled);
        Ok(certificate)
    }

    /// Renews the certificate of the agent whose new signing request names
    /// `key`, and answers the certificate the authority is to sign.
    ///
    /// Once due, the certificate is for the same key, good for a day from
    /// now, and `routing.connector_renewed` is raised. Before then nothing
    /// changes and the answer is the certificate the connector holds now,
    /// ending when it ends: an agent whose last answer was lost gets it
    /// again, and asking early never lengthens what it holds.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the connector is revoked, not
    ///   enrolled, or `key` is not the key it enrolled with. The refusal
    ///   says no more.
    pub fn renew(&mut self, key: &PublicKeyPin) -> Result<ConnectorCertificate, DomainError> {
        let now = crate::shared::clock::now();
        let ConnectorEnrollment::Enrolled {
            key: enrolled,
            certificate_expires_at,
            enrolled_at,
        } = &self.enrollment
        else {
            return Err(renewal_refused());
        };
        if self.status != ConnectorStatus::Active || enrolled != key {
            return Err(renewal_refused());
        }
        let held = ConnectorCertificate::held(*enrolled, *certificate_expires_at);
        if !held.is_due(now) {
            return Ok(held);
        }
        let certificate = ConnectorCertificate::issued(*key, now);
        self.enrollment = ConnectorEnrollment::Enrolled {
            key: *key,
            certificate_expires_at: certificate.expires_at(),
            enrolled_at: *enrolled_at,
        };
        self.updated_at = now;
        self.record_change(ConnectorChange::Renewed);
        Ok(certificate)
    }

    /// Replaces what the connector may be asked to dial. Raises
    /// `routing.connector_updated`.
    ///
    /// Upstreams already reached through it keep their addresses. The
    /// caller checks each of them against the new scope with
    /// [`ConnectorScope::ensure_permits`] first, and the gateway refuses any
    /// that fall outside it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    /// - [`DomainError::InvalidTransition`] when the connector is revoked.
    pub fn change_scope(
        &mut self,
        scope: ConnectorScope,
        by: &RoutingControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        self.ensure_active()?;
        self.scope = scope;
        self.updated_at = crate::shared::clock::now();
        self.record_change(ConnectorChange::Updated);
        Ok(())
    }

    /// Revokes the connector for good: its link is refused, its next
    /// certificate is refused, and nothing is sent through it again.
    /// Raises `routing.connector_revoked`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    /// - [`DomainError::InvalidTransition`] when it is already revoked.
    pub fn revoke(&mut self, by: &RoutingControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        self.status = self.status.try_transition(ConnectorStatus::Revoked)?;
        self.updated_at = crate::shared::clock::now();
        self.record_change(ConnectorChange::Revoked);
        Ok(())
    }

    /// Deletes the connector once `by` may delete routing, it is revoked and
    /// no upstream is reached through it. `reaching` is how many services
    /// are reached through it, as stored. Raises
    /// `routing.connector_deleted`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not delete routing.
    /// - [`DomainError::InvalidTransition`] while it is active.
    /// - [`DomainError::Conflict`] while a service is reached through it.
    pub fn delete(&mut self, reaching: usize, by: &RoutingControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Delete)?;
        if self.status == ConnectorStatus::Active {
            return Err(DomainError::invalid_transition(message!(
                "routing-a-connector-is-revoked-before-it",
                "a connector is revoked before it is deleted"
            )));
        }
        if reaching > 0 {
            return Err(DomainError::conflict(message!(
                "routing-services-are-still-reached-through-this",
                "services are still reached through this connector"
            )));
        }
        self.record_change(ConnectorChange::Deleted);
        Ok(())
    }

    /// Refuses a change to a revoked connector.
    fn ensure_active(&self) -> Result<(), DomainError> {
        if self.status == ConnectorStatus::Revoked {
            return Err(DomainError::invalid_transition(message!(
                "routing-a-revoked-connector-is-not-changed",
                "a revoked connector is not changed"
            )));
        }
        Ok(())
    }

    /// Raises `change` for this connector.
    fn record_change(&mut self, change: ConnectorChange) {
        self.raised.raise(ConnectorChanged {
            connector_id: self.id,
            name: self.name.clone(),
            change,
            occurred_at: crate::shared::clock::now(),
        });
    }
}

impl<T: TenantScope> Raises for PrivateConnector<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

impl<T: TenantScope> Aggregate for PrivateConnector<T> {
    type Id = ConnectorId;

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
    use time::Duration;

    use super::*;
    use crate::domains::routing::fixtures::{routing_admin, routing_editor, routing_viewer};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::builders::label;
    use crate::test_support::events::raised_names;
    use crate::types::{CidrRange, DomainName};

    fn code() -> TokenHash {
        TokenHash::from_stored("code-digest".to_owned())
    }

    fn key(byte: u8) -> PublicKeyPin {
        PublicKeyPin::from_digest([byte; 32])
    }

    fn scope() -> ConnectorScope {
        ConnectorScope::new(
            vec![CidrRange::new("10.20.0.0/16").unwrap()],
            vec![DomainName::new("*.corp.internal").unwrap()],
        )
        .unwrap()
    }

    fn connector() -> PrivateConnector<ResolvedTenant> {
        PrivateConnector::create(
            CreateConnectorParams {
                name: label("payroll-network"),
                scope: scope(),
                code_hash: code(),
            },
            &routing_admin(),
        )
        .unwrap()
    }

    fn enrolled() -> PrivateConnector<ResolvedTenant> {
        let mut connector = connector();
        connector.enroll(&code(), key(1)).unwrap();
        connector
    }

    /// A stored row: created at the epoch, enrolled a minute later with a
    /// day-long certificate, and seen as `last_seen` says.
    fn enrolled_row(last_seen: LastSeen) -> PrivateConnectorRow {
        let created_at = OffsetDateTime::UNIX_EPOCH;
        let enrolled_at = created_at + Duration::minutes(1);
        PrivateConnectorRow {
            id: ConnectorId::new(),
            name: label("payroll-network"),
            scope: scope(),
            enrollment: ConnectorEnrollment::Enrolled {
                key: key(1),
                certificate_expires_at: enrolled_at + Duration::hours(24),
                enrolled_at,
            },
            status: ConnectorStatus::Active,
            last_seen,
            created_at,
            updated_at: enrolled_at,
        }
    }

    /// Routing update permission alone cannot create a connector.
    #[test]
    fn creating_a_connector_needs_the_create_right() {
        let created = PrivateConnector::<ResolvedTenant>::create(
            CreateConnectorParams {
                name: label("mine"),
                scope: scope(),
                code_hash: code(),
            },
            &routing_editor(),
        );

        assert!(matches!(created, Err(DomainError::Forbidden(_))));
    }

    /// A wrong enrollment code is forbidden, and the presented key is not
    /// admitted to the connector's tunnel.
    #[test]
    fn a_wrong_code_does_not_enroll() {
        let mut connector = connector();

        let result = connector.enroll(&TokenHash::from_stored("guess".to_owned()), key(2));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(!connector.admits_tunnel(&key(2)));
    }

    /// Reusing an enrollment code with a different key is forbidden after
    /// enrollment. The different key is not admitted to the tunnel.
    #[test]
    fn a_spent_code_does_not_enroll_again() {
        let mut connector = enrolled();

        let again = connector.enroll(&code(), key(2));

        assert!(matches!(again, Err(DomainError::Forbidden(_))));
        assert!(!connector.admits_tunnel(&key(2)));
    }

    /// Enrollment is forbidden two hours after the one-hour code was issued.
    #[test]
    fn an_expired_code_does_not_enroll() {
        let mut connector = connector();
        let _later =
            crate::shared::clock::freeze(connector.created_at().saturating_add(Duration::hours(2)));

        let result = connector.enroll(&code(), key(1));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Revoking a connector makes its enrolled key inadmissible and prevents
    /// scope changes or another revocation.
    #[test]
    fn a_revoked_connector_admits_no_tunnel() {
        let mut connector = enrolled();

        connector.revoke(&routing_admin()).unwrap();

        assert!(!connector.admits_tunnel(&key(1)));
        assert!(connector.change_scope(scope(), &routing_admin()).is_err());
        assert!(connector.revoke(&routing_admin()).is_err());
    }

    /// A routing viewer cannot replace a connector's scope or revoke it.
    #[test]
    fn a_viewer_cannot_change_a_connector() {
        let mut connector = enrolled();

        let widened = connector.change_scope(scope(), &routing_viewer());
        let revoked = connector.revoke(&routing_viewer());

        assert!(matches!(widened, Err(DomainError::Forbidden(_))));
        assert!(matches!(revoked, Err(DomainError::Forbidden(_))));
    }

    /// An active connector, or a revoked one a service is still reached
    /// through, is not deleted. A revoked one nothing uses is.
    #[test]
    fn a_connector_is_deleted_only_once_revoked_and_unused() {
        let mut connector = enrolled();
        assert!(connector.delete(0, &routing_admin()).is_err());

        connector.revoke(&routing_admin()).unwrap();

        assert!(matches!(
            connector.delete(1, &routing_admin()),
            Err(DomainError::Conflict(_))
        ));
        assert!(connector.delete(0, &routing_admin()).is_ok());
    }

    /// Ann creates a connector and its agent enrolls. Creation, then
    /// enrollment are raised.
    #[test]
    fn creating_and_enrolling_are_raised() {
        let mut connector = enrolled();

        assert_eq!(
            raised_names(&mut connector),
            ["routing.connector_created", "routing.connector_enrolled"]
        );
    }

    /// A stored connector whose code was good for a day is refused as a
    /// corrupt row.
    #[test]
    fn a_stored_code_good_for_longer_than_an_hour_is_refused() {
        let created_at = crate::shared::clock::now();
        let row = PrivateConnectorRow {
            id: ConnectorId::new(),
            name: label("payroll-network"),
            scope: scope(),
            enrollment: ConnectorEnrollment::Awaiting {
                code_hash: code(),
                expires_at: created_at.saturating_add(Duration::days(1)),
            },
            status: ConnectorStatus::Active,
            last_seen: LastSeen::Never,
            created_at,
            updated_at: created_at,
        };

        assert!(refused_as_corrupt(
            &PrivateConnector::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored connector seen after it enrolled reads back as seen; one
    /// seen before it enrolled is refused as a corrupt row.
    #[test]
    fn a_stored_sighting_before_the_enrollment_is_refused() {
        let seen = OffsetDateTime::UNIX_EPOCH + Duration::minutes(30);
        let early = OffsetDateTime::UNIX_EPOCH;

        let read =
            PrivateConnector::<ResolvedTenant>::reconstitute(enrolled_row(LastSeen::At(seen)))
                .unwrap();

        assert_eq!(read.last_seen(), LastSeen::At(seen));
        assert!(refused_as_corrupt(
            &PrivateConnector::<ResolvedTenant>::reconstitute(enrolled_row(LastSeen::At(early)))
        ));
    }

    /// Ann's agent enrolls with its key. It is answered a certificate for
    /// that key good for a day, and its link with that key is let in.
    #[test]
    fn enrolling_pins_the_key_and_issues_a_day_long_certificate() {
        let mut connector = connector();

        let certificate = connector.enroll(&code(), key(1)).unwrap();

        assert_eq!(*certificate.key(), key(1));
        assert_eq!(
            certificate.expires_at(),
            connector.updated_at() + Duration::hours(24)
        );
        assert!(connector.admits_tunnel(&key(1)));
        assert!(!connector.admits_tunnel(&key(2)));
    }

    /// Late in the day, the agent asks again for the same key. A new
    /// certificate is issued and the renewal raised.
    #[test]
    fn a_due_certificate_is_renewed_for_the_same_key() {
        let mut connector = enrolled();
        let _later = crate::shared::clock::freeze(
            connector.updated_at().saturating_add(Duration::hours(17)),
        );

        let renewed = connector.renew(&key(1)).unwrap();

        assert_eq!(*renewed.key(), key(1));
        assert_eq!(
            raised_names(&mut connector),
            [
                "routing.connector_created",
                "routing.connector_enrolled",
                "routing.connector_renewed"
            ]
        );
    }

    /// Renewal before the window returns the held certificate unchanged
    /// and raises no event.
    #[test]
    fn a_renewal_before_its_window_lengthens_nothing() {
        let mut connector = enrolled();
        let held = connector.certificate().unwrap();
        let _ = raised_names(&mut connector);

        let answered = connector.renew(&key(1)).unwrap();

        assert_eq!(answered, held);
        assert!(raised_names(&mut connector).is_empty());
    }

    /// Renewal is forbidden for a different key even within the renewal window.
    #[test]
    fn a_renewal_for_another_key_is_refused() {
        let mut connector = enrolled();
        let _later = crate::shared::clock::freeze(
            connector.updated_at().saturating_add(Duration::hours(17)),
        );

        assert!(matches!(
            connector.renew(&key(2)),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// A revoked connector cannot renew with its enrolled key after expiration.
    #[test]
    fn a_revoked_connector_is_not_renewed() {
        let mut connector = enrolled();
        connector.revoke(&routing_admin()).unwrap();
        let _later = crate::shared::clock::freeze(
            connector.updated_at().saturating_add(Duration::hours(30)),
        );

        assert!(matches!(
            connector.renew(&key(1)),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// Renewal is forbidden for a connector that has never enrolled.
    #[test]
    fn an_unenrolled_connector_is_not_renewed() {
        let mut connector = connector();

        assert!(matches!(
            connector.renew(&key(1)),
            Err(DomainError::Forbidden(_))
        ));
    }
}
