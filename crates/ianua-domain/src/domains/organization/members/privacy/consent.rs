//! A record of one consent decision an organization member made.
//!
//! It keeps the rules of a tenant user's
//! [`ConsentRecord`](crate::domains::identity::privacy::consent::ConsentRecord):
//! a record never changes once made, withdrawing adds a new record, and
//! consent is given only by the member themselves. Withdrawing only lowers
//! what is done with their data, so someone who may update members records
//! it for a member who asked them to.

use time::OffsetDateTime;

use crate::domains::identity::account::control::AccountAction;
use crate::domains::identity::privacy::consent::{ConsentDecision, ConsentTerms, ConsentType};
use crate::domains::organization::events::privacy::{OrgUserConsentGranted, OrgUserConsentRevoked};
use crate::domains::organization::members::account_control::OrgAccountControl;
use crate::domains::organization::members::control::OrgControl;
use crate::domains::organization::members::org_user::OrgUser;
use crate::domains::organization::members::privacy::ensure_in_person;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{RaisedEvents, RaisesComplete};
use crate::types::{ConsentId, EventLabel, Fact, IpAddress, Label, OrgUserId, OrganizationId};

/// One consent decision an organization member made.
#[derive(Debug)]
pub struct OrgConsentRecord {
    id: ConsentId,
    organization_id: OrganizationId,
    org_user_id: OrgUserId,
    consent_type: ConsentType,
    granted: ConsentDecision,
    version: Label,
    ip_address: Fact<IpAddress>,
    recorded_at: OffsetDateTime,
    raised: RaisedEvents,
}

/// A member's consent record as storage keeps it, read back by
/// [`OrgConsentRecord::reconstitute`].
pub struct OrgConsentRecordRow {
    /// The record's id.
    pub id: ConsentId,
    /// The organization the member belongs to.
    pub organization_id: OrganizationId,
    /// The member who made the decision.
    pub org_user_id: OrgUserId,
    /// What kind of consent it is for.
    pub consent_type: ConsentType,
    /// Whether consent was given or withdrawn.
    pub granted: ConsentDecision,
    /// Which version of the terms or policy it is about.
    pub version: Label,
    /// The IP address the decision came from, when known.
    pub ip_address: Fact<IpAddress>,
    /// When the decision was recorded.
    pub recorded_at: OffsetDateTime,
}

impl OrgConsentRecord {
    /// Records `member` giving or withdrawing consent to `terms`, at the
    /// current time, by the member themselves from their own sign-in.
    /// Raises `organization.org_user_consent_granted` for a consent given
    /// and `organization.org_user_consent_revoked` for one withdrawn.
    ///
    /// Ann, an owner, ticking "agreed to marketing" for Sam is no consent
    /// at all.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` is not `member` acting through
    ///   their own session.
    pub fn record(
        member: &OrgUser,
        terms: ConsentTerms,
        decision: ConsentDecision,
        ip_address: Fact<IpAddress>,
        by: &OrgControl<'_>,
    ) -> Result<Self, DomainError> {
        ensure_in_person(member, by)?;
        Ok(Self::made(member, terms, decision, ip_address))
    }

    /// Records that `member`'s consent to `terms` was withdrawn for them,
    /// as `control` allows, at the current time. Raises
    /// `organization.org_user_consent_revoked`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `control` was made for another
    ///   member, or the one acting may not update members.
    pub fn withdraw_for(
        member: &OrgUser,
        terms: ConsentTerms,
        ip_address: Fact<IpAddress>,
        control: &OrgAccountControl<'_>,
    ) -> Result<Self, DomainError> {
        control.ensure_on(member.id(), AccountAction::RecordForThem)?;
        Ok(Self::made(
            member,
            terms,
            ConsentDecision::Withdrawn,
            ip_address,
        ))
    }

    fn made(
        member: &OrgUser,
        terms: ConsentTerms,
        decision: ConsentDecision,
        ip_address: Fact<IpAddress>,
    ) -> Self {
        let mut record = Self {
            id: ConsentId::new(),
            organization_id: *member.organization_id(),
            org_user_id: *member.id(),
            consent_type: terms.consent_type,
            granted: decision,
            version: terms.version.clone(),
            ip_address,
            recorded_at: crate::shared::clock::now(),
            raised: RaisedEvents::default(),
        };
        record.raise_decision(EventLabel::of(member.email().as_str()), terms);
        record
    }

    /// Raises the record of the decision, naming the member by `label`.
    fn raise_decision(&mut self, label: EventLabel, terms: ConsentTerms) {
        match self.granted {
            ConsentDecision::Granted => self.raised.raise_organization(OrgUserConsentGranted {
                organization_id: self.organization_id,
                org_user_id: self.org_user_id,
                org_user_label: label,
                terms,
                occurred_at: self.recorded_at,
            }),
            ConsentDecision::Withdrawn => self.raised.raise_organization(OrgUserConsentRevoked {
                organization_id: self.organization_id,
                org_user_id: self.org_user_id,
                org_user_label: label,
                terms,
                occurred_at: self.recorded_at,
            }),
        }
    }

    /// Rebuilds a member's consent record from storage.
    ///
    /// # Errors
    ///
    /// - Never fails today. No part of the row can contradict another, and
    ///   each part was read through its own checked type.
    pub fn reconstitute(row: OrgConsentRecordRow) -> Result<Self, DomainError> {
        Ok(Self {
            id: row.id,
            organization_id: row.organization_id,
            org_user_id: row.org_user_id,
            consent_type: row.consent_type,
            granted: row.granted,
            version: row.version,
            ip_address: row.ip_address,
            recorded_at: row.recorded_at,
            raised: RaisedEvents::default(),
        })
    }

    /// The record's id.
    #[must_use]
    pub fn id(&self) -> &ConsentId {
        &self.id
    }

    /// The organization the member belongs to.
    #[must_use]
    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// The member who made the decision.
    #[must_use]
    pub fn org_user_id(&self) -> &OrgUserId {
        &self.org_user_id
    }

    /// What kind of consent it is for.
    #[must_use]
    pub fn consent_type(&self) -> ConsentType {
        self.consent_type
    }

    /// Whether consent was given or withdrawn.
    #[must_use]
    pub fn decision(&self) -> ConsentDecision {
        self.granted
    }

    /// Which version of the terms or policy it is about.
    #[must_use]
    pub fn version(&self) -> &Label {
        &self.version
    }

    /// The IP address the decision came from, when known.
    #[must_use]
    pub fn ip_address(&self) -> Fact<&IpAddress> {
        self.ip_address.as_ref()
    }

    /// When the decision was recorded.
    #[must_use]
    pub fn recorded_at(&self) -> OffsetDateTime {
        self.recorded_at
    }
}

impl RaisesComplete for OrgConsentRecord {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::organization::members::control::tests::{
        acting, founder, member_of, session_of,
    };
    use crate::domains::organization::members::privacy::tests::copy_of;
    use crate::test_support::events::raised_complete_names;

    fn marketing() -> ConsentTerms {
        ConsentTerms {
            consent_type: ConsentType::Marketing,
            version: Label::new("version", "mkt-2026").unwrap(),
        }
    }

    /// Sam agrees to marketing mail from his own sign-in. The record holds
    /// his decision and is recorded.
    #[test]
    fn a_member_gives_consent_in_person() {
        let sam = member_of(&founder());
        let session = session_of(&sam);

        let mut record = OrgConsentRecord::record(
            &sam,
            marketing(),
            ConsentDecision::Granted,
            Fact::Unknown,
            &acting(&sam, &session),
        )
        .unwrap();

        assert_eq!(record.decision(), ConsentDecision::Granted);
        assert_eq!(record.org_user_id(), sam.id());
        assert_eq!(
            raised_complete_names(&mut record),
            ["organization.org_user_consent_granted"]
        );
    }

    /// An owner's session cannot record marketing consent on Sam's behalf.
    #[test]
    fn nobody_gives_consent_for_another_member() {
        let ann = founder();
        let sam = member_of(&ann);
        let session = session_of(&ann);

        let refused = OrgConsentRecord::record(
            &sam,
            marketing(),
            ConsentDecision::Granted,
            Fact::Unknown,
            &acting(&ann, &session),
        );

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Sam asks Ann, an owner, to stop his marketing mail. She records the
    /// withdrawal for him.
    #[test]
    fn an_owner_withdraws_consent_for_a_member() {
        let ann = founder();
        let sam = member_of(&ann);
        let target = copy_of(&sam);
        let session = session_of(&ann);
        let control = OrgAccountControl::new(acting(&ann, &session), &target);

        let mut record =
            OrgConsentRecord::withdraw_for(&sam, marketing(), Fact::Unknown, &control).unwrap();

        assert_eq!(record.decision(), ConsentDecision::Withdrawn);
        assert_eq!(
            raised_complete_names(&mut record),
            ["organization.org_user_consent_revoked"]
        );
    }

    /// Sam's member role cannot withdraw Bob's marketing consent.
    #[test]
    fn a_plain_member_cannot_withdraw_for_another() {
        let ann = founder();
        let sam = member_of(&ann);
        let bob = member_of(&ann);
        let target = copy_of(&bob);
        let session = session_of(&sam);
        let control = OrgAccountControl::new(acting(&sam, &session), &target);

        let refused = OrgConsentRecord::withdraw_for(&bob, marketing(), Fact::Unknown, &control);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// An owner's control for Sam cannot withdraw Bob's marketing consent.
    #[test]
    fn a_control_counts_only_for_its_own_member() {
        let ann = founder();
        let sam = member_of(&ann);
        let bob = member_of(&ann);
        let session = session_of(&ann);
        let control = OrgAccountControl::new(acting(&ann, &session), &sam);

        let refused = OrgConsentRecord::withdraw_for(&bob, marketing(), Fact::Unknown, &control);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }
}
