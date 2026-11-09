use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::identity::account::control::{
    AccountAction, AccountControlCheck, SignedInPerson, ensure_holder,
};
use crate::domains::identity::account::user::User;
use crate::domains::identity::events::privacy::{ConsentGranted, ConsentRevoked};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::two_cases::two_cases;
use crate::types::{ConsentId, EventLabel, Fact, IpAddress, Label, UserId};

/// What a consent decision is about.
///
/// Different laws ask for different consents. Each one is tracked on its own
/// and can be withdrawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ConsentType {
    /// GDPR: consent to process personal data.
    DataProcessing,

    /// GDPR: consent to receive marketing communications.
    Marketing,

    /// Terms of service acceptance.
    TermsOfService,

    /// Privacy policy acceptance.
    PrivacyPolicy,

    /// HIPAA: consent to share health information.
    HealthDataSharing,

    /// Consent to cookies and tracking.
    Cookies,
}

/// Which terms a consent decision is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentTerms {
    /// The kind of consent.
    pub consent_type: ConsentType,
    /// Which version of the terms or policy, such as `"tos-2024-01"`.
    pub version: Label,
}

two_cases! {
    /// Whether a person gave or withdrew consent. It is stored as the
    /// `granted` flag.
    pub enum ConsentDecision {
        /// They agreed.
        Granted => true,
        /// They withdrew or refused.
        Withdrawn => false,
    }
}

/// A record of one consent decision a user made in a tenant.
///
/// A record never changes once made. Withdrawing consent adds a new record
/// marked withdrawn, so the full history stays. GDPR Article 7 asks for
/// proof of when consent was given, and lets the person withdraw it at any
/// time.
///
/// It is read and written only through stores opened for its tenant. See
/// [`crate::isolation`].
#[derive(Debug)]
pub struct ConsentRecord<T: TenantScope> {
    id: ConsentId,
    user_id: UserId,
    consent_type: ConsentType,
    granted: ConsentDecision,
    version: Label,
    ip_address: Fact<IpAddress>,
    recorded_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> ConsentRecord<T> {
    /// Records the signed-in person's consent or withdrawal at the current time.
    /// `terms` identifies the consent kind and policy version; administrators cannot consent for others.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] if the signed-in person is not the subject.
    pub fn record(
        user_id: UserId,
        terms: ConsentTerms,
        decision: ConsentDecision,
        ip_address: Fact<IpAddress>,
        by: &impl SignedInPerson<T>,
    ) -> Result<Self, DomainError> {
        ensure_holder(by, &user_id)?;
        Ok(Self::made(user_id, terms, decision, ip_address))
    }

    fn made(
        user_id: UserId,
        terms: ConsentTerms,
        decision: ConsentDecision,
        ip_address: Fact<IpAddress>,
    ) -> Self {
        Self {
            id: ConsentId::new(),
            user_id,
            consent_type: terms.consent_type,
            granted: decision,
            version: terms.version,
            ip_address,
            recorded_at: crate::shared::clock::now(),
            raised: Raised::default(),
            _scope: PhantomData,
        }
    }

    /// Records that consent was withdrawn for the person, as `control`
    /// allows, at the current time.
    ///
    /// Ann calls support and asks to stop the marketing emails. Withdrawing
    /// only lowers what is done with her data, so staff may record it for
    /// her. Giving consent for someone stays theirs alone, through
    /// [`record`](Self::record).
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `control` refuses recording for the
    ///   account.
    pub fn withdraw_for(
        user_id: UserId,
        terms: ConsentTerms,
        ip_address: Fact<IpAddress>,
        control: &impl AccountControlCheck,
    ) -> Result<Self, DomainError> {
        control.ensure_allowed(&user_id, AccountAction::RecordForThem)?;
        Ok(Self::made(
            user_id,
            terms,
            ConsentDecision::Withdrawn,
            ip_address,
        ))
    }

    /// Rebuilds a consent record from storage.
    ///
    /// # Errors
    ///
    /// - Never fails today. No part of the row can contradict another, and
    ///   each part was read through its own checked type.
    pub fn reconstitute(row: ConsentRecordRow) -> Result<Self, DomainError> {
        Ok(Self {
            id: row.id,
            user_id: row.user_id,
            consent_type: row.consent_type,
            granted: row.granted,
            version: row.version,
            ip_address: row.ip_address,
            recorded_at: row.recorded_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// The record's id.
    #[must_use]
    pub fn id(&self) -> &ConsentId {
        &self.id
    }

    /// The user who made the consent decision.
    #[must_use]
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// What kind of consent this record is for.
    #[must_use]
    pub fn consent_type(&self) -> ConsentType {
        self.consent_type
    }

    /// Whether consent was given, as opposed to withdrawn.
    #[must_use]
    pub fn granted(&self) -> bool {
        self.granted == ConsentDecision::Granted
    }

    /// Which version of the terms or policy the decision is about.
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

    /// Names the person this decision is theirs on the audit trail, by the
    /// address `account` has now. Raises `identity.consent_granted` for a
    /// consent given and `identity.consent_revoked` for one withdrawn.
    ///
    /// It is a step of its own because staff who withdraw consent for Ann
    /// may read her account only once the record was allowed. Reading it
    /// first would tell a refused caller which accounts exist.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `account` is not the person the
    ///   decision is about.
    pub fn name_person(&mut self, account: &User<T>) -> Result<(), DomainError> {
        if *account.id() != self.user_id {
            return Err(DomainError::forbidden(message!(
                "identity-a-consent-decision-names-only-the",
                "a consent decision names only the person who made it"
            )));
        }
        let user_label = EventLabel::of(account.email().as_str());
        let terms = ConsentTerms {
            consent_type: self.consent_type,
            version: self.version.clone(),
        };
        match self.granted {
            ConsentDecision::Granted => self.raised.raise(ConsentGranted {
                user_id: self.user_id,
                user_label,
                terms,
                occurred_at: self.recorded_at,
            }),
            ConsentDecision::Withdrawn => self.raised.raise(ConsentRevoked {
                user_id: self.user_id,
                user_label,
                terms,
                occurred_at: self.recorded_at,
            }),
        }
        Ok(())
    }
}

impl<T: TenantScope> Raises for ConsentRecord<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// A consent record as storage keeps it, read back by
/// [`ConsentRecord::reconstitute`].
pub struct ConsentRecordRow {
    /// The record's id.
    pub id: ConsentId,
    /// The user who made the consent decision.
    pub user_id: UserId,
    /// What kind of consent this record is for.
    pub consent_type: ConsentType,
    /// Whether consent was given or withdrawn.
    pub granted: ConsentDecision,
    /// Which version of the terms or policy the decision is about.
    pub version: Label,
    /// The IP address the decision came from, when known.
    pub ip_address: Fact<IpAddress>,
    /// When the decision was recorded.
    pub recorded_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::granter::{AccountControl, Handout};
    use crate::domains::authorization::permission::{SystemPermission, UserAction};
    use crate::domains::identity::account::user::tests::signed_in_as;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::builders::user;
    use crate::test_support::events::{raised, raised_names};

    fn label(s: &str) -> Label {
        Label::new("version", s).unwrap()
    }

    /// A user gives data processing consent under "gdpr-v2". The record says
    /// granted, with that kind and version.
    #[test]
    fn record_consent_grant() {
        let ann = UserId::new();
        let record = ConsentRecord::<ResolvedTenant>::record(
            ann,
            ConsentTerms {
                consent_type: ConsentType::DataProcessing,
                version: label("gdpr-v2"),
            },
            ConsentDecision::Granted,
            Fact::Known(IpAddress::new("1.2.3.4").unwrap()),
            &signed_in_as::<ResolvedTenant>(ann),
        )
        .unwrap();

        assert!(record.granted());
        assert_eq!(record.consent_type(), ConsentType::DataProcessing);
        assert_eq!(record.version().as_str(), "gdpr-v2");
    }

    /// A user withdraws marketing consent. The new record says not granted.
    #[test]
    fn record_consent_withdrawal() {
        let ann = UserId::new();
        let record = ConsentRecord::<ResolvedTenant>::record(
            ann,
            ConsentTerms {
                consent_type: ConsentType::Marketing,
                version: label("marketing-v1"),
            },
            ConsentDecision::Withdrawn,
            Fact::Unknown,
            &signed_in_as::<ResolvedTenant>(ann),
        )
        .unwrap();

        assert!(!record.granted());
    }

    /// A consent from 1.2.3.4 keeps the user, that IP and its own id, since
    /// the record is the proof. A decision with no known IP reads back as
    /// unknown.
    #[test]
    fn a_record_names_the_user_and_where_consent_was_given_from() {
        let user = UserId::new();

        let record = ConsentRecord::<ResolvedTenant>::record(
            user,
            ConsentTerms {
                consent_type: ConsentType::DataProcessing,
                version: label("gdpr-v2"),
            },
            ConsentDecision::Granted,
            Fact::Known(IpAddress::new("1.2.3.4").unwrap()),
            &signed_in_as::<ResolvedTenant>(user),
        )
        .unwrap();

        assert_eq!(*record.user_id(), user);
        assert_eq!(record.ip_address().known().unwrap().as_str(), "1.2.3.4");
        assert!(!record.id().as_uuid().is_nil());

        let no_address = ConsentRecord::<ResolvedTenant>::record(
            user,
            ConsentTerms {
                consent_type: ConsentType::Marketing,
                version: label("marketing-v1"),
            },
            ConsentDecision::Withdrawn,
            Fact::Unknown,
            &signed_in_as::<ResolvedTenant>(user),
        )
        .unwrap();
        assert_eq!(no_address.ip_address(), Fact::Unknown);
    }

    /// Another signed-in person cannot grant marketing consent on Ann's behalf.
    #[test]
    fn only_the_person_records_their_consent() {
        let ann = UserId::new();
        let admin = signed_in_as::<ResolvedTenant>(UserId::new());

        let recorded = ConsentRecord::<ResolvedTenant>::record(
            ann,
            ConsentTerms {
                consent_type: ConsentType::Marketing,
                version: label("marketing-v1"),
            },
            ConsentDecision::Granted,
            Fact::Unknown,
            &admin,
        );

        assert!(matches!(recorded, Err(DomainError::Forbidden(_))));
    }

    /// Ann asks support to stop marketing emails. Sam, who may update users,
    /// records the withdrawal for her. Bob, who holds no user rights, may
    /// not.
    #[test]
    fn staff_may_record_a_withdrawal_for_someone() {
        let ann = UserId::new();
        let acting = |held: &'static [SystemPermission]| {
            AccountControl::assumed(
                anyone_holding(held),
                ann,
                crate::domains::authorization::stewardship::Stewardship::OthersAdminister,
                Handout::NOTHING,
            )
        };
        let terms = || ConsentTerms {
            consent_type: ConsentType::Marketing,
            version: label("marketing-v1"),
        };

        let by_sam = ConsentRecord::<ResolvedTenant>::withdraw_for(
            ann,
            terms(),
            Fact::Unknown,
            &acting(&[SystemPermission::Users(UserAction::Update)]),
        );
        let by_bob = ConsentRecord::<ResolvedTenant>::withdraw_for(
            ann,
            terms(),
            Fact::Unknown,
            &acting(&[]),
        );

        assert!(!by_sam.unwrap().granted());
        assert!(matches!(by_bob, Err(DomainError::Forbidden(_))));
    }

    fn decided(ann: UserId, decision: ConsentDecision) -> ConsentRecord<ResolvedTenant> {
        ConsentRecord::record(
            ann,
            ConsentTerms {
                consent_type: ConsentType::Marketing,
                version: label("marketing-v1"),
            },
            decision,
            Fact::Unknown,
            &signed_in_as::<ResolvedTenant>(ann),
        )
        .unwrap()
    }

    fn user_label_of(event: &DomainEvent) -> String {
        match event.payload().value("user") {
            Some(FieldValue::Reference(reference)) => reference.label().to_owned(),
            other => panic!("user is not a reference: {other:?}"),
        }
    }

    /// Ann agrees to marketing mail and her record names her. It raises
    /// the consent given, naming her by her address.
    #[test]
    fn naming_a_consent_given_raises_identity_consent_granted() {
        let ann = UserId::new();
        let mut record = decided(ann, ConsentDecision::Granted);

        record.name_person(&user(ann, "ann@acme.com")).unwrap();

        let events = raised(&mut record);
        assert_eq!(
            events[0].event_type().to_string(),
            "identity.consent_granted"
        );
        assert_eq!(user_label_of(&events[0]), "ann@acme.com");
    }

    /// Ann withdraws her marketing consent and the record names her. It
    /// raises the consent withdrawn.
    #[test]
    fn naming_a_consent_withdrawn_raises_identity_consent_revoked() {
        let ann = UserId::new();
        let mut record = decided(ann, ConsentDecision::Withdrawn);

        record.name_person(&user(ann, "ann@acme.com")).unwrap();

        assert_eq!(raised_names(&mut record), ["identity.consent_revoked"]);
    }

    /// Naming Bob as the subject of Ann's consent is refused and raises no event.
    #[test]
    fn a_refused_naming_raises_nothing() {
        let ann = UserId::new();
        let mut record = decided(ann, ConsentDecision::Granted);

        let named = record.name_person(&user(UserId::new(), "bob@acme.com"));

        assert!(matches!(named, Err(DomainError::Forbidden(_))));
        assert!(raised_names(&mut record).is_empty());
    }

    /// Ann's consent is read back from storage. It has raised nothing.
    #[test]
    fn a_consent_read_back_from_storage_has_raised_nothing() {
        let mut record = ConsentRecord::<ResolvedTenant>::reconstitute(ConsentRecordRow {
            id: ConsentId::new(),
            user_id: UserId::new(),
            consent_type: ConsentType::Marketing,
            granted: ConsentDecision::Granted,
            version: label("marketing-v1"),
            ip_address: Fact::Unknown,
            recorded_at: crate::shared::clock::now(),
        })
        .unwrap();

        assert!(raised_names(&mut record).is_empty());
    }
}
