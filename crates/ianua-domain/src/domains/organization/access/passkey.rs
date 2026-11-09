//! An in-flight `WebAuthn` ceremony on the management plane.
//!
//! It works like the tenant-scoped [`PasskeyCeremony`], with two differences.
//! The owner is an [`OrgUserId`]. And the owner is optional, because a
//! discoverable sign-in opens before anyone has claimed an identity or any
//! organization is known. The credential presented at confirm names both.
//!
//! [`PasskeyCeremony`]: crate::domains::authentication::credentials::passkey_ceremony::PasskeyCeremony

use time::OffsetDateTime;

use crate::domains::authentication::credentials::passkey_ceremony::{
    CeremonyPurpose, CeremonySubject, PasskeyChallenge, TargetedPurpose,
};
use crate::domains::identity::sealed::Sealed;
use crate::isolation::organization::scope::ResolvedOrganization;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::RowCheck;
use crate::types::{CeremonyId, Lifetime, OrgUserId, Usage};

/// A ceremony as stored, for rebuilding it with
/// [`OrgPasskeyCeremony::reconstitute`].
pub struct OrgPasskeyCeremonyRow {
    /// Unique identifier.
    pub id: CeremonyId,
    /// Whose ceremony it is. See [`CeremonySubject::from_stored`].
    pub subject: CeremonySubject<OrgUserId>,
    /// Registration, authentication, or discoverable authentication.
    pub purpose: CeremonyPurpose,
    /// Opaque verifier state.
    pub state: Vec<u8>,
    /// When the ceremony was opened.
    pub created_at: OffsetDateTime,
    /// When it stops being answerable.
    pub expires_at: OffsetDateTime,
    /// Whether it was settled, and when.
    pub usage: Usage,
}

/// One management-plane `WebAuthn` ceremony awaiting the client's answer.
///
/// It has no `Debug`, because the state carries the challenge bytes. A
/// challenge in a log is one an attacker can answer.
pub struct OrgPasskeyCeremony {
    id: CeremonyId,
    subject: CeremonySubject<OrgUserId>,
    purpose: CeremonyPurpose,
    state: Vec<u8>,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    usage: Usage,
}

impl OrgPasskeyCeremony {
    /// Opens a ceremony bound to a known org user, expiring `ttl` from now.
    #[must_use]
    pub fn open(
        org_user_id: OrgUserId,
        purpose: TargetedPurpose,
        state: Vec<u8>,
        ttl: Lifetime,
    ) -> Self {
        let now = crate::shared::clock::now();
        Self {
            id: CeremonyId::new(),
            subject: CeremonySubject::Claimed(org_user_id),
            purpose: purpose.into(),
            state,
            created_at: now,
            expires_at: ttl.ends_after(now),
            usage: Usage::Unused,
        }
    }

    /// Opens a discoverable-credential ceremony, expiring `ttl` from now.
    ///
    /// Nobody has claimed an identity, so there is no org user to bind. The
    /// authenticator presents a credential at confirm, and the credential
    /// names its owner.
    #[must_use]
    pub fn open_discoverable(state: Vec<u8>, ttl: Lifetime) -> Self {
        let now = crate::shared::clock::now();
        Self {
            id: CeremonyId::new(),
            subject: CeremonySubject::Unclaimed,
            purpose: CeremonyPurpose::DiscoverableAuthentication,
            state,
            created_at: now,
            expires_at: ttl.ends_after(now),
            usage: Usage::Unused,
        }
    }

    /// Rebuilds a ceremony from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row binds a discoverable
    ///   ceremony to a member, or another kind to nobody.
    /// - [`DomainError::Infrastructure`] when the row expires or is settled
    ///   before it was opened.
    /// - [`DomainError::Infrastructure`] when it was settled at or after it
    ///   expired.
    pub fn reconstitute(row: OrgPasskeyCeremonyRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            subject: row.subject,
            purpose: row.purpose,
            state: row.state,
            created_at: row.created_at,
            expires_at: row.expires_at,
            usage: row.usage,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &OrgPasskeyCeremonyRow) -> Result<(), DomainError> {
        RowCheck::of("organization passkey ceremony")
            .holds(
                row.subject.account().is_some()
                    != (row.purpose == CeremonyPurpose::DiscoverableAuthentication),
                "a discoverable ceremony bound to a member, or another one bound to none",
            )
            .in_order(
                row.created_at,
                row.expires_at,
                "expires before it was opened",
            )
            .in_order_if(
                row.created_at,
                row.usage.used_at(),
                "settled before it was opened",
            )
            .holds(
                row.usage.used_at().is_none_or(|at| at < row.expires_at),
                "settled after it expired",
            )
            .finish()
    }

    /// Unique identifier. It is the only part the client holds.
    #[must_use]
    pub fn id(&self) -> &CeremonyId {
        &self.id
    }

    /// The org user the ceremony is bound to, absent for discoverable ones.
    #[must_use]
    pub fn org_user_id(&self) -> Option<&OrgUserId> {
        self.subject.account()
    }

    /// Registration, authentication, or discoverable authentication.
    #[must_use]
    pub fn purpose(&self) -> CeremonyPurpose {
        self.purpose
    }

    /// When the ceremony was opened.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When it stops being answerable.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// When it was settled, if it has been.
    #[must_use]
    pub fn consumed_at(&self) -> Option<OffsetDateTime> {
        self.usage.used_at()
    }

    /// The raw state, for the repository to write down.
    ///
    /// For storage only. Everything that *uses* the state goes through
    /// [`consume`](Self::consume), which keeps it to one use.
    #[must_use]
    pub fn state_for_storage(&self) -> &[u8] {
        &self.state
    }

    /// Closes the ceremony and hands over the state to verify against.
    ///
    /// This is the one way to reach the state, and it works once. A replayed
    /// or stale ceremony gets an error, not a second verification. Callers
    /// name the purpose they expect, so a registration state can never settle
    /// a sign-in. A refused call leaves the ceremony unspent.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the ceremony was already consumed.
    /// - [`DomainError::Validation`] when it was opened for a different purpose.
    /// - [`DomainError::Validation`] when it has expired.
    pub fn consume(&mut self, expected: CeremonyPurpose) -> Result<&[u8], DomainError> {
        if self.usage.is_used() {
            return Err(DomainError::invalid(message!(
                "authentication-this-challenge-has-already-been-used",
                "this challenge has already been used"
            )));
        }

        if self.purpose != expected {
            return Err(DomainError::invalid(message!(
                "authentication-this-challenge-was-issued-for-a",
                "this challenge was issued for a different ceremony"
            )));
        }

        let now = crate::shared::clock::now();
        if now >= self.expires_at {
            return Err(DomainError::invalid(message!(
                "authentication-this-challenge-has-expired",
                "this challenge has expired"
            )));
        }

        self.usage = Usage::Used { at: now };
        Ok(&self.state)
    }
}

impl Sealed for OrgPasskeyCeremony {}

impl PasskeyChallenge<ResolvedOrganization> for OrgPasskeyCeremony {
    fn opened_for(&self) -> Option<OrgUserId> {
        self.subject.account().copied()
    }

    fn opened_as(&self) -> CeremonyPurpose {
        self.purpose
    }

    fn spent_at(&self) -> Option<OffsetDateTime> {
        self.usage.used_at()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::model::row_check::refused_as_corrupt;

    fn open(purpose: TargetedPurpose) -> OrgPasskeyCeremony {
        OrgPasskeyCeremony::open(
            OrgUserId::new(),
            purpose,
            b"opaque-verifier-state".to_vec(),
            five_minutes(),
        )
    }

    fn five_minutes() -> Lifetime {
        Lifetime::seconds(300).unwrap()
    }

    /// Ann starts a passkey sign-in after typing her address. The ceremony
    /// names her as its owner and is not yet settled.
    #[test]
    fn a_targeted_ceremony_is_bound_to_its_org_user() {
        let ceremony = open(TargetedPurpose::Authentication);

        assert!(ceremony.org_user_id().is_some());
        assert!(ceremony.consumed_at().is_none());
    }

    /// Someone clicks "sign in with a passkey" without typing an address.
    /// The ceremony names no owner, and its purpose is discoverable sign-in.
    #[test]
    fn a_discoverable_ceremony_binds_no_org_user() {
        let ceremony = OrgPasskeyCeremony::open_discoverable(
            b"opaque-verifier-state".to_vec(),
            five_minutes(),
        );

        assert!(ceremony.org_user_id().is_none());
        assert_eq!(
            ceremony.purpose(),
            CeremonyPurpose::DiscoverableAuthentication
        );
    }

    /// Consuming a ceremony returns its original state once and refuses a replay.
    #[test]
    fn consume_hands_over_the_state_exactly_once() {
        let mut ceremony = open(TargetedPurpose::Authentication);

        let state = ceremony.consume(CeremonyPurpose::Authentication).unwrap();
        assert_eq!(state, b"opaque-verifier-state");

        let second = ceremony.consume(CeremonyPurpose::Authentication);
        assert!(matches!(second, Err(DomainError::Validation(_))));
    }

    /// A registration ceremony cannot settle authentication and remains unspent after refusal.
    #[test]
    fn a_registration_state_cannot_settle_an_authentication() {
        let mut ceremony = open(TargetedPurpose::Registration);

        let result = ceremony.consume(CeremonyPurpose::Authentication);

        assert!(matches!(result, Err(DomainError::Validation(_))));
        assert!(
            ceremony.consumed_at().is_none(),
            "a refused consume must not burn the ceremony"
        );
    }

    /// Ann answers her passkey prompt at the exact moment it expires. The
    /// answer is refused.
    #[test]
    fn an_expired_ceremony_is_refused() {
        let mut ceremony = open(TargetedPurpose::Authentication);

        let _later = crate::shared::clock::freeze(ceremony.expires_at());
        let result = ceremony.consume(CeremonyPurpose::Authentication);

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A new ceremony has a real id, not the nil uuid, and stores the exact
    /// verifier state it was opened with. The client holds the id and the
    /// answer is checked against that state.
    #[test]
    fn a_ceremony_carries_its_id_and_the_state_it_was_opened_with() {
        let ceremony = open(TargetedPurpose::Authentication);

        assert_ne!(*ceremony.id().as_uuid(), uuid::Uuid::nil());
        assert_eq!(ceremony.state_for_storage(), b"opaque-verifier-state");
    }

    /// Ann answers her passkey prompt a minute after it opened. The ceremony
    /// records that minute as when it was settled.
    #[test]
    fn settling_a_ceremony_records_when_it_was_settled() {
        let mut ceremony = open(TargetedPurpose::Authentication);
        assert_eq!(ceremony.consumed_at(), None);

        let settled_at = crate::shared::clock::now() + time::Duration::minutes(1);
        let _frozen = crate::shared::clock::freeze(settled_at);
        ceremony.consume(CeremonyPurpose::Authentication).unwrap();

        assert_eq!(ceremony.consumed_at(), Some(settled_at));
    }

    /// A discoverable ceremony with a five-minute lifetime opens at a frozen
    /// time. It expires five minutes after that, so the browser has time to
    /// answer.
    #[test]
    fn a_discoverable_ceremony_expires_after_it_opened_not_before() {
        let opened_at = crate::shared::clock::now();
        let _frozen = crate::shared::clock::freeze(opened_at);

        let ceremony = OrgPasskeyCeremony::open_discoverable(
            b"opaque-verifier-state".to_vec(),
            five_minutes(),
        );

        assert_eq!(ceremony.created_at(), opened_at);
        assert_eq!(
            ceremony.expires_at(),
            opened_at + time::Duration::minutes(5)
        );
    }

    /// A stored row is a discoverable ceremony that also names a member.
    /// Loading it is refused as a corrupt row.
    #[test]
    fn a_stored_discoverable_ceremony_bound_to_a_member_is_refused() {
        let now = crate::shared::clock::now();

        let ceremony = OrgPasskeyCeremony::reconstitute(OrgPasskeyCeremonyRow {
            id: CeremonyId::new(),
            subject: CeremonySubject::Claimed(OrgUserId::new()),
            purpose: CeremonyPurpose::DiscoverableAuthentication,
            state: vec![1],
            created_at: now,
            expires_at: now + time::Duration::minutes(5),
            usage: Usage::Unused,
        });

        assert!(refused_as_corrupt(&ceremony));
    }

    /// A stored ceremony was settled a minute after it expired. Nothing
    /// settles a lapsed ceremony, so loading it is refused as a corrupt row.
    #[test]
    fn a_stored_ceremony_settled_after_it_expired_is_refused() {
        let now = crate::shared::clock::now();
        let expires_at = now + time::Duration::minutes(5);

        let ceremony = OrgPasskeyCeremony::reconstitute(OrgPasskeyCeremonyRow {
            id: CeremonyId::new(),
            subject: CeremonySubject::Claimed(OrgUserId::new()),
            purpose: CeremonyPurpose::Registration,
            state: vec![1],
            created_at: now,
            expires_at,
            usage: Usage::Used {
                at: expires_at + time::Duration::minutes(1),
            },
        });

        assert!(refused_as_corrupt(&ceremony));
    }
}
