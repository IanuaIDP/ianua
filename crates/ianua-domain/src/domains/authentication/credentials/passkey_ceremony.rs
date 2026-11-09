//! A `WebAuthn` ceremony in progress, held on the server.
//!
//! A ceremony has two halves. The browser needs the challenge bytes and the
//! list of acceptable credentials. The server needs the same challenge and
//! the credentials it will accept, to check the answer. If the server sent
//! its half to the client and took it back on confirm, the client would
//! choose what its own assertion is checked against. Anyone could present a
//! challenge they made up and a signature over it.
//!
//! So the state stays here, under an opaque [`CeremonyId`], and works once.
//! [`consume`](PasskeyCeremony::consume) both proves the ceremony is still
//! open and closes it, so one challenge can never settle two logins.

use time::OffsetDateTime;

use crate::domains::authentication::credentials::passkey::PasskeyPlane;
use crate::domains::authentication::events::credential::PasskeyRegistrationStarted;
use crate::domains::authentication::events::login::{PasskeyChallengeIssued, PasskeySignInStarted};
use crate::domains::identity::sealed::Sealed;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{RaisedEvents, RaisesComplete};
use crate::shared::model::row_check::RowCheck;
use crate::types::{CeremonyId, Lifetime, TenantId, Usage, UserId};

/// Which ceremony a stored state belongs to.
///
/// A registration state must never settle an authentication, or the other
/// way round. So the purpose is recorded and checked, not guessed from the
/// endpoint that reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyPurpose {
    /// Enrolling a new authenticator for a known user.
    Registration,
    /// Proving possession of an already-registered authenticator.
    Authentication,
    /// Proving possession of a discoverable credential. Nobody has said who
    /// they are. The credential names its owner at confirm.
    DiscoverableAuthentication,
}

impl CeremonyPurpose {
    /// The stable storage name of this purpose.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Registration => "Registration",
            Self::Authentication => "Authentication",
            Self::DiscoverableAuthentication => "DiscoverableAuthentication",
        }
    }

    /// Parses a stored purpose name.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "Registration" => Some(Self::Registration),
            "Authentication" => Some(Self::Authentication),
            "DiscoverableAuthentication" => Some(Self::DiscoverableAuthentication),
            _ => None,
        }
    }
}

/// A ceremony for someone who has already said who they are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetedPurpose {
    /// Enrolling a new authenticator.
    Registration,
    /// Proving possession of an already-registered authenticator.
    Authentication,
}

impl From<TargetedPurpose> for CeremonyPurpose {
    fn from(purpose: TargetedPurpose) -> Self {
        match purpose {
            TargetedPurpose::Registration => Self::Registration,
            TargetedPurpose::Authentication => Self::Authentication,
        }
    }
}

/// Whose ceremony it is. Either the account it was opened for, or nobody yet.
///
/// Only a discoverable ceremony is unclaimed, and it always is, because the
/// credential names its owner when it answers. It is one value, not an
/// optional account beside the purpose. So a targeted ceremony can never be
/// stored without the account it targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonySubject<Id> {
    /// Opened for this account.
    Claimed(Id),
    /// Opened before anyone said who they are.
    Unclaimed,
}

impl<Id> CeremonySubject<Id> {
    /// The subject a stored account column records. An empty column means
    /// nobody has claimed one yet. Whether that fits the ceremony's purpose is
    /// checked when the ceremony is rebuilt.
    #[must_use]
    pub fn from_stored(account: Option<Id>) -> Self {
        account.map_or(Self::Unclaimed, Self::Claimed)
    }

    /// The account, when the ceremony was opened for one.
    #[must_use]
    pub fn account(&self) -> Option<&Id> {
        match self {
            Self::Claimed(id) => Some(id),
            Self::Unclaimed => None,
        }
    }
}

impl std::fmt::Display for CeremonyPurpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parameters for opening a ceremony.
pub struct OpenCeremonyParams {
    /// The tenant the ceremony belongs to.
    pub tenant_id: TenantId,
    /// The user the ceremony is bound to.
    pub user_id: UserId,
    /// Registration or authentication.
    pub purpose: TargetedPurpose,
    /// Opaque verifier state. The domain cannot read it. Only the `WebAuthn`
    /// adapter that made it can.
    pub state: Vec<u8>,
    /// How long the user has to answer.
    pub ttl: Lifetime,
}

/// Persisted state for repository hydration.
pub struct PasskeyCeremonyRow {
    /// Unique identifier.
    pub id: CeremonyId,
    /// The tenant the ceremony belongs to.
    pub tenant_id: TenantId,
    /// Whose ceremony it is. See [`CeremonySubject::from_stored`].
    pub subject: CeremonySubject<UserId>,
    /// Registration or authentication.
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

/// One `WebAuthn` ceremony awaiting the client's answer.
///
/// It has no `Debug`. The state carries the challenge bytes, and an attacker
/// who reads a challenge in a log can answer it.
pub struct PasskeyCeremony {
    id: CeremonyId,
    tenant_id: TenantId,
    subject: CeremonySubject<UserId>,
    purpose: CeremonyPurpose,
    state: Vec<u8>,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    usage: Usage,
    raised: RaisedEvents,
}

impl PasskeyCeremony {
    /// Opens a ceremony bound to a known user, expiring `ttl` from now.
    ///
    /// Raises `authentication.passkey_registration_started` for a
    /// registration, `authentication.passkey_sign_in_started` for a sign-in.
    #[must_use]
    pub fn open(params: OpenCeremonyParams) -> Self {
        let now = crate::shared::clock::now();
        let mut ceremony = Self {
            id: CeremonyId::new(),
            tenant_id: params.tenant_id,
            subject: CeremonySubject::Claimed(params.user_id),
            purpose: params.purpose.into(),
            state: params.state,
            created_at: now,
            expires_at: params.ttl.ends_after(now),
            usage: Usage::Unused,
            raised: RaisedEvents::default(),
        };
        ceremony.raise_opened(params.user_id, params.purpose, now);
        ceremony
    }

    /// Raises the start of the ceremony `purpose` names, for `user_id`.
    fn raise_opened(&mut self, user_id: UserId, purpose: TargetedPurpose, at: OffsetDateTime) {
        match purpose {
            TargetedPurpose::Registration => self.raised.raise_tenant(
                self.tenant_id,
                PasskeyRegistrationStarted {
                    user_id,
                    occurred_at: at,
                },
            ),
            TargetedPurpose::Authentication => self.raised.raise_tenant(
                self.tenant_id,
                PasskeySignInStarted {
                    user_id,
                    occurred_at: at,
                },
            ),
        }
    }

    /// Opens a discoverable-credential ceremony, expiring `ttl` from now.
    ///
    /// Nobody has claimed an identity yet, so there is no user to bind. The
    /// authenticator presents a credential at confirm, and the credential
    /// names its owner.
    ///
    /// Raises `authentication.passkey_challenge_issued`, naming nobody.
    #[must_use]
    pub fn open_discoverable(tenant_id: TenantId, state: Vec<u8>, ttl: Lifetime) -> Self {
        let now = crate::shared::clock::now();
        let mut ceremony = Self {
            id: CeremonyId::new(),
            tenant_id,
            subject: CeremonySubject::Unclaimed,
            purpose: CeremonyPurpose::DiscoverableAuthentication,
            state,
            created_at: now,
            expires_at: ttl.ends_after(now),
            usage: Usage::Unused,
            raised: RaisedEvents::default(),
        };
        ceremony
            .raised
            .raise_tenant(tenant_id, PasskeyChallengeIssued { occurred_at: now });
        ceremony
    }

    /// Rebuilds a ceremony from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row binds a discoverable
    ///   ceremony to a user, or another kind to nobody.
    /// - [`DomainError::Infrastructure`] when the row expires before it was
    ///   opened.
    /// - [`DomainError::Infrastructure`] when the row was settled before it
    ///   was opened, or once it had expired.
    pub fn reconstitute(row: PasskeyCeremonyRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            tenant_id: row.tenant_id,
            subject: row.subject,
            purpose: row.purpose,
            state: row.state,
            created_at: row.created_at,
            expires_at: row.expires_at,
            usage: row.usage,
            raised: RaisedEvents::default(),
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &PasskeyCeremonyRow) -> Result<(), DomainError> {
        RowCheck::of("passkey ceremony")
            .holds(
                row.subject.account().is_some()
                    != (row.purpose == CeremonyPurpose::DiscoverableAuthentication),
                "a discoverable ceremony bound to a user, or another one bound to none",
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

    /// The tenant the ceremony belongs to.
    #[must_use]
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The user the ceremony is bound to, absent for discoverable ceremonies.
    #[must_use]
    pub fn user_id(&self) -> Option<&UserId> {
        self.subject.account()
    }

    /// Registration or authentication.
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
    /// For storage only. Everything that uses the state goes through
    /// [`consume`](Self::consume), which makes sure it is used once. Reading
    /// it here to verify an assertion would skip that check.
    #[must_use]
    pub fn state_for_storage(&self) -> &[u8] {
        &self.state
    }

    /// Closes the ceremony and hands over the state to verify against.
    ///
    /// This is the one way to reach the state, and it works exactly once. A
    /// replayed or stale ceremony gives an error, not a second verification.
    /// Callers name the purpose they expect, so a registration state can
    /// never settle a login.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the ceremony was already consumed.
    /// - [`DomainError::Validation`] when the ceremony was opened for a
    ///   different purpose.
    /// - [`DomainError::Validation`] when the ceremony has expired.
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

/// A `WebAuthn` challenge on plane `S`, as a passkey's answer is held to it.
///
/// A tenant's ceremony and an organization's answer it alike, so a passkey
/// proves its holder the same way on either plane. Only the ceremonies of
/// this crate answer it, so no caller makes up a challenge that was spent.
pub trait PasskeyChallenge<S: PasskeyPlane>: Sealed {
    /// The account the challenge was opened for, unless it was
    /// discoverable.
    fn opened_for(&self) -> Option<S::Owner>;

    /// What the challenge was opened for.
    fn opened_as(&self) -> CeremonyPurpose;

    /// When the challenge was spent, if it was.
    fn spent_at(&self) -> Option<OffsetDateTime>;
}

impl RaisesComplete for PasskeyCeremony {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}

impl Sealed for PasskeyCeremony {}

impl<T: TenantScope> PasskeyChallenge<T> for PasskeyCeremony {
    fn opened_for(&self) -> Option<UserId> {
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
    use crate::test_support::events::raised_complete_names;

    fn params(purpose: TargetedPurpose) -> OpenCeremonyParams {
        OpenCeremonyParams {
            tenant_id: TenantId::new(),
            user_id: UserId::new(),
            purpose,
            state: b"opaque-verifier-state".to_vec(),
            ttl: five_minutes(),
        }
    }

    fn five_minutes() -> Lifetime {
        Lifetime::seconds(300).unwrap()
    }

    fn open(purpose: TargetedPurpose) -> PasskeyCeremony {
        PasskeyCeremony::open(params(purpose))
    }

    /// Ann starts a passkey sign-in. The new ceremony is not settled yet and
    /// expires after it was opened.
    #[test]
    fn a_fresh_ceremony_is_unconsumed() {
        let ceremony = open(TargetedPurpose::Authentication);

        assert!(ceremony.consumed_at().is_none());
        assert!(ceremony.expires_at() > ceremony.created_at());
    }

    /// Ann answers her sign-in ceremony in time. Consuming it gives back the
    /// exact verifier state it was opened with.
    #[test]
    fn consume_hands_over_the_state() {
        let mut ceremony = open(TargetedPurpose::Authentication);

        let state = ceremony
            .consume(CeremonyPurpose::Authentication)
            .expect("a fresh ceremony is answerable");

        assert_eq!(state, b"opaque-verifier-state");
    }

    /// After Ann's ceremony is consumed, it records when it was settled.
    #[test]
    fn consume_marks_it_settled() {
        let mut ceremony = open(TargetedPurpose::Authentication);

        ceremony.consume(CeremonyPurpose::Authentication).unwrap();

        assert!(ceremony.consumed_at().is_some());
    }

    /// Consuming a settled passkey ceremony again returns a validation error.
    #[test]
    fn a_ceremony_cannot_be_consumed_twice() {
        let mut ceremony = open(TargetedPurpose::Authentication);
        ceremony.consume(CeremonyPurpose::Authentication).unwrap();

        let second = ceremony.consume(CeremonyPurpose::Authentication);

        assert!(matches!(second, Err(DomainError::Validation(_))));
    }

    /// A registration ceremony cannot answer a sign-in and remains unspent after refusal.
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

    /// Ann answers at the exact moment her ceremony expires. The answer is
    /// refused, because the window is closed at its end time.
    #[test]
    fn an_expired_ceremony_is_refused() {
        let mut ceremony = open(TargetedPurpose::Authentication);

        let _later = crate::shared::clock::freeze(ceremony.expires_at());
        let result = ceremony.consume(CeremonyPurpose::Authentication);

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// Each purpose parses back from its storage name. An unknown name such
    /// as "Nonsense" parses to nothing.
    #[test]
    fn purpose_round_trips_through_its_storage_name() {
        for purpose in [
            CeremonyPurpose::Registration,
            CeremonyPurpose::Authentication,
            CeremonyPurpose::DiscoverableAuthentication,
        ] {
            assert_eq!(CeremonyPurpose::parse(purpose.as_str()), Some(purpose));
        }
        assert_eq!(CeremonyPurpose::parse("Nonsense"), None);
    }

    /// Ann has said who she is and starts a passkey sign-in. The ceremony
    /// records her as its user.
    #[test]
    fn a_targeted_ceremony_is_bound_to_its_user() {
        let ceremony = open(TargetedPurpose::Authentication);

        assert!(ceremony.user_id().is_some());
    }

    /// A visitor clicks "sign in with a passkey" without typing a name. The
    /// ceremony has no user and is marked as discoverable.
    #[test]
    fn a_discoverable_ceremony_binds_no_user() {
        let ceremony = PasskeyCeremony::open_discoverable(
            TenantId::new(),
            b"opaque-verifier-state".to_vec(),
            five_minutes(),
        );

        assert!(ceremony.user_id().is_none());
        assert_eq!(
            ceremony.purpose(),
            CeremonyPurpose::DiscoverableAuthentication
        );
    }

    /// A discoverable ceremony cannot answer a sign-in ceremony bound to Ann.
    #[test]
    fn a_discoverable_ceremony_cannot_settle_a_targeted_authentication() {
        let mut ceremony = PasskeyCeremony::open_discoverable(
            TenantId::new(),
            b"opaque-verifier-state".to_vec(),
            five_minutes(),
        );

        let result = ceremony.consume(CeremonyPurpose::Authentication);

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A discoverable ceremony opened with a five minute lifetime has no
    /// user. It still belongs to its tenant and expires five minutes after it
    /// was opened.
    #[test]
    fn a_discoverable_ceremony_is_bound_to_a_tenant_and_expires_after_its_ttl() {
        let tenant = TenantId::new();
        let ttl = five_minutes();

        let ceremony = PasskeyCeremony::open_discoverable(tenant, b"state".to_vec(), ttl);

        assert_eq!(ceremony.tenant_id(), &tenant);
        assert_eq!(ceremony.user_id(), None);
        assert_eq!(
            ceremony.purpose(),
            CeremonyPurpose::DiscoverableAuthentication
        );
        assert_eq!(ceremony.expires_at(), ttl.ends_after(ceremony.created_at()));
        assert!(
            ceremony.expires_at() > ceremony.created_at(),
            "a window that closed before it opened is answerable by nobody"
        );
    }

    /// Two ceremonies opened for two tenants get different ids and each keeps
    /// its own tenant. The id is all the browser holds, and the tenant keeps
    /// one tenant's ceremony from being answered in another.
    #[test]
    fn a_ceremony_carries_its_own_id_and_its_tenant() {
        let first = open(TargetedPurpose::Registration);
        let second = open(TargetedPurpose::Registration);

        assert_ne!(first.id(), second.id());
        assert_ne!(
            first.tenant_id(),
            second.tenant_id(),
            "each ceremony records the tenant it was opened in"
        );
    }

    /// The state handed to the repository is the exact bytes the ceremony was
    /// opened with. Altered bytes would make every later confirm fail.
    #[test]
    fn the_stored_state_is_the_state_the_ceremony_was_opened_with() {
        let ceremony = open(TargetedPurpose::Authentication);

        assert_eq!(ceremony.state_for_storage(), b"opaque-verifier-state");
    }

    /// Each purpose is stored, displayed and parsed under one fixed name,
    /// such as "Registration". A confirm checks the purpose, so two purposes
    /// must never share a name.
    #[test]
    fn every_ceremony_purpose_round_trips_and_renders_under_its_own_name() {
        let purposes = [
            (CeremonyPurpose::Registration, "Registration"),
            (CeremonyPurpose::Authentication, "Authentication"),
            (
                CeremonyPurpose::DiscoverableAuthentication,
                "DiscoverableAuthentication",
            ),
        ];

        for (purpose, name) in purposes {
            assert_eq!(purpose.as_str(), name);
            assert_eq!(purpose.to_string(), name);
            assert_eq!(CeremonyPurpose::parse(name), Some(purpose));
        }

        assert_eq!(CeremonyPurpose::parse("Something else"), None);
    }

    fn stored(purpose: CeremonyPurpose, subject: CeremonySubject<UserId>) -> PasskeyCeremonyRow {
        let now = crate::shared::clock::now();
        PasskeyCeremonyRow {
            id: CeremonyId::new(),
            tenant_id: TenantId::new(),
            subject,
            purpose,
            state: vec![1],
            created_at: now,
            expires_at: now + time::Duration::minutes(5),
            usage: Usage::Unused,
        }
    }

    /// A stored sign-in ceremony with no user, or a discoverable one with a
    /// user, is refused as corrupt. A targeted ceremony with no user would
    /// sign in whoever answered it.
    #[test]
    fn a_stored_account_must_match_the_purpose() {
        let user = UserId::new();

        for fits in [
            stored(
                CeremonyPurpose::Authentication,
                CeremonySubject::Claimed(user),
            ),
            stored(
                CeremonyPurpose::DiscoverableAuthentication,
                CeremonySubject::Unclaimed,
            ),
        ] {
            assert!(PasskeyCeremony::reconstitute(fits).is_ok());
        }
        for contradicts in [
            stored(CeremonyPurpose::Authentication, CeremonySubject::Unclaimed),
            stored(
                CeremonyPurpose::DiscoverableAuthentication,
                CeremonySubject::Claimed(user),
            ),
        ] {
            assert!(matches!(
                PasskeyCeremony::reconstitute(contradicts),
                Err(DomainError::Infrastructure(_))
            ));
        }
    }

    /// A stored row says the ceremony was settled one second before it was
    /// opened. Loading it is refused as corrupt.
    #[test]
    fn a_ceremony_settled_before_it_was_opened_is_refused() {
        let mut row = stored(
            CeremonyPurpose::Registration,
            CeremonySubject::Claimed(UserId::new()),
        );
        row.usage = Usage::Used {
            at: row.created_at - time::Duration::SECOND,
        };

        assert!(matches!(
            PasskeyCeremony::reconstitute(row),
            Err(DomainError::Infrastructure(_))
        ));
    }

    /// A stored row says the ceremony was settled at the instant it
    /// expired. No answer is taken once it expires, so loading it is refused
    /// as corrupt.
    #[test]
    fn a_ceremony_settled_once_it_expired_is_refused() {
        let mut row = stored(
            CeremonyPurpose::Registration,
            CeremonySubject::Claimed(UserId::new()),
        );
        row.usage = Usage::Used { at: row.expires_at };

        assert!(refused_as_corrupt(&PasskeyCeremony::reconstitute(row)));
    }

    /// Ann starts adding a passkey. The ceremony raises
    /// `authentication.passkey_registration_started` in its tenant.
    #[test]
    fn opening_a_registration_raises_its_start_in_the_tenant() {
        let params = params(TargetedPurpose::Registration);
        let tenant = params.tenant_id;
        let mut ceremony = PasskeyCeremony::open(params);

        let events = ceremony.take_events();

        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().as_str(),
            "authentication.passkey_registration_started"
        );
        assert_eq!(events[0].tenant_id(), Some(&tenant));
    }

    /// Ann starts a passkey sign-in. The ceremony raises
    /// `authentication.passkey_sign_in_started`.
    #[test]
    fn opening_a_sign_in_raises_its_start() {
        let mut ceremony = open(TargetedPurpose::Authentication);

        assert_eq!(
            raised_complete_names(&mut ceremony),
            ["authentication.passkey_sign_in_started"]
        );
    }

    /// Someone offers a passkey from the empty sign-in field. The ceremony
    /// raises `authentication.passkey_challenge_issued`.
    #[test]
    fn opening_a_discoverable_ceremony_raises_the_challenge() {
        let mut ceremony =
            PasskeyCeremony::open_discoverable(TenantId::new(), b"state".to_vec(), five_minutes());

        assert_eq!(
            raised_complete_names(&mut ceremony),
            ["authentication.passkey_challenge_issued"]
        );
    }

    /// Replaying a settled ceremony is refused without raising another event.
    #[test]
    fn a_refused_consume_raises_nothing() {
        let mut ceremony = open(TargetedPurpose::Authentication);
        ceremony.consume(CeremonyPurpose::Authentication).unwrap();
        raised_complete_names(&mut ceremony);

        let replayed = ceremony.consume(CeremonyPurpose::Authentication);

        assert!(replayed.is_err());
        assert!(ceremony.take_events().is_empty());
    }

    /// A ceremony read back from storage has raised nothing.
    #[test]
    fn a_ceremony_read_back_has_raised_nothing() {
        let row = stored(
            CeremonyPurpose::Registration,
            CeremonySubject::Claimed(UserId::new()),
        );

        let mut ceremony = PasskeyCeremony::reconstitute(row).unwrap();

        assert!(ceremony.take_events().is_empty());
    }
}
