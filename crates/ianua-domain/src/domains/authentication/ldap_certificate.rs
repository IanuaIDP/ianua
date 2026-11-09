//! LDAP client certificates, the possession factor that an LDAP simple bind
//! cannot carry.
//!
//! A simple bind is a DN and a password. The protocol has no way to send a
//! second factor. A client certificate adds one, the same way a passkey
//! does. Its private key never leaves the user's device, and the server
//! checks possession of it with cryptography instead of trusting a shared
//! secret. It travels over `SASL EXTERNAL`, which LDAP already defines. Only
//! a bind made with a certificate may try a write. A password bind stays
//! read-only.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authentication::credentials::password::PasswordHasher;
use crate::domains::authentication::events::directory::{
    LdapCertificateIssued, LdapCertificateRevoked,
};
use crate::domains::authentication::keeper::AccountKeeper;
use crate::domains::authentication::sessions::fresh_sign_in::{FreshSignIn, PasswordCheck};
use crate::domains::identity::account::control::{AccountAction, RecentProof, SignedInPerson};
use crate::domains::identity::account::user::User;
use crate::domains::identity::sealed::Sealed;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::numeric::validate_range;
use crate::types::{
    CertificateFingerprint, EventLabel, Label, LdapCertificateId, PrincipalId, Revocation, UserId,
};

/// How many days an LDAP client certificate stays valid.
///
/// A certificate is a write credential that outlives every session it is
/// used in, so its life has limits. It lasts at least a day and never longer
/// than the 397 days public certificate authorities are held to. A raw day
/// count could be zero, negative or decades long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateValidity(u16);

impl CertificateValidity {
    const MIN_DAYS: u16 = 1;
    const MAX_DAYS: u16 = 397;

    /// A validity of `days` days.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `days` is below one or above 397.
    pub fn days(days: u16) -> Result<Self, DomainError> {
        validate_range("validity_days", days, Self::MIN_DAYS..=Self::MAX_DAYS)?;
        Ok(Self(days))
    }

    /// The validity as a duration.
    #[must_use]
    pub fn as_duration(self) -> time::Duration {
        time::Duration::days(i64::from(self.0))
    }

    /// The validity in whole days.
    #[must_use]
    pub fn as_days(self) -> u16 {
        self.0
    }

    /// Whether a certificate may stay valid for `length`, from one day to
    /// 397 days.
    fn allows(length: time::Duration) -> bool {
        let shortest = time::Duration::days(i64::from(Self::MIN_DAYS));
        let longest = time::Duration::days(i64::from(Self::MAX_DAYS));
        (shortest..=longest).contains(&length)
    }
}

/// A client certificate issued for LDAP write access.
///
/// It belongs to one tenant. It is read and written only through stores
/// opened for the resolved tenant. See [`crate::isolation`].
#[derive(Debug)]
pub struct LdapClientCertificate<T: TenantScope> {
    id: LdapCertificateId,
    user_id: UserId,
    fingerprint: CertificateFingerprint,
    device_label: Label,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    /// Whether it was revoked, and when.
    revocation: Revocation,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// Parameters for issuing a new certificate.
pub struct IssueLdapCertificateParams {
    /// The user the certificate authenticates as.
    pub user_id: UserId,
    /// How the user is named in the record of the issue: the address
    /// their account holds.
    pub holder_label: EventLabel,
    /// The signed certificate's fingerprint.
    pub fingerprint: CertificateFingerprint,
    /// The label the user gave the device, such as "MacBook VPN client".
    pub device_label: Label,
    /// How long from now the certificate is valid.
    pub validity: CertificateValidity,
}

/// Persisted state for repository hydration.
pub struct LdapClientCertificateRow {
    /// Unique certificate record identifier.
    pub id: LdapCertificateId,
    /// The user the certificate authenticates as.
    pub user_id: UserId,
    /// The signed certificate's fingerprint.
    pub fingerprint: CertificateFingerprint,
    /// User-supplied label.
    pub device_label: Label,
    /// When the certificate was issued.
    pub issued_at: OffsetDateTime,
    /// When the certificate stops being valid.
    pub expires_at: OffsetDateTime,
    /// Whether it was revoked, and when.
    pub revocation: Revocation,
}

impl<T: TenantScope> LdapClientCertificate<T> {
    /// Issues a new certificate record, for a person who proved who they
    /// are just now.
    ///
    /// This records that a certificate was signed. It does not sign one.
    /// Signing happens behind the app layer's certificate authority port,
    /// because the CA never lives in the domain. Only the fingerprint of the
    /// result is kept here.
    ///
    /// A certificate writes to the directory for up to 397 days. Mallory
    /// steals Ann's session and asks for one. Without the fresh proof she
    /// writes as Ann long after the session ends.
    ///
    /// Raises `authentication.ldap_certificate_issued`, naming the holder as
    /// `params.holder_label`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `proof` is not a fresh proof of the
    ///   account the certificate is for.
    pub fn issue(
        params: IssueLdapCertificateParams,
        proof: &impl RecentProof,
    ) -> Result<Self, DomainError> {
        if !proof.proves_recently(&PrincipalId::from(params.user_id)) {
            return Err(DomainError::forbidden(message!(
                "authentication-a-directory-certificate-needs-the-person",
                "a directory certificate needs the person to prove who they are again"
            )));
        }
        let now = crate::shared::clock::now();
        let mut certificate = Self {
            id: LdapCertificateId::new(),
            user_id: params.user_id,
            fingerprint: params.fingerprint,
            device_label: params.device_label,
            issued_at: now,
            expires_at: now.saturating_add(params.validity.as_duration()),
            revocation: Revocation::InForce,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        certificate.raised.raise(LdapCertificateIssued {
            user_id: certificate.user_id,
            user_label: params.holder_label,
            certificate_id: certificate.id,
            device_label: EventLabel::of(certificate.device_label.as_str()),
            expires_at: certificate.expires_at,
            occurred_at: now,
        });
        Ok(certificate)
    }

    /// Rebuilds a client certificate from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row expires no later than it
    ///   was issued.
    /// - [`DomainError::Infrastructure`] when the row is valid for less than
    ///   a day or more than 397 days.
    /// - [`DomainError::Infrastructure`] when the row was revoked before it
    ///   was issued.
    pub fn reconstitute(row: LdapClientCertificateRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            user_id: row.user_id,
            fingerprint: row.fingerprint,
            device_label: row.device_label,
            issued_at: row.issued_at,
            expires_at: row.expires_at,
            revocation: row.revocation,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &LdapClientCertificateRow) -> Result<(), DomainError> {
        RowCheck::of("LDAP client certificate")
            .holds(
                row.issued_at < row.expires_at,
                "expires before it was issued",
            )
            .holds(
                CertificateValidity::allows(crate::shared::clock::between(
                    row.issued_at,
                    row.expires_at,
                )),
                "valid for less than a day or more than 397 days",
            )
            .in_order_if(
                row.issued_at,
                row.revocation.revoked_at(),
                "revoked before it was issued",
            )
            .finish()
    }

    /// Unique certificate record identifier.
    #[must_use]
    pub fn id(&self) -> &LdapCertificateId {
        &self.id
    }

    /// The user the certificate authenticates as.
    #[must_use]
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// The signed certificate's fingerprint.
    #[must_use]
    pub fn fingerprint(&self) -> &CertificateFingerprint {
        &self.fingerprint
    }

    /// User-supplied label.
    #[must_use]
    pub fn device_label(&self) -> &Label {
        &self.device_label
    }

    /// When the certificate was issued.
    #[must_use]
    pub fn issued_at(&self) -> OffsetDateTime {
        self.issued_at
    }

    /// When the certificate stops being valid.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// When the certificate was revoked, if it has been.
    #[must_use]
    pub fn revoked_at(&self) -> Option<OffsetDateTime> {
        self.revocation.revoked_at()
    }

    /// Whether this certificate allows `account` a write at `now`.
    ///
    /// It must be neither revoked nor expired, be `account`'s, and the
    /// account must still be able to sign in. A certificate outlives every
    /// session. Without the account check, Ann's admin locks her account and
    /// her laptop keeps writing to the directory as her.
    #[must_use]
    pub fn admits_write(&self, account: &User<T>, now: OffsetDateTime) -> bool {
        self.in_force_at(now) && *account.id() == self.user_id && account.can_authenticate()
    }

    /// Whether the certificate is neither revoked nor expired at `now`.
    fn in_force_at(&self, now: OffsetDateTime) -> bool {
        !self.revocation.is_revoked() && self.expires_at > now
    }

    /// Revokes the certificate, as its holder or an admin acting on their
    /// account decides. Revoking it again keeps the first revocation time.
    ///
    /// Sam may only view users. Without this check, he revokes the
    /// certificate Ann's directory client writes with, and her sync stops.
    ///
    /// The first revocation raises `authentication.ldap_certificate_revoked`,
    /// naming the holder as `holder_label`. Revoking again raises nothing.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] in the cases
    ///   [`AccountKeeper::ensure_may`] lists, for changing how the account
    ///   signs in.
    pub fn revoke(
        &mut self,
        by: &impl AccountKeeper<T>,
        holder_label: EventLabel,
    ) -> Result<(), DomainError> {
        by.ensure_may(
            &PrincipalId::from(self.user_id),
            AccountAction::ChangeSignIn,
        )?;
        if self.revocation.is_revoked() {
            return Ok(());
        }
        let now = crate::shared::clock::now();
        self.revocation = self.revocation.revoke_at(now);
        self.raised.raise(LdapCertificateRevoked {
            user_id: self.user_id,
            user_label: holder_label,
            certificate_id: self.id,
            occurred_at: now,
        });
        Ok(())
    }
}

impl<T: TenantScope> Raises for LdapClientCertificate<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// A directory client bound as an account: the account's password, checked
/// just now, over a connection that presented a client certificate in
/// force for it.
///
/// LDAP has no sessions, so each bind proves the person again, and a bind
/// opens none. A password alone is one factor. Mallory, who phished Ann's
/// password, binds with it from her own machine. Without the certificate
/// Ann's laptop holds, that bind proves nothing about Ann.
///
/// It answers identity's rule for a signed-in person, so
/// [`TenantAccess::authority_of`] works out what the account holds for it.
/// It keeps when it was made, so a password reset or any other change of
/// how the account signs in ends it, as it ends a session opened before.
///
/// [`TenantAccess::authority_of`]: crate::domains::authorization::authority::TenantAccess::authority_of
#[derive(Debug)]
pub struct DirectoryBind<T: TenantScope> {
    account: UserId,
    certificate: LdapCertificateId,
    bound_at: OffsetDateTime,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> DirectoryBind<T> {
    /// `account` bound with `password`, over a connection that presented
    /// the certificate whose fingerprint is `presented`, recorded as
    /// `certificate`.
    ///
    /// The certificate is checked before the password. A machine without
    /// one never learns whether a guessed password was right.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `certificate` is not the one
    ///   presented.
    /// - [`DomainError::Forbidden`] when `certificate` is revoked, expired
    ///   or another account's, or `account` may not sign in now.
    /// - The cases [`FreshSignIn::by_password`] lists for the password.
    ///
    /// [`FreshSignIn::by_password`]: crate::domains::authentication::sessions::fresh_sign_in::FreshSignIn::by_password
    pub fn with_certificate<H: PasswordHasher>(
        account: &User<T>,
        password: PasswordCheck<'_, H>,
        certificate: &LdapClientCertificate<T>,
        presented: &CertificateFingerprint,
    ) -> Result<Self, DomainError> {
        let now = crate::shared::clock::now();
        if certificate.fingerprint() != presented {
            return Err(DomainError::forbidden(message!(
                "authentication-the-certificate-presented-is-not-this",
                "the certificate presented is not this one"
            )));
        }
        if !certificate.admits_write(account, now) {
            return Err(DomainError::forbidden(message!(
                "authentication-no-certificate-in-force-for-this",
                "no certificate in force for this account was presented"
            )));
        }
        password.ensure_matches(now)?;
        Ok(Self {
            account: *account.id(),
            certificate: *certificate.id(),
            bound_at: now,
            _scope: PhantomData,
        })
    }

    /// The account bound as.
    #[must_use]
    pub fn account(&self) -> &UserId {
        &self.account
    }

    /// The record of the certificate the bind was made over.
    #[must_use]
    pub fn certificate(&self) -> &LdapCertificateId {
        &self.certificate
    }

    /// When the bind was made.
    #[must_use]
    pub fn bound_at(&self) -> OffsetDateTime {
        self.bound_at
    }

    /// Whether this bind still lets a request through at `now`, with
    /// `account` and `certificate` loaded fresh for it.
    ///
    /// LDAP keeps a bind for the whole connection, so each request asks
    /// again. The certificate must be the one bound over and still admit
    /// the account, and the account's credentials must not have changed
    /// since the bind. Ann's admin resets her password after her laptop
    /// was stolen. Without the last check, the connection the thief bound
    /// before the reset keeps writing until it closes.
    #[must_use]
    pub fn still_admits(
        &self,
        account: &User<T>,
        certificate: &LdapClientCertificate<T>,
        now: OffsetDateTime,
    ) -> bool {
        *account.id() == self.account
            && *certificate.id() == self.certificate
            && certificate.admits_write(account, now)
            && !account.credentials_changed_at().since(self.bound_at)
    }

    /// Proves the bound person afresh with their password and freshly loaded account
    /// and certificate. The client certificate supplies the second factor: it was issued
    /// after fresh proof and checked with the password during the bind. LDAP carries no code.
    /// Only binds within `FRESH_FOR` qualify; older connections must bind again.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] if [`Self::still_admits`] refuses or the bind is stale,
    /// before checking the password. Also propagates [`FreshSignIn::by_password`] errors.
    ///
    pub fn fresh_sign_in<H: PasswordHasher>(
        &self,
        account: &User<T>,
        certificate: &LdapClientCertificate<T>,
        password: PasswordCheck<'_, H>,
    ) -> Result<FreshSignIn, DomainError> {
        if !self.still_admits(account, certificate, crate::shared::clock::now()) {
            return Err(DomainError::forbidden(message!(
                "authentication-the-directory-bind-no-longer-counts",
                "the directory bind no longer counts; bind again"
            )));
        }
        FreshSignIn::beside_certificate(self.account.into(), password, self.bound_at)
    }
}

impl<T: TenantScope> Sealed for DirectoryBind<T> {}

impl<T: TenantScope> SignedInPerson<T> for DirectoryBind<T> {
    fn is_holder_of(&self, account: &UserId) -> bool {
        self.account == *account
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::risk_engine::rate_limit::{
        AttemptTally, LoginAttemptTracker,
    };
    use crate::domains::authentication::sessions::account_check::tests::account_with;
    use crate::domains::authentication::sessions::fresh_sign_in::fresh_proof_of;
    use crate::domains::authentication::sessions::sign_in_progress::{
        SignedIn, finished_sign_in_of,
    };
    use crate::domains::authorization::authority::TenantAccess;
    use crate::domains::authorization::granter::{AccountControl, Handout};
    use crate::domains::authorization::group::{Group, GroupMembership};
    use crate::domains::authorization::permission::{SystemPermission, UserAction};
    use crate::domains::authorization::role::{Role, RoleAssignment};
    use crate::domains::authorization::stewardship::{Stewardship, TenantGrants};
    use crate::domains::identity::account::user_status::UserStatus;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{CredentialChange, PasswordHash, TenantId};

    fn params() -> IssueLdapCertificateParams {
        IssueLdapCertificateParams {
            user_id: UserId::new(),
            holder_label: EventLabel::of("ann@acme.com"),
            fingerprint: CertificateFingerprint::parse(
                "sha256:0707070707070707070707070707070707070707070707070707070707070707",
            )
            .unwrap(),
            device_label: Label::new("name", "MacBook").unwrap(),
            validity: CertificateValidity::days(90).unwrap(),
        }
    }

    fn issued(params: IssueLdapCertificateParams) -> LdapClientCertificate<ResolvedTenant> {
        let proof = fresh_proof_of(params.user_id.into());
        LdapClientCertificate::issue(params, &proof).unwrap()
    }

    fn holder_of(
        cert: &LdapClientCertificate<ResolvedTenant>,
        status: UserStatus,
    ) -> User<ResolvedTenant> {
        account_with(*cert.user_id(), status, CredentialChange::Never)
    }

    /// Ann is issued a 90 day certificate. It allows her a write straight
    /// away.
    #[test]
    fn a_freshly_issued_certificate_is_valid() {
        let cert = issued(params());
        let ann = holder_of(&cert, UserStatus::Active);

        assert!(cert.admits_write(&ann, crate::shared::clock::now()));
    }

    /// A fresh proof for another account cannot authorize Ann's certificate.
    #[test]
    fn a_certificate_is_not_issued_without_a_fresh_proof_of_its_account() {
        let mallorys = fresh_proof_of(UserId::new().into());

        let refused = LdapClientCertificate::<ResolvedTenant>::issue(params(), &mallorys);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Locking, deactivating, or closing an account removes its certificate's write authority.
    #[test]
    fn a_certificate_allows_no_write_once_its_account_is_shut() {
        let cert = issued(params());

        for status in [
            UserStatus::Locked,
            UserStatus::Deactivated,
            UserStatus::Closing,
        ] {
            let shut = holder_of(&cert, status);
            assert!(
                !cert.admits_write(&shut, crate::shared::clock::now()),
                "{status:?} still writes"
            );
        }
    }

    /// Ann's certificate grants no write authority to Bob.
    #[test]
    fn a_certificate_allows_writes_only_to_its_own_account() {
        let cert = issued(params());
        let bob = account_with(UserId::new(), UserStatus::Active, CredentialChange::Never);

        assert!(!cert.admits_write(&bob, crate::shared::clock::now()));
    }

    /// One second after Ann's certificate expires, it refuses a write.
    #[test]
    fn a_certificate_past_its_expiry_is_not_valid() {
        let cert = issued(params());
        let past_expiry = cert.expires_at() + time::Duration::seconds(1);
        assert!(!cert.in_force_at(past_expiry));
    }

    /// Ann's laptop is stolen and she revokes its certificate. It stops
    /// allowing writes at once and records when it was revoked.
    #[test]
    fn revoking_makes_a_certificate_invalid() {
        let mut cert = issued(params());
        let ann = signed_in_holder(&cert);

        cert.revoke(&ann, anns_label()).unwrap();

        assert!(!cert.in_force_at(crate::shared::clock::now()));
        assert!(cert.revoked_at().is_some());
    }

    /// An admin revokes a certificate twice. The second revoke keeps the
    /// first time, so the record shows when access really ended.
    #[test]
    fn revoking_twice_keeps_the_original_revocation_time() {
        static EDITOR: [SystemPermission; 1] = [SystemPermission::Users(UserAction::Update)];
        let mut cert = issued(params());
        let admin = AccountControl::assumed(
            anyone_holding(&EDITOR),
            *cert.user_id(),
            Stewardship::OthersAdminister,
            Handout::NOTHING,
        );

        cert.revoke(&admin, anns_label()).unwrap();
        let first = cert.revoked_at();
        cert.revoke(&admin, anns_label()).unwrap();

        assert_eq!(cert.revoked_at(), first);
    }

    /// Mallory cannot revoke Ann's certificate, which retains no revocation time.
    #[test]
    fn someone_else_does_not_revoke_a_certificate() {
        let mut cert = issued(params());
        let mallory = finished_sign_in_of::<ResolvedTenant>(UserId::new().into());

        let refused = cert.revoke(&mallory, anns_label());

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert!(cert.revoked_at().is_none());
    }

    fn signed_in_holder(cert: &LdapClientCertificate<ResolvedTenant>) -> SignedIn<ResolvedTenant> {
        finished_sign_in_of((*cert.user_id()).into())
    }

    fn anns_label() -> EventLabel {
        EventLabel::of("ann@acme.com")
    }

    /// Ann is issued a certificate for her MacBook. It raises
    /// `authentication.ldap_certificate_issued`, naming her by address, the
    /// device and when the certificate runs out.
    #[test]
    fn issuing_raises_the_issue() {
        let mut cert = issued(params());

        let events = raised(&mut cert);

        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().as_str(),
            "authentication.ldap_certificate_issued"
        );
        let payload = events[0].payload();
        assert_eq!(payload.get("device_label"), Some("MacBook"));
        assert_eq!(
            payload.get("certificate_id"),
            Some(cert.id().to_string().as_str())
        );
        assert_eq!(
            payload.get("expires_at"),
            Some(cert.expires_at().to_string().as_str())
        );
    }

    /// Ann revokes her laptop's certificate. It raises
    /// `authentication.ldap_certificate_revoked`.
    #[test]
    fn revoking_raises_the_revocation() {
        let mut cert = issued(params());
        raised_names(&mut cert);
        let ann = signed_in_holder(&cert);

        cert.revoke(&ann, anns_label()).unwrap();

        assert_eq!(
            raised_names(&mut cert),
            ["authentication.ldap_certificate_revoked"]
        );
    }

    /// Ann revokes a certificate she already revoked. The second time
    /// raises nothing, so the record shows one revocation.
    #[test]
    fn revoking_again_raises_nothing() {
        let mut cert = issued(params());
        let ann = signed_in_holder(&cert);
        cert.revoke(&ann, anns_label()).unwrap();
        raised_names(&mut cert);

        cert.revoke(&ann, anns_label()).unwrap();

        assert!(raised_names(&mut cert).is_empty());
    }

    /// Refusing another account's certificate revocation raises no event.
    #[test]
    fn a_refused_revocation_raises_nothing() {
        let mut cert = issued(params());
        raised_names(&mut cert);
        let mallory = finished_sign_in_of::<ResolvedTenant>(UserId::new().into());

        let refused = cert.revoke(&mallory, anns_label());

        assert!(refused.is_err());
        assert!(raised_names(&mut cert).is_empty());
    }

    /// A certificate read back from storage has raised nothing.
    #[test]
    fn a_certificate_read_back_has_raised_nothing() {
        let cert = issued(params());
        let mut read_back =
            LdapClientCertificate::<ResolvedTenant>::reconstitute(stored(&cert)).unwrap();

        assert!(raised_names(&mut read_back).is_empty());
    }

    /// A digest of 32 bytes of 7 prints as `sha256:` and 64 hex digits of
    /// `07`. A presented certificate is matched to its record by this text.
    #[test]
    fn a_fingerprint_reads_back_as_the_hex_it_was_wrapped_around() {
        let fingerprint = CertificateFingerprint::from_digest([7; 32]);

        assert_eq!(
            fingerprint.to_string(),
            "sha256:0707070707070707070707070707070707070707070707070707070707070707"
        );
    }

    /// Ann is issued a certificate. It names Ann, keeps the fingerprint it
    /// was issued with and has its own record id. Writes act as Ann, and a
    /// revoke names that id.
    #[test]
    fn a_certificate_names_the_user_it_was_issued_to_and_its_own_record() {
        let user = UserId::new();
        let cert = issued(IssueLdapCertificateParams {
            user_id: user,
            ..params()
        });

        assert_eq!(cert.user_id(), &user);
        assert_eq!(
            cert.fingerprint().to_string(),
            "sha256:0707070707070707070707070707070707070707070707070707070707070707"
        );
        assert!(!cert.id().as_uuid().is_nil());
    }

    /// A certificate valid for 0 days is refused, since it could never be
    /// used.
    #[test]
    fn a_validity_of_zero_days_is_refused() {
        assert!(CertificateValidity::days(0).is_err());
    }

    /// 397 days is accepted, the most public certificate authorities allow.
    /// 398 days is refused.
    #[test]
    fn a_validity_longer_than_a_public_certificate_is_refused() {
        assert!(CertificateValidity::days(397).is_ok());
        assert!(CertificateValidity::days(398).is_err());
    }

    /// A certificate issued for 90 days expires exactly 90 days after it was
    /// issued.
    #[test]
    fn a_certificate_expires_after_its_validity() {
        let cert = issued(params());

        assert_eq!(
            cert.expires_at() - cert.issued_at(),
            time::Duration::days(90)
        );
    }

    /// One second before expiry the certificate allows a write. At the expiry
    /// instant itself it does not.
    #[test]
    fn a_certificate_is_not_valid_at_the_moment_it_expires() {
        let cert = issued(params());

        assert!(cert.in_force_at(cert.expires_at() - time::Duration::seconds(1)));
        assert!(!cert.in_force_at(cert.expires_at()));
    }

    fn stored(cert: &LdapClientCertificate<ResolvedTenant>) -> LdapClientCertificateRow {
        LdapClientCertificateRow {
            id: *cert.id(),
            user_id: *cert.user_id(),
            fingerprint: *cert.fingerprint(),
            device_label: cert.device_label().clone(),
            issued_at: cert.issued_at(),
            expires_at: cert.expires_at(),
            revocation: Revocation::from_stored(cert.revoked_at()),
        }
    }

    /// A stored row expires at the same instant it was issued. Loading it is
    /// refused as corrupt.
    #[test]
    fn a_stored_certificate_that_expires_before_it_was_issued_is_refused() {
        let mut row = stored(&issued(params()));
        row.expires_at = row.issued_at;

        assert!(refused_as_corrupt(
            &LdapClientCertificate::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored certificate with a fifty-year lifetime is rejected as corrupt.
    #[test]
    fn a_stored_certificate_valid_longer_than_397_days_is_refused() {
        let mut row = stored(&issued(params()));
        row.expires_at = row.issued_at + time::Duration::days(50 * 365);

        assert!(refused_as_corrupt(
            &LdapClientCertificate::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored row issued for exactly 397 days loads, since it is the
    /// longest validity a new certificate may get.
    #[test]
    fn a_stored_certificate_valid_for_397_days_loads() {
        let mut row = stored(&issued(params()));
        row.expires_at = row.issued_at + time::Duration::days(397);

        assert!(LdapClientCertificate::<ResolvedTenant>::reconstitute(row).is_ok());
    }

    /// A stored row valid for one hour is refused as corrupt. No new
    /// certificate is issued for less than a day.
    #[test]
    fn a_stored_certificate_valid_less_than_a_day_is_refused() {
        let mut row = stored(&issued(params()));
        row.expires_at = row.issued_at + time::Duration::HOUR;

        assert!(refused_as_corrupt(
            &LdapClientCertificate::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A stored row says the certificate was revoked one second before it
    /// was issued. Loading it is refused as corrupt.
    #[test]
    fn a_stored_certificate_revoked_before_it_was_issued_is_refused() {
        let mut row = stored(&issued(params()));
        row.revocation = Revocation::Revoked {
            at: row.issued_at - time::Duration::SECOND,
        };

        assert!(refused_as_corrupt(
            &LdapClientCertificate::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// Says yes to "right" and no to anything else.
    struct KnowsOnePassword;

    impl PasswordHasher for KnowsOnePassword {
        fn hash(&self, raw: &str) -> Result<PasswordHash, DomainError> {
            Ok(PasswordHash::from_stored(raw.to_owned()))
        }

        fn verify(&self, raw: &str, _hash: &PasswordHash) -> Result<bool, DomainError> {
            Ok(raw == "right")
        }
    }

    /// `account` binding with `raw` over a connection that presented
    /// `presented`, recorded as `cert`.
    fn bind(
        account: &User<ResolvedTenant>,
        raw: &str,
        cert: &LdapClientCertificate<ResolvedTenant>,
        presented: &CertificateFingerprint,
    ) -> Result<DirectoryBind<ResolvedTenant>, DomainError> {
        let stored = PasswordHash::from_stored("hash".to_owned());
        DirectoryBind::with_certificate(
            account,
            PasswordCheck {
                raw,
                stored: &stored,
                hasher: &KnowsOnePassword,
                tracker: &mut LoginAttemptTracker::new(),
            },
            cert,
            presented,
        )
    }

    /// Ann's laptop binds with her password and her certificate. What her
    /// account holds is worked out for the bind, as for a sign-in.
    #[test]
    fn a_password_and_a_certificate_in_force_bind_as_the_account() {
        let cert = issued(params());
        let ann = holder_of(&cert, UserStatus::Active);
        let access = TenantAccess {
            tenant: TenantId::new(),
            grants: TenantGrants {
                roles: &[] as &[Role<ResolvedTenant>],
                assignments: &[] as &[RoleAssignment<ResolvedTenant>],
                groups: &[] as &[Group<ResolvedTenant>],
                memberships: &[] as &[GroupMembership<ResolvedTenant>],
            },
            catalogue: &[],
            break_glass: &[],
        };

        let bound = bind(&ann, "right", &cert, cert.fingerprint()).unwrap();

        assert!(
            access
                .authority_of(&ann, &bound, crate::shared::clock::now())
                .is_ok()
        );
    }

    /// Ann's password cannot establish a bind with a different certificate.
    #[test]
    fn a_password_without_the_accounts_certificate_binds_nothing() {
        let cert = issued(params());
        let ann = holder_of(&cert, UserStatus::Active);
        let mallorys = CertificateFingerprint::parse(
            "sha256:0808080808080808080808080808080808080808080808080808080808080808",
        )
        .unwrap();

        let bound = bind(&ann, "right", &cert, &mallorys);

        assert!(matches!(bound, Err(DomainError::Forbidden(_))));
    }

    /// The correct certificate cannot establish a bind with a wrong password.
    #[test]
    fn a_certificate_without_the_password_binds_nothing() {
        let cert = issued(params());
        let ann = holder_of(&cert, UserStatus::Active);

        let bound = bind(&ann, "guess", &cert, cert.fingerprint());

        assert!(matches!(bound, Err(DomainError::Forbidden(_))));
    }

    /// A revoked certificate or locked account refuses a password bind.
    #[test]
    fn a_revoked_certificate_or_a_shut_account_binds_nothing() {
        let mut revoked = issued(params());
        let ann = holder_of(&revoked, UserStatus::Active);
        revoked
            .revoke(&signed_in_holder(&revoked), anns_label())
            .unwrap();
        let live = issued(params());
        let locked = holder_of(&live, UserStatus::Locked);

        let with_revoked = bind(&ann, "right", &revoked, revoked.fingerprint());
        let while_locked = bind(&locked, "right", &live, live.fingerprint());

        assert!(matches!(with_revoked, Err(DomainError::Forbidden(_))));
        assert!(matches!(while_locked, Err(DomainError::Forbidden(_))));
    }

    /// Bob's password cannot establish a bind using Ann's certificate.
    #[test]
    fn another_accounts_certificate_binds_nothing() {
        let cert = issued(params());
        let bob = account_with(UserId::new(), UserStatus::Active, CredentialChange::Never);

        let bound = bind(&bob, "right", &cert, cert.fingerprint());

        assert!(matches!(bound, Err(DomainError::Forbidden(_))));
    }

    /// Ann's laptop is bound, then her admin resets her password. The
    /// next request on that connection is turned away, as a session opened
    /// before the reset is.
    #[test]
    fn a_password_reset_after_the_bind_ends_it() {
        let cert = issued(params());
        let mut ann = holder_of(&cert, UserStatus::Active);
        let bound = bind(&ann, "right", &cert, cert.fingerprint()).unwrap();
        let before = bound.still_admits(&ann, &cert, crate::shared::clock::now());

        ann.record_credential_change();

        assert!(before);
        assert!(!bound.still_admits(&ann, &cert, crate::shared::clock::now()));
    }

    /// An existing bind accepts only its original certificate, even when
    /// another certificate belongs to the same account.
    #[test]
    fn a_bind_counts_only_with_the_certificate_it_was_made_over() {
        let cert = issued(params());
        let other = issued(IssueLdapCertificateParams {
            user_id: *cert.user_id(),
            ..params()
        });
        let ann = holder_of(&cert, UserStatus::Active);
        let bound = bind(&ann, "right", &cert, cert.fingerprint()).unwrap();

        assert!(!bound.still_admits(&ann, &other, crate::shared::clock::now()));
    }

    /// A password typed again, `raw`, checked by [`KnowsOnePassword`] on
    /// `tracker`.
    fn typed_again<'a>(
        raw: &'a str,
        stored: &'a PasswordHash,
        tracker: &'a mut LoginAttemptTracker,
    ) -> PasswordCheck<'a, KnowsOnePassword> {
        PasswordCheck {
            raw,
            stored,
            hasher: &KnowsOnePassword,
            tracker,
        }
    }

    /// Ann has an authenticator app, which LDAP cannot ask for. She binds
    /// with her password over her laptop's certificate and types her
    /// password again to change it. The certificate stands in for her
    /// factor, so she is proved.
    #[test]
    fn a_fresh_bind_stands_in_for_the_second_factor() {
        let cert = issued(params());
        let ann = holder_of(&cert, UserStatus::Active);
        let bound = bind(&ann, "right", &cert, cert.fingerprint()).unwrap();
        let stored = PasswordHash::from_stored("hash".to_owned());
        let mut tracker = LoginAttemptTracker::new();

        let fresh = bound
            .fresh_sign_in(&ann, &cert, typed_again("right", &stored, &mut tracker))
            .unwrap();

        assert_eq!(fresh.account(), PrincipalId::from(*ann.id()));
    }

    /// An hour-old bind cannot provide fresh sign-in proof and leaves the lockout tally untouched.
    #[test]
    fn a_bind_too_old_stands_in_for_no_factor() {
        let cert = issued(params());
        let ann = holder_of(&cert, UserStatus::Active);
        let fresh = bind(&ann, "right", &cert, cert.fingerprint()).unwrap();
        let old = DirectoryBind {
            bound_at: fresh.bound_at - time::Duration::HOUR,
            ..fresh
        };
        let stored = PasswordHash::from_stored("hash".to_owned());
        let mut tracker = LoginAttemptTracker::new();

        let refused = old.fresh_sign_in(&ann, &cert, typed_again("guess", &stored, &mut tracker));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(tracker.tally(), AttemptTally::Untouched);
    }

    /// A credential reset prevents an earlier bind from providing fresh sign-in proof.
    #[test]
    fn a_bind_ended_by_a_reset_proves_nobody() {
        let cert = issued(params());
        let mut ann = holder_of(&cert, UserStatus::Active);
        let bound = bind(&ann, "right", &cert, cert.fingerprint()).unwrap();
        ann.record_credential_change();
        let stored = PasswordHash::from_stored("hash".to_owned());
        let mut tracker = LoginAttemptTracker::new();

        let refused = bound.fresh_sign_in(&ann, &cert, typed_again("right", &stored, &mut tracker));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }
}
