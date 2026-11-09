use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authentication::device_status::DeviceStatus;
use crate::domains::authentication::keeper::AccountKeeper;
use crate::domains::authentication::risk_engine::assurance::AssuranceLevel;
use crate::domains::authentication::sessions::sign_in_progress::SignedIn;
use crate::domains::identity::account::control::AccountAction;
use crate::isolation::SecurityScope;
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::RowCheck;
use crate::shared::security::secret::Secret;
use crate::shared::validation::{Charset, TextValue, Validator, text_value};
use crate::types::{
    CredentialChange, DomainName, IpAddress, Label, PrincipalId, TokenHash, TrustedDeviceId,
    UserAgent,
};

text_value! {
    redacted
    /// The secret a trusted browser holds and presents at sign-in. It is 64
    /// hex digits that the browser made at random and keeps for itself.
    ///
    /// Presenting it lets a sign-in skip the second factor, so it is a
    /// credential. It is never stored, logged or put in an event. The server
    /// keeps only its digest, a [`TokenHash`] it makes itself, and matches a
    /// device by that alone.
    pub struct DeviceSecret;
}

impl TextValue for DeviceSecret {
    const FIELD: &'static str = "fingerprint_hash";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .length(Self::HEX_LENGTH..=Self::HEX_LENGTH)
            .charset(Charset::DIGIT | Charset::HEX_LETTER)
    }

    fn normalized(value: String) -> String {
        value.to_ascii_lowercase()
    }
}

impl DeviceSecret {
    /// Hex digits in the secret.
    const HEX_LENGTH: usize = 64;
}

/// Where a person signs in, which a remembered browser counts at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignInPlace {
    /// The platform's own sign-in, from the dashboard.
    Dashboard,
    /// The sign-in pages the gateway answers on one app's host.
    AppHost(DomainName),
}

/// A remembered browser's secret, as it was presented at a place.
///
/// A device is remembered at one place and counts there alone: the digest
/// the server keeps is made from the secret bound to its place. Ann's
/// device cookie, copied from `shop.acme.example` and sent to
/// `billing.acme.example`, or to another tenant's app, matches nothing.
/// The dashboard's devices keep the digest of the bare secret they always
/// had.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentedSecret {
    secret: DeviceSecret,
    place: SignInPlace,
}

impl PresentedSecret {
    /// `secret` presented at `place`.
    #[must_use]
    pub fn new(secret: DeviceSecret, place: SignInPlace) -> Self {
        Self { secret, place }
    }

    /// `secret` presented at the dashboard's own sign-in.
    #[must_use]
    pub fn on_dashboard(secret: DeviceSecret) -> Self {
        Self::new(secret, SignInPlace::Dashboard)
    }

    /// Where it was presented.
    #[must_use]
    pub fn place(&self) -> &SignInPlace {
        &self.place
    }

    /// What the server digests to remember or find the device: the secret,
    /// bound to the host it was presented on when that is an app's.
    #[must_use]
    pub fn bound(&self) -> Secret {
        match &self.place {
            SignInPlace::Dashboard => Secret::new(self.secret.as_str()),
            SignInPlace::AppHost(host) => Secret::new(format!(
                "app-host:{}:{}",
                host.as_str().to_ascii_lowercase(),
                self.secret.as_str()
            )),
        }
    }
}

/// How long a remembered device may go unused before it stops counting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TrustWindow(u32);

impl TrustWindow {
    /// At least a day, so a device is not forgotten between two visits.
    const MIN_DAYS: u32 = 1;

    /// At most a year. A device unused for longer is more likely lost than in
    /// its owner's hands.
    const MAX_DAYS: u32 = 365;

    /// The window unless something asks otherwise.
    #[must_use]
    pub fn standard() -> Self {
        Self(30)
    }

    /// A specific window, in days.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `value` is under one day or over a
    ///   year.
    pub fn days(value: u32) -> Result<Self, DomainError> {
        crate::shared::validation::numeric::validate_range(
            "device_trust_days",
            value,
            Self::MIN_DAYS..=Self::MAX_DAYS,
        )?;
        Ok(Self(value))
    }

    /// The window in days.
    #[must_use]
    pub fn as_days(self) -> u32 {
        self.0
    }
}

impl Default for TrustWindow {
    fn default() -> Self {
        Self::standard()
    }
}

/// What a remembered device is judged against when it is presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceTrustRules {
    /// Who is signing in. A device counts only for the person who
    /// remembered it, however the caller found it.
    pub signing_in: PrincipalId,
    /// How long the device may have gone unused.
    pub idle_window: TrustWindow,
    /// When the person last changed how they sign in, if ever. That means a
    /// new password, or a second factor added or removed. A device remembered
    /// before then does not count, because whoever remembered it may have
    /// held what was just replaced.
    pub credentials_changed_at: CredentialChange,
}

/// Whose a remembered device is and whether it is still trusted: what a
/// check made away from the sign-in, such as a device posture check, reads
/// of the device, never the digest of its secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceStanding {
    holder: PrincipalId,
    status: DeviceStatus,
}

impl DeviceStanding {
    /// The standing of a device `holder` remembered, now in `status`.
    #[must_use]
    pub fn new(holder: PrincipalId, status: DeviceStatus) -> Self {
        Self { holder, status }
    }

    /// Whether this is a device `person` remembered and still trusts, so a
    /// request coming from it may be held to what is reported about it.
    ///
    /// Bob's revoked laptop, or Ann's laptop named in Bob's request, is no
    /// device of the one asking: a report about it says nothing about them.
    #[must_use]
    pub fn is_trusted_by(&self, person: PrincipalId) -> bool {
        self.holder == person && self.status.is_trusted()
    }
}

/// Why a device could not be remembered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DeviceTrustRefused {
    /// The sign-in asking to remember the device proved no second factor.
    #[error("a device can only be remembered after a second factor")]
    SecondFactorNotProven,
}

/// A device that a subject has signed in from and chosen to remember.
///
/// The `S: SecurityScope` parameter keeps tenant users' devices and
/// organization users' devices apart at compile time.
#[derive(Debug)]
pub struct TrustedDevice<S: SecurityScope> {
    /// Unique device record identifier.
    id: TrustedDeviceId,
    /// The subject who owns this trusted device.
    subject_id: PrincipalId,
    /// Digest of the secret the device presents.
    secret_hash: TokenHash,
    /// Device name shown in the subject's device list.
    device_name: Label,
    /// The User-Agent string from the last login on this device.
    last_user_agent: UserAgent,
    /// The IP address from the last login on this device.
    last_ip: IpAddress,
    /// Current lifecycle status.
    status: DeviceStatus,
    /// When this device was last used for authentication.
    last_seen_at: OffsetDateTime,
    /// When this device was first trusted.
    created_at: OffsetDateTime,
    /// Which plane this belongs to. See [`crate::isolation`].
    _scope: PhantomData<S>,
}

/// Parameters for trusting a new device.
pub struct TrustDeviceParams {
    /// Digest of the secret the device presented, made by the server.
    pub secret_hash: TokenHash,
    /// Device name shown in the subject's device list.
    pub device_name: Label,
    /// The User-Agent from the current request.
    pub user_agent: UserAgent,
    /// The IP address from the current request.
    pub ip: IpAddress,
}

/// Persisted state for repository hydration.
pub struct TrustedDeviceRow {
    /// Unique device record identifier.
    pub id: TrustedDeviceId,
    /// The subject who owns this trusted device.
    pub subject_id: PrincipalId,
    /// Digest of the secret the device presents.
    pub secret_hash: TokenHash,
    /// Device name shown in the subject's device list.
    pub device_name: Label,
    /// The User-Agent from the last login.
    pub last_user_agent: UserAgent,
    /// The IP address from the last login.
    pub last_ip: IpAddress,
    /// Current lifecycle status.
    pub status: DeviceStatus,
    /// When this device was last used.
    pub last_seen_at: OffsetDateTime,
    /// When this device was first trusted.
    pub created_at: OffsetDateTime,
}

impl<S: SecurityScope> TrustedDevice<S> {
    /// Trusts a new device for whoever `signed_in` names, from the sign-in
    /// that asks for it.
    ///
    /// A remembered device skips the second factor later. So only a sign-in
    /// that proved one can remember a device. Otherwise whoever held the
    /// password alone could remember their own device and skip a factor the
    /// owner adds afterwards. The device belongs to the account that signed
    /// in, taken from the same proof. So one account's sign-in never
    /// remembers a device for another.
    ///
    /// # Errors
    ///
    /// - [`DeviceTrustRefused::SecondFactorNotProven`] when the sign-in is
    ///   not complete or did not reach AAL2.
    pub fn trust(
        params: TrustDeviceParams,
        signed_in: &SignedIn<S>,
    ) -> Result<Self, DeviceTrustRefused> {
        let progress = signed_in.progress();
        if !progress.is_complete() || progress.assurance_level() < AssuranceLevel::Aal2 {
            return Err(DeviceTrustRefused::SecondFactorNotProven);
        }
        let now = crate::shared::clock::now();
        Ok(Self {
            id: TrustedDeviceId::new(),
            subject_id: signed_in.subject(),
            secret_hash: params.secret_hash,
            device_name: params.device_name,
            last_user_agent: params.user_agent,
            last_ip: params.ip,
            status: DeviceStatus::Trusted,
            last_seen_at: now,
            created_at: now,
            _scope: PhantomData,
        })
    }

    /// Rebuilds a trusted device from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says the device was
    ///   seen before it was trusted.
    pub fn reconstitute(row: TrustedDeviceRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            subject_id: row.subject_id,
            secret_hash: row.secret_hash,
            device_name: row.device_name,
            last_user_agent: row.last_user_agent,
            last_ip: row.last_ip,
            status: row.status,
            last_seen_at: row.last_seen_at,
            created_at: row.created_at,
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &TrustedDeviceRow) -> Result<(), DomainError> {
        RowCheck::of("trusted device")
            .in_order(
                row.created_at,
                row.last_seen_at,
                "seen before it was trusted",
            )
            .finish()
    }

    /// Unique device record identifier.
    #[must_use]
    pub fn id(&self) -> &TrustedDeviceId {
        &self.id
    }

    /// The subject who owns this trusted device.
    #[must_use]
    pub fn subject_id(&self) -> PrincipalId {
        self.subject_id
    }

    /// Digest of the secret the device presents.
    #[must_use]
    pub fn secret_hash(&self) -> &TokenHash {
        &self.secret_hash
    }

    /// Device name shown in the subject's device list.
    #[must_use]
    pub fn device_name(&self) -> &Label {
        &self.device_name
    }

    /// The User-Agent from the last login on this device.
    #[must_use]
    pub fn last_user_agent(&self) -> &UserAgent {
        &self.last_user_agent
    }

    /// The IP address from the last login on this device.
    #[must_use]
    pub fn last_ip(&self) -> &IpAddress {
        &self.last_ip
    }

    /// Current lifecycle status.
    #[must_use]
    pub fn status(&self) -> DeviceStatus {
        self.status
    }

    /// When this device was last used for authentication.
    #[must_use]
    pub fn last_seen_at(&self) -> OffsetDateTime {
        self.last_seen_at
    }

    /// When this device was first trusted.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Whether a sign-in presenting a secret with this digest comes from
    /// this device, and the device still counts under `rules`.
    ///
    /// The device must be remembered by the person signing in, still
    /// trusted, used inside the idle window, and remembered after the person
    /// last changed their credentials. Every condition is checked here. So a
    /// device past its window stops counting even if nothing ever deletes it.
    ///
    /// It takes the digest, never the secret. The server hashes the secret,
    /// so a copy of what is stored cannot be presented in its place.
    #[must_use]
    pub fn matches(&self, presented: &TokenHash, rules: &DeviceTrustRules) -> bool {
        self.subject_id == rules.signing_in
            && self.status.is_trusted()
            && self.secret_hash == *presented
            && !self.is_stale(rules.idle_window)
            && !rules.credentials_changed_at.since(self.created_at)
    }

    /// Whether this is a device `person` remembered and still trusts. See
    /// [`DeviceStanding::is_trusted_by`].
    #[must_use]
    pub fn is_trusted_by(&self, person: PrincipalId) -> bool {
        self.standing().is_trusted_by(person)
    }

    /// Whose device this is and whether it is still trusted.
    #[must_use]
    pub fn standing(&self) -> DeviceStanding {
        DeviceStanding::new(self.subject_id, self.status)
    }

    /// Whether this device has gone unused for longer than `window`.
    #[must_use]
    pub fn is_stale(&self, window: TrustWindow) -> bool {
        let window = time::Duration::days(i64::from(window.as_days()));
        self.last_seen_at < crate::shared::clock::now().saturating_sub(window)
    }

    /// Records that the device was used for a login, with its User-Agent and
    /// IP, at the current time.
    pub fn record_login(&mut self, user_agent: UserAgent, ip: IpAddress) {
        self.last_user_agent = user_agent;
        self.last_ip = ip;
        self.last_seen_at = crate::shared::clock::now();
    }

    /// Gives the device the name the subject sees, as its holder or an admin
    /// acting on their account decides.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] in the cases
    ///   [`AccountKeeper::ensure_may`] lists, for changing how the account
    ///   signs in.
    pub fn rename(&mut self, name: Label, by: &impl AccountKeeper<S>) -> Result<(), DomainError> {
        by.ensure_may(&self.subject_id, AccountAction::ChangeSignIn)?;
        self.device_name = name;
        Ok(())
    }

    /// Revokes remembered-device trust for its holder or an authorized account administrator.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] when [`AccountKeeper::ensure_may`] refuses changes
    /// to the account's sign-in methods.
    /// [`DomainError::InvalidTransition`] if already revoked.
    pub fn revoke(&mut self, by: &impl AccountKeeper<S>) -> Result<(), DomainError> {
        by.ensure_may(&self.subject_id, AccountAction::ChangeSignIn)?;
        self.status = self.status.try_transition(DeviceStatus::Revoked)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::mfa::owed::SecondFactor;
    use crate::domains::authentication::risk_engine::step_up::StepUpPolicy;
    use crate::domains::authentication::sessions::mfa_factor::MfaFactor;
    use crate::domains::authentication::sessions::sign_in_progress::{
        LocalMethod, SignInProgress, finished_sign_in_of,
    };
    use crate::domains::authorization::granter::{AccountControl, Handout};
    use crate::domains::authorization::permission::{SystemPermission, UserAction};
    use crate::domains::authorization::stewardship::Stewardship;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::anyone_holding;
    use crate::types::UserId;

    const LAPTOP: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    fn digest(value: &str) -> TokenHash {
        TokenHash::from_stored(value.to_owned())
    }

    fn params() -> TrustDeviceParams {
        TrustDeviceParams {
            secret_hash: digest("laptop-digest"),
            device_name: Label::new("device_name", "Chrome on MacOS").unwrap(),
            user_agent: UserAgent::new("Mozilla/5.0 (Macintosh)").unwrap(),
            ip: IpAddress::new("10.0.0.1").unwrap(),
        }
    }

    fn password_owing(owed: SecondFactor) -> SignInProgress {
        SignInProgress::begin(LocalMethod::Password, owed, &StepUpPolicy::relaxed()).unwrap()
    }

    fn password_then(factor: MfaFactor) -> SignInProgress {
        password_owing(SecondFactor::Verify)
            .answer(factor, &StepUpPolicy::relaxed())
            .unwrap()
    }

    fn by(progress: SignInProgress) -> SignedIn<ResolvedTenant> {
        SignedIn::of(UserId::new().into(), progress)
    }

    /// Ann signs in with a password and TOTP and remembers her laptop. The
    /// device belongs to Ann, read from the same sign-in proof.
    #[test]
    fn a_device_is_remembered_for_the_account_that_signed_in() {
        let signed_in = by(password_then(MfaFactor::Totp));
        let subject = signed_in.subject();

        let device = TrustedDevice::<ResolvedTenant>::trust(params(), &signed_in).unwrap();

        assert_eq!(device.subject_id(), subject);
    }

    fn test_device() -> TrustedDevice<ResolvedTenant> {
        TrustedDevice::trust(params(), &by(password_then(MfaFactor::Totp))).unwrap()
    }

    fn rules(device: &TrustedDevice<ResolvedTenant>) -> DeviceTrustRules {
        DeviceTrustRules {
            signing_in: device.subject_id(),
            idle_window: TrustWindow::standard(),
            credentials_changed_at: CredentialChange::Never,
        }
    }

    /// A newly remembered device keeps the name and secret digest it was
    /// trusted with.
    #[test]
    fn trust_creates_device_with_current_timestamp() {
        let device = test_device();
        assert_eq!(device.device_name().as_str(), "Chrome on MacOS");
        assert_eq!(device.secret_hash(), &digest("laptop-digest"));
    }

    /// Ann's laptop presents the digest it was remembered with. It matches
    /// for Ann inside the standard window.
    #[test]
    fn a_device_matches_the_digest_of_its_own_secret() {
        let device = test_device();
        assert!(device.matches(&digest("laptop-digest"), &rules(&device)));
    }

    /// Sam's remembered device does not match Eve's account.
    #[test]
    fn a_device_does_not_count_for_someone_else() {
        let device = test_device();
        let someone_else = DeviceTrustRules {
            signing_in: UserId::new().into(),
            ..rules(&device)
        };

        assert!(!device.matches(&digest("laptop-digest"), &someone_else));
    }

    /// Ann's phone presents its own digest. It does not match the record
    /// for her laptop.
    #[test]
    fn a_device_does_not_match_another_digest() {
        let device = test_device();
        assert!(!device.matches(&digest("phone-digest"), &rules(&device)));
    }

    /// Password authentication alone cannot authorize remembering a device.
    #[test]
    fn a_password_alone_cannot_remember_a_device() {
        let refused = TrustedDevice::<ResolvedTenant>::trust(
            params(),
            &by(password_owing(SecondFactor::NotOwed)),
        );

        assert_eq!(
            refused.err(),
            Some(DeviceTrustRefused::SecondFactorNotProven)
        );
    }

    /// Ann has typed her password but not yet her TOTP code. Remembering the
    /// device is refused until the factor is proven.
    #[test]
    fn a_sign_in_still_owing_its_factor_cannot_remember_a_device() {
        let refused = TrustedDevice::<ResolvedTenant>::trust(
            params(),
            &by(password_owing(SecondFactor::Verify)),
        );

        assert_eq!(
            refused.err(),
            Some(DeviceTrustRefused::SecondFactorNotProven)
        );
    }

    /// Recovery-code and email-confirmation proofs cannot authorize remembering a device.
    #[test]
    fn neither_a_recovery_code_nor_an_email_confirmation_can_remember_a_device() {
        let recovered = password_then(MfaFactor::RecoveryCode);
        let confirmed = password_owing(SecondFactor::ConfirmByEmail)
            .answer(MfaFactor::EmailConfirmation, &StepUpPolicy::relaxed())
            .unwrap();

        for signed_in in [recovered, confirmed] {
            assert!(TrustedDevice::<ResolvedTenant>::trust(params(), &by(signed_in)).is_err());
        }
    }

    /// Ann signs in with a passkey alone. The passkey already reaches AAL2,
    /// so she may remember the device.
    #[test]
    fn a_passkey_sign_in_can_remember_a_device() {
        let signed_in = SignInProgress::begin(
            LocalMethod::Passkey,
            SecondFactor::NotOwed,
            &StepUpPolicy::relaxed(),
        )
        .unwrap();

        assert!(TrustedDevice::<ResolvedTenant>::trust(params(), &by(signed_in)).is_ok());
    }

    /// Ann's laptop was last seen 31 days ago and the window is 30. It no
    /// longer matches, even though its record still exists.
    #[test]
    fn a_device_unused_past_its_window_no_longer_matches() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let _frozen = crate::shared::clock::freeze(now);

        let device = device_last_seen(now - time::Duration::days(31));

        assert!(!device.matches(&digest("laptop-digest"), &rules(&device)));
    }

    /// A credential change invalidates a device remembered before that change.
    #[test]
    fn a_device_remembered_before_the_credentials_changed_no_longer_matches() {
        let device = test_device();
        let changed = DeviceTrustRules {
            credentials_changed_at: CredentialChange::from_stored(Some(
                device.created_at() + time::Duration::seconds(1),
            )),
            ..rules(&device)
        };

        assert!(!device.matches(&digest("laptop-digest"), &changed));
    }

    /// Ann changes her password and remembers her laptop a second later. The
    /// laptop still matches, because it was remembered with the new password.
    #[test]
    fn a_device_remembered_after_the_credentials_changed_still_matches() {
        let device = test_device();
        let changed = DeviceTrustRules {
            credentials_changed_at: CredentialChange::from_stored(Some(
                device.created_at() - time::Duration::seconds(1),
            )),
            ..rules(&device)
        };

        assert!(device.matches(&digest("laptop-digest"), &changed));
    }

    /// A device was remembered at the same instant Ann changed her password.
    /// It does not match, because it may have been remembered with the old
    /// password.
    #[test]
    fn a_device_remembered_at_the_instant_of_the_change_no_longer_matches() {
        let device = test_device();
        let changed = DeviceTrustRules {
            credentials_changed_at: CredentialChange::from_stored(Some(device.created_at())),
            ..rules(&device)
        };

        assert!(!device.matches(&digest("laptop-digest"), &changed));
    }

    /// A window of 1 or 365 days is accepted. A window of 0 or 366 days is
    /// refused.
    #[test]
    fn a_trust_window_runs_from_a_day_to_a_year() {
        assert!(TrustWindow::days(0).is_err());
        assert_eq!(TrustWindow::days(1).unwrap().as_days(), 1);
        assert_eq!(TrustWindow::days(365).unwrap().as_days(), 365);
        assert!(TrustWindow::days(366).is_err());
    }

    /// The secret comes straight from the client. An empty value, a short
    /// one, one digit too many or a non-hex letter is refused before it is
    /// hashed or compared.
    #[test]
    fn a_secret_that_is_not_64_hex_digits_is_refused() {
        for bad in [
            "",
            "abc123",
            &LAPTOP[1..],
            &format!("{LAPTOP}0"),
            &LAPTOP.replace('9', "g"),
        ] {
            assert!(DeviceSecret::new(bad).is_err(), "{bad:?} was accepted");
        }
    }

    /// A device secret printed with `{:?}` does not show its digits. The
    /// secret skips the second factor, so it must never reach a log.
    #[test]
    fn a_device_secret_is_never_printed() {
        let secret = DeviceSecret::new(LAPTOP).unwrap();

        assert!(!format!("{secret:?}").contains(LAPTOP));
        let presented = PresentedSecret::on_dashboard(secret);
        assert!(!format!("{presented:?}").contains(LAPTOP));
    }

    fn on_host(host: &str) -> PresentedSecret {
        PresentedSecret::new(
            DeviceSecret::new(LAPTOP).unwrap(),
            SignInPlace::AppHost(DomainName::new(host).unwrap()),
        )
    }

    /// The dashboard's devices keep the digest of the bare secret, as they
    /// were remembered before app hosts could remember any.
    #[test]
    fn a_dashboard_secret_is_bound_to_nothing_more() {
        let presented = PresentedSecret::on_dashboard(DeviceSecret::new(LAPTOP).unwrap());

        assert_eq!(presented.bound().expose(), LAPTOP);
    }

    /// Binding one device secret to the shop, billing host, and dashboard
    /// produces different bytes for each destination.
    #[test]
    fn the_same_secret_is_bound_apart_at_each_place() {
        let shop = on_host("shop.acme.example");
        let billing = on_host("billing.acme.example");
        let dashboard = PresentedSecret::on_dashboard(DeviceSecret::new(LAPTOP).unwrap());

        assert_ne!(shop.bound().expose(), billing.bound().expose());
        assert_ne!(shop.bound().expose(), dashboard.bound().expose());
    }

    /// A host is bound the same however it was written.
    #[test]
    fn a_host_is_bound_whatever_its_case() {
        assert_eq!(
            on_host("Shop.Acme.Example").bound().expose(),
            on_host("shop.acme.example").bound().expose()
        );
    }

    /// A device remembered just now is inside the standard window.
    #[test]
    fn fresh_device_is_not_stale() {
        let device = test_device();
        assert!(!device.is_stale(TrustWindow::standard()));
    }

    /// Ann signs in on her remembered device from a new address. The device
    /// keeps the new address and a last-seen time no earlier than before.
    #[test]
    fn record_login_updates_last_seen() {
        let mut device = test_device();
        let original_seen = device.last_seen_at();

        std::thread::sleep(std::time::Duration::from_millis(10));

        device.record_login(
            UserAgent::new("Mozilla/5.0 (Windows)").unwrap(),
            IpAddress::new("192.168.1.1").unwrap(),
        );

        assert!(device.last_seen_at() >= original_seen);
        assert_eq!(device.last_ip().as_str(), "192.168.1.1");
    }

    /// Ann renames her device to "Work Laptop". It is listed under the new
    /// name.
    #[test]
    fn rename_updates_device_name() {
        let mut device = test_device();
        let ann = holder_of(&device);

        device
            .rename(Label::new("device_name", "Work Laptop").unwrap(), &ann)
            .unwrap();

        assert_eq!(device.device_name().as_str(), "Work Laptop");
    }

    fn holder_of(device: &TrustedDevice<ResolvedTenant>) -> SignedIn<ResolvedTenant> {
        finished_sign_in_of(device.subject_id())
    }

    /// Mallory cannot revoke Ann's device, which remains trusted.
    #[test]
    fn someone_else_does_not_revoke_a_device() {
        let mut device = test_device();
        let mallory = finished_sign_in_of::<ResolvedTenant>(UserId::new().into());

        let refused = device.revoke(&mallory);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(device.status(), DeviceStatus::Trusted);
    }

    /// A user viewer cannot revoke Ann's device, while a user editor can.
    #[test]
    fn revoking_someone_elses_device_needs_the_right_to_change_their_sign_in() {
        static VIEWER: [SystemPermission; 1] = [SystemPermission::Users(UserAction::View)];
        static EDITOR: [SystemPermission; 1] = [SystemPermission::Users(UserAction::Update)];
        let mut device = test_device();
        let ann = UserId::from_uuid(*device.subject_id().as_uuid());
        let acting = |rights: &'static [SystemPermission]| {
            AccountControl::assumed(
                anyone_holding(rights),
                ann,
                Stewardship::OthersAdminister,
                Handout::NOTHING,
            )
        };

        let by_sam = device.revoke(&acting(&VIEWER));
        let by_fay = device.revoke(&acting(&EDITOR));

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert!(by_fay.is_ok());
    }

    /// A secret read from a JSON request body is checked like any other. 64
    /// hex digits are accepted and "not-a-hash" is refused.
    #[cfg(feature = "serde")]
    #[test]
    fn a_secret_read_from_json_is_held_to_the_same_rules() {
        assert!(serde_json::from_str::<DeviceSecret>(&format!("\"{LAPTOP}\"")).is_ok());
        assert!(serde_json::from_str::<DeviceSecret>("\"not-a-hash\"").is_err());
    }

    fn device_last_seen(last_seen_at: OffsetDateTime) -> TrustedDevice<ResolvedTenant> {
        TrustedDevice::reconstitute(TrustedDeviceRow {
            id: TrustedDeviceId::new(),
            subject_id: UserId::new().into(),
            secret_hash: digest("laptop-digest"),
            device_name: Label::new("device_name", "Chrome on MacOS").unwrap(),
            last_user_agent: UserAgent::new("Mozilla/5.0 (Macintosh)").unwrap(),
            last_ip: IpAddress::new("10.0.0.1").unwrap(),
            status: DeviceStatus::Trusted,
            last_seen_at,
            created_at: last_seen_at,
        })
        .unwrap()
    }

    /// With a 30 day window, a device last seen 31 days ago is stale and one
    /// seen 29 days ago is not. Abandoned devices stop being trusted.
    #[test]
    fn a_device_unseen_for_longer_than_the_window_is_stale() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let _frozen = crate::shared::clock::freeze(now);
        let window = TrustWindow::days(30).unwrap();

        assert!(device_last_seen(now - time::Duration::days(31)).is_stale(window));
        assert!(!device_last_seen(now - time::Duration::days(29)).is_stale(window));
    }

    /// A device seen exactly 30 days ago is still inside a 30 day window. One
    /// second earlier and it is stale.
    #[test]
    fn a_device_seen_exactly_at_the_cutoff_is_not_yet_stale() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let _frozen = crate::shared::clock::freeze(now);
        let window = TrustWindow::days(30).unwrap();
        let cutoff = now - time::Duration::days(30);

        assert!(!device_last_seen(cutoff).is_stale(window));
        assert!(device_last_seen(cutoff - time::Duration::seconds(1)).is_stale(window));
    }

    /// Ann revokes her laptop. It stops matching its own secret, and a
    /// second revoke is refused instead of reported as done.
    #[test]
    fn revoking_ends_trust_and_cannot_be_repeated() {
        let mut device = test_device();
        let ann = holder_of(&device);
        let laptop = digest("laptop-digest");

        device.revoke(&ann).unwrap();

        assert_eq!(device.status(), DeviceStatus::Revoked);
        assert!(
            !device.matches(&laptop, &rules(&device)),
            "a revoked device must not match its own secret"
        );
        assert!(device.revoke(&ann).is_err());
    }

    /// Ann's laptop is trusted by Ann, and not by Bob, who names it in his
    /// own request.
    #[test]
    fn a_device_is_trusted_by_its_owner_alone() {
        let device = test_device();

        assert!(device.is_trusted_by(device.subject_id()));
        assert!(!device.is_trusted_by(PrincipalId::from(UserId::new())));
    }

    /// Revoking a device removes its trust for the account that remembered it.
    #[test]
    fn a_revoked_device_is_trusted_by_nobody() {
        let mut device = test_device();
        let ann = holder_of(&device);

        device.revoke(&ann).unwrap();

        assert!(!device.is_trusted_by(device.subject_id()));
    }

    /// A remembered device has a real, non-nil id. A revoke request names
    /// that id, so a nil one would revoke nothing.
    #[test]
    fn a_trusted_device_carries_its_own_record_id() {
        let device = test_device();

        assert!(!device.id().as_uuid().is_nil());
    }

    /// A stored row says the device was seen one second before it was
    /// trusted. Loading it is refused as corrupt.
    #[test]
    fn a_stored_device_seen_before_it_was_trusted_is_refused() {
        let device = test_device();
        let row = TrustedDeviceRow {
            id: *device.id(),
            subject_id: device.subject_id(),
            secret_hash: device.secret_hash().clone(),
            device_name: device.device_name().clone(),
            last_user_agent: device.last_user_agent().clone(),
            last_ip: device.last_ip().clone(),
            status: device.status(),
            last_seen_at: device.created_at() - time::Duration::SECOND,
            created_at: device.created_at(),
        };

        assert!(refused_as_corrupt(
            &TrustedDevice::<ResolvedTenant>::reconstitute(row)
        ));
    }
}
