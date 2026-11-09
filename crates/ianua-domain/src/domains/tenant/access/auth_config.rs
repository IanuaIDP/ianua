//! How a tenant's own users sign in.

use crate::domains::authentication::credentials::breach::BreachedPasswordCheck;
use crate::domains::authentication::methods::{AuthMethod, MfaPolicy, ensure_baseline_reachable};
use crate::domains::authentication::mfa::enrollment::MfaMethod;
use crate::domains::authentication::mfa::offer::{
    FactorOffer, FactorSettings, ensure_offered_factors, offer_factor,
};
use crate::domains::authentication::risk_engine::pressure::FailureThreshold;
use crate::domains::authentication::risk_engine::step_up::StepUpPolicy;
use crate::domains::authentication::sessions::timeout::SessionTimeoutPolicy;
use crate::domains::authentication::sign_in_limits::{SignInLimits, SignInNumbers};
use crate::domains::identity::impersonation::state::ImpersonationConsent;
use crate::shared::errors::DomainError;
use crate::shared::model::two_cases::two_cases;
use crate::shared::validation::numeric::validate_count;
use crate::types::{CidrRange, HttpUrl, PasswordPolicy, Seconds};

/// How a tenant's users sign in, with every value in range and none
/// contradicting another.
///
/// It holds the enabled methods, password rules, session lifetimes, MFA
/// policy, self-registration and IP restrictions. Every step of sign-in
/// reads it. It is built from [`TenantAuthSettings`] by [`new`](Self::new),
/// and reading one back from storage runs the same checks.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(try_from = "TenantAuthSettings", into = "TenantAuthSettings")
)]
pub struct TenantAuthConfig(TenantAuthSettings);

#[cfg(feature = "serde")]
impl TryFrom<TenantAuthSettings> for TenantAuthConfig {
    type Error = DomainError;

    fn try_from(settings: TenantAuthSettings) -> Result<Self, Self::Error> {
        Self::new(settings)
    }
}

#[cfg(feature = "serde")]
impl From<TenantAuthConfig> for TenantAuthSettings {
    fn from(config: TenantAuthConfig) -> Self {
        config.0
    }
}

two_cases! {
    /// Whether people may sign up to a tenant without an invitation.
    pub enum SelfRegistration {
        /// Anyone may sign up.
        Open => true,
        /// Only invited people join.
        Closed => false,
    }
}

/// Who issues the tokens a tenant's routes accept: the platform, under the
/// tenant's own issuer, or another issuer the tenant configured.
///
/// Never "none": a token is always checked against an issuer, and a missing
/// one must not read as "accept any".
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(from = "Option<HttpUrl>", into = "Option<HttpUrl>")
)]
pub enum TokenIssuer {
    /// The platform's own issuer for the tenant.
    #[default]
    Platform,
    /// This issuer instead.
    Custom(HttpUrl),
}

impl TokenIssuer {
    /// Whether the platform's own issuer stands.
    #[must_use]
    pub fn is_platform(&self) -> bool {
        matches!(self, Self::Platform)
    }
}

impl From<Option<HttpUrl>> for TokenIssuer {
    /// The stored setting. `None` stands for the platform's issuer.
    fn from(stored: Option<HttpUrl>) -> Self {
        stored.map_or(Self::Platform, Self::Custom)
    }
}

impl From<TokenIssuer> for Option<HttpUrl> {
    fn from(issuer: TokenIssuer) -> Self {
        match issuer {
            TokenIssuer::Platform => None,
            TokenIssuer::Custom(url) => Some(url),
        }
    }
}

/// The values a tenant's sign-in configuration is made of, before they are
/// checked.
///
/// Change these freely. [`TenantAuthConfig::new`] decides whether they hold
/// together.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TenantAuthSettings {
    /// Which authentication methods this tenant allows.
    ///
    /// The auth flow rejects any method not in this list.
    pub enabled_methods: Vec<AuthMethod>,

    /// Password complexity requirements.
    pub password_policy: PasswordPolicy,

    /// Whether MFA is disabled, optional, or required.
    pub mfa_policy: MfaPolicy,

    /// How many seconds a session stays valid after it is created.
    pub session_lifetime_secs: Seconds,

    /// How many seconds a session may sit idle before it expires.
    pub idle_timeout_secs: Seconds,

    /// Whether users can register themselves without an admin invite.
    pub self_registration: SelfRegistration,

    /// Maximum failed login attempts from one network before it is locked
    /// out of the account.
    pub max_login_attempts: u8,

    /// How many seconds a network stays locked out of the account after too
    /// many failures from it.
    pub lockout_duration_secs: Seconds,

    /// Optional IP allowlist. When set, only these CIDRs may sign in, by any
    /// method. Empty means all IPs are allowed.
    pub ip_allowlist: Vec<CidrRange>,

    /// Expected JWT issuer for this tenant.
    ///
    /// The proxy checks the `iss` claim of incoming JWTs against it. Tokens
    /// from a different issuer are rejected.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "TokenIssuer::is_platform")
    )]
    pub jwt_issuer: TokenIssuer,

    /// When a sign-in has to clear a higher bar than a password.
    ///
    /// A stored configuration without this field reads as
    /// [`StepUpPolicy::relaxed`] until an administrator chooses otherwise.
    #[cfg_attr(feature = "serde", serde(default = "StepUpPolicy::relaxed"))]
    pub step_up_policy: StepUpPolicy,

    /// The kinds of second factor users may set up. Each must be able to
    /// reach the baseline to be offered.
    pub second_factors: Vec<MfaMethod>,

    /// What setting a new password does about one found in known breaches.
    pub breached_passwords: BreachedPasswordCheck,

    /// Whether a person approves before a tenant admin acts as them for
    /// support, or the admin decides.
    ///
    /// A stored configuration without this field has the person approve.
    #[cfg_attr(feature = "serde", serde(default))]
    pub impersonation_consent: ImpersonationConsent,

    /// How many failed password sign-ins across the tenant, in the window,
    /// put its sign-in under high pressure. Under it, a device nobody
    /// trusted must pass a challenge before its password is checked.
    ///
    /// A stored configuration without this field takes the default.
    #[cfg_attr(feature = "serde", serde(default))]
    pub challenge_threshold: FailureThreshold,
}

impl TenantAuthConfig {
    /// Checks `settings` hold together and wraps them.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when no method is enabled, which locks
    ///   every user out.
    /// - [`DomainError::Validation`] when no enabled method can reach the
    ///   baseline assurance. See `ensure_baseline_reachable`.
    /// - [`DomainError::Validation`] when a number is out of range or
    ///   contradicts another. See [`SignInLimits::new`].
    /// - [`DomainError::Validation`] when no kind of second factor is
    ///   listed, or one is listed twice.
    pub fn new(settings: TenantAuthSettings) -> Result<Self, DomainError> {
        validate_count(
            "enabled_methods",
            settings.enabled_methods.len(),
            1..=usize::MAX,
        )?;
        ensure_offered_factors(&settings.second_factors)?;
        ensure_baseline_reachable(
            &settings.enabled_methods,
            settings.step_up_policy.baseline_aal(),
            settings.mfa_policy,
        )?;
        let config = Self(settings);
        SignInLimits::new(config.numbers())?;
        Ok(config)
    }

    /// The values this configuration was made from, to change and pass back
    /// to [`new`](Self::new).
    #[must_use]
    pub fn settings(&self) -> &TenantAuthSettings {
        &self.0
    }

    /// The set of authentication methods enabled for this tenant.
    #[must_use]
    pub fn enabled_methods(&self) -> &[AuthMethod] {
        &self.0.enabled_methods
    }

    /// Whether a specific authentication method is allowed.
    #[must_use]
    pub fn is_method_enabled(&self, method: AuthMethod) -> bool {
        self.0.enabled_methods.contains(&method)
    }

    /// The rules a newly chosen password is held to, or `None` when this
    /// tenant signs nobody in with a password.
    ///
    /// A tenant without password login takes no new passwords. Say Ann sets
    /// one anyway on a passkey-only tenant and forgets it. When an admin
    /// later turns password login on, that old password becomes a working way
    /// into her account.
    #[must_use]
    pub fn new_password_policy(&self) -> Option<&PasswordPolicy> {
        self.is_method_enabled(AuthMethod::Password)
            .then_some(&self.0.password_policy)
    }

    /// The password complexity requirements.
    #[must_use]
    pub fn password_policy(&self) -> &PasswordPolicy {
        &self.0.password_policy
    }

    /// The numbers this configuration sets.
    #[must_use]
    pub fn limits(&self) -> SignInLimits {
        SignInLimits::from_checked(self.numbers())
    }

    fn numbers(&self) -> SignInNumbers {
        SignInNumbers {
            session_lifetime_secs: self.0.session_lifetime_secs,
            idle_timeout_secs: self.0.idle_timeout_secs,
            max_login_attempts: self.0.max_login_attempts,
            lockout_duration_secs: self.0.lockout_duration_secs,
        }
    }

    /// The MFA enforcement level.
    #[must_use]
    pub fn mfa_policy(&self) -> MfaPolicy {
        self.0.mfa_policy
    }

    /// When a sign-in has to clear a higher bar than a password.
    #[must_use]
    pub fn step_up_policy(&self) -> &StepUpPolicy {
        &self.0.step_up_policy
    }

    /// The offer of `method` to a user setting up a second factor here,
    /// which [`MfaEnrollment::begin`] takes.
    ///
    /// [`MfaEnrollment::begin`]: crate::domains::authentication::mfa::enrollment::MfaEnrollment::begin
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when second factors are off, the tenant
    ///   does not list `method`, or `method` cannot reach the baseline.
    ///   See [`offer_factor`].
    pub fn offer_factor(&self, method: MfaMethod) -> Result<FactorOffer, DomainError> {
        offer_factor(
            FactorSettings {
                policy: self.0.mfa_policy,
                offered: &self.0.second_factors,
                baseline: self.0.step_up_policy.baseline_aal(),
            },
            method,
        )
    }

    /// What setting a new password does about one found in known breaches.
    #[must_use]
    pub fn breached_passwords(&self) -> BreachedPasswordCheck {
        self.0.breached_passwords
    }

    /// Whether a person approves before a tenant admin acts as them, or the
    /// admin decides.
    #[must_use]
    pub fn impersonation_consent(&self) -> ImpersonationConsent {
        self.0.impersonation_consent
    }

    /// How many seconds a session stays valid after it is created.
    #[must_use]
    pub fn session_lifetime_secs(&self) -> Seconds {
        self.0.session_lifetime_secs
    }

    /// How many seconds a session may sit idle before it expires.
    #[must_use]
    pub fn idle_timeout_secs(&self) -> Seconds {
        self.0.idle_timeout_secs
    }

    /// How long a session started in this tenant lasts, whichever way the
    /// person signed in.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the configured lifetimes do not make
    ///   a session policy. See [`SignInLimits::session_timeout`].
    pub fn session_timeout(&self) -> Result<SessionTimeoutPolicy, DomainError> {
        self.limits().session_timeout()
    }

    /// Whether users can self-register without an admin invite.
    #[must_use]
    pub fn self_registration(&self) -> bool {
        self.0.self_registration == SelfRegistration::Open
    }

    /// Failed login attempts from one network before it is locked out of the
    /// account.
    #[must_use]
    pub fn max_login_attempts(&self) -> u8 {
        self.0.max_login_attempts
    }

    /// How many seconds a network stays locked out of the account after too
    /// many failures from it.
    #[must_use]
    pub fn lockout_duration_secs(&self) -> Seconds {
        self.0.lockout_duration_secs
    }

    /// The failures across the tenant that put its password sign-in under
    /// high pressure.
    #[must_use]
    pub fn challenge_threshold(&self) -> FailureThreshold {
        self.0.challenge_threshold
    }

    /// IP CIDRs allowed to sign in to this tenant, by any method.
    /// Empty means unrestricted.
    #[must_use]
    pub fn ip_allowlist(&self) -> &[CidrRange] {
        &self.0.ip_allowlist
    }

    /// Whether IP restrictions are active for this tenant.
    #[must_use]
    pub fn has_ip_restrictions(&self) -> bool {
        !self.0.ip_allowlist.is_empty()
    }

    /// Expected JWT issuer URL for this tenant.
    #[must_use]
    pub fn jwt_issuer(&self) -> &TokenIssuer {
        &self.0.jwt_issuer
    }
}

impl Default for TenantAuthSettings {
    /// Sensible defaults for a newly provisioned tenant.
    ///
    /// Password and passkey, no MFA, 8-hour sessions, 1-hour idle timeout, no
    /// self-registration, 10 attempts before lockout. Once MFA is turned on,
    /// an authenticator app is the factor offered. A breached password is
    /// refused when it is set. Sign-in comes under pressure at the default
    /// failure threshold.
    ///
    /// Passkeys are on because every tenant can register them, and sign-in
    /// checks this list. With passkeys off, a user could enrol a passkey they
    /// may never sign in with.
    fn default() -> Self {
        Self {
            enabled_methods: vec![AuthMethod::Password, AuthMethod::Passkey],
            password_policy: PasswordPolicy::default(),
            mfa_policy: MfaPolicy::Disabled,
            session_lifetime_secs: Seconds::new(28800),
            idle_timeout_secs: Seconds::new(3600),
            self_registration: SelfRegistration::Closed,
            max_login_attempts: 10,
            lockout_duration_secs: Seconds::new(900),
            ip_allowlist: Vec::new(),
            jwt_issuer: TokenIssuer::Platform,
            step_up_policy: StepUpPolicy::relaxed(),
            second_factors: vec![MfaMethod::Totp],
            breached_passwords: BreachedPasswordCheck::Block,
            impersonation_consent: ImpersonationConsent::HolderApproves,
            challenge_threshold: FailureThreshold::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::risk_engine::assessment::RiskLevel;
    use crate::domains::authentication::risk_engine::assurance::AssuranceLevel::{Aal2, Aal3};
    use crate::domains::authentication::risk_engine::step_up::{MfaTrigger, StepUpPolicyParams};
    use crate::types::CharacterRequirements;
    use crate::types::password_policy::CharacterRule;

    /// The default settings a new tenant gets pass every check in `new`.
    #[test]
    fn the_defaults_are_valid() {
        assert!(TenantAuthConfig::new(TenantAuthSettings::default()).is_ok());
    }

    fn with_baseline(
        methods: Vec<AuthMethod>,
        mfa_policy: MfaPolicy,
        baseline: crate::domains::authentication::risk_engine::assurance::AssuranceLevel,
    ) -> TenantAuthSettings {
        TenantAuthSettings {
            enabled_methods: methods,
            mfa_policy,
            step_up_policy: StepUpPolicy::new(StepUpPolicyParams {
                baseline_aal: baseline,
                sensitive_aal: baseline,
                new_device: MfaTrigger::Ignored,
                new_country: MfaTrigger::Ignored,
                mfa_risk_threshold: RiskLevel::Critical,
                deny_risk_threshold: RiskLevel::Critical,
            })
            .unwrap(),
            ..TenantAuthSettings::default()
        }
    }

    /// A tenant asks for AAL3 with only passwords on, or AAL2 with passwords
    /// and magic links but no second factor. Both are refused, since nobody
    /// could sign in to change it back.
    #[test]
    fn a_baseline_no_enabled_method_can_reach_is_refused() {
        let password_only_at_aal3 =
            with_baseline(vec![AuthMethod::Password], MfaPolicy::Optional, Aal3);
        let password_without_factors_at_aal2 = with_baseline(
            vec![AuthMethod::Password, AuthMethod::MagicLink],
            MfaPolicy::Disabled,
            Aal2,
        );

        assert!(TenantAuthConfig::new(password_only_at_aal3).is_err());
        assert!(TenantAuthConfig::new(password_without_factors_at_aal2).is_err());
    }

    /// AAL3 with passkeys on, and AAL2 with passwords and optional second
    /// factors, are both accepted. One enabled method that can reach the
    /// baseline is enough.
    #[test]
    fn a_baseline_one_enabled_method_can_reach_is_accepted() {
        let with_passkeys = with_baseline(
            vec![AuthMethod::Password, AuthMethod::Passkey],
            MfaPolicy::Disabled,
            Aal3,
        );
        let with_factors = with_baseline(vec![AuthMethod::Password], MfaPolicy::Optional, Aal2);

        assert!(TenantAuthConfig::new(with_passkeys).is_ok());
        assert!(TenantAuthConfig::new(with_factors).is_ok());
    }

    /// A tenant turns every sign-in method off. It is refused, since that
    /// locks every user out.
    #[test]
    fn a_tenant_with_no_sign_in_method_is_refused() {
        let config = TenantAuthSettings {
            enabled_methods: Vec::new(),
            ..TenantAuthSettings::default()
        };

        assert!(
            TenantAuthConfig::new(config).is_err(),
            "enabling nothing locks every user out of the tenant"
        );
    }

    /// A tenant sets one-hour sessions with a two-hour idle timeout. It is
    /// refused, since the idle timeout could never fire.
    #[test]
    fn an_idle_timeout_cannot_outlast_its_session() {
        let config = TenantAuthSettings {
            session_lifetime_secs: Seconds::new(3600),
            idle_timeout_secs: Seconds::new(7200),
            ..TenantAuthSettings::default()
        };

        assert!(
            TenantAuthConfig::new(config).is_err(),
            "the session would expire before it could ever go idle"
        );
    }

    /// A tenant sets one-hour sessions with a one-hour idle timeout. Equal
    /// values are accepted.
    #[test]
    fn an_idle_timeout_equal_to_the_session_is_allowed() {
        let config = TenantAuthSettings {
            session_lifetime_secs: Seconds::new(3600),
            idle_timeout_secs: Seconds::new(3600),
            ..TenantAuthSettings::default()
        };

        assert!(TenantAuthConfig::new(config).is_ok());
    }

    /// A tenant locks accounts after one failed attempt. It is refused, so a
    /// single typo never locks Bob out.
    #[test]
    fn locking_an_account_on_the_first_attempt_is_refused() {
        let config = TenantAuthSettings {
            max_login_attempts: 1,
            ..TenantAuthSettings::default()
        };

        assert!(
            TenantAuthConfig::new(config).is_err(),
            "one attempt locks an account on a single typo"
        );
    }

    /// A stored configuration is edited by hand to enable no methods. It is
    /// refused when read, so the edit cannot lock the tenant out.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stored_configuration_that_breaks_the_rules_is_refused() {
        let mut stored = serde_json::to_value(TenantAuthSettings::default()).unwrap();
        stored["enabled_methods"] = serde_json::json!([]);

        assert!(serde_json::from_value::<TenantAuthConfig>(stored).is_err());
    }

    /// A configuration stored before tenants set a challenge threshold is
    /// read back with the default one, and a stored threshold of zero is
    /// refused.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stored_configuration_without_a_threshold_takes_the_default() {
        let mut stored = serde_json::to_value(TenantAuthSettings::default()).unwrap();
        stored
            .as_object_mut()
            .unwrap()
            .remove("challenge_threshold");
        let mut zero = stored.clone();
        zero["challenge_threshold"] = serde_json::json!(0);

        let config = serde_json::from_value::<TenantAuthConfig>(stored).unwrap();

        assert_eq!(config.challenge_threshold(), FailureThreshold::default());
        assert!(serde_json::from_value::<TenantAuthConfig>(zero).is_err());
    }

    /// The default configuration is written to JSON and read back. It comes
    /// back equal.
    #[cfg(feature = "serde")]
    #[test]
    fn a_configuration_round_trips_through_storage() {
        let config = TenantAuthConfig::default();

        let stored = serde_json::to_string(&config).unwrap();

        assert_eq!(
            serde_json::from_str::<TenantAuthConfig>(&stored).unwrap(),
            config
        );
    }

    /// A new tenant allows passwords and passkeys. Magic links and SAML are
    /// off until an admin turns them on.
    #[test]
    fn default_enables_password_and_passkey_only() {
        let config = TenantAuthConfig::default();

        assert!(config.is_method_enabled(AuthMethod::Password));
        assert!(config.is_method_enabled(AuthMethod::Passkey));
        assert!(!config.is_method_enabled(AuthMethod::MagicLink));
        assert!(!config.is_method_enabled(AuthMethod::Saml));
    }

    /// A new tenant starts with MFA disabled.
    #[test]
    fn default_disables_mfa() {
        assert_eq!(
            TenantAuthConfig::default().mfa_policy(),
            MfaPolicy::Disabled
        );
    }

    /// A new tenant lets in only invited people. Nobody signs up on their
    /// own.
    #[test]
    fn default_disables_self_registration() {
        assert!(!TenantAuthConfig::default().self_registration());
    }

    /// A new tenant has an empty address list and so no IP restrictions.
    #[test]
    fn default_has_no_ip_restrictions() {
        let config = TenantAuthConfig::default();

        assert!(config.ip_allowlist().is_empty());
        assert!(!config.has_ip_restrictions());
    }

    /// A new tenant's sessions last 28,800 seconds, which is eight hours.
    #[test]
    fn default_session_lifetime_is_8_hours() {
        assert_eq!(
            TenantAuthConfig::default().session_lifetime_secs(),
            Seconds::new(28800)
        );
    }

    /// A new tenant's sessions expire after 3,600 idle seconds, one hour.
    #[test]
    fn default_idle_timeout_is_1_hour() {
        assert_eq!(
            TenantAuthConfig::default().idle_timeout_secs(),
            Seconds::new(3600)
        );
    }

    /// A new tenant locks an account after ten failed attempts, for 900
    /// seconds.
    #[test]
    fn default_lockout_after_10_attempts() {
        let config = TenantAuthConfig::default();

        assert_eq!(config.max_login_attempts(), 10);
        assert_eq!(config.lockout_duration_secs(), Seconds::new(900));
    }

    /// An enterprise tenant allows only SAML, requires MFA, sets short
    /// sessions and admits only `10.0.0.0/8`. Every value reads back and
    /// passwords are off.
    #[test]
    fn enterprise_config_with_saml_and_mfa() {
        let config = TenantAuthConfig::new(TenantAuthSettings {
            enabled_methods: vec![AuthMethod::Saml],
            password_policy: PasswordPolicy::default(),
            mfa_policy: MfaPolicy::Required,
            session_lifetime_secs: Seconds::new(1800),
            idle_timeout_secs: Seconds::new(900),
            self_registration: SelfRegistration::Closed,
            max_login_attempts: 5,
            lockout_duration_secs: Seconds::new(1800),
            ip_allowlist: vec![CidrRange::new("10.0.0.0/8").unwrap()],
            jwt_issuer: TokenIssuer::Platform,
            step_up_policy: StepUpPolicy::relaxed(),
            second_factors: vec![MfaMethod::Totp],
            breached_passwords: BreachedPasswordCheck::Block,
            impersonation_consent: ImpersonationConsent::HolderApproves,
            challenge_threshold: FailureThreshold::default(),
        })
        .unwrap();

        assert!(config.is_method_enabled(AuthMethod::Saml));
        assert!(!config.is_method_enabled(AuthMethod::Password));
        assert_eq!(config.mfa_policy(), MfaPolicy::Required);
        assert_eq!(config.session_lifetime_secs(), Seconds::new(1800));
        assert_eq!(config.idle_timeout_secs(), Seconds::new(900));
        assert!(config.has_ip_restrictions());
        assert_eq!(config.ip_allowlist()[0].as_str(), "10.0.0.0/8");
    }

    /// A tenant allows passwords, OIDC and magic links with open sign-up.
    /// Those three are on, SAML is off and self-registration reads as open.
    #[test]
    fn multiple_auth_methods() {
        let config = TenantAuthConfig::new(TenantAuthSettings {
            enabled_methods: vec![
                AuthMethod::Password,
                AuthMethod::Oidc,
                AuthMethod::MagicLink,
            ],
            password_policy: PasswordPolicy::default(),
            mfa_policy: MfaPolicy::Optional,
            session_lifetime_secs: Seconds::new(28800),
            idle_timeout_secs: Seconds::new(3600),
            self_registration: SelfRegistration::Open,
            max_login_attempts: 10,
            lockout_duration_secs: Seconds::new(900),
            ip_allowlist: Vec::new(),
            jwt_issuer: TokenIssuer::Platform,
            step_up_policy: StepUpPolicy::relaxed(),
            second_factors: vec![MfaMethod::Totp],
            breached_passwords: BreachedPasswordCheck::Block,
            impersonation_consent: ImpersonationConsent::HolderApproves,
            challenge_threshold: FailureThreshold::default(),
        })
        .unwrap();

        assert!(config.is_method_enabled(AuthMethod::Password));
        assert!(config.is_method_enabled(AuthMethod::Oidc));
        assert!(config.is_method_enabled(AuthMethod::MagicLink));
        assert!(!config.is_method_enabled(AuthMethod::Saml));
        assert!(config.self_registration());
    }

    /// The default password policy asks for 12 characters with upper case,
    /// lower case and a digit. A special character is optional.
    #[test]
    fn default_password_policy() {
        let policy = PasswordPolicy::default();

        assert_eq!(policy.min_length(), 12);
        assert_eq!(policy.require().uppercase, CharacterRule::Required);
        assert_eq!(policy.require().lowercase, CharacterRule::Required);
        assert_eq!(policy.require().digit, CharacterRule::Required);
        assert_eq!(policy.require().special, CharacterRule::Optional);
    }

    /// A tenant picks the strict password rules. The configuration hands back
    /// a policy that also requires a special character.
    #[test]
    fn strict_password_policy() {
        let config = TenantAuthConfig::new(TenantAuthSettings {
            enabled_methods: vec![AuthMethod::Password],
            password_policy: PasswordPolicy::new(12, CharacterRequirements::strict()).unwrap(),
            mfa_policy: MfaPolicy::Disabled,
            session_lifetime_secs: Seconds::new(28800),
            idle_timeout_secs: Seconds::new(3600),
            self_registration: SelfRegistration::Closed,
            max_login_attempts: 10,
            lockout_duration_secs: Seconds::new(900),
            ip_allowlist: Vec::new(),
            jwt_issuer: TokenIssuer::Platform,
            step_up_policy: StepUpPolicy::relaxed(),
            second_factors: vec![MfaMethod::Totp],
            breached_passwords: BreachedPasswordCheck::Block,
            impersonation_consent: ImpersonationConsent::HolderApproves,
            challenge_threshold: FailureThreshold::default(),
        })
        .unwrap();

        let policy = config.password_policy();
        assert_eq!(policy.min_length(), 12);
        assert_eq!(policy.require().uppercase, CharacterRule::Required);
        assert_eq!(policy.require().lowercase, CharacterRule::Required);
        assert_eq!(policy.require().digit, CharacterRule::Required);
        assert_eq!(policy.require().special, CharacterRule::Required);
    }

    /// Text that is not a range, an empty string and `999.999.999.999/8` are
    /// all refused as address ranges, so a bad entry never reaches the list.
    #[test]
    fn cidr_range_rejects_invalid_on_construction() {
        assert!(CidrRange::new("not-a-cidr").is_err());
        assert!(CidrRange::new("").is_err());
        assert!(CidrRange::new("999.999.999.999/8").is_err());
    }

    /// A tenant lists one IPv4 and one IPv6 range. Both are kept and the
    /// tenant reads as restricted.
    #[test]
    fn config_with_valid_cidrs() {
        let config = TenantAuthConfig::new(TenantAuthSettings {
            ip_allowlist: vec![
                CidrRange::new("10.0.0.0/8").unwrap(),
                CidrRange::new("2001:db8::/32").unwrap(),
            ],
            ..TenantAuthSettings::default()
        })
        .unwrap();
        assert!(config.has_ip_restrictions());
        assert_eq!(config.ip_allowlist().len(), 2);
    }

    /// The default tenant lists passwords among its methods. The list and
    /// `is_method_enabled` give the same answer, so sign-in offers what it
    /// accepts.
    #[test]
    fn a_tenant_lists_the_methods_it_enabled() {
        let config = TenantAuthConfig::default();

        assert!(config.enabled_methods().contains(&AuthMethod::Password));
        assert_eq!(
            config.is_method_enabled(AuthMethod::Password),
            config.enabled_methods().contains(&AuthMethod::Password)
        );
    }

    /// Acme sets `https://auth.acme.com` as its issuer and gets it back. A
    /// tenant without its own reports the platform's, never that there is
    /// none to check `iss` against.
    #[test]
    fn a_configured_jwt_issuer_is_reported_back() {
        let issuer = HttpUrl::new("https://auth.acme.com").unwrap();
        let config = TenantAuthConfig::new(TenantAuthSettings {
            jwt_issuer: TokenIssuer::Custom(issuer.clone()),
            ..TenantAuthSettings::default()
        })
        .unwrap();

        assert_eq!(config.jwt_issuer(), &TokenIssuer::Custom(issuer));
        assert_eq!(
            TenantAuthConfig::default().jwt_issuer(),
            &TokenIssuer::Platform
        );
    }

    /// A tenant with password login on gives its password policy for a new
    /// password.
    #[test]
    fn a_tenant_with_password_login_holds_new_passwords_to_its_policy() {
        let config = TenantAuthConfig::default();

        assert_eq!(config.new_password_policy(), Some(config.password_policy()));
    }

    /// A new tenant refuses a breached password when one is set, and offers
    /// an authenticator app once second factors are on.
    #[test]
    fn a_new_tenant_blocks_breached_passwords_and_offers_an_app() {
        let config = TenantAuthConfig::new(TenantAuthSettings {
            mfa_policy: MfaPolicy::Optional,
            ..TenantAuthSettings::default()
        })
        .unwrap();

        assert_eq!(config.breached_passwords(), BreachedPasswordCheck::Block);
        assert!(config.offer_factor(MfaMethod::Totp).is_ok());
        assert!(config.offer_factor(MfaMethod::SmsCode).is_err());
    }

    /// Acme asks for AAL2 and lists an app, mailed and texted codes. The app
    /// is offered; mailed and texted codes are not, since neither ever
    /// reaches AAL2.
    #[test]
    fn a_tenant_offers_only_listed_factors_that_reach_its_baseline() {
        let config = TenantAuthConfig::new(TenantAuthSettings {
            second_factors: vec![MfaMethod::Totp, MfaMethod::EmailCode, MfaMethod::SmsCode],
            ..with_baseline(vec![AuthMethod::Password], MfaPolicy::Required, Aal2)
        })
        .unwrap();

        assert!(config.offer_factor(MfaMethod::Totp).is_ok());
        assert!(config.offer_factor(MfaMethod::SmsCode).is_err());
        assert!(config.offer_factor(MfaMethod::EmailCode).is_err());
    }

    /// A tenant listing no kind of second factor, or one twice, is refused.
    #[test]
    fn the_listed_second_factors_are_checked() {
        for second_factors in [Vec::new(), vec![MfaMethod::Totp, MfaMethod::Totp]] {
            let settings = TenantAuthSettings {
                second_factors,
                ..TenantAuthSettings::default()
            };

            assert!(TenantAuthConfig::new(settings).is_err());
        }
    }

    /// A passkey-only tenant supplies no policy for setting a new password,
    /// so callers cannot accept one while password sign-in is disabled.
    #[test]
    fn a_tenant_without_password_login_takes_no_new_passwords() {
        let config = TenantAuthConfig::new(TenantAuthSettings {
            enabled_methods: vec![AuthMethod::Passkey],
            ..TenantAuthSettings::default()
        })
        .unwrap();

        assert_eq!(config.new_password_policy(), None);
    }
}
