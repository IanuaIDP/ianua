//! How the people who administer an organization sign in.
//!
//! This is a separate type from
//! [`crate::domains::tenant::access::auth_config::TenantAuthConfig`]. The two
//! share most controls. But an organization has no JWT issuer to pin, because
//! nothing proxies its traffic. And it has no self-registration, because an
//! organization exists before anyone can register into it. One shared struct
//! would carry two settings that never do anything here.

use crate::domains::authentication::admission::{SignInAdmitted, allowlist_admits};
use crate::domains::authentication::credentials::breach::BreachedPasswordCheck;
use crate::domains::authentication::methods::{AuthMethod, MfaPolicy, ensure_baseline_reachable};
use crate::domains::authentication::mfa::enrolled_factor::CodeDelivery;
use crate::domains::authentication::mfa::enrollment::MfaMethod;
use crate::domains::authentication::mfa::offer::{
    FactorOffer, FactorSettings, ensure_offered_factors, offer_factor,
};
use crate::domains::authentication::risk_engine::pressure::FailureThreshold;
use crate::domains::authentication::risk_engine::step_up::StepUpPolicy;
use crate::domains::authentication::sign_in_limits::{SignInLimits, SignInNumbers};
use crate::domains::organization::members::membership::OrgRole;
use crate::domains::organization::members::org_user::OrgUser;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_count;
use crate::types::{CidrRange, Fact, IpAddress, PasswordPolicy, Seconds};

/// The ways into an organization's management plane: a password, a passkey,
/// a link mailed to the member, and single sign-on through the
/// organization's own SAML or OIDC identity provider.
const SUPPORTED_METHODS: [AuthMethod; 5] = [
    AuthMethod::Password,
    AuthMethod::Passkey,
    AuthMethod::MagicLink,
    AuthMethod::Saml,
    AuthMethod::Oidc,
];

/// Whether members must sign in through the organization's identity
/// provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SsoEnforcement {
    /// Members may use any enabled way in.
    #[default]
    Optional,
    /// Members sign in only through single sign-on. Owners may still use a
    /// password, a passkey or a mailed link, as break-glass: an identity
    /// provider that is down or misconfigured must not lock every owner out
    /// of the organization that could fix it.
    Enforced,
}

/// Per-organization authentication configuration.
///
/// Says how org administrators reach the management plane. It sets which
/// methods they may use, how strong passwords must be, how long sessions
/// last, how fast guessing locks them out, where they may sign in from, and
/// when a password alone is not enough.
///
/// Loaded from the organization row and read at every step of org sign-in.
/// Built from [`OrganizationAuthSettings`] by [`new`](Self::new). Reading one
/// back from storage goes through the same checks.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(
        try_from = "OrganizationAuthSettings",
        into = "OrganizationAuthSettings"
    )
)]
pub struct OrganizationAuthConfig(OrganizationAuthSettings);

#[cfg(feature = "serde")]
impl TryFrom<OrganizationAuthSettings> for OrganizationAuthConfig {
    type Error = DomainError;

    fn try_from(settings: OrganizationAuthSettings) -> Result<Self, Self::Error> {
        Self::new(settings)
    }
}

#[cfg(feature = "serde")]
impl From<OrganizationAuthConfig> for OrganizationAuthSettings {
    fn from(config: OrganizationAuthConfig) -> Self {
        config.0
    }
}

/// The values an organization's authentication configuration is made of,
/// before they are checked. Change these freely.
/// [`OrganizationAuthConfig::new`] decides whether they hold together.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OrganizationAuthSettings {
    /// Which authentication methods this organization allows.
    ///
    /// Org sign-in rejects any method not in this list.
    pub enabled_methods: Vec<AuthMethod>,

    /// Password complexity requirements for org administrators.
    pub password_policy: PasswordPolicy,

    /// Whether MFA is disabled, optional, or required.
    pub mfa_policy: MfaPolicy,

    /// How long an org session stays valid from creation, in seconds.
    pub session_lifetime_secs: Seconds,

    /// How long an org session can be idle before it expires, in seconds.
    pub idle_timeout_secs: Seconds,

    /// Maximum failed sign-in attempts from one network before it is locked
    /// out of the account.
    pub max_login_attempts: u8,

    /// How long a network stays locked out of the account after the maximum
    /// attempts, in seconds.
    pub lockout_duration_secs: Seconds,

    /// Optional IP allowlist. When set, only these CIDRs can reach org
    /// sign-in. Empty means every address is allowed.
    pub ip_allowlist: Vec<CidrRange>,

    /// When an org sign-in has to clear a higher bar than a password.
    ///
    /// A stored config without this field reads as [`StepUpPolicy::relaxed`].
    /// A new organization starts with [`StepUpPolicy::untrusted_devices`]
    /// instead.
    #[cfg_attr(feature = "serde", serde(default = "StepUpPolicy::relaxed"))]
    pub step_up_policy: StepUpPolicy,

    /// Whether members must sign in through single sign-on.
    pub sso: SsoEnforcement,

    /// The kinds of second factor members may set up.
    pub second_factors: Vec<MfaMethod>,

    /// What setting a new password does about one found in known breaches.
    pub breached_passwords: BreachedPasswordCheck,

    /// How many failed password sign-ins to the organization, in the
    /// window, put its sign-in under high pressure. Under it, a device no
    /// member trusted must pass a challenge before its password is checked.
    ///
    /// A stored config without this field takes the default.
    #[cfg_attr(feature = "serde", serde(default))]
    pub challenge_threshold: FailureThreshold,
}

impl OrganizationAuthConfig {
    /// Checks `settings` hold together and wraps them.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] for no enabled methods, unsupported methods,
    /// unreachable baseline assurance (see `ensure_baseline_reachable`), or invalid
    /// [`SignInLimits`]. Enforced SSO requires SAML or OIDC. Second factors must be
    /// nonempty and distinct; mail and text factors are unsupported for members.
    pub fn new(settings: OrganizationAuthSettings) -> Result<Self, DomainError> {
        ensure_methods_supported(&settings.enabled_methods)?;
        ensure_sso_reachable(&settings)?;
        ensure_offered_factors(&settings.second_factors)?;
        ensure_member_factors(&settings.second_factors)?;
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
    pub fn settings(&self) -> &OrganizationAuthSettings {
        &self.0
    }

    /// The set of authentication methods enabled for this organization.
    #[must_use]
    pub fn enabled_methods(&self) -> &[AuthMethod] {
        &self.0.enabled_methods
    }

    /// Whether a member may sign in with `method` from `client_ip`. The
    /// [`SignInAdmitted`] it gives is the proof every credential check then
    /// takes.
    ///
    /// A password followed by a TOTP code cannot meet a hardware-key
    /// baseline. So under that baseline the password is refused up front,
    /// rather than half-trusted.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the organization has switched the
    ///   method off.
    /// - [`DomainError::Forbidden`] when the method can never reach the
    ///   organization's baseline assurance. See [`AuthMethod::can_reach`].
    /// - [`DomainError::Forbidden`] when the address is not on the
    ///   organization's list, read the way `allowlist_admits` reads every
    ///   list.
    pub fn admits(
        &self,
        method: AuthMethod,
        client_ip: Fact<&IpAddress>,
    ) -> Result<SignInAdmitted, DomainError> {
        if !self.is_method_enabled(method) {
            return Err(DomainError::forbidden(message!(
                "organization-this-organization-does-not-allow-signing-2",
                "this organization does not allow signing in this way"
            )));
        }
        let baseline = self.step_up_policy().baseline_aal();
        if !method.can_reach(baseline, self.mfa_policy()) {
            return Err(DomainError::forbidden(message!(
                "organization-this-way-of-signing-in-cannot",
                "this way of signing in cannot reach the assurance this organization requires"
            )));
        }
        if !allowlist_admits(self.ip_allowlist(), client_ip) {
            return Err(DomainError::forbidden(message!(
                "organization-this-organization-does-not-allow-signing",
                "this organization does not allow signing in from this address"
            )));
        }
        Ok(SignInAdmitted::new(method, client_ip))
    }

    /// Whether a specific authentication method is allowed.
    #[must_use]
    pub fn is_method_enabled(&self, method: AuthMethod) -> bool {
        self.0.enabled_methods.contains(&method)
    }

    /// The password complexity requirements.
    #[must_use]
    pub fn password_policy(&self) -> &PasswordPolicy {
        &self.0.password_policy
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

    /// Whether members must sign in through single sign-on.
    #[must_use]
    pub fn sso(&self) -> SsoEnforcement {
        self.0.sso
    }

    /// Refuses a sign-in of `member` begun without the identity provider,
    /// while single sign-on is enforced, unless `member` is an owner.
    ///
    /// Acme enforces single sign-on so leavers lose access the moment the
    /// identity provider drops them. Without this, Bob, who left, still
    /// signs in with the password he set years ago. Owners keep their own
    /// ways in as break-glass, see [`SsoEnforcement::Enforced`].
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when it is enforced and `member` is not
    ///   an owner.
    pub fn ensure_may_skip_sso(&self, member: &OrgUser) -> Result<(), DomainError> {
        match (self.0.sso, member.role()) {
            (SsoEnforcement::Optional, _) | (SsoEnforcement::Enforced, OrgRole::Owner) => Ok(()),
            (
                SsoEnforcement::Enforced,
                OrgRole::Admin | OrgRole::Member | OrgRole::Billing | OrgRole::Viewer,
            ) => Err(DomainError::forbidden(message!(
                "organization-this-organization-signs-its-members-in",
                "this organization signs its members in through single sign-on"
            ))),
        }
    }

    /// The offer of `method` to a member setting up a second factor, which
    /// [`MfaEnrollment::begin`] takes.
    ///
    /// [`MfaEnrollment::begin`]: crate::domains::authentication::mfa::enrollment::MfaEnrollment::begin
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when second factors are off, the
    ///   organization does not list `method`, or `method` cannot reach the
    ///   baseline. See [`offer_factor`].
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

    /// Maximum session duration from creation, in seconds.
    #[must_use]
    pub fn session_lifetime_secs(&self) -> Seconds {
        self.0.session_lifetime_secs
    }

    /// Maximum idle time before the session expires, in seconds.
    #[must_use]
    pub fn idle_timeout_secs(&self) -> Seconds {
        self.0.idle_timeout_secs
    }

    /// Failed sign-in attempts from one network before it is locked out of
    /// the account.
    #[must_use]
    pub fn max_login_attempts(&self) -> u8 {
        self.0.max_login_attempts
    }

    /// How long a network stays locked out of the account after the maximum
    /// failed attempts, in seconds.
    #[must_use]
    pub fn lockout_duration_secs(&self) -> Seconds {
        self.0.lockout_duration_secs
    }

    /// The failures across the organization that put its password sign-in
    /// under high pressure.
    #[must_use]
    pub fn challenge_threshold(&self) -> FailureThreshold {
        self.0.challenge_threshold
    }

    /// IP CIDRs allowed to reach org sign-in. Empty means unrestricted.
    #[must_use]
    pub fn ip_allowlist(&self) -> &[CidrRange] {
        &self.0.ip_allowlist
    }

    /// Whether IP restrictions are active for this organization.
    #[must_use]
    pub fn has_ip_restrictions(&self) -> bool {
        !self.0.ip_allowlist.is_empty()
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
}

/// Refuses no methods at all, and methods org sign-in does not implement.
fn ensure_methods_supported(methods: &[AuthMethod]) -> Result<(), DomainError> {
    validate_count("enabled_methods", methods.len(), 1..=usize::MAX)?;
    let Some(unsupported) = methods
        .iter()
        .find(|method| !SUPPORTED_METHODS.contains(method))
    else {
        return Ok(());
    };
    Err(DomainError::invalid(message!(
        "organization-org-sign-in-supports-passwords-passkeys",
        format!(
            "org sign-in supports passwords, passkeys, mailed links, SAML and OIDC; \
         {unsupported:?} would show as enabled without ever being accepted"
        )
    )))
}

/// Refuses listing a second factor whose codes are sent, mailed or texted.
///
/// Members run the management plane of every tenant in the organization,
/// and nothing on that plane sends them codes: a member answers a code their
/// own authenticator app works out, or uses a passkey. Listing a sent kind
/// would offer a factor no member sign-in can answer.
fn ensure_member_factors(offered: &[MfaMethod]) -> Result<(), DomainError> {
    let Some(sent) = offered
        .iter()
        .find(|method| method.delivery() == CodeDelivery::Sent)
    else {
        return Ok(());
    };
    Err(DomainError::invalid(message!(
        "organization-members-answer-codes-from-an-authenticator",
        format!(
            "members answer codes from an authenticator app; {} codes are not sent to members",
            sent.as_str()
        )
    )))
}

/// Refuses enforcing single sign-on with no single sign-on enabled.
fn ensure_sso_reachable(settings: &OrganizationAuthSettings) -> Result<(), DomainError> {
    let federated = settings
        .enabled_methods
        .iter()
        .any(|method| method.is_federated());
    match (settings.sso, federated) {
        (SsoEnforcement::Optional, _) | (SsoEnforcement::Enforced, true) => Ok(()),
        (SsoEnforcement::Enforced, false) => Err(DomainError::invalid(message!(
            "organization-single-sign-on-is-enforced-but",
            "single sign-on is enforced, but neither SAML nor OIDC is enabled"
        ))),
    }
}

impl Default for OrganizationAuthSettings {
    /// The settings a new organization starts with.
    ///
    /// Password and passkey, 8-hour sessions, 1-hour idle timeout, 10 attempts
    /// before a 15-minute lockout, no address restrictions.
    ///
    /// A second factor is [`MfaPolicy::Optional`]. [`MfaPolicy::Required`]
    /// makes everyone without one set one up at their next sign-in. An owner
    /// should choose that, not find it switched on. Someone who did set one
    /// up is still asked for it on every device they have not trusted, by
    /// [`StepUpPolicy::untrusted_devices`].
    fn default() -> Self {
        Self {
            enabled_methods: vec![AuthMethod::Password, AuthMethod::Passkey],
            password_policy: PasswordPolicy::default(),
            mfa_policy: MfaPolicy::Optional,
            session_lifetime_secs: Seconds::new(28800),
            idle_timeout_secs: Seconds::new(3600),
            max_login_attempts: 10,
            lockout_duration_secs: Seconds::new(900),
            ip_allowlist: Vec::new(),
            step_up_policy: StepUpPolicy::untrusted_devices(),
            sso: SsoEnforcement::Optional,
            second_factors: vec![MfaMethod::Totp],
            breached_passwords: BreachedPasswordCheck::Block,
            challenge_threshold: FailureThreshold::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::risk_engine::assurance::AssuranceLevel;
    use crate::domains::authentication::sign_in_limits::MAX_LOCKOUT_SECS;
    use crate::domains::organization::members::control::tests::{founder, member_of};
    use crate::types::CharacterRequirements;
    use crate::types::password_policy::MIN_PASSWORD_LENGTH;

    fn config() -> OrganizationAuthConfig {
        OrganizationAuthConfig::default()
    }

    fn settings() -> OrganizationAuthSettings {
        OrganizationAuthSettings::default()
    }

    /// A hardware-assurance requirement refuses password admission while allowing a passkey.
    #[test]
    fn a_hardware_only_organization_refuses_passwords() {
        let mut s = settings();
        s.enabled_methods = vec![AuthMethod::Password, AuthMethod::Passkey];
        s.step_up_policy = StepUpPolicy::new(
            crate::domains::authentication::risk_engine::step_up::StepUpPolicyParams {
                baseline_aal: AssuranceLevel::Aal3,
                sensitive_aal: AssuranceLevel::Aal3,
                new_device:
                    crate::domains::authentication::risk_engine::step_up::MfaTrigger::Ignored,
                new_country:
                    crate::domains::authentication::risk_engine::step_up::MfaTrigger::Ignored,
                mfa_risk_threshold:
                    crate::domains::authentication::risk_engine::assessment::RiskLevel::Critical,
                deny_risk_threshold:
                    crate::domains::authentication::risk_engine::assessment::RiskLevel::Critical,
            },
        )
        .unwrap();
        let config = OrganizationAuthConfig::new(s).unwrap();

        assert!(config.admits(AuthMethod::Password, Fact::Unknown).is_err());
        assert!(config.admits(AuthMethod::Passkey, Fact::Unknown).is_ok());
    }

    /// An owner allows only passwords but demands hardware-key assurance. The
    /// settings are refused, since no administrator could sign in to undo them.
    #[test]
    fn a_baseline_no_enabled_method_can_reach_is_refused() {
        let mut s = settings();
        s.enabled_methods = vec![AuthMethod::Password];
        s.step_up_policy = StepUpPolicy::new(
            crate::domains::authentication::risk_engine::step_up::StepUpPolicyParams {
                baseline_aal: AssuranceLevel::Aal3,
                sensitive_aal: AssuranceLevel::Aal3,
                new_device:
                    crate::domains::authentication::risk_engine::step_up::MfaTrigger::Ignored,
                new_country:
                    crate::domains::authentication::risk_engine::step_up::MfaTrigger::Ignored,
                mfa_risk_threshold:
                    crate::domains::authentication::risk_engine::assessment::RiskLevel::Critical,
                deny_risk_threshold:
                    crate::domains::authentication::risk_engine::assessment::RiskLevel::Critical,
            },
        )
        .unwrap();

        assert!(OrganizationAuthConfig::new(s).is_err());
    }

    /// Under the default settings an admin tries SAML, which is not enabled.
    /// It is refused, while a password is let through.
    #[test]
    fn a_switched_off_method_is_refused() {
        assert!(config().admits(AuthMethod::Saml, Fact::Unknown).is_err());
        assert!(config().admits(AuthMethod::Password, Fact::Unknown).is_ok());
    }

    /// The settings a new organization starts with pass every check, so
    /// signing up never fails on them.
    #[test]
    fn the_default_config_is_valid() {
        assert!(OrganizationAuthConfig::new(settings()).is_ok());
    }

    /// An owner turns off every sign-in method. It is refused, since it
    /// would lock every administrator out.
    #[test]
    fn enabling_no_method_is_rejected() {
        let mut c = settings();
        c.enabled_methods.clear();

        assert!(matches!(
            OrganizationAuthConfig::new(c),
            Err(DomainError::Validation(_))
        ));
    }

    /// An owner turns on SAML, OIDC and mailed links for the dashboard.
    /// Each is accepted and admitted.
    #[test]
    fn single_sign_on_and_mailed_links_are_org_sign_in_methods() {
        let mut c = settings();
        c.enabled_methods
            .extend([AuthMethod::Saml, AuthMethod::Oidc, AuthMethod::MagicLink]);

        let c = OrganizationAuthConfig::new(c).unwrap();

        for method in [AuthMethod::Saml, AuthMethod::Oidc, AuthMethod::MagicLink] {
            assert!(c.admits(method, Fact::Unknown).is_ok(), "{method:?}");
        }
    }

    /// An owner enforces single sign-on without enabling SAML or OIDC. It is
    /// refused, since only owners could then sign in.
    #[test]
    fn enforcing_sso_without_a_provider_is_refused() {
        let mut c = settings();
        c.sso = SsoEnforcement::Enforced;

        assert!(matches!(
            OrganizationAuthConfig::new(c),
            Err(DomainError::Validation(_))
        ));
    }

    fn enforcing_sso() -> OrganizationAuthConfig {
        let mut c = settings();
        c.enabled_methods.push(AuthMethod::Saml);
        c.sso = SsoEnforcement::Enforced;
        OrganizationAuthConfig::new(c).unwrap()
    }

    /// Enforced single sign-on prevents an ordinary member from using an independent sign-in method.
    #[test]
    fn enforced_sso_refuses_a_members_own_way_in() {
        let bob = member_of(&founder());

        assert!(matches!(
            enforcing_sso().ensure_may_skip_sso(&bob),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// Acme's identity provider is down. Ann, an owner, still signs in with
    /// her own password to fix it: owners are the break-glass.
    #[test]
    fn enforced_sso_lets_owners_use_their_own_way_in() {
        let ann = founder();

        assert!(enforcing_sso().ensure_may_skip_sso(&ann).is_ok());
    }

    /// Without enforcement, every member may use their own way in.
    #[test]
    fn optional_sso_lets_every_member_choose() {
        let bob = member_of(&founder());

        assert!(config().ensure_may_skip_sso(&bob).is_ok());
    }

    /// A new organization blocks breached passwords, offers authenticator
    /// apps, and leaves single sign-on optional.
    #[test]
    fn a_new_organization_blocks_breached_passwords_and_offers_an_app() {
        let c = config();

        assert_eq!(c.breached_passwords(), BreachedPasswordCheck::Block);
        assert_eq!(c.sso(), SsoEnforcement::Optional);
        assert!(c.offer_factor(MfaMethod::Totp).is_ok());
        assert!(c.offer_factor(MfaMethod::EmailCode).is_err());
    }

    /// An owner sets 10-minute sessions with a 20-minute idle timeout. It is
    /// refused, since the idle timeout could never apply.
    #[test]
    fn an_idle_timeout_outlasting_its_session_is_rejected() {
        let mut c = settings();
        c.session_lifetime_secs = Seconds::new(600);
        c.idle_timeout_secs = Seconds::new(1200);

        assert!(matches!(
            OrganizationAuthConfig::new(c),
            Err(DomainError::Validation(_))
        ));
    }

    /// An owner sets the idle timeout equal to the 10-minute session. That is
    /// allowed.
    #[test]
    fn an_idle_timeout_equal_to_its_session_is_allowed() {
        let mut c = settings();
        c.session_lifetime_secs = Seconds::new(600);
        c.idle_timeout_secs = Seconds::new(600);

        assert!(OrganizationAuthConfig::new(c).is_ok());
    }

    /// An owner locks accounts after one failed attempt. It is refused, since
    /// a single typo would lock an administrator out.
    #[test]
    fn locking_on_a_single_attempt_is_rejected() {
        let mut c = settings();
        c.max_login_attempts = 1;

        assert!(matches!(
            OrganizationAuthConfig::new(c),
            Err(DomainError::Validation(_))
        ));
    }

    /// An owner sets a lockout one second past the maximum. It is refused.
    #[test]
    fn a_lockout_longer_than_a_day_is_rejected() {
        let mut c = settings();
        c.lockout_duration_secs = Seconds::new(MAX_LOCKOUT_SECS + 1);

        assert!(matches!(
            OrganizationAuthConfig::new(c),
            Err(DomainError::Validation(_))
        ));
    }

    /// A new organization never set an IP allowlist. It reads as having no
    /// restriction, not as allowing nobody.
    #[test]
    fn an_empty_allowlist_means_unrestricted_not_locked_out() {
        assert!(
            !config().has_ip_restrictions(),
            "an organization that never set an allowlist must not be treated as \
             one that allowed nothing"
        );
    }

    /// A new organization's settings allow passkeys, so passkeys that admins
    /// register can be used to sign in.
    #[test]
    fn passkey_is_enabled_out_of_the_box() {
        assert!(
            config().is_method_enabled(AuthMethod::Passkey),
            "org passkey endpoints ship enabled, so the config must not refuse \
             the credentials they register"
        );
    }

    /// The default settings never enabled SAML. Asked about SAML they say no,
    /// and about passkeys they answer from the enabled list.
    #[test]
    fn a_method_nobody_enabled_is_not_enabled() {
        let c = config();

        assert!(!c.enabled_methods().is_empty());
        assert!(!c.is_method_enabled(AuthMethod::Saml));
        assert_eq!(
            c.is_method_enabled(AuthMethod::Passkey),
            c.enabled_methods().contains(&AuthMethod::Passkey)
        );
    }

    /// An owner sets 2-hour sessions, a 15-minute idle timeout, 7 attempts
    /// and a 30-minute lockout. Each number reads back as set.
    #[test]
    fn the_session_and_lockout_limits_read_back_as_configured() {
        let mut c = settings();
        c.session_lifetime_secs = Seconds::new(7_200);
        c.idle_timeout_secs = Seconds::new(900);
        c.max_login_attempts = 7;
        c.lockout_duration_secs = Seconds::new(1_800);

        let c = OrganizationAuthConfig::new(c).unwrap();
        assert_eq!(c.session_lifetime_secs(), Seconds::new(7_200));
        assert_eq!(c.idle_timeout_secs(), Seconds::new(900));
        assert_eq!(c.max_login_attempts(), 7);
        assert_eq!(c.lockout_duration_secs(), Seconds::new(1_800));
    }

    /// An owner limits sign-in to `10.0.0.0/8`. The settings report a
    /// restriction holding that one range.
    #[test]
    fn a_configured_allowlist_reads_back_as_a_restriction() {
        let mut c = settings();
        c.ip_allowlist = vec![CidrRange::new("10.0.0.0/8").unwrap()];
        let c = OrganizationAuthConfig::new(c).unwrap();

        assert!(c.has_ip_restrictions());
        assert_eq!(c.ip_allowlist().len(), 1);
        assert_eq!(c.ip_allowlist()[0].as_str(), "10.0.0.0/8");
    }

    /// The `10.0.0.0/8` allowlist admits `10.1.2.3` and refuses both an
    /// outside address and an unknown address.
    #[test]
    fn the_gate_refuses_an_address_off_the_list() {
        let mut c = settings();
        c.ip_allowlist = vec![CidrRange::new("10.0.0.0/8").unwrap()];
        let c = OrganizationAuthConfig::new(c).unwrap();
        let inside = IpAddress::new("10.1.2.3").unwrap();
        let outside = IpAddress::new("192.168.1.1").unwrap();

        assert!(c.admits(AuthMethod::Password, Fact::Known(&inside)).is_ok());
        assert!(
            c.admits(AuthMethod::Password, Fact::Known(&outside))
                .is_err()
        );
        assert!(c.admits(AuthMethod::Password, Fact::Unknown).is_err());
    }

    /// An owner raises the minimum password length by four. The policy read
    /// back has that length, not the default.
    #[test]
    fn the_password_policy_read_back_is_the_one_configured() {
        let mut c = settings();
        c.password_policy =
            PasswordPolicy::new(MIN_PASSWORD_LENGTH + 4, CharacterRequirements::none()).unwrap();

        let c = OrganizationAuthConfig::new(c).unwrap();
        assert_eq!(c.password_policy().min_length(), MIN_PASSWORD_LENGTH + 4);
    }

    /// Organization factor settings reject email and SMS codes while accepting an authenticator app.
    #[test]
    fn members_are_offered_no_factor_whose_codes_are_sent() {
        for sent in [MfaMethod::EmailCode, MfaMethod::SmsCode] {
            let mut s = settings();
            s.second_factors = vec![MfaMethod::Totp, sent];

            assert!(matches!(
                OrganizationAuthConfig::new(s),
                Err(DomainError::Validation(_))
            ));
        }
        assert!(OrganizationAuthConfig::new(settings()).is_ok());
    }
}
