//! Sign-in: how long sessions, tokens, codes and ceremonies last, what a
//! second factor allows, passkeys' relying party, and the challenge a
//! flooded sign-in page asks for.

use std::fmt;
use std::time::Duration;

use ianua_boot::env::{ConfigError, Env, Read};
use ianua_boot::environment::Environment;
use ianua_domain::domains::authentication::credentials::breach::BreachPolicy;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::Label;
use ianua_infra::cache::{HARDEST_PUZZLE_BITS, PuzzleSettings};
use ianua_infra::http::PWNED_PASSWORDS;
use ianua_infra::proofs::{PasskeySettings, SubdomainOrigins};

/// The setting naming the password breach service.
const BREACH_URL: &str = "PASSWORD_BREACH_URL";

const MINUTE: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(3600);
const DAY: Duration = Duration::from_secs(86_400);

/// How long OAuth's tokens and codes last.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TokenConfig {
    /// `OAUTH_ACCESS_TOKEN_TTL_SECONDS` (3600), at most a day.
    pub access: Duration,
    /// `OAUTH_ID_TOKEN_TTL_SECONDS` (3600), at most a day.
    pub id_token: Duration,
    /// `OAUTH_REFRESH_TOKEN_IDLE_SECONDS` (604800): how long a refresh
    /// token lasts unless used.
    pub refresh_idle: Duration,
    /// `OAUTH_REFRESH_TOKEN_FAMILY_SECONDS` (2592000): how long a family of
    /// refresh tokens lasts from its first, at most ninety days.
    pub refresh_family: Duration,
    /// `OAUTH_DEVICE_CODE_TTL_SECONDS` (600).
    pub device_code: Duration,
    /// `OAUTH_DEVICE_POLL_INTERVAL_SECONDS` (5).
    pub device_poll_interval: Duration,
    /// `JWKS_ROTATION_GRACE_SECONDS` (86400): how long a rotated signing
    /// key stays published, and so how long tokens it signed still check.
    pub jwks_grace: Duration,
}

/// What a second factor allows.
#[derive(Debug, Clone)]
pub(crate) struct MfaConfig {
    /// `MFA_MAX_ATTEMPTS` (5): wrong codes before a factor locks.
    pub max_attempts: u32,
    /// `MFA_LOCKOUT_SECONDS` (900): how long a lock lasts.
    pub lockout: Duration,
    /// `MFA_CHALLENGE_TTL_SECONDS` (300): an app sign-in's second-factor
    /// step.
    pub challenge_ttl: Duration,
    /// `MFA_SENT_CODE_TTL_SECONDS` (600): a mailed or texted code, at most
    /// ten minutes.
    pub sent_code_ttl: Duration,
    /// `MFA_SENT_CODE_RESEND_SECONDS` (30): the wait before another code
    /// may be sent.
    pub sent_code_resend: Duration,
    /// `MFA_ISSUER` (`Ianua`): the name an authenticator app shows beside
    /// a code.
    pub issuer: Label,
}

/// The challenge a flooded sign-in page asks for, when Turnstile is set
/// up. `Debug` shows no secret.
#[derive(Clone)]
pub(crate) struct TurnstileConfig {
    /// `TURNSTILE_SECRET_KEY` or `TURNSTILE_SECRET_KEY_FILE`.
    pub secret: Secret,
    /// `TURNSTILE_HOSTNAMES`: the hostnames the sign-in page is served on.
    pub hostnames: Vec<String>,
    /// `TURNSTILE_TIMEOUT_SECONDS` (5): one check of a solved challenge,
    /// which a sign-in waits for.
    pub timeout: Duration,
}

impl fmt::Debug for TurnstileConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TurnstileConfig")
            .field("hostnames", &self.hostnames)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

/// Sign-in, sessions, tokens and second factors.
#[derive(Debug, Clone)]
pub(crate) struct SignInConfig {
    /// OAuth's tokens and codes.
    pub tokens: TokenConfig,
    /// Second factors.
    pub mfa: MfaConfig,
    /// `WEBAUTHN_RP_ID`, `WEBAUTHN_RP_NAME` (`Ianua`), `WEBAUTHN_RP_ORIGIN`,
    /// `WEBAUTHN_OTHER_ORIGINS` and `WEBAUTHN_SUBDOMAINS` (off).
    pub passkeys: PasskeySettings,
    /// `AUTH_PASSKEY_CEREMONY_TTL_SECONDS` (300).
    pub passkey_ceremony_ttl: Duration,
    /// `AUTH_MAX_PASSKEYS_PER_USER` (10).
    pub max_passkeys_per_user: usize,
    /// `AUTH_MAX_TRUSTED_DEVICES_PER_USER` (10).
    pub max_trusted_devices_per_user: usize,
    /// `AUTH_DEVICE_TRUST_DAYS` (30): how long a remembered device may go
    /// unused, from 1 to 365 days.
    pub device_trust_days: u32,
    /// `AUTH_BREAK_GLASS_MAX_SECONDS` (86400): the longest emergency grant.
    pub break_glass_max: Duration,
    /// `AUTH_PASSWORD_HISTORY_COUNT` (5).
    pub password_history_count: u32,
    /// `AUTH_PASSWORD_MIN_AGE_SECONDS` (0).
    pub password_min_age: Duration,
    /// `AUTH_PASSWORD_BREACH_POLICY` (`step_up`): what a sign-in with a
    /// breached password must do, `step_up`, `record` or `off`.
    pub breach_policy: BreachPolicy,
    /// `PASSWORD_BREACH_URL` (`https://api.pwnedpasswords.com`): the Pwned
    /// Passwords range service passwords are checked against, another
    /// address only for a mirror or a stand-in of it; `https` in
    /// production.
    pub breach_service: url::Url,
    /// `AUTH_APP_SIGN_IN_ACCESS_TTL_SECONDS` (300).
    pub app_sign_in_access_ttl: Duration,
    /// `AUTH_HANDOFF_CODE_TTL_SECONDS` (60).
    pub handoff_code_ttl: Duration,
    /// `AUTH_SIGN_IN_CODE_TTL_SECONDS` (60).
    pub sign_in_code_ttl: Duration,
    /// `AUTH_FEDERATION_FLOW_TTL_SECONDS` (600): a sign-in at an identity
    /// provider, and the cookie holding its secret.
    pub federation_flow_ttl: Duration,
    /// `AUTH_SIGN_IN_CONFIRMATION_TTL_SECONDS` (900): a link confirming a
    /// sign-in from the mailbox.
    pub sign_in_confirmation_ttl: Duration,
    /// `OPERATOR_KEY_TTL_SECONDS` (43200, from 60 to 86400): how long the
    /// key an operator's password sign-in makes works.
    pub operator_key_ttl: Duration,
    /// `TURNSTILE_SECRET_KEY` and `TURNSTILE_HOSTNAMES`; none sets the
    /// platform's own puzzle instead.
    pub turnstile: Option<TurnstileConfig>,
    /// `SIGN_IN_PUZZLE_DIFFICULTY_BITS` (18, from 8 to 32) and
    /// `SIGN_IN_PUZZLE_TTL_SECONDS` (300): the platform's own puzzle, set
    /// while sign-in is under pressure when Turnstile is not set up.
    pub puzzles: PuzzleSettings,
}

impl SignInConfig {
    /// The sign-in settings `vars` holds.
    ///
    /// # Errors
    ///
    /// A setting missing or out of its range, refresh lifetimes that do
    /// not nest, a relying party origin that is no URL, or half the
    /// Turnstile settings, and a breach service that is no URL, or is not
    /// `https` in production.
    pub(crate) fn read(vars: &Env, environment: Environment) -> Read<Self> {
        Ok(Self {
            tokens: tokens(vars)?,
            mfa: mfa(vars)?,
            passkeys: passkeys(vars)?,
            passkey_ceremony_ttl: vars.seconds("AUTH_PASSKEY_CEREMONY_TTL_SECONDS", 5 * MINUTE)?,
            max_passkeys_per_user: vars.number_in("AUTH_MAX_PASSKEYS_PER_USER", 10, 1..=100)?,
            max_trusted_devices_per_user: vars.number_in(
                "AUTH_MAX_TRUSTED_DEVICES_PER_USER",
                10,
                1..=100,
            )?,
            device_trust_days: vars.number_in("AUTH_DEVICE_TRUST_DAYS", 30, 1..=365)?,
            break_glass_max: vars.seconds("AUTH_BREAK_GLASS_MAX_SECONDS", DAY)?,
            password_history_count: vars.number_in("AUTH_PASSWORD_HISTORY_COUNT", 5, 0..=50)?,
            password_min_age: vars.seconds("AUTH_PASSWORD_MIN_AGE_SECONDS", Duration::ZERO)?,
            breach_policy: breach_policy(vars)?,
            breach_service: breach_service(vars, environment)?,
            app_sign_in_access_ttl: vars
                .seconds("AUTH_APP_SIGN_IN_ACCESS_TTL_SECONDS", 5 * MINUTE)?,
            handoff_code_ttl: vars.seconds("AUTH_HANDOFF_CODE_TTL_SECONDS", MINUTE)?,
            sign_in_code_ttl: vars.seconds("AUTH_SIGN_IN_CODE_TTL_SECONDS", MINUTE)?,
            federation_flow_ttl: vars.seconds("AUTH_FEDERATION_FLOW_TTL_SECONDS", 10 * MINUTE)?,
            sign_in_confirmation_ttl: vars
                .seconds("AUTH_SIGN_IN_CONFIRMATION_TTL_SECONDS", 15 * MINUTE)?,
            operator_key_ttl: operator_key_ttl(vars)?,
            turnstile: turnstile(vars)?,
            puzzles: puzzles(vars)?,
        })
    }
}

/// Reads the action taken when a password appears in the breach service.
fn breach_policy(vars: &Env) -> Read<BreachPolicy> {
    vars.choice(
        "AUTH_PASSWORD_BREACH_POLICY",
        BreachPolicy::StepUp,
        &[
            ("step_up", BreachPolicy::StepUp),
            ("record", BreachPolicy::Record),
            ("off", BreachPolicy::Off),
        ],
    )
}

/// Reads the operator session lifetime within its one-minute to one-day range.
fn operator_key_ttl(vars: &Env) -> Read<Duration> {
    vars.seconds_in(
        "OPERATOR_KEY_TTL_SECONDS",
        12 * HOUR,
        MINUTE.as_secs()..=DAY.as_secs(),
    )
}

/// Bounds the local sign-in puzzle's work and redemption lifetime.
fn puzzles(vars: &Env) -> Read<PuzzleSettings> {
    Ok(PuzzleSettings {
        difficulty_bits: vars.number_in(
            "SIGN_IN_PUZZLE_DIFFICULTY_BITS",
            18,
            8..=HARDEST_PUZZLE_BITS,
        )?,
        lifetime: vars.seconds_in("SIGN_IN_PUZZLE_TTL_SECONDS", 5 * MINUTE, 1..=HOUR.as_secs())?,
    })
}

/// The refresh token idle and total family lifetimes, checked together.
struct RefreshLifetimes {
    idle: Duration,
    family: Duration,
}

impl RefreshLifetimes {
    /// Refuses a refresh idle period that would outlive its token family.
    fn read(vars: &Env) -> Read<Self> {
        let idle = vars.seconds_in(
            "OAUTH_REFRESH_TOKEN_IDLE_SECONDS",
            7 * DAY,
            1..=(90 * DAY).as_secs(),
        )?;
        let family = vars.seconds_in(
            "OAUTH_REFRESH_TOKEN_FAMILY_SECONDS",
            30 * DAY,
            1..=(90 * DAY).as_secs(),
        )?;
        if idle > family {
            return Err(ConfigError::contradicts(
                "OAUTH_REFRESH_TOKEN_IDLE_SECONDS",
                "is longer than OAUTH_REFRESH_TOKEN_FAMILY_SECONDS",
            ));
        }
        Ok(Self { idle, family })
    }
}

/// Reads token and code lifetimes after validating the refresh family bounds.
fn tokens(vars: &Env) -> Read<TokenConfig> {
    let refresh = RefreshLifetimes::read(vars)?;
    Ok(TokenConfig {
        access: vars.seconds_in("OAUTH_ACCESS_TOKEN_TTL_SECONDS", HOUR, 1..=DAY.as_secs())?,
        id_token: vars.seconds_in("OAUTH_ID_TOKEN_TTL_SECONDS", HOUR, 1..=DAY.as_secs())?,
        refresh_idle: refresh.idle,
        refresh_family: refresh.family,
        device_code: vars.seconds_in(
            "OAUTH_DEVICE_CODE_TTL_SECONDS",
            10 * MINUTE,
            1..=HOUR.as_secs(),
        )?,
        device_poll_interval: vars.seconds_in(
            "OAUTH_DEVICE_POLL_INTERVAL_SECONDS",
            Duration::from_secs(5),
            1..=MINUTE.as_secs(),
        )?,
        jwks_grace: vars.seconds_in(
            "JWKS_ROTATION_GRACE_SECONDS",
            DAY,
            1..=(30 * DAY).as_secs(),
        )?,
    })
}

fn mfa(vars: &Env) -> Read<MfaConfig> {
    let issuer = vars.text("MFA_ISSUER", "Ianua")?;
    Ok(MfaConfig {
        max_attempts: vars.number_in("MFA_MAX_ATTEMPTS", 5, 1..=100)?,
        lockout: vars.seconds_in("MFA_LOCKOUT_SECONDS", 15 * MINUTE, 1..=DAY.as_secs())?,
        challenge_ttl: vars.seconds_in(
            "MFA_CHALLENGE_TTL_SECONDS",
            5 * MINUTE,
            1..=HOUR.as_secs(),
        )?,
        sent_code_ttl: vars.seconds_in(
            "MFA_SENT_CODE_TTL_SECONDS",
            10 * MINUTE,
            1..=(10 * MINUTE).as_secs(),
        )?,
        sent_code_resend: vars.seconds("MFA_SENT_CODE_RESEND_SECONDS", Duration::from_secs(30))?,
        issuer: Label::new("MFA_ISSUER", issuer)
            .map_err(|cause| ConfigError::rejected("MFA_ISSUER", cause))?,
    })
}

/// The Pwned Passwords range service, or the mirror or stand-in
/// `PASSWORD_BREACH_URL` names. A plain `http` address is refused in
/// production: whoever answers in its place could call every breached
/// password clean.
fn breach_service(vars: &Env, environment: Environment) -> Read<url::Url> {
    let Some(url) = vars.url(BREACH_URL)? else {
        return url::Url::parse(PWNED_PASSWORDS)
            .map_err(|cause| ConfigError::rejected(BREACH_URL, cause));
    };
    if url.scheme() != "https" && environment.is_production() {
        return Err(ConfigError::contradicts(
            BREACH_URL,
            "is not https in production, where whoever answers in the service's place could call every breached password clean",
        ));
    }
    Ok(url)
}

/// Passkeys' relying party.
fn passkeys(vars: &Env) -> Read<PasskeySettings> {
    let origin = vars
        .url("WEBAUTHN_RP_ORIGIN")?
        .ok_or_else(|| ConfigError::missing("WEBAUTHN_RP_ORIGIN"))?;
    let mut other_origins = Vec::new();
    for entry in vars.list("WEBAUTHN_OTHER_ORIGINS")? {
        other_origins.push(url::Url::parse(&entry).map_err(|_| {
            ConfigError::invalid(
                "WEBAUTHN_OTHER_ORIGINS",
                format!("must list origins, got {entry:?}"),
            )
        })?);
    }
    let subdomains = vars.flag("WEBAUTHN_SUBDOMAINS", false)?;
    Ok(PasskeySettings {
        relying_party_id: vars.required("WEBAUTHN_RP_ID")?,
        relying_party_name: vars.text("WEBAUTHN_RP_NAME", "Ianua")?,
        origin,
        other_origins,
        subdomains: if subdomains {
            SubdomainOrigins::Accepted
        } else {
            SubdomainOrigins::Refused
        },
    })
}

/// Turnstile, when its secret is set, with the hostnames it must have.
fn turnstile(vars: &Env) -> Read<Option<TurnstileConfig>> {
    let secret = vars.secret("TURNSTILE_SECRET_KEY")?;
    let hostnames = vars.list("TURNSTILE_HOSTNAMES")?;
    match (secret, hostnames.is_empty()) {
        (None, true) => Ok(None),
        (None, false) => Err(ConfigError::contradicts(
            "TURNSTILE_HOSTNAMES",
            "is set without TURNSTILE_SECRET_KEY",
        )),
        (Some(_), true) => Err(ConfigError::contradicts(
            "TURNSTILE_SECRET_KEY",
            "is set without TURNSTILE_HOSTNAMES, the hostnames the sign-in page is served on",
        )),
        (Some(secret), false) => Ok(Some(TurnstileConfig {
            secret,
            hostnames,
            timeout: vars.seconds("TURNSTILE_TIMEOUT_SECONDS", Duration::from_secs(5))?,
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relying_party() -> Vec<(&'static str, &'static str)> {
        vec![
            ("WEBAUTHN_RP_ID", "example.com"),
            ("WEBAUTHN_RP_ORIGIN", "https://app.example.com"),
        ]
    }

    /// The sign-in settings `vars` holds, in development.
    fn development(vars: &Env) -> Read<SignInConfig> {
        SignInConfig::read(vars, Environment::Development)
    }

    /// With no breach service named, passwords are checked against the
    /// public Pwned Passwords range service.
    #[test]
    fn with_no_breach_service_named_the_public_one_is_asked() {
        let config = development(&Env::of(relying_party())).unwrap();

        assert_eq!(
            config.breach_service.as_str(),
            "https://api.pwnedpasswords.com/"
        );
    }

    /// A stand-in of the breach service is asked at the address named, in
    /// development as the end-to-end tests run.
    #[test]
    fn a_breach_service_stand_in_is_asked_where_named() {
        let mut pairs = relying_party();
        pairs.push(("PASSWORD_BREACH_URL", "http://127.0.0.1:4100"));

        let config = development(&Env::of(pairs)).unwrap();

        assert_eq!(config.breach_service.as_str(), "http://127.0.0.1:4100/");
    }

    /// Production sign-in configuration refuses an HTTP breach service,
    /// naming its URL setting.
    #[test]
    fn a_plain_breach_service_in_production_is_refused() {
        let mut pairs = relying_party();
        pairs.push(("PASSWORD_BREACH_URL", "http://breaches.internal"));

        let read = SignInConfig::read(&Env::of(pairs), Environment::Production);

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "PASSWORD_BREACH_URL")
        );
    }

    /// With only the relying party set, the documented lifetimes hold.
    #[test]
    fn with_only_the_relying_party_the_documented_lifetimes_hold() {
        let config = development(&Env::of(relying_party())).unwrap();

        assert_eq!(config.tokens.access, HOUR);
        assert_eq!(config.mfa.sent_code_ttl, 10 * MINUTE);
        assert_eq!(config.breach_policy, BreachPolicy::StepUp);
        assert_eq!(config.passkeys.subdomains, SubdomainOrigins::Refused);
        assert!(config.turnstile.is_none());
    }

    /// A passkey origin without a relying party ID is refused, naming the
    /// missing ID setting.
    #[test]
    fn the_relying_party_must_be_set() {
        let read = development(&Env::of([(
            "WEBAUTHN_RP_ORIGIN",
            "https://app.example.com",
        )]));

        assert!(matches!(read, Err(ConfigError::Missing { name }) if name == "WEBAUTHN_RP_ID"));
    }

    /// Configuration refuses a week-long access token lifetime because it
    /// exceeds the one-day maximum.
    #[test]
    fn an_access_token_past_a_day_is_refused() {
        let mut pairs = relying_party();
        pairs.push(("OAUTH_ACCESS_TOKEN_TTL_SECONDS", "604800"));

        assert!(development(&Env::of(pairs)).is_err());
    }

    /// Refresh lifetimes must nest: a token's idle time within its family's.
    #[test]
    fn refresh_lifetimes_must_nest() {
        let mut pairs = relying_party();
        pairs.push(("OAUTH_REFRESH_TOKEN_IDLE_SECONDS", "2592000"));
        pairs.push(("OAUTH_REFRESH_TOKEN_FAMILY_SECONDS", "86400"));

        let read = development(&Env::of(pairs));

        assert!(matches!(read, Err(ConfigError::Contradicts { .. })));
    }

    /// Configuration refuses an hour-long sent code lifetime because it
    /// exceeds the ten-minute maximum.
    #[test]
    fn a_sent_code_past_ten_minutes_is_refused() {
        let mut pairs = relying_party();
        pairs.push(("MFA_SENT_CODE_TTL_SECONDS", "3600"));

        assert!(development(&Env::of(pairs)).is_err());
    }

    /// Configuration refuses an MFA attempt limit of zero.
    #[test]
    fn a_lockout_of_no_attempts_is_refused() {
        let mut pairs = relying_party();
        pairs.push(("MFA_MAX_ATTEMPTS", "0"));

        assert!(development(&Env::of(pairs)).is_err());
    }

    /// Turnstile configuration requires both its secret and hostnames;
    /// providing either alone is refused.
    #[test]
    fn half_the_turnstile_settings_are_refused() {
        let mut secret_only = relying_party();
        secret_only.push(("TURNSTILE_SECRET_KEY", "0x4AAA-secret"));
        let mut hostnames_only = relying_party();
        hostnames_only.push(("TURNSTILE_HOSTNAMES", "app.example.com"));

        assert!(development(&Env::of(secret_only)).is_err());
        assert!(development(&Env::of(hostnames_only)).is_err());
    }

    /// Turnstile set up whole is read, its secret never printed.
    #[test]
    fn turnstile_set_up_whole_is_read_and_never_prints_its_secret() {
        let mut pairs = relying_party();
        pairs.push(("TURNSTILE_SECRET_KEY", "0x4AAA-secret"));
        pairs.push(("TURNSTILE_HOSTNAMES", "app.example.com"));

        let config = development(&Env::of(pairs)).unwrap();

        assert!(config.turnstile.is_some());
        assert!(!format!("{config:?}").contains("0x4AAA-secret"));
    }
}
