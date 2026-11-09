//! The settings the use cases are built with, from the configuration's
//! plain values: each read into the domain's or the app's own type, and
//! refused with the name of the setting it came from when that type will
//! not hold it.

use std::num::NonZeroU8;
use std::time::Duration;

use ianua_app::email::ResendCooldown;
use ianua_app::use_cases::agents::approvals::{ApprovalLimits, GatePolicy};
use ianua_app::use_cases::agents::runs::StepLimits;
use ianua_app::use_cases::audit::exports::ExportLimits;
use ianua_app::use_cases::authentication::app_sign_in::AppSignInLifetimes;
use ianua_app::use_cases::authentication::mfa::SentCodePolicy;
use ianua_app::use_cases::oauth::flows::DeviceCodeTiming;
use ianua_app::use_cases::onboarding::Enrollment;
use ianua_app::use_cases::scim::groups::MemberCap;
use ianua_assembly::deps::Settings;
use ianua_assembly::domain::CustomDomainSettings;
use ianua_assembly::tunables::Tunables;
use ianua_boot::env::{ConfigError, Read};
use ianua_domain::domains::agents::identity::credential::CredentialLifetimes;
use ianua_domain::domains::authentication::device_trust::TrustWindow;
use ianua_domain::domains::authentication::ldap_certificate::CertificateValidity;
use ianua_domain::domains::authentication::mfa::enrollment::LockoutPolicy;
use ianua_domain::domains::authentication::risk_engine::pressure::FailureThreshold;
use ianua_domain::domains::identity::privacy::erasure::GracePeriod;
use ianua_domain::domains::oauth::clients::lifetimes::{RefreshLifetimes, TokenTerms};
use ianua_domain::domains::oauth::grants::device_authorization::PollInterval;
use ianua_domain::domains::tenant::compliance_limits::ComplianceLimits;
use ianua_domain::domains::tenant::custom_domains::registered_domain::ClaimLifetimes;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::types::{Lifetime, Seconds};

use crate::config::Config;
use crate::config::deployment::Deployment;
use crate::config::serving::agents::AgentsConfig;
use crate::config::serving::sign_in::{MfaConfig, TokenConfig};

const DAY: u64 = 86_400;

/// The settings the use cases are built with, as `config` holds them.
///
/// # Errors
///
/// [`ConfigError::Rejected`] naming the setting whose value the type it is
/// read into refuses.
pub(crate) fn settings(config: &Config) -> Read<Settings> {
    Ok(Settings {
        domain_limits: DomainLimits::default(),
        tunables: tunables(config)?,
        app_base_url: config.deployment.app_base_url.clone(),
        upstream_networks: config.http.upstream_networks.clone(),
        compliance_limits: ComplianceLimits::default(),
        enrollment: enrollment(&config.deployment.deployment),
        cloud_console_template: config.cloud.console_template.clone(),
        device_verification_uri: config.deployment.device_verification_uri.clone(),
        agent_token_audience: config.agents.token_audience.clone(),
        base_domain: config.deployment.base_domain.clone(),
        platform_addressing: config.deployment.platform_addressing,
        platform_hosts: config.deployment.platform_hosts.clone(),
        custom_domains: custom_domains(config)?,
        own_images: config.sandboxes.own_images,
    })
}

/// Strangers may sign up on the hosted service alone.
fn enrollment(deployment: &Deployment) -> Enrollment {
    match deployment {
        Deployment::Cloud => Enrollment::Open,
        Deployment::SelfHosted => Enrollment::Closed,
    }
}

/// What the deployment offers tenants' own domains.
fn custom_domains(config: &Config) -> Read<CustomDomainSettings> {
    let domains = &config.domains;
    Ok(CustomDomainSettings {
        nameservers: domains.nameservers.clone(),
        proxy_address: domains.proxy_address.clone(),
        trusted: config.deployment.trusted_domains.clone(),
        claim_lifetimes: ClaimLifetimes {
            unproved: lifetime("DOMAIN_UNPROVED_CLAIM_TTL_DAYS", domains.unproved_claim_ttl)?,
            failed_grace: lifetime("DOMAIN_FAILED_CLAIM_GRACE_DAYS", domains.failed_claim_grace)?,
        },
    })
}

/// Every lifetime, limit and window the use cases are built with.
fn tunables(config: &Config) -> Read<Tunables> {
    let erasure_days = days("PRIVACY_ERASURE_GRACE_DAYS", config.worker.erasure_grace)?;
    configured_tunables(config, erasure_days)
}

/// Converts each configured limit in field order after the erasure-day count is checked.
/// This exhaustive initializer keeps the public tunables' settings and refusal names together.
#[allow(clippy::too_many_lines)]
fn configured_tunables(config: &Config, erasure_days: u32) -> Read<Tunables> {
    let (links, sign_in, agents) = (&config.mail.links, &config.sign_in, &config.agents);
    Ok(Tunables {
        agent_credential_ttl: Seconds::new(count(
            "AGENT_CREDENTIAL_TTL_SECONDS",
            agents.lifetimes.bootstrap_credential.as_secs(),
        )?),
        org_invitation_lifetime: lifetime("ORG_INVITATION_TTL_SECONDS", links.org_invitation)?,
        org_verification_lifetime: lifetime(
            "EMAIL_ORG_VERIFICATION_TTL_SECONDS",
            links.org_verification,
        )?,
        jwks_grace: lifetime("JWKS_ROTATION_GRACE_SECONDS", sign_in.tokens.jwks_grace)?,
        verification_lifetime: lifetime("EMAIL_VERIFICATION_TTL_SECONDS", links.verification)?,
        email_change_lifetime: lifetime("EMAIL_CHANGE_TTL_SECONDS", links.email_change)?,
        operator_key_lifetime: lifetime("OPERATOR_KEY_TTL_SECONDS", sign_in.operator_key_ttl)?,
        invitation_lifetime: lifetime("INVITATION_TTL_SECONDS", links.invitation)?,
        erasure_grace: GracePeriod::days(erasure_days)
            .map_err(|cause| ConfigError::rejected("PRIVACY_ERASURE_GRACE_DAYS", cause))?,
        mfa_lockout: lockout(&sign_in.mfa)?,
        sent_code: SentCodePolicy {
            lifetime: lifetime("MFA_SENT_CODE_TTL_SECONDS", sign_in.mfa.sent_code_ttl)?,
            resend_after: span("MFA_SENT_CODE_RESEND_SECONDS", sign_in.mfa.sent_code_resend)?,
        },
        resend_cooldown: ResendCooldown::new(span(
            "MAIL_RESEND_COOLDOWN_SECONDS",
            config.mail.resend_cooldown,
        )?),
        password_reset_ttl: lifetime("EMAIL_PASSWORD_RESET_TTL_SECONDS", links.password_reset)?,
        magic_link_ttl: lifetime("EMAIL_MAGIC_LINK_TTL_SECONDS", links.magic_link)?,
        sign_in_confirmation_ttl: lifetime(
            "AUTH_SIGN_IN_CONFIRMATION_TTL_SECONDS",
            sign_in.sign_in_confirmation_ttl,
        )?,
        breach_policy: sign_in.breach_policy,
        device_trust: TrustWindow::days(sign_in.device_trust_days)
            .map_err(|cause| ConfigError::rejected("AUTH_DEVICE_TRUST_DAYS", cause))?,
        unnamed_org_challenge_threshold: FailureThreshold::new(
            config.limits.unnamed_org_failure_threshold,
        )
        .map_err(|cause| ConfigError::rejected("SIGN_IN_FAILURE_THRESHOLD", cause))?,
        mfa_issuer: sign_in.mfa.issuer.clone(),
        password_history_count: sign_in.password_history_count,
        password_min_age_seconds: whole_seconds(
            "AUTH_PASSWORD_MIN_AGE_SECONDS",
            sign_in.password_min_age,
        )?,
        break_glass_max_seconds: whole_seconds(
            "AUTH_BREAK_GLASS_MAX_SECONDS",
            sign_in.break_glass_max,
        )?,
        max_trusted_devices_per_user: sign_in.max_trusted_devices_per_user,
        max_passkeys_per_user: sign_in.max_passkeys_per_user,
        passkey_ceremony_ttl: lifetime(
            "AUTH_PASSKEY_CEREMONY_TTL_SECONDS",
            sign_in.passkey_ceremony_ttl,
        )?,
        ldap_certificate_validity: certificate_validity(config)?,
        sign_in_code_ttl: lifetime("AUTH_SIGN_IN_CODE_TTL_SECONDS", sign_in.sign_in_code_ttl)?,
        app_sign_in: app_sign_in(config)?,
        token_terms: token_terms(&sign_in.tokens)?,
        device_code: device_code(&sign_in.tokens)?,
        credential_lifetimes: credential_lifetimes(agents)?,
        approval_limits: ApprovalLimits {
            max_ttl: span(
                "AGENT_APPROVAL_MAX_TTL_SECONDS",
                agents.lifetimes.approval_max,
            )?,
            per_person_per_hour: agents.approvals_per_hour,
        },
        run_steps: StepLimits {
            default: agents.run_default_steps,
            max: agents.run_max_steps,
        },
        run_approval_ttl: span(
            "AGENT_RUN_APPROVAL_TTL_SECONDS",
            agents.lifetimes.run_approval,
        )?,
        approval_facts_window: span(
            "AGENT_APPROVAL_FACTS_WINDOW_HOURS",
            agents.lifetimes.approval_facts_window,
        )?,
        gate_policy: GatePolicy {
            decision_window: Seconds::new(count(
                "AGENT_APPROVAL_DECISION_WINDOW_SECONDS",
                agents.lifetimes.approval_decision_window.as_secs(),
            )?),
            max_open_per_delegation: agents.approval_max_open_per_delegation,
        },
        task_token_max_ttl: lifetime(
            "AGENT_TASK_TOKEN_MAX_TTL_SECONDS",
            agents.lifetimes.task_token_max,
        )?,
        attestation_challenge_ttl: lifetime(
            "AGENT_ATTESTATION_CHALLENGE_TTL_SECONDS",
            agents.lifetimes.attestation_challenge,
        )?,
        certificate_attempts: config.worker.jobs.max_attempts.get(),
        audit_export_limits: ExportLimits {
            pending_per_log: config.limits.audit_exports_pending_per_log,
        },
        scim_group_member_cap: MemberCap::new(config.limits.scim_group_member_cap)
            .map_err(|cause| ConfigError::rejected("SCIM_GROUP_MEMBER_CAP", cause))?,
    })
}

/// Wrong second-factor codes tolerated, and how long a lock lasts.
fn lockout(mfa: &MfaConfig) -> Read<LockoutPolicy> {
    LockoutPolicy::new(mfa.max_attempts, span("MFA_LOCKOUT_SECONDS", mfa.lockout)?)
        .map_err(|cause| ConfigError::rejected("MFA_MAX_ATTEMPTS", cause))
}

/// The short-lived steps of an app sign-in.
fn app_sign_in(config: &Config) -> Read<AppSignInLifetimes> {
    let sign_in = &config.sign_in;
    let attempts = u8::try_from(sign_in.mfa.max_attempts)
        .ok()
        .and_then(NonZeroU8::new)
        .ok_or_else(|| ConfigError::invalid("MFA_MAX_ATTEMPTS", "must be from 1 to 255"))?;
    Ok(AppSignInLifetimes {
        mfa_challenge: lifetime("MFA_CHALLENGE_TTL_SECONDS", sign_in.mfa.challenge_ttl)?,
        mfa_challenge_attempts: attempts,
        handoff: lifetime("AUTH_HANDOFF_CODE_TTL_SECONDS", sign_in.handoff_code_ttl)?,
        access: lifetime(
            "AUTH_APP_SIGN_IN_ACCESS_TTL_SECONDS",
            sign_in.app_sign_in_access_ttl,
        )?,
    })
}

/// How long the platform's OAuth tokens last.
fn token_terms(tokens: &TokenConfig) -> Read<TokenTerms> {
    let refresh = RefreshLifetimes::new(
        lifetime("OAUTH_REFRESH_TOKEN_IDLE_SECONDS", tokens.refresh_idle)?,
        lifetime("OAUTH_REFRESH_TOKEN_FAMILY_SECONDS", tokens.refresh_family)?,
    )
    .map_err(|cause| ConfigError::rejected("OAUTH_REFRESH_TOKEN_FAMILY_SECONDS", cause))?;
    TokenTerms::new(
        lifetime("OAUTH_ACCESS_TOKEN_TTL_SECONDS", tokens.access)?,
        lifetime("OAUTH_ID_TOKEN_TTL_SECONDS", tokens.id_token)?,
        refresh,
    )
    .map_err(|cause| ConfigError::rejected("OAUTH_ACCESS_TOKEN_TTL_SECONDS", cause))
}

/// The device flow's code lifetime and poll interval.
fn device_code(tokens: &TokenConfig) -> Read<DeviceCodeTiming> {
    let name = "OAUTH_DEVICE_POLL_INTERVAL_SECONDS";
    let seconds = u16::try_from(tokens.device_poll_interval.as_secs())
        .map_err(|cause| ConfigError::rejected(name, cause))?;
    Ok(DeviceCodeTiming {
        lifetime: lifetime("OAUTH_DEVICE_CODE_TTL_SECONDS", tokens.device_code)?,
        poll_interval: PollInterval::seconds(seconds)
            .map_err(|cause| ConfigError::rejected(name, cause))?,
    })
}

/// How long agent credentials live.
fn credential_lifetimes(agents: &AgentsConfig) -> Read<CredentialLifetimes> {
    let lifetimes = &agents.lifetimes;
    CredentialLifetimes::new(
        span(
            "AGENT_CREDENTIAL_DEFAULT_TTL_DAYS",
            lifetimes.credential_default,
        )?,
        span("AGENT_CREDENTIAL_MAX_TTL_DAYS", lifetimes.credential_max)?,
        span(
            "AGENT_CREDENTIAL_ROTATION_GRACE_SECONDS",
            lifetimes.credential_rotation_grace,
        )?,
    )
    .map_err(|cause| ConfigError::rejected("AGENT_CREDENTIAL_DEFAULT_TTL_DAYS", cause))
}

/// How long an LDAP client certificate is valid.
fn certificate_validity(config: &Config) -> Read<CertificateValidity> {
    let name = "LDAP_CLIENT_CERT_VALIDITY_DAYS";
    let days = u16::try_from(config.directory.client_cert_validity.as_secs() / DAY)
        .map_err(|cause| ConfigError::rejected(name, cause))?;
    CertificateValidity::days(days).map_err(|cause| ConfigError::rejected(name, cause))
}

/// `duration` as the lifetime `name` sets.
fn lifetime(name: &str, duration: Duration) -> Read<Lifetime> {
    Lifetime::new(span(name, duration)?).map_err(|cause| ConfigError::rejected(name, cause))
}

/// `duration` as the span of time the domain counts in, for `name`.
fn span(name: &str, duration: Duration) -> Read<time::Duration> {
    time::Duration::try_from(duration).map_err(|cause| ConfigError::rejected(name, cause))
}

/// `duration` in whole seconds, for `name`.
fn whole_seconds(name: &str, duration: Duration) -> Read<i64> {
    i64::try_from(duration.as_secs()).map_err(|cause| ConfigError::rejected(name, cause))
}

/// `duration` in whole days, for `name`.
fn days(name: &str, duration: Duration) -> Read<u32> {
    count(name, duration.as_secs() / DAY)
}

/// `value` as the count `name` holds.
pub(crate) fn count(name: &str, value: u64) -> Read<u32> {
    u32::try_from(value).map_err(|cause| ConfigError::rejected(name, cause))
}
