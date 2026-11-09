//! The operator's tuning, resolved into the values the use cases take.
//!
//! Filled by the composition root from its settings, so every lifetime,
//! limit and window a use case enforces comes from configuration rather than
//! from a number written into the wiring.

use ianua_app::email::ResendCooldown;
use ianua_app::use_cases::agents::approvals::{ApprovalLimits, GatePolicy};
use ianua_app::use_cases::agents::runs::StepLimits;
use ianua_app::use_cases::authentication::app_sign_in::AppSignInLifetimes;
use ianua_app::use_cases::oauth::flows::DeviceCodeTiming;
use ianua_domain::domains::agents::identity::credential::CredentialLifetimes;
use ianua_domain::domains::authentication::mfa::enrollment::LockoutPolicy;

/// Every tunable value the use cases are built with.
#[derive(Debug, Clone)]
pub struct Tunables {
    /// Lifetime of a credential an agent bootstraps from an attestation.
    pub agent_credential_ttl: ianua_domain::types::Seconds,
    /// How long an organization invitation link lives.
    pub org_invitation_lifetime: ianua_domain::types::Lifetime,
    /// How long an organization member's address verification link lives.
    pub org_verification_lifetime: ianua_domain::types::Lifetime,
    /// How long a rotated signing key stays in the JWKS document.
    pub jwks_grace: ianua_domain::types::Lifetime,
    /// How long an address verification link lives.
    pub verification_lifetime: ianua_domain::types::Lifetime,
    /// How long an email change confirmation link lives.
    pub email_change_lifetime: ianua_domain::types::Lifetime,
    /// How long the key an operator's password sign-in makes works.
    pub operator_key_lifetime: ianua_domain::types::Lifetime,
    /// How long an invitation link lives, at most 30 days.
    pub invitation_lifetime: ianua_domain::types::Lifetime,
    /// How long a person has to cancel an erasure.
    pub erasure_grace: ianua_domain::domains::identity::privacy::erasure::GracePeriod,
    /// Wrong second-factor codes tolerated, and how long a lock lasts.
    pub mfa_lockout: LockoutPolicy,
    /// How long a mailed or texted second-factor code works, and how soon
    /// another may be sent.
    pub sent_code: ianua_app::use_cases::authentication::mfa::SentCodePolicy,
    /// The wait before another emailed link may be asked for.
    pub resend_cooldown: ResendCooldown,
    /// How long a password reset link lives.
    pub password_reset_ttl: ianua_domain::types::Lifetime,
    /// How long an emailed sign-in link lives.
    pub magic_link_ttl: ianua_domain::types::Lifetime,
    /// How long a link confirming a sign-in from the mailbox lives.
    pub sign_in_confirmation_ttl: ianua_domain::types::Lifetime,
    /// What a sign-in with a breached password must do.
    pub breach_policy: ianua_domain::domains::authentication::credentials::breach::BreachPolicy,
    /// How long a trusted device stays trusted.
    pub device_trust: ianua_domain::domains::authentication::device_trust::TrustWindow,
    /// The failures, across every organization sign-in that names no
    /// organization, that put those sign-ins under high pressure.
    pub unnamed_org_challenge_threshold:
        ianua_domain::domains::authentication::risk_engine::pressure::FailureThreshold,
    /// The issuer an authenticator app shows beside a code.
    pub mfa_issuer: ianua_domain::types::Label,
    /// Earlier passwords a new one may not repeat.
    pub password_history_count: u32,
    /// Least time between two password changes, in seconds.
    pub password_min_age_seconds: i64,
    /// Longest break-glass grant, in seconds.
    pub break_glass_max_seconds: i64,
    /// Devices one person may trust.
    pub max_trusted_devices_per_user: usize,
    /// Passkeys one person may register.
    pub max_passkeys_per_user: usize,
    /// How long a passkey ceremony stays answerable.
    pub passkey_ceremony_ttl: ianua_domain::types::Lifetime,
    /// How long an LDAP client certificate is valid.
    pub ldap_certificate_validity:
        ianua_domain::domains::authentication::ldap_certificate::CertificateValidity,
    /// Lifetime of the one-time code an identity provider sign-in hands back.
    pub sign_in_code_ttl: ianua_domain::types::Lifetime,
    /// The short-lived steps of an app sign-in.
    pub app_sign_in: AppSignInLifetimes,
    /// How long the platform's OAuth tokens last, for every client without
    /// terms of its own: access, ID and refresh tokens.
    pub token_terms: ianua_domain::domains::oauth::clients::lifetimes::TokenTerms,
    /// Device authorization code lifetime and poll interval.
    pub device_code: DeviceCodeTiming,
    /// How long agent credentials live.
    pub credential_lifetimes: CredentialLifetimes,
    /// How long approvals stay open and how many may be asked for and given.
    pub approval_limits: ApprovalLimits,
    /// How many loop iterations a run gets.
    pub run_steps: StepLimits,
    /// How long a run-raised approval request stays decidable.
    pub run_approval_ttl: time::Duration,
    /// How far back the facts shown to an approver look.
    pub approval_facts_window: time::Duration,
    /// How long a person has to decide an action the gateway paused, and
    /// how many such requests one delegation may have open.
    pub gate_policy: GatePolicy,
    /// Longest lifetime of a task token an agent issues itself.
    pub task_token_max_ttl: ianua_domain::types::Lifetime,
    /// How long an agent has to answer an attestation challenge.
    pub attestation_challenge_ttl: ianua_domain::types::Lifetime,
    /// Tries a certificate request gets.
    pub certificate_attempts: u32,
    /// How many exports one audit log may have waiting for the worker.
    pub audit_export_limits: ianua_app::use_cases::audit::exports::ExportLimits,
    /// The most members one SCIM group write may name.
    pub scim_group_member_cap: ianua_app::use_cases::scim::groups::MemberCap,
}
