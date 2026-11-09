//! Authentication events grouped by concern.
//!
//! Each submodule holds the events of one area of authentication. Every
//! event is a `TenantEventBody`:
//! the aggregate or sign-in that raises it is kept per tenant, and the
//! tenant it was saved for is stamped on it when it is taken.

pub mod app_session;
pub mod break_glass;
pub mod credential;
pub mod device;
pub mod directory;
pub mod login;
pub mod mfa;
pub mod pressure;
pub mod recovery;
pub mod service_account;
pub mod session;

use crate::domains::authentication::keeper::ChangedBy;
use crate::shared::events::data::{RefKind, Reference};
use crate::types::UserId;

/// The account a change to its ways in was made to, as its record names it
/// when someone other than its holder made the change: an admin, or the
/// platform. `None` when the holder made it, since the record's actor
/// already names them.
///
/// The change knows the account by its id only, so the id labels it too.
fn changed_account(by: ChangedBy<UserId>) -> Option<Reference> {
    let ChangedBy::SomeoneElse(user) = by else {
        return None;
    };
    Some(Reference::new(
        RefKind::USER,
        user.to_string(),
        user.to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;

    use crate::domains::authentication::credentials::passkey::AuthenticatorType;
    use crate::domains::authentication::directory_service::account::ServiceAccountStatus;
    use crate::domains::authentication::directory_service::scope::DirectoryAccess;
    use crate::domains::authentication::events::app_session::*;
    use crate::domains::authentication::events::break_glass::*;
    use crate::domains::authentication::events::credential::*;
    use crate::domains::authentication::events::device::*;
    use crate::domains::authentication::events::directory::*;
    use crate::domains::authentication::events::login::*;
    use crate::domains::authentication::events::mfa::*;
    use crate::domains::authentication::events::pressure::*;
    use crate::domains::authentication::events::recovery::*;
    use crate::domains::authentication::events::service_account::*;
    use crate::domains::authentication::events::session::*;
    use crate::domains::authentication::keeper::ChangedBy;
    use crate::domains::authentication::methods::AuthMethod;
    use crate::domains::authentication::mfa::enrollment::MfaMethod;
    use crate::domains::authentication::recovery::reset::ResetInitiator;
    use crate::domains::authentication::risk_engine::assurance::AssuranceLevel;
    use crate::domains::authentication::risk_engine::origin::AttemptOrigin;
    use crate::shared::events::raised::TenantEventBody;
    use crate::types::{
        DirectoryServiceAccountId, DomainName, EventLabel, Fact, IpAddress, Label,
        LdapCertificateId, PasskeyCredentialId, ServiceId, SessionId, Text, UserId,
    };

    fn now() -> OffsetDateTime {
        crate::shared::clock::now()
    }

    fn text(value: &str) -> Text {
        Text::new("reason", value).unwrap()
    }

    /// Every authentication event, across all the submodules.
    ///
    /// They are listed in one place so no event misses the checks below.
    /// The exhaustive inventory stays inline so convention checks find every event.
    #[allow(clippy::too_many_lines)]
    fn every_event() -> Vec<Box<dyn TenantEventBody>> {
        let user_id = UserId::new();
        let session_id = SessionId::new();
        let ip = IpAddress::new("10.0.0.1").unwrap();

        vec![
            Box::new(AppSessionHandedOver {
                session_id,
                service_id: ServiceId::new(),
                service_name: Label::new("name", "files-api").unwrap(),
                host: DomainName::new("api.example.com").unwrap(),
                occurred_at: now(),
            }),
            Box::new(AppTokenIssued {
                session_id,
                service_id: ServiceId::new(),
                service_name: Label::new("name", "files-api").unwrap(),
                expires_at: now(),
                occurred_at: now(),
            }),
            Box::new(BreakGlassGranted {
                user_id,
                user_label: EventLabel::of("ada@acme.com"),
                reason: text("the console is down"),
                expires_at: now(),
                occurred_at: now(),
            }),
            Box::new(BreakGlassRevoked {
                user_id,
                user_label: EventLabel::of("ada@acme.com"),
                occurred_at: now(),
            }),
            Box::new(PasswordChanged { occurred_at: now() }),
            Box::new(PasskeyRegistered {
                credential_id: crate::types::PasskeyCredentialId::new(vec![1]).unwrap(),
                authenticator: AuthenticatorType::Platform,
                occurred_at: now(),
            }),
            Box::new(PasskeyRemoved {
                credential_id: crate::types::PasskeyCredentialId::new(vec![1]).unwrap(),
                authenticator: AuthenticatorType::CrossPlatform,
                by: ChangedBy::SomeoneElse(user_id),
                occurred_at: now(),
            }),
            Box::new(RecoveryCodesGenerated {
                count: 10,
                occurred_at: now(),
            }),
            Box::new(RecoveryCodeUsed {
                remaining: 9,
                occurred_at: now(),
            }),
            Box::new(PasswordResetRequested {
                user_id,
                user_label: EventLabel::of("ada@acme.com"),
                initiator: ResetInitiator::User,
                occurred_at: now(),
            }),
            Box::new(PasswordResetCompleted { occurred_at: now() }),
            Box::new(PasswordBreachDetected {
                user_id,
                user_label: EventLabel::of("ada@acme.com"),
                occurrence_count: 3,
                occurred_at: now(),
            }),
            Box::new(RiskySignIn {
                user_id,
                user_label: EventLabel::of("ada@acme.com"),
                country: Fact::Unknown,
                sign: RiskSign::FastTravel,
                occurred_at: now(),
            }),
            Box::new(DeviceTrusted {
                device_id: crate::types::TrustedDeviceId::new(),
                occurred_at: now(),
            }),
            Box::new(DeviceRevoked {
                device_id: crate::types::TrustedDeviceId::new(),
                by: ChangedBy::Holder,
                occurred_at: now(),
            }),
            Box::new(MfaEnrolled { occurred_at: now() }),
            Box::new(MfaVerified {
                session_id,
                assurance: AssuranceLevel::Aal2,
                occurred_at: now(),
            }),
            Box::new(MfaUnenrolled {
                by: ChangedBy::Holder,
                occurred_at: now(),
            }),
            Box::new(MfaCodeSent {
                method: MfaMethod::SmsCode,
                expires_at: now(),
                occurred_at: now(),
            }),
            Box::new(FactorsReset {
                user_id,
                user_label: EventLabel::of("ada@acme.com"),
                enrollments_turned_off: 1,
                passkeys_removed: 2,
                occurred_at: now(),
            }),
            Box::new(DirectoryServiceAccountCreated {
                account_id: DirectoryServiceAccountId::new(),
                name: EventLabel::of("jira"),
                access: DirectoryAccess::ReadOnly,
                occurred_at: now(),
            }),
            Box::new(DirectoryServiceAccountDeleted {
                account_id: DirectoryServiceAccountId::new(),
                name: EventLabel::of("jira"),
                occurred_at: now(),
            }),
            Box::new(DirectoryServiceSearchPerformed {
                account_id: DirectoryServiceAccountId::new(),
                name: EventLabel::of("jira"),
                users_returned: 3,
                groups_returned: 1,
                occurred_at: now(),
            }),
            Box::new(DirectoryServiceSearchDenied {
                account_id: DirectoryServiceAccountId::new(),
                name: EventLabel::of("jira"),
                occurred_at: now(),
            }),
            Box::new(DirectoryServiceAccountSecretRotated {
                account_id: DirectoryServiceAccountId::new(),
                name: EventLabel::of("jira"),
                occurred_at: now(),
            }),
            Box::new(DirectoryServiceAccountScopeChanged {
                account_id: DirectoryServiceAccountId::new(),
                name: EventLabel::of("jira"),
                access: DirectoryAccess::ReadOnly,
                base_dns: 2,
                occurred_at: now(),
            }),
            Box::new(DirectoryServiceAccountStatusChanged {
                account_id: DirectoryServiceAccountId::new(),
                name: EventLabel::of("jira"),
                status: ServiceAccountStatus::Disabled,
                occurred_at: now(),
            }),
            Box::new(DirectoryServiceBound {
                account_id: DirectoryServiceAccountId::new(),
                name: EventLabel::of("jira"),
                occurred_at: now(),
            }),
            Box::new(LoginSucceeded {
                session_id,
                auth_method: AuthMethod::Password,
                ip_address: Fact::Known(ip.clone()),
                auth_duration_ms: Fact::Known(42),
                occurred_at: now(),
            }),
            Box::new(LoginFailed {
                email: crate::types::UntrustedText::record("ada@acme.com"),
                reason: LoginFailureReason::BadPassword,
                ip_address: Fact::Known(ip.clone()),
                occurred_at: now(),
            }),
            Box::new(AccountLockedOut {
                user_id: LockedAddress::Account(user_id),
                user_label: EventLabel::of("ada@acme.com"),
                failed_attempts: 5,
                locked_until: now(),
                origin: AttemptOrigin::of(Fact::Known(&ip)),
                ip_address: Fact::Known(ip.clone()),
                occurred_at: now(),
            }),
            Box::new(AccountUnderAttack {
                user_id: LockedAddress::Account(user_id),
                user_label: EventLabel::of("ada@acme.com"),
                networks: 10,
                until: now(),
                occurred_at: now(),
            }),
            Box::new(DirectoryBindSucceeded {
                user_id,
                user_label: EventLabel::of("ada@acme.com"),
                occurred_at: now(),
            }),
            Box::new(DirectorySearchPerformed {
                user_id,
                user_label: EventLabel::of("ada@acme.com"),
                users_returned: 12,
                groups_returned: 3,
                occurred_at: now(),
            }),
            Box::new(DirectorySearchDenied {
                user_id,
                user_label: EventLabel::of("ada@acme.com"),
                occurred_at: now(),
            }),
            Box::new(LdapCertificateIssued {
                user_id,
                user_label: EventLabel::of("ada@acme.com"),
                certificate_id: LdapCertificateId::new(),
                device_label: EventLabel::of("ada's laptop"),
                expires_at: now(),
                occurred_at: now(),
            }),
            Box::new(LdapCertificateRevoked {
                user_id,
                user_label: EventLabel::of("ada@acme.com"),
                certificate_id: LdapCertificateId::new(),
                occurred_at: now(),
            }),
            Box::new(SessionRevoked {
                session_id,
                user_id,
                user_label: Some(EventLabel::of("ada@acme.com")),
                reason: RevocationReason::TokenTheft,
                occurred_at: now(),
            }),
            Box::new(SessionSuspended {
                session_id,
                user_id,
                user_label: EventLabel::of("ada@acme.com"),
                reason: SuspensionReason::BindingViolation,
                occurred_at: now(),
            }),
            Box::new(SessionResumed {
                session_id,
                occurred_at: now(),
            }),
            Box::new(TokenRefreshed {
                session_id,
                new_session_id: SessionId::new(),
                occurred_at: now(),
            }),
            Box::new(MagicLinkRequested {
                user_id,
                occurred_at: now(),
            }),
            Box::new(MfaEnrollmentStarted {
                user_id,
                occurred_at: now(),
            }),
            Box::new(MfaFailed {
                factor: FailedFactor::Totp,
                locked: FactorLock::StillOpen,
                occurred_at: now(),
            }),
            Box::new(PasskeyChallengeIssued { occurred_at: now() }),
            Box::new(PasskeyRegistrationStarted {
                user_id,
                occurred_at: now(),
            }),
            Box::new(PasskeyRenamed {
                user_id,
                credential_id: PasskeyCredentialId::new(vec![0x0a, 0xff]).unwrap(),
                occurred_at: now(),
            }),
            Box::new(PasskeySignInStarted {
                user_id,
                occurred_at: now(),
            }),
            Box::new(SignInCheckUnavailable {
                user_id,
                user_label: EventLabel::of("alice@acme.com"),
                check: SignInCheck::Breach,
                occurred_at: now(),
            }),
            Box::new(SignInCodeExchanged {
                user_id,
                occurred_at: now(),
            }),
            Box::new(SignInPressureRose {
                failures: 250,
                threshold: 200,
                occurred_at: now(),
            }),
            Box::new(SignInPressureEased {
                threshold: 200,
                occurred_at: now(),
            }),
            Box::new(SingleSignOnStarted {
                connection: EventLabel::of("Okta"),
                occurred_at: now(),
            }),
        ]
    }

    /// The events whose envelope says everything, so their payload is empty.
    ///
    /// Who changed their password, completed a reset, or enrolled or
    /// unenrolled a factor is on the envelope as the actor and the tenant.
    /// Naming the user again in the payload would repeat it. A discoverable
    /// passkey challenge goes out before anyone is known, so it has nobody to
    /// name.
    const WITHOUT_PAYLOAD: [&str; 5] = [
        "authentication.password_changed",
        "authentication.password_reset_completed",
        "authentication.mfa_enrolled",
        "authentication.mfa_unenrolled",
        "authentication.passkey_challenge_issued",
    ];

    /// Every authentication event has a payload, except the five listed in
    /// `WITHOUT_PAYLOAD`. Those five must stay empty, so one that grows a
    /// field is noticed here.
    #[test]
    fn every_event_carries_a_payload_unless_its_subject_is_the_whole_story() {
        for event in every_event() {
            let name = event.event_type().as_str().to_owned();
            let payload = event.payload();

            if WITHOUT_PAYLOAD.contains(&name.as_str()) {
                assert!(payload.is_empty(), "{name} grew a payload");
                continue;
            }

            assert!(!payload.is_empty(), "{name} has an empty payload");
        }
    }

    /// Every event type starts with `authentication.` and no two events share
    /// a type. Two events under one name would be filed as the same thing.
    #[test]
    fn every_event_names_itself_exactly_once() {
        let mut seen = std::collections::HashSet::new();

        for event in every_event() {
            let name = event.event_type().as_str().to_owned();
            assert!(
                name.starts_with("authentication."),
                "unexpected type {name}"
            );
            assert!(seen.insert(name.clone()), "{name} listed twice");
        }
    }
}
