//! What the events of organizations, operators, tenants and their keys
//! and looks touch.

use ianua_domain::types::event_type::{
    BrandingEvent, CryptoEvent, OperatorEvent, OrganizationEvent, TenantEvent,
};

use crate::cache::stores::touched::{
    ASSERTION_KEYS, CALLERS, EVERYTHING, HOLDINGS, NOTHING, SIGNING_KEYS,
};
use crate::cache::stores::versions::Cached;

/// An organization's members and their sessions and keys: every end, move
/// or raise of a session, every revoked key, a sign-in (which ends the
/// member's earlier sessions), and every change to a member's role,
/// standing or erasure or to the organization's standing that ends their
/// credentials, drops the
/// callers, the organization's own and its tenants' credentials its member
/// made. A member's tenant grants are read afresh with every holdings
/// read, so a change to them touches no holdings.
/// This single exhaustive mapping keeps new events from silently missing cache invalidation.
#[allow(clippy::too_many_lines)]
pub(super) fn organization(event: OrganizationEvent) -> &'static [Cached] {
    match event {
        OrganizationEvent::StatusChanged
        | OrganizationEvent::TenantSwitched
        | OrganizationEvent::OrgUserDeleted
        | OrganizationEvent::OrgUserStatusChanged
        | OrganizationEvent::OrgUserTenantAccessRevoked
        | OrganizationEvent::OrgUserPasswordReset
        | OrganizationEvent::OrgUserPasswordChanged
        | OrganizationEvent::OrgApiKeyRevoked
        | OrganizationEvent::OrgMfaEnrolled
        | OrganizationEvent::OrgDeviceRevoked
        | OrganizationEvent::OrgMfaVerified
        | OrganizationEvent::OrgMfaUnenrolled
        | OrganizationEvent::OrgMemberMfaReset
        | OrganizationEvent::OrgPasskeyRemoved
        | OrganizationEvent::OrgSessionRevoked
        | OrganizationEvent::OrgSessionMoved
        | OrganizationEvent::OrgLoginSucceeded
        | OrganizationEvent::OrgUserRoleChanged
        | OrganizationEvent::OrgUserErasureRequested
        | OrganizationEvent::OrgUserErasureStarted
        | OrganizationEvent::OrgUserErasureCompleted => CALLERS,
        OrganizationEvent::Created
        | OrganizationEvent::Renamed
        | OrganizationEvent::TenantCreated
        | OrganizationEvent::ContactEmailChanged
        | OrganizationEvent::DisplayNameChanged
        | OrganizationEvent::IdentityLinked
        | OrganizationEvent::IdentityUnlinked
        | OrganizationEvent::PlanChanged
        | OrganizationEvent::AuthConfigUpdated
        | OrganizationEvent::OrgUserCreated
        | OrganizationEvent::OrgUserInvited
        | OrganizationEvent::OrgUserInvitationAccepted
        | OrganizationEvent::OrgUserInvitationRevoked
        | OrganizationEvent::OrgUserInvitationDeclined
        | OrganizationEvent::OrgUserInvitationExpired
        | OrganizationEvent::OrgUserInvitationResent
        | OrganizationEvent::OrgUserReopened
        | OrganizationEvent::OwnershipTransferred
        | OrganizationEvent::SubscriptionStarted
        | OrganizationEvent::SubscriptionChanged
        | OrganizationEvent::TrialEnded
        | OrganizationEvent::PaymentMethodChanged
        | OrganizationEvent::PaymentFailed
        | OrganizationEvent::PaymentSettled
        | OrganizationEvent::CheckoutStarted
        | OrganizationEvent::BrandingUpdated
        | OrganizationEvent::BrandingReset
        | OrganizationEvent::OrgUserTenantAccessGranted
        | OrganizationEvent::OrgUserPasswordResetRequested
        | OrganizationEvent::OrgUserEmailChanged
        | OrganizationEvent::OrgUserEmailVerified
        | OrganizationEvent::OrgUserDisplayNameChanged
        | OrganizationEvent::OrgUserPreferencesUpdated
        | OrganizationEvent::OrgApiKeyCreated
        | OrganizationEvent::OrgDeviceTrusted
        | OrganizationEvent::OrgMfaEnrollmentStarted
        | OrganizationEvent::OrgRecoveryCodesGenerated
        | OrganizationEvent::OrgIdentityProviderAdded
        | OrganizationEvent::OrgIdentityProviderChanged
        | OrganizationEvent::OrgIdentityProviderRemoved
        | OrganizationEvent::OrgPasskeyRegistrationStarted
        | OrganizationEvent::OrgPasskeyRegistered
        | OrganizationEvent::OrgPasskeyRenamed
        | OrganizationEvent::OrgLoginFailed
        | OrganizationEvent::OrgAccountUnderAttack
        | OrganizationEvent::OrgPasskeySignInStarted
        | OrganizationEvent::OrgPasskeyChallengeIssued
        | OrganizationEvent::OrgMagicLinkRequested
        | OrganizationEvent::OrgSsoSignInStarted
        | OrganizationEvent::CloudConnectionStarted
        | OrganizationEvent::CloudCredentialAttached
        | OrganizationEvent::CloudAccountVerified
        | OrganizationEvent::CloudAccountDisconnected
        | OrganizationEvent::OrgVerificationEmailSent
        | OrganizationEvent::OrgWelcomeEmailSent
        | OrganizationEvent::OrgUserConsentGranted
        | OrganizationEvent::OrgUserConsentRevoked
        | OrganizationEvent::OrgUserErasureCancelled
        | OrganizationEvent::OrgUserErasureHeld
        | OrganizationEvent::OrgUserErasureReleased
        | OrganizationEvent::OrgUserErasureFailed
        | OrganizationEvent::AuditLogExportRequested
        | OrganizationEvent::AuditLogExportDownloaded => NOTHING,
    }
}

/// Operators: a disabled operator, a revoked key and a revoked
/// impersonation grant stop answering at once.
pub(super) fn operator(event: OperatorEvent) -> &'static [Cached] {
    match event {
        OperatorEvent::OperatorDisabled
        | OperatorEvent::ImpersonationRevoked
        | OperatorEvent::OperatorApiKeyRevoked => CALLERS,
        OperatorEvent::OperatorCreated
        | OperatorEvent::OperatorEnabled
        | OperatorEvent::ImpersonationGranted
        | OperatorEvent::OperatorApiKeyCreated
        | OperatorEvent::OperatorSignInFailed
        | OperatorEvent::AuditLogExportRequested
        | OperatorEvent::AuditLogExportDownloaded
        | OperatorEvent::DeadJobRetried => NOTHING,
    }
}

/// A tenant: its deletion purges its data by plain deletes and drops
/// everything; a change of its standing ends what its credentials may do;
/// a finished clone brings in roles and groups. Its settings, domains,
/// certificates and audit streams are read apart from every cache.
/// This single exhaustive mapping keeps new events from silently missing cache invalidation.
#[allow(clippy::too_many_lines)]
pub(super) fn tenant(event: TenantEvent) -> &'static [Cached] {
    match event {
        TenantEvent::Deleted | TenantEvent::DeletedEarly | TenantEvent::TornDown => EVERYTHING,
        TenantEvent::StatusChanged => CALLERS,
        TenantEvent::CloneCompleted => HOLDINGS,
        TenantEvent::Provisioned
        | TenantEvent::ReadableAddressChanged
        | TenantEvent::Renamed
        | TenantEvent::ContactEmailChanged
        | TenantEvent::TimezoneChanged
        | TenantEvent::LocaleChanged
        | TenantEvent::DomainRegistered
        | TenantEvent::DomainRemoved
        | TenantEvent::DomainVerified
        | TenantEvent::DomainVerificationLost
        | TenantEvent::PrimaryDomainChanged
        | TenantEvent::AuthConfigUpdated
        | TenantEvent::MtlsConfigUpdated
        | TenantEvent::ComplianceChanged
        | TenantEvent::InfraFailed
        | TenantEvent::DomainTlsProvisioned
        | TenantEvent::DomainHandoverOffered
        | TenantEvent::DomainTransferred
        | TenantEvent::DnsRecordSetChanged
        | TenantEvent::DnsRecordSetRemoved
        | TenantEvent::TeardownFailed
        | TenantEvent::AuditChainBroken
        | TenantEvent::DomainTlsRequested
        | TenantEvent::DomainCertificateUploaded
        | TenantEvent::DomainCertificateReplaced
        | TenantEvent::DomainCertificateRemoved
        | TenantEvent::DomainCertificateExpiring
        | TenantEvent::EnvironmentChanged
        | TenantEvent::CloneStarted
        | TenantEvent::CloneFailed
        | TenantEvent::AuditStreamCreated
        | TenantEvent::AuditStreamChanged
        | TenantEvent::AuditStreamPaused
        | TenantEvent::AuditStreamResumed
        | TenantEvent::AuditStreamRemoved
        | TenantEvent::AuditRecordsPurged
        | TenantEvent::AuditLogExportRequested
        | TenantEvent::AuditLogExportDownloaded => NOTHING,
    }
}

/// A tenant's signing keys: every key made, rotated, revoked, promoted or
/// rolled back drops the public halves the gateway checks tokens against.
/// A migration only planned or cancelled has changed no key. Every
/// assertion key made, rotated or retired drops the opened key the gateway
/// signs assertions with.
pub(super) fn crypto(event: CryptoEvent) -> &'static [Cached] {
    match event {
        CryptoEvent::KeyCreated
        | CryptoEvent::KeyRotated
        | CryptoEvent::KeyRevoked
        | CryptoEvent::MigrationStarted
        | CryptoEvent::MigrationPromoted
        | CryptoEvent::MigrationCompleted
        | CryptoEvent::MigrationRolledBack => SIGNING_KEYS,
        CryptoEvent::AssertionKeyCreated
        | CryptoEvent::AssertionKeyRotated
        | CryptoEvent::AssertionKeyRetired => ASSERTION_KEYS,
        CryptoEvent::MigrationPlanned | CryptoEvent::MigrationCancelled => NOTHING,
    }
}

/// A tenant's look and mail provider are read apart from every cache.
pub(super) fn branding(event: BrandingEvent) -> &'static [Cached] {
    match event {
        BrandingEvent::Updated
        | BrandingEvent::MailProviderChanged
        | BrandingEvent::MailProviderTested => NOTHING,
    }
}
