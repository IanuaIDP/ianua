//! What the events of people and their sign-ins touch.

use ianua_domain::types::event_type::{AuthenticationEvent, IdentityEvent};

use crate::cache::stores::touched::{CALLERS, EVERYTHING, HOLDINGS, NOTHING};
use crate::cache::stores::versions::Cached;

/// A user's account: its removal ends their credentials and cascades their
/// assignments away; a lock, a reset, or an erasure asked for or begun ends
/// their sessions; a new account may be given a default role.
/// This single exhaustive mapping keeps new events from silently missing cache invalidation.
#[allow(clippy::too_many_lines)]
pub(super) fn identity(event: IdentityEvent) -> &'static [Cached] {
    match event {
        IdentityEvent::UserDeleted | IdentityEvent::ErasureCompleted => EVERYTHING,
        IdentityEvent::UserStatusChanged
        | IdentityEvent::PasswordReset
        | IdentityEvent::ErasureRequested
        | IdentityEvent::ErasureStarted => CALLERS,
        IdentityEvent::UserRegistered
        | IdentityEvent::InvitationAccepted
        | IdentityEvent::UserImported
        | IdentityEvent::UsersImported => HOLDINGS,
        IdentityEvent::UserInvited
        | IdentityEvent::EmailVerified
        | IdentityEvent::EmailChanged
        | IdentityEvent::ConsentGranted
        | IdentityEvent::ConsentRevoked
        | IdentityEvent::InvitationExpired
        | IdentityEvent::InvitationRevoked
        | IdentityEvent::InvitationDeclined
        | IdentityEvent::InvitationResent
        | IdentityEvent::UserRenamed
        | IdentityEvent::UserPreferencesUpdated
        | IdentityEvent::ErasureCancelled
        | IdentityEvent::ErasureHeld
        | IdentityEvent::ErasureReleased
        | IdentityEvent::ErasureFailed
        | IdentityEvent::MetadataUpdated
        | IdentityEvent::MetadataDeleted
        | IdentityEvent::AttributeDeclared
        | IdentityEvent::AttributeUpdated
        | IdentityEvent::AttributeArchived
        | IdentityEvent::AttributeRestored
        | IdentityEvent::AttributeDeleted
        | IdentityEvent::EmailChangeRequested
        | IdentityEvent::EmailChangeLinkResent
        | IdentityEvent::EmailChangeCancelled
        | IdentityEvent::ManagementEmailChangeRequested
        | IdentityEvent::ManagementEmailChangeLinkResent
        | IdentityEvent::ManagementEmailChangeCancelled
        | IdentityEvent::VerificationEmailSent
        | IdentityEvent::WelcomeEmailSent
        | IdentityEvent::ManagementEmailChangeConfirmed
        | IdentityEvent::UserProfileUpdated
        | IdentityEvent::UserImportStarted
        | IdentityEvent::DataExportRequested
        | IdentityEvent::DataExportReady
        | IdentityEvent::DataExportDownloaded
        | IdentityEvent::DataExportExpired
        | IdentityEvent::SupportImpersonationRequested
        | IdentityEvent::SupportImpersonationStarted
        | IdentityEvent::SupportImpersonationDeclined
        | IdentityEvent::SupportImpersonationEnded => NOTHING,
    }
}

/// A tenant user's sign-ins: every end, suspension, rotation or raise of a
/// session (a recovery code raises one too), and every change of a factor
/// that ends sessions, drops the
/// callers; a break-glass grant changes what its holder holds. Sign-in
/// steps and directory traffic change nothing a cache holds.
/// This single exhaustive mapping keeps new events from silently missing cache invalidation.
#[allow(clippy::too_many_lines)]
pub(super) fn authentication(event: AuthenticationEvent) -> &'static [Cached] {
    match event {
        AuthenticationEvent::SessionRevoked
        | AuthenticationEvent::SessionSuspended
        | AuthenticationEvent::SessionResumed
        | AuthenticationEvent::TokenRefreshed
        | AuthenticationEvent::PasswordChanged
        | AuthenticationEvent::PasskeyRemoved
        | AuthenticationEvent::MfaVerified
        | AuthenticationEvent::MfaEnrolled
        | AuthenticationEvent::MfaUnenrolled
        | AuthenticationEvent::DeviceRevoked
        | AuthenticationEvent::AccountLockedOut
        | AuthenticationEvent::PasswordResetCompleted
        | AuthenticationEvent::FactorsReset
        | AuthenticationEvent::RecoveryCodeUsed => CALLERS,
        AuthenticationEvent::BreakGlassGranted | AuthenticationEvent::BreakGlassRevoked => HOLDINGS,
        AuthenticationEvent::LoginSucceeded
        | AuthenticationEvent::LoginFailed
        | AuthenticationEvent::PasskeyRegistered
        | AuthenticationEvent::MfaFailed
        | AuthenticationEvent::DeviceTrusted
        | AuthenticationEvent::RecoveryCodesGenerated
        | AuthenticationEvent::PasswordBreachDetected
        | AuthenticationEvent::SignInCheckUnavailable
        | AuthenticationEvent::RiskySignIn
        | AuthenticationEvent::PasswordResetRequested
        | AuthenticationEvent::DirectoryBindSucceeded
        | AuthenticationEvent::DirectorySearchPerformed
        | AuthenticationEvent::DirectorySearchDenied
        | AuthenticationEvent::LdapCertificateIssued
        | AuthenticationEvent::LdapCertificateRevoked
        | AuthenticationEvent::AppSessionHandedOver
        | AuthenticationEvent::AppTokenIssued
        | AuthenticationEvent::MfaEnrollmentStarted
        | AuthenticationEvent::PasskeyRegistrationStarted
        | AuthenticationEvent::PasskeyRenamed
        | AuthenticationEvent::SingleSignOnStarted
        | AuthenticationEvent::SignInCodeExchanged
        | AuthenticationEvent::SignInPressureRose
        | AuthenticationEvent::SignInPressureEased
        | AuthenticationEvent::AccountUnderAttack
        | AuthenticationEvent::PasskeySignInStarted
        | AuthenticationEvent::PasskeyChallengeIssued
        | AuthenticationEvent::MagicLinkRequested
        | AuthenticationEvent::MfaCodeSent
        | AuthenticationEvent::DirectoryServiceAccountCreated
        | AuthenticationEvent::DirectoryServiceAccountSecretRotated
        | AuthenticationEvent::DirectoryServiceAccountScopeChanged
        | AuthenticationEvent::DirectoryServiceAccountStatusChanged
        | AuthenticationEvent::DirectoryServiceBound
        | AuthenticationEvent::DirectoryServiceAccountDeleted
        | AuthenticationEvent::DirectoryServiceSearchPerformed
        | AuthenticationEvent::DirectoryServiceSearchDenied => NOTHING,
    }
}
