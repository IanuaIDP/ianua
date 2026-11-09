event_types! {
    /// The events the identity context publishes.
    pub enum IdentityEvent {
        /// A new user registered.
        UserRegistered => "identity.user_registered",
        /// A user was invited.
        UserInvited => "identity.user_invited",
        /// A user's email was verified.
        EmailVerified => "identity.email_verified",
        /// A user's status changed, for example to locked or deactivated.
        UserStatusChanged => "identity.user_status_changed",
        /// A user's email address was changed.
        EmailChanged => "identity.email_changed",
        /// An admin reset a user's password.
        PasswordReset => "identity.password_reset",
        /// A user was permanently deleted.
        UserDeleted => "identity.user_deleted",
        /// A user granted consent to an application scope.
        ConsentGranted => "identity.consent_granted",
        /// A user revoked consent from an application scope.
        ConsentRevoked => "identity.consent_revoked",
        /// A user accepted an invitation.
        InvitationAccepted => "identity.invitation_accepted",
        /// An invitation expired without being accepted.
        InvitationExpired => "identity.invitation_expired",
        /// An invitation was revoked before being accepted.
        InvitationRevoked => "identity.invitation_revoked",
        /// The invited person turned an invitation down.
        InvitationDeclined => "identity.invitation_declined",
        /// An invitation was sent again, with a new token and a later expiry.
        InvitationResent => "identity.invitation_resent",
        /// A user's display name was changed.
        UserRenamed => "identity.user_renamed",
        /// A user updated their locale or timezone preferences.
        UserPreferencesUpdated => "identity.user_preferences_updated",
        /// A data erasure request was submitted.
        ErasureRequested => "identity.erasure_requested",
        /// A data erasure request was cancelled by the user.
        ErasureCancelled => "identity.erasure_cancelled",
        /// A legal hold paused a data erasure request.
        ErasureHeld => "identity.erasure_held",
        /// A legal hold on a data erasure request was lifted.
        ErasureReleased => "identity.erasure_released",
        /// Data erasure processing started.
        ErasureStarted => "identity.erasure_started",
        /// Data erasure completed, and all of the user's data is deleted.
        ErasureCompleted => "identity.erasure_completed",
        /// Data erasure failed and needs retry.
        ErasureFailed => "identity.erasure_failed",
        /// A user's metadata was updated, in the user or the app namespace.
        MetadataUpdated => "identity.metadata_updated",
        /// All metadata for a user was deleted.
        MetadataDeleted => "identity.metadata_deleted",
        /// A tenant declared a custom user attribute.
        AttributeDeclared => "identity.attribute_declared",
        /// A tenant changed a custom user attribute's declaration.
        AttributeUpdated => "identity.attribute_updated",
        /// A tenant withdrew a custom user attribute from use, keeping the values
        /// stored under it.
        AttributeArchived => "identity.attribute_archived",
        /// A tenant brought a withdrawn attribute back into use.
        AttributeRestored => "identity.attribute_restored",
        /// A tenant discarded a custom user attribute and every value stored
        /// under it.
        AttributeDeleted => "identity.attribute_deleted",
        /// A user asked to change their email.
        EmailChangeRequested => "identity.email_change_requested",
        /// An email-change link was sent again.
        EmailChangeLinkResent => "identity.email_change_link_resent",
        /// An email change was cancelled from the old address.
        EmailChangeCancelled => "identity.email_change_cancelled",
        /// A management-plane account asked to change its email.
        ManagementEmailChangeRequested => "identity.management_email_change_requested",
        /// A management-plane email-change link was sent again.
        ManagementEmailChangeLinkResent => "identity.management_email_change_link_resent",
        /// A management-plane email change was cancelled from the old address.
        ManagementEmailChangeCancelled => "identity.management_email_change_cancelled",
        /// A verification email was sent.
        VerificationEmailSent => "identity.verification_email_sent",
        /// A welcome email was sent.
        WelcomeEmailSent => "identity.welcome_email_sent",
        /// A management-plane email change was confirmed.
        ManagementEmailChangeConfirmed => "identity.management_email_change_confirmed",
        /// Fields of a user's profile changed: their details or the
        /// directory's records about them.
        UserProfileUpdated => "identity.user_profile_updated",
        /// An account was opened from another system's records.
        UserImported => "identity.user_imported",
        /// Accounts were sent to import from another system.
        UserImportStarted => "identity.user_import_started",
        /// An import of accounts from another system finished or was given
        /// up on.
        UsersImported => "identity.users_imported",
        /// A copy of a person's data was asked for.
        DataExportRequested => "identity.data_export_requested",
        /// A person's export may be downloaded.
        DataExportReady => "identity.data_export_ready",
        /// A person downloaded their export.
        DataExportDownloaded => "identity.data_export_downloaded",
        /// A person's export reached the end of its window and was deleted.
        DataExportExpired => "identity.data_export_expired",
        /// A tenant admin asked to act as a person.
        SupportImpersonationRequested => "identity.support_impersonation_requested",
        /// A tenant admin may act as a person until a time.
        SupportImpersonationStarted => "identity.support_impersonation_started",
        /// A person refused to let a tenant admin act as them.
        SupportImpersonationDeclined => "identity.support_impersonation_declined",
        /// A tenant admin's acting as a person was ended or withdrawn.
        SupportImpersonationEnded => "identity.support_impersonation_ended",
    }
}

impl IdentityEvent {
    /// Whether other members hear about this event.
    ///
    /// Mails sent to a user, email change requests, consent, preferences,
    /// profile details and copies of their data are that user's own
    /// business. They go in the audit trail but not in colleagues' feeds.
    /// An import's start and each account it opens are recorded on their
    /// own, but colleagues hear of the import once, through
    /// `identity.users_imported`.
    #[must_use]
    pub fn is_notifiable(&self) -> bool {
        !matches!(
            self,
            Self::UserImported
                | Self::UserImportStarted
                | Self::ConsentGranted
                | Self::ConsentRevoked
                | Self::UserPreferencesUpdated
                | Self::UserProfileUpdated
                | Self::DataExportRequested
                | Self::DataExportReady
                | Self::DataExportDownloaded
                | Self::DataExportExpired
                | Self::EmailChangeRequested
                | Self::EmailChangeLinkResent
                | Self::ManagementEmailChangeRequested
                | Self::ManagementEmailChangeLinkResent
                | Self::VerificationEmailSent
                | Self::WelcomeEmailSent
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ann imports ten thousand accounts. Colleagues hear of the import
    /// once, not of every account it opened.
    #[test]
    fn an_import_is_notified_once_not_per_account() {
        assert!(!IdentityEvent::UserImportStarted.is_notifiable());
        assert!(!IdentityEvent::UserImported.is_notifiable());
        assert!(IdentityEvent::UsersImported.is_notifiable());
    }
}
