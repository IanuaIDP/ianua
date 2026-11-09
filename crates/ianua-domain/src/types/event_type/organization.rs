event_types! {
    /// The events the organization context publishes.
    pub enum OrganizationEvent {
        /// A new organization was created.
        Created => "organization.created",
        /// An organization's status changed.
        StatusChanged => "organization.status_changed",
        /// An organization was renamed.
        Renamed => "organization.renamed",
        /// A tenant was created within the organization.
        TenantCreated => "organization.tenant_created",
        /// The organization's contact email was changed.
        ContactEmailChanged => "organization.contact_email_changed",
        /// The organization's display name was changed.
        DisplayNameChanged => "organization.display_name_changed",
        /// A user switched between tenants via linked identity.
        TenantSwitched => "organization.tenant_switched",
        /// A user identity was linked across tenants.
        IdentityLinked => "organization.identity_linked",
        /// A user identity was unlinked from a tenant.
        IdentityUnlinked => "organization.identity_unlinked",
        /// The organization's subscription plan was changed.
        PlanChanged => "organization.plan_changed",
        /// The organization's sign-in settings were changed.
        AuthConfigUpdated => "organization.auth_config_updated",
        /// An org user was created directly.
        OrgUserCreated => "organization.org_user_created",
        /// An org user was invited.
        OrgUserInvited => "organization.org_user_invited",
        /// An org user accepted their invitation and joined.
        OrgUserInvitationAccepted => "organization.org_user_invitation_accepted",
        /// An org user invitation was revoked before being accepted.
        OrgUserInvitationRevoked => "organization.org_user_invitation_revoked",
        /// An invited org user turned the invitation down.
        OrgUserInvitationDeclined => "organization.org_user_invitation_declined",
        /// An org invitation ran out without an answer.
        OrgUserInvitationExpired => "organization.org_user_invitation_expired",
        /// An org user invitation was sent again, with a new token and a later
        /// expiry.
        OrgUserInvitationResent => "organization.org_user_invitation_resent",
        /// A closed org user's account was opened again for a new
        /// invitation, its tenant access withdrawn.
        OrgUserReopened => "organization.org_user_reopened",
        /// An org user was deleted.
        OrgUserDeleted => "organization.org_user_deleted",
        /// An org user was deactivated, reactivated, locked or unlocked.
        OrgUserStatusChanged => "organization.org_user_status_changed",
        /// An org user was promoted or demoted in the organization.
        OrgUserRoleChanged => "organization.org_user_role_changed",
        /// An owner handed the organization over to another member.
        OwnershipTransferred => "organization.ownership_transferred",
        /// The organization's subscription began.
        SubscriptionStarted => "organization.subscription_started",
        /// The organization's subscription moved to another plan or cycle.
        SubscriptionChanged => "organization.subscription_changed",
        /// The organization's trial ran out.
        TrialEnded => "organization.trial_ended",
        /// The payment provider reported a new payment method.
        PaymentMethodChanged => "organization.payment_method_changed",
        /// A charge to the organization failed.
        PaymentFailed => "organization.payment_failed",
        /// What the organization owed was paid.
        PaymentSettled => "organization.payment_settled",
        /// A member was sent to the payment provider's page to add a
        /// payment method.
        CheckoutStarted => "organization.checkout_started",
        /// The organization's own logo, colors or sender name changed.
        BrandingUpdated => "organization.branding_updated",
        /// The organization's own look went back to the platform's.
        BrandingReset => "organization.branding_reset",
        /// An org user was granted roles in a tenant.
        OrgUserTenantAccessGranted => "organization.org_user_tenant_access_granted",
        /// An org user's access to a tenant was withdrawn.
        OrgUserTenantAccessRevoked => "organization.org_user_tenant_access_revoked",
        /// An org user's password was reset by an admin.
        OrgUserPasswordReset => "organization.org_user_password_reset",
        /// An org user asked for a password reset link.
        OrgUserPasswordResetRequested => "organization.org_user_password_reset_requested",
        /// An org user changed their own password.
        OrgUserPasswordChanged => "organization.org_user_password_changed",
        /// An org user's email was changed.
        OrgUserEmailChanged => "organization.org_user_email_changed",
        /// An org user confirmed their email address.
        OrgUserEmailVerified => "organization.org_user_email_verified",
        /// An org user's display name was changed.
        OrgUserDisplayNameChanged => "organization.org_user_display_name_changed",
        /// An org user updated their locale or timezone preferences.
        OrgUserPreferencesUpdated => "organization.org_user_preferences_updated",
        /// An org API key was created.
        OrgApiKeyCreated => "organization.org_api_key_created",
        /// An org API key was revoked.
        OrgApiKeyRevoked => "organization.org_api_key_revoked",
        /// An org user enrolled MFA.
        OrgMfaEnrolled => "organization.org_mfa_enrolled",
        /// An org user trusted a device, letting it skip MFA.
        OrgDeviceTrusted => "organization.org_device_trusted",
        /// An org user revoked a trusted device.
        OrgDeviceRevoked => "organization.org_device_revoked",
        /// An org user began MFA enrollment.
        OrgMfaEnrollmentStarted => "organization.org_mfa_enrollment_started",
        /// An org user passed an MFA check.
        OrgMfaVerified => "organization.org_mfa_verified",
        /// An org user disabled MFA.
        OrgMfaUnenrolled => "organization.org_mfa_unenrolled",
        /// An owner reset a member's second factor.
        OrgMemberMfaReset => "organization.org_member_mfa_reset",
        /// An org user replaced their recovery codes with a fresh set.
        OrgRecoveryCodesGenerated => "organization.org_recovery_codes_generated",
        /// The organization added its identity provider.
        OrgIdentityProviderAdded => "organization.org_identity_provider_added",
        /// The organization's identity provider was changed, switched on or off.
        OrgIdentityProviderChanged => "organization.org_identity_provider_changed",
        /// The organization removed its identity provider.
        OrgIdentityProviderRemoved => "organization.org_identity_provider_removed",
        /// An org user began passkey registration.
        OrgPasskeyRegistrationStarted => "organization.org_passkey_registration_started",
        /// An org user registered a passkey.
        OrgPasskeyRegistered => "organization.org_passkey_registered",
        /// An org user renamed a passkey.
        OrgPasskeyRenamed => "organization.org_passkey_renamed",
        /// An org user removed a passkey.
        OrgPasskeyRemoved => "organization.org_passkey_removed",
        /// An org user signed in.
        OrgLoginSucceeded => "organization.org_login_succeeded",
        /// An org user's sign-in was refused.
        OrgLoginFailed => "organization.org_login_failed",
        /// Failed sign-ins against an org user's account came from so many
        /// networks that it counts as under attack for a while.
        OrgAccountUnderAttack => "organization.org_account_under_attack",
        /// An org session was revoked.
        OrgSessionRevoked => "organization.org_session_revoked",
        /// An org session moved to another tenant of the organization.
        OrgSessionMoved => "organization.org_session_moved",
        /// A passkey sign-in began for an org user.
        OrgPasskeySignInStarted => "organization.org_passkey_sign_in_started",
        /// A discoverable passkey challenge was issued.
        OrgPasskeyChallengeIssued => "organization.org_passkey_challenge_issued",
        /// A sign-in link was mailed to an org user.
        OrgMagicLinkRequested => "organization.org_magic_link_requested",
        /// A sign-in through the organization's identity provider was started.
        OrgSsoSignInStarted => "organization.org_sso_sign_in_started",
        /// A cloud connection was started.
        CloudConnectionStarted => "organization.cloud_connection_started",
        /// A cloud credential was attached.
        CloudCredentialAttached => "organization.cloud_credential_attached",
        /// A cloud account was checked.
        CloudAccountVerified => "organization.cloud_account_verified",
        /// A cloud account was disconnected.
        CloudAccountDisconnected => "organization.cloud_account_disconnected",
        /// An org verification email was sent.
        OrgVerificationEmailSent => "organization.org_verification_email_sent",
        /// An org welcome email was sent.
        OrgWelcomeEmailSent => "organization.org_welcome_email_sent",
        /// An org user gave their consent to some terms.
        OrgUserConsentGranted => "organization.org_user_consent_granted",
        /// An org user's consent was withdrawn.
        OrgUserConsentRevoked => "organization.org_user_consent_revoked",
        /// An org user's data is to be erased after a grace period.
        OrgUserErasureRequested => "organization.org_user_erasure_requested",
        /// An org user's erasure was cancelled.
        OrgUserErasureCancelled => "organization.org_user_erasure_cancelled",
        /// A legal hold paused an org user's erasure.
        OrgUserErasureHeld => "organization.org_user_erasure_held",
        /// A legal hold on an org user's erasure was lifted.
        OrgUserErasureReleased => "organization.org_user_erasure_released",
        /// Deleting an org user's data started.
        OrgUserErasureStarted => "organization.org_user_erasure_started",
        /// All of an org user's data was deleted.
        OrgUserErasureCompleted => "organization.org_user_erasure_completed",
        /// Deleting an org user's data stopped part way.
        OrgUserErasureFailed => "organization.org_user_erasure_failed",
        /// An export of the organization's audit log was asked for.
        AuditLogExportRequested => "organization.audit_log_export_requested",
        /// The file of an export of the organization's audit log was handed
        /// out.
        AuditLogExportDownloaded => "organization.audit_log_export_downloaded",
    }
}

impl OrganizationEvent {
    /// Whether the org's other members hear about this event.
    ///
    /// Sign-in attempts and the links and provider sign-ins that start
    /// them, MFA and passkey steps, challenges, moving a session between
    /// tenants, mails sent, consent, opening a checkout page and exporting
    /// the audit log are a member's own activity. They go in the audit trail but not in
    /// colleagues' feeds. An account coming under attack is a security
    /// alert instead, told to admins and owners at most once an hour.
    #[must_use]
    pub fn is_notifiable(&self) -> bool {
        !matches!(
            self,
            Self::OrgMfaEnrollmentStarted
                | Self::OrgAccountUnderAttack
                | Self::OrgMfaVerified
                | Self::OrgPasskeyRegistrationStarted
                | Self::OrgLoginSucceeded
                | Self::OrgLoginFailed
                | Self::OrgPasskeySignInStarted
                | Self::OrgPasskeyChallengeIssued
                | Self::OrgMagicLinkRequested
                | Self::OrgSsoSignInStarted
                | Self::CheckoutStarted
                | Self::OrgSessionMoved
                | Self::OrgVerificationEmailSent
                | Self::OrgWelcomeEmailSent
                | Self::OrgUserConsentGranted
                | Self::OrgUserConsentRevoked
                | Self::AuditLogExportRequested
                | Self::AuditLogExportDownloaded
        )
    }
}
