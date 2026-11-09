event_types! {
    /// The events the authentication context publishes.
    pub enum AuthenticationEvent {
        /// A user successfully authenticated.
        LoginSucceeded => "authentication.login_succeeded",
        /// A login attempt failed.
        LoginFailed => "authentication.login_failed",
        /// A session was explicitly revoked.
        SessionRevoked => "authentication.session_revoked",
        /// A session was suspended until the user signs in again.
        SessionSuspended => "authentication.session_suspended",
        /// A suspended session was resumed after step-up auth.
        SessionResumed => "authentication.session_resumed",
        /// A refresh token was used to obtain a new access token.
        TokenRefreshed => "authentication.token_refreshed",
        /// A user changed their password.
        PasswordChanged => "authentication.password_changed",
        /// A passkey was registered for a user.
        PasskeyRegistered => "authentication.passkey_registered",
        /// A passkey was removed from a user.
        PasskeyRemoved => "authentication.passkey_removed",
        /// MFA step-up verification was completed.
        MfaVerified => "authentication.mfa_verified",
        /// A second-factor code or recovery code was wrong.
        MfaFailed => "authentication.mfa_failed",
        /// MFA was enrolled for a user.
        MfaEnrolled => "authentication.mfa_enrolled",
        /// MFA was unenrolled from a user.
        MfaUnenrolled => "authentication.mfa_unenrolled",
        /// A device was added to a user's trusted list.
        DeviceTrusted => "authentication.device_trusted",
        /// A device was removed from a user's trusted list.
        DeviceRevoked => "authentication.device_revoked",
        /// An emergency break-glass grant was created.
        BreakGlassGranted => "authentication.break_glass_granted",
        /// A break-glass grant was revoked.
        BreakGlassRevoked => "authentication.break_glass_revoked",
        /// A user was locked out after too many failed login attempts.
        AccountLockedOut => "authentication.account_locked_out",
        /// Failed sign-ins against an account came from so many networks
        /// that it counts as under attack for a while.
        AccountUnderAttack => "authentication.account_under_attack",
        /// Recovery codes were generated for a user.
        RecoveryCodesGenerated => "authentication.recovery_codes_generated",
        /// A login used a password found in a known breach.
        PasswordBreachDetected => "authentication.password_breach_detected",
        /// A sign-in went ahead without its breach or location check, because
        /// the service behind it could not be reached.
        SignInCheckUnavailable => "authentication.sign_in_check_unavailable",
        /// A sign-in went ahead though it looked risky, such as from a new
        /// country or after a fast journey.
        RiskySignIn => "authentication.risky_sign_in",
        /// A recovery code was used to log in.
        RecoveryCodeUsed => "authentication.recovery_code_used",
        /// A password reset was requested.
        PasswordResetRequested => "authentication.password_reset_requested",
        /// A password reset was completed.
        PasswordResetCompleted => "authentication.password_reset_completed",
        /// A directory client authenticated via LDAP simple bind.
        DirectoryBindSucceeded => "authentication.directory_bind_succeeded",
        /// A bound directory client read the directory via LDAP search.
        DirectorySearchPerformed => "authentication.directory_search_performed",
        /// A bound directory client was denied an LDAP search.
        DirectorySearchDenied => "authentication.directory_search_denied",
        /// A client certificate was issued for LDAP write access.
        LdapCertificateIssued => "authentication.ldap_certificate_issued",
        /// A client certificate was revoked, ending its LDAP write access.
        LdapCertificateRevoked => "authentication.ldap_certificate_revoked",
        /// An app session was set as the cookie of a service on another host.
        AppSessionHandedOver => "authentication.app_session_handed_over",
        /// A short-lived token was issued under an app session for a service
        /// accepting the app's sign-in by token.
        AppTokenIssued => "authentication.app_token_issued",
        /// A user began MFA enrollment.
        MfaEnrollmentStarted => "authentication.mfa_enrollment_started",
        /// A user began passkey registration.
        PasskeyRegistrationStarted => "authentication.passkey_registration_started",
        /// A user renamed a passkey.
        PasskeyRenamed => "authentication.passkey_renamed",
        /// A single sign-on began.
        SingleSignOnStarted => "authentication.single_sign_on_started",
        /// A sign-in code was exchanged.
        SignInCodeExchanged => "authentication.sign_in_code_exchanged",
        /// Failed password sign-ins across a tenant reached its threshold, so
        /// devices nobody trusted must pass a challenge to sign in.
        SignInPressureRose => "authentication.sign_in_pressure_rose",
        /// Failed password sign-ins across a tenant fell back under its
        /// threshold.
        SignInPressureEased => "authentication.sign_in_pressure_eased",
        /// A passkey sign-in began.
        PasskeySignInStarted => "authentication.passkey_sign_in_started",
        /// A discoverable passkey challenge was issued.
        PasskeyChallengeIssued => "authentication.passkey_challenge_issued",
        /// A magic sign-in link was sent.
        MagicLinkRequested => "authentication.magic_link_requested",
        /// A one-time code was mailed or texted for a second factor.
        MfaCodeSent => "authentication.mfa_code_sent",
        /// An admin cleared every second factor of a user's account.
        FactorsReset => "authentication.factors_reset",
        /// An admin made a service account for the LDAP directory.
        DirectoryServiceAccountCreated => "authentication.directory_service_account_created",
        /// An admin replaced a directory service account's secret.
        DirectoryServiceAccountSecretRotated => "authentication.directory_service_account_secret_rotated",
        /// An admin changed what a directory service account may do.
        DirectoryServiceAccountScopeChanged => "authentication.directory_service_account_scope_changed",
        /// An admin switched a directory service account off or on.
        DirectoryServiceAccountStatusChanged => "authentication.directory_service_account_status_changed",
        /// An application bound to the directory as a service account.
        DirectoryServiceBound => "authentication.directory_service_bound",
        /// An admin deleted a directory service account.
        DirectoryServiceAccountDeleted => "authentication.directory_service_account_deleted",
        /// An application bound as a service account read the directory.
        DirectoryServiceSearchPerformed => "authentication.directory_service_search_performed",
        /// An application bound as a service account was refused a search.
        DirectoryServiceSearchDenied => "authentication.directory_service_search_denied",
    }
}

impl AuthenticationEvent {
    /// Whether other members hear about this event.
    ///
    /// Signing in and its steps are a user's own activity. They go in the
    /// audit trail but not in colleagues' feeds. A password reset request is
    /// left out too, since anyone may send one without signing in. Signs of
    /// trouble, such as a lockout, a breached password or a wrong second
    /// factor, are still told. A check that could not run is left out,
    /// because during an outage it would post once for every sign-in.
    /// Sign-in coming under pressure is told, so administrators learn of an
    /// attack while it runs; its easing is only kept on record. An account
    /// coming under attack is a security alert instead, told at most once
    /// an hour, so it is left out here.
    #[must_use]
    pub fn is_notifiable(&self) -> bool {
        !matches!(
            self,
            Self::LoginSucceeded
                | Self::AccountUnderAttack
                | Self::LoginFailed
                | Self::TokenRefreshed
                | Self::MfaVerified
                | Self::DirectoryBindSucceeded
                | Self::DirectorySearchPerformed
                | Self::AppSessionHandedOver
                | Self::AppTokenIssued
                | Self::MfaEnrollmentStarted
                | Self::PasskeyRegistrationStarted
                | Self::SingleSignOnStarted
                | Self::SignInCodeExchanged
                | Self::PasskeySignInStarted
                | Self::PasskeyChallengeIssued
                | Self::MagicLinkRequested
                | Self::PasswordResetRequested
                | Self::SignInCheckUnavailable
                | Self::RiskySignIn
                | Self::SignInPressureEased
                | Self::MfaCodeSent
                | Self::DirectoryServiceBound
                | Self::DirectoryServiceSearchPerformed
        )
    }
}
