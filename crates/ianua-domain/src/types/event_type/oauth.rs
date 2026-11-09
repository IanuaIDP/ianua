event_types! {
    /// The events the OAuth context publishes.
    pub enum OAuthEvent {
        /// An OAuth client was created.
        ClientCreated => "oauth.client_created",
        /// An OAuth client's configuration was updated.
        ClientUpdated => "oauth.client_updated",
        /// An OAuth client was revoked.
        ClientRevoked => "oauth.client_revoked",
        /// An API key was created.
        ApiKeyCreated => "oauth.api_key_created",
        /// An API key's configuration was updated.
        ApiKeyUpdated => "oauth.api_key_updated",
        /// An API key was revoked.
        ApiKeyRevoked => "oauth.api_key_revoked",
        /// An API key expired.
        ApiKeyExpired => "oauth.api_key_expired",
        /// An API key was paused and signs in nothing until resumed.
        ApiKeyPaused => "oauth.api_key_paused",
        /// An API key signed in from a country it never signed in from
        /// before.
        ApiKeyUsedFromNewCountry => "oauth.api_key_used_from_new_country",
        /// A paused API key was resumed.
        ApiKeyResumed => "oauth.api_key_resumed",
        /// An authorization code was issued.
        AuthorizationCodeIssued => "oauth.authorization_code_issued",
        /// An authorization code was exchanged for tokens.
        AuthorizationCodeExchanged => "oauth.authorization_code_exchanged",
        /// An access token was issued to a client on a user's behalf.
        AccessTokenIssued => "oauth.access_token_issued",
        /// A refresh token already rotated was presented again, and its
        /// family was revoked.
        RefreshTokenReused => "oauth.refresh_token_reused",
        /// A client revoked one of its tokens.
        TokenRevoked => "oauth.token_revoked",
        /// A device authorization was requested.
        DeviceAuthorizationRequested => "oauth.device_authorization_requested",
        /// A device authorization was approved by the user.
        DeviceAuthorizationApproved => "oauth.device_authorization_approved",
        /// A device authorization was denied by the user.
        DeviceAuthorizationDenied => "oauth.device_authorization_denied",
        /// A device collected the approval of its request.
        DeviceAuthorizationCollected => "oauth.device_authorization_collected",
        /// OAuth consent was granted by a user.
        ConsentGranted => "oauth.consent_granted",
        /// OAuth consent was revoked by a user.
        ConsentRevoked => "oauth.consent_revoked",
        /// An OAuth client's secret was rotated.
        ClientSecretRotated => "oauth.client_secret_rotated",
        /// An app registered itself as an OAuth client.
        ClientRegistered => "oauth.client_registered",
        /// An initial access token for registering clients was issued.
        InitialAccessTokenIssued => "oauth.initial_access_token_issued",
        /// An initial access token for registering clients was revoked.
        InitialAccessTokenRevoked => "oauth.initial_access_token_revoked",
        /// A client exchanged a token for one for another audience.
        TokenExchanged => "oauth.token_exchanged",
        /// A client pushed an authorization request (RFC 9126).
        AuthorizationRequestPushed => "oauth.authorization_request_pushed",
        /// A logout token was posted to an app's server after a person
        /// signed out.
        BackChannelLogoutSent => "oauth.back_channel_logout_sent",
    }
}

impl OAuthEvent {
    /// Whether the tenant's other members hear about this event.
    ///
    /// Codes, tokens, device approvals, exchanges and consent are the
    /// signed-in user's own activity. They go in the audit trail but not in
    /// colleagues' feeds. Changes to clients and to what lets apps register
    /// do reach them.
    #[must_use]
    pub fn is_notifiable(&self) -> bool {
        match self {
            Self::ClientCreated
            | Self::ClientUpdated
            | Self::ClientRevoked
            | Self::ClientSecretRotated
            | Self::ClientRegistered
            | Self::InitialAccessTokenIssued
            | Self::InitialAccessTokenRevoked
            | Self::ApiKeyCreated
            | Self::ApiKeyUpdated
            | Self::ApiKeyRevoked
            | Self::ApiKeyExpired
            | Self::ApiKeyPaused
            | Self::ApiKeyUsedFromNewCountry
            | Self::ApiKeyResumed => true,
            Self::AuthorizationCodeIssued
            | Self::AuthorizationCodeExchanged
            | Self::AccessTokenIssued
            | Self::RefreshTokenReused
            | Self::TokenRevoked
            | Self::TokenExchanged
            | Self::AuthorizationRequestPushed
            | Self::BackChannelLogoutSent
            | Self::DeviceAuthorizationRequested
            | Self::DeviceAuthorizationApproved
            | Self::DeviceAuthorizationDenied
            | Self::DeviceAuthorizationCollected
            | Self::ConsentGranted
            | Self::ConsentRevoked => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A client gets an access token for a user. That is audited but
    /// notifies no colleague.
    #[test]
    fn an_issued_access_token_is_not_notified() {
        assert!(!OAuthEvent::AccessTokenIssued.is_notifiable());
    }

    /// Bob signs in to a tenant app through a code or device flow and grants
    /// consent. None of those steps reach the feed of colleagues who manage
    /// the clients.
    #[test]
    fn a_sign_in_through_a_client_is_not_notified() {
        for event in [
            OAuthEvent::AuthorizationCodeIssued,
            OAuthEvent::AuthorizationCodeExchanged,
            OAuthEvent::AuthorizationRequestPushed,
            OAuthEvent::BackChannelLogoutSent,
            OAuthEvent::DeviceAuthorizationRequested,
            OAuthEvent::DeviceAuthorizationApproved,
            OAuthEvent::DeviceAuthorizationDenied,
            OAuthEvent::DeviceAuthorizationCollected,
            OAuthEvent::ConsentGranted,
            OAuthEvent::ConsentRevoked,
        ] {
            assert!(!event.is_notifiable(), "{event:?}");
        }
    }

    /// An admin creates an OAuth client. Colleagues are notified.
    #[test]
    fn a_change_to_a_client_is_notified() {
        assert!(OAuthEvent::ClientCreated.is_notifiable());
    }

    /// An app registers itself, a client's secret is rotated, and an
    /// initial access token is issued. The admins who manage clients hear of
    /// each; a token exchanged for a person does not reach them.
    #[test]
    fn registration_and_rotation_are_notified_but_an_exchange_is_not() {
        for event in [
            OAuthEvent::ClientRegistered,
            OAuthEvent::ClientSecretRotated,
            OAuthEvent::InitialAccessTokenIssued,
            OAuthEvent::InitialAccessTokenRevoked,
        ] {
            assert!(event.is_notifiable(), "{event:?}");
        }
        assert!(!OAuthEvent::TokenExchanged.is_notifiable());
    }
}
