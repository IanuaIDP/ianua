event_types! {
    /// The events the federation context publishes.
    pub enum FederationEvent {
        /// A federated `IdP` connection was created.
        ConnectionCreated => "federation.connection_created",
        /// A federated `IdP` connection was enabled again.
        ConnectionActivated => "federation.connection_activated",
        /// A federated `IdP` connection was disabled.
        ConnectionDisabled => "federation.connection_disabled",
        /// A federated `IdP` connection's configuration was updated.
        ConnectionUpdated => "federation.connection_updated",
        /// A federated `IdP` connection was deleted.
        ConnectionDeleted => "federation.connection_deleted",
        /// A user was created at first sign-in through just-in-time
        /// provisioning.
        JitUserProvisioned => "federation.jit_user_provisioned",
        /// An existing account was linked to who its owner is at a provider.
        AccountLinked => "federation.account_linked",
        /// A sign-in provider was taken off an account.
        AccountUnlinked => "federation.account_unlinked",
        /// An account holder confirmed their link again after the provider's
        /// signing key changed.
        LinkReconfirmed => "federation.link_reconfirmed",
        /// SCIM provisioning was enabled for the tenant.
        ScimEnabled => "federation.scim_enabled",
        /// SCIM provisioning was disabled for the tenant.
        ScimDisabled => "federation.scim_disabled",
        /// A SCIM bearer token was rotated.
        ScimTokenRotated => "federation.scim_token_rotated",
        /// What SCIM does with the users it creates and removes was changed.
        ScimSettingsUpdated => "federation.scim_settings_updated",
        /// A SAML app was added, signing people in with this platform as
        /// the identity provider.
        ServiceProviderCreated => "federation.service_provider_created",
        /// A SAML app's settings or status were changed.
        ServiceProviderUpdated => "federation.service_provider_updated",
        /// A SAML app was deleted.
        ServiceProviderDeleted => "federation.service_provider_deleted",
        /// A person was signed in to a SAML app with an assertion from here.
        SamlAssertionIssued => "federation.saml_assertion_issued",
        /// A sign-out asked a SAML peer to end the person's session there.
        LogoutRequestSent => "federation.logout_request_sent",
        /// A SAML peer answered a logout request sent from here.
        LogoutResponseTaken => "federation.logout_response_taken",
    }
}

impl FederationEvent {
    /// Whether other members hear about this event.
    ///
    /// Signing in to an app and signing out of the peers a session reached
    /// are a person's own activity. They go in the audit trail but not in
    /// colleagues' feeds.
    #[must_use]
    pub fn is_notifiable(&self) -> bool {
        !matches!(
            self,
            Self::SamlAssertionIssued | Self::LogoutRequestSent | Self::LogoutResponseTaken
        )
    }
}
