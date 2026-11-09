//! What the events of rights, keys, federation and consumers touch.

use ianua_domain::types::event_type::{
    AuthorizationEvent, ConsumersEvent, FederationEvent, OAuthEvent,
};

use crate::cache::stores::touched::{CALLERS, HOLDINGS, NOTHING};
use crate::cache::stores::versions::Cached;

/// Roles, groups, assignments, memberships and resource types are what a
/// holder's holdings are worked out from; an approved request or a decided
/// review changes them. Policies, relationships, separation and clearance
/// rules are read apart from the holdings, so they touch nothing cached.
/// This single exhaustive mapping keeps new events from silently missing cache invalidation.
#[allow(clippy::too_many_lines)]
pub(super) fn authorization(event: AuthorizationEvent) -> &'static [Cached] {
    match event {
        AuthorizationEvent::RoleCreated
        | AuthorizationEvent::RoleAssigned
        | AuthorizationEvent::RoleRevoked
        | AuthorizationEvent::RoleDeleted
        | AuthorizationEvent::RoleReassigned
        | AuthorizationEvent::RoleRenamed
        | AuthorizationEvent::RoleDefaultAssignmentChanged
        | AuthorizationEvent::PermissionGranted
        | AuthorizationEvent::PermissionRevoked
        | AuthorizationEvent::GroupCreated
        | AuthorizationEvent::GroupDeleted
        | AuthorizationEvent::GroupRenamed
        | AuthorizationEvent::GroupRoleAssigned
        | AuthorizationEvent::GroupRoleUnassigned
        | AuthorizationEvent::GroupMemberAdded
        | AuthorizationEvent::GroupMemberRemoved
        | AuthorizationEvent::GroupMoved
        | AuthorizationEvent::ResourceTypeDeclared
        | AuthorizationEvent::ResourceTypeUpdated
        | AuthorizationEvent::ResourceTypeDeleted
        | AuthorizationEvent::RoleAssignmentExpired
        | AuthorizationEvent::GroupMembershipExpired
        | AuthorizationEvent::AccessRequestApproved
        | AuthorizationEvent::AccessReviewDecided
        | AuthorizationEvent::AccessReviewCompleted => HOLDINGS,
        AuthorizationEvent::PolicyRuleAdded
        | AuthorizationEvent::PolicyRuleRemoved
        | AuthorizationEvent::PolicyRuleSwitched
        | AuthorizationEvent::PolicyDefaultActionChanged
        | AuthorizationEvent::PolicyDraftStarted
        | AuthorizationEvent::BreakGlassPolicyChanged
        | AuthorizationEvent::PolicySubmittedForReview
        | AuthorizationEvent::PolicyActivated
        | AuthorizationEvent::PolicyRejected
        | AuthorizationEvent::PolicyArchived
        | AuthorizationEvent::PolicySimulated
        | AuthorizationEvent::PolicyRuleChanged
        | AuthorizationEvent::PolicyRulesReordered
        | AuthorizationEvent::AccessRequested
        | AuthorizationEvent::AccessRequestDenied
        | AuthorizationEvent::AccessRequestCancelled
        | AuthorizationEvent::AccessRequestExpired
        | AuthorizationEvent::AccessRequestPolicyChanged
        | AuthorizationEvent::RelationshipAdded
        | AuthorizationEvent::RelationshipRemoved
        | AuthorizationEvent::AccessReviewStarted
        | AuthorizationEvent::AccessReviewSuggested
        | AuthorizationEvent::AccessReviewCancelled
        | AuthorizationEvent::SeparationRuleAdded
        | AuthorizationEvent::SeparationRuleRemoved
        | AuthorizationEvent::ClearanceRuleAdded
        | AuthorizationEvent::ClearanceRuleChanged
        | AuthorizationEvent::ClearanceRuleRemoved => NOTHING,
    }
}

/// A tenant's API keys and clients: a revoked, expired or changed key, a
/// revoked client and a reused or revoked token stop answering at once.
/// OAuth flows and their tokens are checked apart from the bearer lookup.
pub(super) fn oauth(event: OAuthEvent) -> &'static [Cached] {
    match event {
        OAuthEvent::ClientRevoked
        | OAuthEvent::ApiKeyUpdated
        | OAuthEvent::ApiKeyRevoked
        | OAuthEvent::ApiKeyExpired
        | OAuthEvent::ApiKeyPaused
        | OAuthEvent::ApiKeyResumed
        | OAuthEvent::RefreshTokenReused
        | OAuthEvent::TokenRevoked => CALLERS,
        OAuthEvent::ClientCreated
        | OAuthEvent::ClientUpdated
        | OAuthEvent::ApiKeyCreated
        | OAuthEvent::ApiKeyUsedFromNewCountry
        | OAuthEvent::AuthorizationCodeIssued
        | OAuthEvent::AuthorizationCodeExchanged
        | OAuthEvent::AccessTokenIssued
        | OAuthEvent::DeviceAuthorizationRequested
        | OAuthEvent::DeviceAuthorizationApproved
        | OAuthEvent::DeviceAuthorizationDenied
        | OAuthEvent::DeviceAuthorizationCollected
        | OAuthEvent::ConsentGranted
        | OAuthEvent::ConsentRevoked
        | OAuthEvent::ClientSecretRotated
        | OAuthEvent::ClientRegistered
        | OAuthEvent::InitialAccessTokenIssued
        | OAuthEvent::InitialAccessTokenRevoked
        | OAuthEvent::TokenExchanged
        | OAuthEvent::AuthorizationRequestPushed
        | OAuthEvent::BackChannelLogoutSent => NOTHING,
    }
}

/// Federation: a single logout ends sessions; a user made just in time may
/// be given roles and groups by the connection's rules.
pub(super) fn federation(event: FederationEvent) -> &'static [Cached] {
    match event {
        FederationEvent::LogoutRequestSent | FederationEvent::LogoutResponseTaken => CALLERS,
        FederationEvent::JitUserProvisioned => HOLDINGS,
        FederationEvent::ConnectionCreated
        | FederationEvent::ConnectionActivated
        | FederationEvent::ConnectionDisabled
        | FederationEvent::ConnectionUpdated
        | FederationEvent::ConnectionDeleted
        | FederationEvent::AccountLinked
        | FederationEvent::AccountUnlinked
        | FederationEvent::LinkReconfirmed
        | FederationEvent::ScimEnabled
        | FederationEvent::ScimDisabled
        | FederationEvent::ScimTokenRotated
        | FederationEvent::ScimSettingsUpdated
        | FederationEvent::ServiceProviderCreated
        | FederationEvent::ServiceProviderUpdated
        | FederationEvent::ServiceProviderDeleted
        | FederationEvent::SamlAssertionIssued => NOTHING,
    }
}

/// Consumers sign in with credentials of their own, never through the
/// bearer lookup; a deleted consumer's assignments cascade away.
pub(super) fn consumers(event: ConsumersEvent) -> &'static [Cached] {
    match event {
        ConsumersEvent::ConsumerDeleted => HOLDINGS,
        ConsumersEvent::ConsumerCreated
        | ConsumersEvent::ConsumerDisabled
        | ConsumersEvent::ConsumerEnabled
        | ConsumersEvent::ConsumerRenamed
        | ConsumersEvent::DescriptionChanged
        | ConsumersEvent::ClearanceChanged
        | ConsumersEvent::CredentialRotated
        | ConsumersEvent::CredentialOverlapEnded
        | ConsumersEvent::CredentialExpiryChanged
        | ConsumersEvent::QuotaChanged => NOTHING,
    }
}
