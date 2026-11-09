//! Where a sealed secret belongs: the owner, the field and the record it is
//! kept in.
//!
//! The sealer binds every value it seals to the place it is sealed for, so
//! a value copied by someone who can write the database into another row,
//! another field or another tenant's tables does not open there. Sealing and
//! opening name the same place; a value asked to open anywhere else is
//! refused as a corrupt row.

use std::fmt;

use ianua_domain::types::{OrganizationId, SealedSecret, TenantId};

use crate::tenancy::ScopedTenant;

/// Whose secret a sealed value is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealOwner {
    /// The platform's own, kept for no tenant or organization.
    Platform,
    /// An organization's.
    Organization(OrganizationId),
    /// A tenant's.
    Tenant(TenantId),
}

impl From<&ScopedTenant> for SealOwner {
    fn from(tenant: &ScopedTenant) -> Self {
        Self::Tenant(**tenant)
    }
}

impl From<Option<TenantId>> for SealOwner {
    fn from(tenant: Option<TenantId>) -> Self {
        tenant.map_or(Self::Platform, Self::Tenant)
    }
}

/// Each field a sealed value is kept in.
///
/// Its label is bound into every value sealed for it, so it never changes:
/// a new label makes every value already sealed for the field unreadable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealedField {
    /// A tenant user's authenticator app seed.
    TotpSeed,
    /// An organization member's authenticator app seed.
    MemberTotpSeed,
    /// The client secret of a tenant's OIDC provider.
    FederationClientSecret,
    /// The private key a tenant's SAML provider encrypts assertions to.
    FederationDecryptionKey,
    /// The client secret of an organization's OIDC provider.
    OrgProviderClientSecret,
    /// The PKCE verifier of a tenant's OIDC sign-in in flight.
    OidcFlowVerifier,
    /// The PKCE verifier of a dashboard sign-in in flight.
    OrgSsoVerifier,
    /// A webhook subscription's signing secrets.
    WebhookSigningSecret,
    /// A push subscription's signing secrets.
    PushSecret,
    /// The credentials of an audit stream's destination.
    AuditStreamCredential,
    /// The credential of a log shipping target.
    LogShippingCredential,
    /// The header a signal stream's receiver asks its pushes to carry.
    SignalReceiverHeader,
    /// The credential of a tenant's own mail provider.
    MailProviderCredential,
    /// A mail waiting in the outbox.
    QueuedMail,
    /// The credential of a workflow's integration account.
    IntegrationCredential,
    /// The PKCE verifier of an account connection in flight.
    ConnectionVerifier,
    /// The credential a service issued for an account connection, kept
    /// until the person who began it finishes.
    ConnectionCredential,
    /// The secret a service signs a workflow's events with.
    SubscriptionSecret,
    /// What proves a delivery to an account's channel: the platform's own
    /// secret, or a key or token the service gave.
    AccountChannelSecret,
    /// The API key of an agent's model provider.
    ModelProviderKey,
    /// The private key a service presents to its upstream.
    UpstreamClientKey,
    /// The private key of a custom domain's certificate.
    DomainCertificateKey,
    /// The account key of an ACME directory.
    AcmeAccountKey,
    /// The private key of a signing key.
    SigningKey,
    /// The private key of an assertion key, which the gateway signs the
    /// identity it hands upstreams with.
    AssertionKey,
    /// The code a device sign-in shows its user.
    DeviceUserCode,
    /// An organization's notification destination: its address and secret.
    NotificationEndpoint,
    /// The credential of an organization's cloud account.
    CloudCredential,
    /// The external id of an organization's cloud account.
    CloudExternalId,
    /// The password of a stream route's workflow login, which Protected
    /// data steps sign in to the system behind it with.
    StreamRouteLogin,
    /// The password or token a tenant's own images are pulled from an
    /// allowed registry with.
    RegistryLogin,
}

impl SealedField {
    /// The fixed label a value sealed for this field is bound to.
    // One arm per field, with no catch-all: a new field must be given its
    // label here before it builds. Splitting it would bring a catch-all
    // back.
    #[allow(clippy::too_many_lines)]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::TotpSeed => "mfa_enrollments.sealed_secret",
            Self::MemberTotpSeed => "org_mfa_enrollments.sealed_secret",
            Self::FederationClientSecret => "federation_connections.client_secret",
            Self::FederationDecryptionKey => "federation_connections.decryption_key",
            Self::OrgProviderClientSecret => "org_identity_providers.client_secret",
            Self::OidcFlowVerifier => "oidc_flows.sealed_pkce_verifier",
            Self::OrgSsoVerifier => "org_sso_requests.pkce_verifier",
            Self::WebhookSigningSecret => "webhook_subscriptions.signing_secret",
            Self::PushSecret => "topic_subscriptions.push_secret",
            Self::AuditStreamCredential => "audit_streams.destination",
            Self::LogShippingCredential => "log_shipping_targets.credential",
            Self::SignalReceiverHeader => "signal_streams.authorization",
            Self::MailProviderCredential => "tenant_mail_providers.credential",
            Self::QueuedMail => "scheduled_jobs.mail_payload",
            Self::IntegrationCredential => "integration_accounts.credential",
            Self::ConnectionVerifier => "pending_connections.verifier",
            Self::ConnectionCredential => "pending_connections.credential",
            Self::SubscriptionSecret => "service_subscriptions.secret",
            Self::AccountChannelSecret => "account_channels.secret",
            Self::ModelProviderKey => "agent_model_providers.api_key",
            Self::UpstreamClientKey => "services.client_key",
            Self::DomainCertificateKey => "domain_certificates.private_key",
            Self::AcmeAccountKey => "acme_accounts.account_key",
            Self::SigningKey => "signing_keys.private_key",
            Self::AssertionKey => "assertion_keys.private_key",
            Self::DeviceUserCode => "oauth_device_authorizations.user_code",
            Self::NotificationEndpoint => "org_notification_destinations.endpoint",
            Self::CloudCredential => "org_cloud_accounts.credential",
            Self::CloudExternalId => "org_cloud_accounts.external_id",
            Self::StreamRouteLogin => "stream_routes.workflow_login_password",
            Self::RegistryLogin => "image_registries.password",
        }
    }
}

/// The place a secret is sealed for: whose it is, the field it is kept in,
/// and the record that holds it.
///
/// The record is what names the row: the id of the aggregate the value
/// belongs to, or the key of a row that has no id of its own. It is never a
/// secret, so the place may print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedFor {
    owner: SealOwner,
    field: SealedField,
    record: String,
}

impl SealedFor {
    /// The value of `owner` kept in `field` of the record `record` names.
    #[must_use]
    pub fn new(owner: SealOwner, field: SealedField, record: impl fmt::Display) -> Self {
        Self {
            owner,
            field,
            record: record.to_string(),
        }
    }

    /// Whose secret it is.
    #[must_use]
    pub fn owner(&self) -> SealOwner {
        self.owner
    }

    /// The field it is kept in.
    #[must_use]
    pub fn field(&self) -> SealedField {
        self.field
    }

    /// The record that holds it.
    #[must_use]
    pub fn record(&self) -> &str {
        &self.record
    }
}

/// A sealed secret beside the place it was sealed for, handed to an
/// adapter that opens it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedAt {
    /// The sealed secret.
    pub secret: SealedSecret,
    /// Where it was sealed for.
    pub place: SealedFor,
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    const EVERY_FIELD: [SealedField; 31] = [
        SealedField::TotpSeed,
        SealedField::MemberTotpSeed,
        SealedField::FederationClientSecret,
        SealedField::FederationDecryptionKey,
        SealedField::OrgProviderClientSecret,
        SealedField::OidcFlowVerifier,
        SealedField::OrgSsoVerifier,
        SealedField::WebhookSigningSecret,
        SealedField::PushSecret,
        SealedField::AuditStreamCredential,
        SealedField::LogShippingCredential,
        SealedField::SignalReceiverHeader,
        SealedField::MailProviderCredential,
        SealedField::QueuedMail,
        SealedField::IntegrationCredential,
        SealedField::ConnectionVerifier,
        SealedField::ConnectionCredential,
        SealedField::SubscriptionSecret,
        SealedField::AccountChannelSecret,
        SealedField::ModelProviderKey,
        SealedField::UpstreamClientKey,
        SealedField::DomainCertificateKey,
        SealedField::AcmeAccountKey,
        SealedField::SigningKey,
        SealedField::AssertionKey,
        SealedField::DeviceUserCode,
        SealedField::NotificationEndpoint,
        SealedField::CloudCredential,
        SealedField::CloudExternalId,
        SealedField::StreamRouteLogin,
        SealedField::RegistryLogin,
    ];

    /// Each sealed field has a distinct binding label, so no two fields share a label.
    #[test]
    fn every_field_has_a_label_of_its_own() {
        let labels: HashSet<&str> = EVERY_FIELD.iter().map(|field| field.label()).collect();

        assert_eq!(labels.len(), EVERY_FIELD.len());
    }

    /// A tenant named by work outside a request is the owner of what it
    /// seals, and no tenant at all is the platform.
    #[test]
    fn a_tenant_or_none_names_its_owner() {
        let tenant = TenantId::new();

        assert_eq!(SealOwner::from(Some(tenant)), SealOwner::Tenant(tenant));
        assert_eq!(SealOwner::from(None), SealOwner::Platform);
        assert_eq!(
            SealOwner::from(&ScopedTenant::for_background(tenant)),
            SealOwner::Tenant(tenant)
        );
    }
}
