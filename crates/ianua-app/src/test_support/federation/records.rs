//! Test connections and SCIM endpoints, read back as storage keeps them.

use std::collections::HashMap;

use ianua_domain::domains::federation::connection::{
    AssertionDecryption, AssuranceTrust, AuthnRequestSigning, ConnectionConfig, ConnectionRow,
    EmailTrust, FederatedIdpConnection, GroupMapping, GroupRule, GroupRules, IdpCertificates,
    JitProvisioning, MappedGrant, ProviderGroupName, SamlConfig,
};
use ianua_domain::domains::federation::connection_status::ConnectionStatus;
use ianua_domain::domains::federation::link::{FederatedLink, FederatedLinkRow};
use ianua_domain::domains::federation::scim::{
    ScimActivation, ScimEndpoint, ScimEndpointRow, ScimRemoval,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::types::{
    CertificatePem, ConnectionId, Enablement, FederatedSubject, HttpsUrl, Label, SamlNameIdFormat,
    Setting, TokenHash, UserId,
};
use time::OffsetDateTime;

use crate::use_cases::federation::connections::{ProviderConfig, SamlProviderConfig};

/// The certificate Acme's Okta signs its answers with.
pub const TEST_IDP_CERTIFICATE: &str =
    "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----";

/// The SAML settings of Acme's Okta: its entity id, its sign-in and logout
/// addresses, one signing certificate and the persistent `NameID` format.
/// Requests go unsigned and assertions come readable.
///
/// # Panics
///
/// Never: every value is a literal that is valid.
#[must_use]
pub fn test_saml_settings() -> SamlConfig {
    SamlConfig {
        entity_id: HttpsUrl::new("https://idp.acme.com").expect("a valid url"),
        sso_url: HttpsUrl::new("https://idp.acme.com/sso").expect("a valid url"),
        slo_url: Setting::Set(HttpsUrl::new("https://idp.acme.com/slo").expect("a valid url")),
        certificates: IdpCertificates::single(
            CertificatePem::new(TEST_IDP_CERTIFICATE).expect("a valid certificate"),
        ),
        name_id_format: SamlNameIdFormat::new(SamlNameIdFormat::PERSISTENT)
            .expect("the persistent format is valid"),
        request_signing: AuthnRequestSigning::Unsigned,
        assertion_decryption: AssertionDecryption::NotExpected,
        metadata_url: Setting::Unset,
    }
}

/// [`test_saml_settings`] as an administrator gives them by hand.
#[must_use]
pub fn test_saml_provider_config() -> ProviderConfig {
    let saml = test_saml_settings();
    ProviderConfig::Saml(Box::new(SamlProviderConfig {
        entity_id: saml.entity_id,
        sso_url: saml.sso_url,
        slo_url: saml.slo_url,
        certificates: saml.certificates,
        name_id_format: saml.name_id_format,
        request_signing: saml.request_signing,
    }))
}

/// [`test_saml_settings`] as a connection's configuration.
#[must_use]
pub fn test_saml_config() -> ConnectionConfig {
    ConnectionConfig::Saml(Box::new(test_saml_settings()))
}

/// A connection to Acme's Okta under `id`, in `status`. It vouches for no
/// domain, makes no accounts and trusts nothing the provider says.
#[must_use]
pub fn test_connection(
    id: ConnectionId,
    status: ConnectionStatus,
) -> FederatedIdpConnection<ResolvedTenant> {
    test_connection_named(id, "Okta", status)
}

/// [`test_connection`], shown as `name`.
///
/// # Panics
///
/// If `name` is not a valid label. Tests pass literals that are.
#[must_use]
pub fn test_connection_named(
    id: ConnectionId,
    name: &str,
    status: ConnectionStatus,
) -> FederatedIdpConnection<ResolvedTenant> {
    reconstituted(TestConnection {
        id,
        name,
        status,
        config: test_saml_config(),
        group_mapping: GroupMapping::Off,
    })
}

/// An active connection to Acme's Okta under `id`, reaching it by `saml`
/// and mapping its groups by `group_mapping`. Otherwise as
/// [`test_connection`].
#[must_use]
pub fn test_saml_connection(
    id: ConnectionId,
    saml: SamlConfig,
    group_mapping: GroupMapping,
) -> FederatedIdpConnection<ResolvedTenant> {
    reconstituted(TestConnection {
        id,
        name: "Okta",
        status: ConnectionStatus::Active,
        config: ConnectionConfig::Saml(Box::new(saml)),
        group_mapping,
    })
}

/// Acme's Okta over SAML, mapping its `engineering` group to `grant`.
///
/// # Panics
///
/// Never: one rule under a fixed claim is a valid mapping.
#[must_use]
pub fn test_connection_mapping_to(grant: MappedGrant) -> FederatedIdpConnection<ResolvedTenant> {
    let rules = GroupRules::new(
        Label::new("claim", "groups").expect("a valid claim"),
        vec![GroupRule {
            provider_group: ProviderGroupName::new("engineering").expect("a valid group"),
            grant,
        }],
    )
    .expect("one rule is a valid mapping");
    test_saml_connection(
        ConnectionId::new(),
        test_saml_settings(),
        GroupMapping::On(rules),
    )
}

/// The parts a test connection differs in.
struct TestConnection<'a> {
    id: ConnectionId,
    name: &'a str,
    status: ConnectionStatus,
    config: ConnectionConfig,
    group_mapping: GroupMapping,
}

/// `connection` as storage reads it back: vouching for no domain, making no
/// accounts and trusting nothing the provider says.
///
/// # Panics
///
/// If the name is not a valid label. Tests pass literals that are.
fn reconstituted(connection: TestConnection<'_>) -> FederatedIdpConnection<ResolvedTenant> {
    let now = clock::now();
    FederatedIdpConnection::reconstitute(ConnectionRow {
        id: connection.id,
        provider_name: Label::new("name", connection.name).expect("a valid name"),
        status: connection.status,
        config: connection.config,
        jit_provisioning: JitProvisioning::Disabled,
        jit_default_role_id: Setting::Unset,
        email_trust: EmailTrust::Unverified,
        assurance_trust: AssuranceTrust::Untrusted,
        domain_hint: Setting::Unset,
        allowed_domains: Vec::new(),
        attribute_mapping: HashMap::new(),
        group_mapping: connection.group_mapping,
        created_at: now,
        keyed_at: now,
    })
    .expect("a connection that vouches for nobody is a consistent row")
}

/// The link from `user_id` to their subject at `connection_id`'s provider,
/// made and last confirmed at `linked_at`. The subject is the account's id.
///
/// # Panics
///
/// Never: a link confirmed when it was made is a consistent row.
#[must_use]
pub fn test_link(
    connection_id: ConnectionId,
    user_id: UserId,
    linked_at: OffsetDateTime,
) -> FederatedLink<ResolvedTenant> {
    FederatedLink::reconstitute(FederatedLinkRow {
        connection_id,
        subject: FederatedSubject::new(user_id.to_string()).expect("a valid subject"),
        user_id,
        linked_at,
        confirmed_at: linked_at,
    })
    .expect("a link confirmed when it was made is a consistent row")
}

/// A SCIM endpoint whose bearer token hashes to `hash`, switched on or off
/// as `enabled` says, with no default role.
///
/// # Panics
///
/// Never: an endpoint that never synced is a consistent row.
#[must_use]
pub fn test_scim_endpoint(hash: &str, enabled: Enablement) -> ScimEndpoint<ResolvedTenant> {
    ScimEndpoint::reconstitute(ScimEndpointRow {
        bearer_token_hash: TokenHash::from_stored(hash.to_owned()),
        enabled,
        default_role_id: Setting::Unset,
        auto_activate: ScimActivation::Immediate,
        deactivate_on_remove: ScimRemoval::Deactivate,
        last_sync_at: None,
        created_at: clock::now(),
    })
    .expect("an endpoint that never synced is a consistent row")
}
