//! Rows of the federation context.
//!
//! Every builder makes a record valid by default, and a test changes what
//! it is about with struct update syntax. Records that wait for an answer,
//! such as a sign-in in flight, are dated from now, since the stores drop
//! them once their time has run out.
//!
//! # Panics
//!
//! Every builder panics when given a name, address or id that is not a
//! valid one, which is a mistake in the test.

use std::collections::HashMap;

use ianua_app::ports::federation::{
    HeldSamlSignIn, InboundSamlMessage, OidcLoginFlow, ProviderSession, SamlAppSession,
    SamlBinding, SamlLoginRequest,
};
use ianua_domain::domains::federation::connection::{
    AssertionDecryption, AssuranceTrust, AuthnRequestSigning, ConnectionConfig, ConnectionRow,
    EmailTrust, GroupMapping, IdpCertificates, JitProvisioning, OidcConfig, SamlConfig, ScopeToken,
};
use ianua_domain::domains::federation::connection_status::ConnectionStatus;
use ianua_domain::domains::federation::link::FederatedLinkRow;
use ianua_domain::domains::federation::saml::logout::SentLogoutRequestRow;
use ianua_domain::domains::federation::saml::name_id::{NameIdFormat, SamlNameIdValue};
use ianua_domain::domains::federation::scim::{ScimActivation, ScimEndpointRow, ScimRemoval};
use ianua_domain::domains::federation::service_provider::{
    AcsUrls, AssertionEncryption, AttributeStatements, RequestSigningRule, SamlServiceProviderRow,
    SamlServiceProviderSettings, SignedParts,
};
use ianua_domain::shared::clock;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    CertificatePem, ConnectionId, Enablement, FederatedSubject, HttpsUrl, Label, Nonce,
    PublicHttpsUrl, SamlArrivalId, SamlEntityId, SamlNameIdFormat, SamlRequestId,
    SamlServiceProviderId, SealedSecret, SessionId, SessionIndex, Setting, TokenHash, UserId,
};
use time::Duration;

use crate::test_support::rows::at;

/// `text` as an HTTPS address.
#[must_use]
pub fn url(text: &str) -> HttpsUrl {
    HttpsUrl::new(text).expect("a valid url")
}

/// SAML settings for Okta: unsigned requests, readable assertions, no
/// metadata address.
#[must_use]
pub fn saml_settings() -> SamlConfig {
    SamlConfig {
        entity_id: url("https://acme.okta.com/saml"),
        sso_url: url("https://acme.okta.com/saml/sso"),
        slo_url: Setting::Unset,
        certificates: IdpCertificates::single(
            CertificatePem::new("-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----")
                .expect("a valid certificate"),
        ),
        name_id_format: SamlNameIdFormat::new(SamlNameIdFormat::PERSISTENT)
            .expect("a valid format"),
        request_signing: AuthnRequestSigning::Unsigned,
        assertion_decryption: AssertionDecryption::NotExpected,
        metadata_url: Setting::Unset,
    }
}

/// [`saml_settings`] as a connection's settings.
#[must_use]
pub fn saml_config() -> ConnectionConfig {
    ConnectionConfig::Saml(Box::new(saml_settings()))
}

/// [`saml_settings`] read again from the metadata Okta publishes at
/// `address`.
#[must_use]
pub fn saml_config_following(address: &str) -> ConnectionConfig {
    ConnectionConfig::Saml(Box::new(SamlConfig {
        metadata_url: Setting::Set(PublicHttpsUrl::new(address).expect("a public url")),
        ..saml_settings()
    }))
}

/// OIDC settings for Okta, its client secret already sealed.
#[must_use]
pub fn oidc_config() -> ConnectionConfig {
    ConnectionConfig::Oidc(OidcConfig {
        issuer: url("https://acme.okta.com"),
        client_id: Label::new("client_id", "ianua-app").expect("a valid client id"),
        encrypted_client_secret: SealedSecret::new("v1.sealedclientsecret")
            .expect("a valid sealed secret"),
        scopes: vec![
            ScopeToken::new("openid").expect("a valid scope"),
            ScopeToken::new("email").expect("a valid scope"),
        ],
    })
}

/// An active connection called `name`, reached through `config`, making no
/// accounts, trusting nothing it says, vouching for no domain, mapping no
/// claim and no group, made at the fixed moment.
#[must_use]
pub fn connection_row(name: &str, config: ConnectionConfig) -> ConnectionRow {
    ConnectionRow {
        id: ConnectionId::new(),
        provider_name: Label::new("provider_name", name).expect("a valid name"),
        status: ConnectionStatus::Active,
        config,
        jit_provisioning: JitProvisioning::Disabled,
        jit_default_role_id: Setting::Unset,
        email_trust: EmailTrust::Unverified,
        assurance_trust: AssuranceTrust::Untrusted,
        domain_hint: Setting::Unset,
        allowed_domains: Vec::new(),
        attribute_mapping: HashMap::new(),
        group_mapping: GroupMapping::Off,
        created_at: at(0),
        keyed_at: at(0),
    }
}

/// `subject` at `connection`'s provider linked to `user` at the fixed
/// moment, and not confirmed since.
#[must_use]
pub fn link_row(connection: ConnectionId, subject: &str, user: UserId) -> FederatedLinkRow {
    FederatedLinkRow {
        connection_id: connection,
        subject: FederatedSubject::new(subject).expect("a valid subject"),
        user_id: user,
        linked_at: at(0),
        confirmed_at: at(0),
    }
}

/// A sign-in through `connection` started now, waiting on the provider.
#[must_use]
pub fn oidc_flow(connection: ConnectionId) -> OidcLoginFlow {
    OidcLoginFlow {
        connection_id: connection,
        nonce: Nonce::new("n".repeat(32)).expect("a valid nonce"),
        pkce_verifier: Secret::new("pkce-verifier-0123456789abcdefghijklmnopqrstuvwxyz"),
        redirect_uri: url("https://acme.ianua.example/callback"),
        binding_hash: TokenHash::from_stored("browser-binding-hash".to_owned()),
        dashboard_hash: TokenHash::from_stored("dashboard-hash".to_owned()),
    }
}

/// A SAML sign-in request sent through `connection`.
#[must_use]
pub fn saml_login_request(connection: ConnectionId) -> SamlLoginRequest {
    SamlLoginRequest {
        connection_id: connection,
        binding_hash: TokenHash::from_stored("browser-binding-hash".to_owned()),
        dashboard_hash: TokenHash::from_stored("dashboard-hash".to_owned()),
    }
}

/// A logout request `id` sent now to Okta for `name_id`, its answer taken
/// for ten minutes.
#[must_use]
pub fn sent_logout_row(id: &str, name_id: &str) -> SentLogoutRequestRow {
    let now = clock::now();
    SentLogoutRequestRow {
        id: SamlRequestId::new(id).expect("a valid request id"),
        peer: SamlEntityId::new("https://acme.okta.com/saml").expect("a valid entity id"),
        destination: url("https://acme.okta.com/saml/slo"),
        name_id_format: SamlNameIdFormat::new(SamlNameIdFormat::PERSISTENT)
            .expect("a valid format"),
        name_id: SamlNameIdValue::new(name_id).expect("a valid name id"),
        session_index: SessionIndex::new("_idp-session-1").expect("a valid session index"),
        sent_at: now,
        expires_at: now.saturating_add(Duration::minutes(10)),
    }
}

/// The session Okta keeps for `subject` behind `session`, signed in
/// through `connection`.
#[must_use]
pub fn provider_session(
    session: SessionId,
    connection: ConnectionId,
    subject: &str,
) -> ProviderSession {
    ProviderSession {
        session_id: session,
        connection_id: connection,
        subject: FederatedSubject::new(subject).expect("a valid subject"),
        session_index: SessionIndex::new("_idp-session-1").expect("a valid session index"),
    }
}

/// An active SAML app called `name`, naming itself `entity_id`, sent the
/// address and display name, answered with a signed assertion at its one
/// address.
#[must_use]
pub fn service_provider_row(name: &str, entity_id: &str) -> SamlServiceProviderRow {
    SamlServiceProviderRow {
        id: SamlServiceProviderId::new(),
        name: Label::new("name", name).expect("a valid name"),
        entity_id: SamlEntityId::new(entity_id).expect("a valid entity id"),
        status: ConnectionStatus::Active,
        settings: SamlServiceProviderSettings {
            acs_urls: AcsUrls::new(url("https://app.acme.example/acs"), Vec::new())
                .expect("valid addresses"),
            logout_url: Setting::Unset,
            name_id_format: NameIdFormat::Persistent,
            attributes: AttributeStatements::standard().expect("the standard statements"),
            signing: SignedParts::Assertion,
            encryption: AssertionEncryption::Plain,
            request_signing: RequestSigningRule::NotRequired,
        },
        created_at: at(0),
        updated_at: at(0),
    }
}

/// `session` signed in to `provider` as `name_id`, under `session_index`.
#[must_use]
pub fn app_session(
    session: SessionId,
    provider: SamlServiceProviderId,
    name_id: &str,
    session_index: &str,
) -> SamlAppSession {
    SamlAppSession {
        session_id: session,
        provider_id: provider,
        name_id: SamlNameIdValue::new(name_id).expect("a valid name id"),
        session_index: SessionIndex::new(session_index).expect("a valid session index"),
    }
}

/// A sign-in request posted by an app just now, with what it wants back.
#[must_use]
pub fn held_sign_in(message: &str) -> HeldSamlSignIn {
    HeldSamlSignIn {
        id: SamlArrivalId::new(),
        message: InboundSamlMessage {
            binding: SamlBinding::Post,
            message: message.to_owned(),
        },
        relay_state: Some("dashboard-state".to_owned()),
        arrived_at: clock::now(),
    }
}

/// The tenant's SCIM endpoint under the token hash `hash`, switched on,
/// giving no role, activating at once and switching off removed accounts,
/// set up at the fixed moment and never synced.
#[must_use]
pub fn scim_endpoint_row(hash: &str) -> ScimEndpointRow {
    ScimEndpointRow {
        bearer_token_hash: TokenHash::from_stored(hash.to_owned()),
        enabled: Enablement::Enabled,
        default_role_id: Setting::Unset,
        auto_activate: ScimActivation::Immediate,
        deactivate_on_remove: ScimRemoval::Deactivate,
        last_sync_at: None,
        created_at: at(0),
    }
}
