//! Connections and controls the federation context's tests share.

use time::OffsetDateTime;

use crate::domains::authentication::risk_engine::assurance::AssuranceLevel;
use crate::domains::authorization::permission::SystemPermission;
use crate::domains::federation::connection::{
    AssertionDecryption, AuthnRequestSigning, ConnectionConfig, ConnectionDomains, EmailTrust,
    FederatedIdpConnection, IdpCertificates, JitProvisioning, SamlConfig, own_tenant, owned_domain,
};
use crate::domains::federation::control::FederationControl;
use crate::domains::federation::saml::assertion_builder::AssertionParams;
use crate::domains::federation::saml::name_id::{IssuedNameId, NameIdFormat};
use crate::domains::federation::scim::ScimEndpoint;
use crate::domains::federation::service_provider::ReleasedAttribute;
use crate::isolation::scope::ResolvedTenant;
use crate::test_support::authority::anyone_holding;
use crate::types::{
    CertificatePem, ConnectionId, HttpsUrl, Label, Lifetime, SamlAssertionId, SamlEntityId,
    SamlNameIdFormat, SamlRequestId, SessionIndex, Setting, TokenHash,
};

/// Someone changing a connection or SCIM who holds `system` and no custom
/// permission.
pub(crate) fn holding(system: &[SystemPermission]) -> FederationControl<'_> {
    FederationControl::new(anyone_holding(system))
}

/// A federation admin who holds every permission.
pub(crate) fn federation_admin() -> FederationControl<'static> {
    holding(SystemPermission::all())
}

/// A tenant's SCIM endpoint, just set up and switched on.
pub(crate) fn switched_on_directory() -> ScimEndpoint<ResolvedTenant> {
    ScimEndpoint::create(
        TokenHash::from_stored("scim".to_owned()),
        &federation_admin(),
    )
    .expect("an admin may set up SCIM")
}

/// The id of the connection to Acme's Okta.
pub(crate) fn okta() -> ConnectionId {
    ConnectionId::from_uuid(uuid::Uuid::from_u128(7))
}

/// The SAML configuration of Acme's Okta, signing with `certificate`.
pub(crate) fn saml_config_signed_by(certificate: &str) -> ConnectionConfig {
    ConnectionConfig::Saml(Box::new(SamlConfig {
        entity_id: HttpsUrl::new("https://idp.acme.com").expect("a test passes a valid url"),
        sso_url: HttpsUrl::new("https://idp.acme.com/sso").expect("a test passes a valid url"),
        slo_url: Setting::Unset,
        certificates: IdpCertificates::single(
            CertificatePem::new(certificate).expect("a test passes a valid certificate"),
        ),
        name_id_format: SamlNameIdFormat::new(SamlNameIdFormat::PERSISTENT)
            .expect("persistent is a valid format"),
        request_signing: AuthnRequestSigning::Unsigned,
        assertion_decryption: AssertionDecryption::NotExpected,
        metadata_url: Setting::Unset,
    }))
}

/// The SAML configuration of Acme's Okta, with its usual certificate.
pub(crate) fn saml_config() -> ConnectionConfig {
    saml_config_signed_by("-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----")
}

/// An active SAML connection to Acme's Okta, bound to `domain`, which the
/// tenant proved it owns, trusting addresses as `trust` says and making
/// accounts as `provisioning` says.
pub(crate) fn connection_for(
    domain: &str,
    trust: EmailTrust,
    provisioning: JitProvisioning,
) -> FederatedIdpConnection<ResolvedTenant> {
    connection_at(okta(), domain, trust, provisioning)
}

/// The same connection as [`connection_for`], under the id `id`.
pub(crate) fn connection_at(
    id: ConnectionId,
    domain: &str,
    trust: EmailTrust,
    provisioning: JitProvisioning,
) -> FederatedIdpConnection<ResolvedTenant> {
    let admin = federation_admin();
    let mut conn = FederatedIdpConnection::create(
        id,
        Label::new("name", "Okta").expect("a test passes a valid name"),
        saml_config(),
        &admin,
    )
    .expect("an admin may create a connection");
    conn.change_domains(
        ConnectionDomains {
            allowed: vec![owned_domain(domain)],
            hint: Setting::Unset,
        },
        &admin,
        own_tenant(),
    )
    .expect("the tenant proved the domain");
    conn.change_email_trust(trust, &admin)
        .expect("an admin may set how far addresses are trusted");
    let provisioned = match provisioning {
        JitProvisioning::Enabled => conn.provision_new_accounts(Setting::Unset, &admin),
        JitProvisioning::Disabled => conn.stop_provisioning(&admin),
    };
    provisioned.expect("an admin may choose whether accounts are made");
    conn
}

/// Alice's sign-in to `app.acme.com` through this IdP, answering request
/// `_authn_req_1`.
pub(crate) fn alice_assertion() -> AssertionParams {
    AssertionParams {
        assertion_id: SamlAssertionId::new("_assertion_1").unwrap(),
        issuer: SamlEntityId::new("https://auth.acme.com").unwrap(),
        sp_entity_id: SamlEntityId::new("https://app.acme.com").unwrap(),
        acs_url: HttpsUrl::new("https://app.acme.com/saml/acs").unwrap(),
        authenticated_at: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
        assurance: AssuranceLevel::Aal1,
        name_id: IssuedNameId::of(NameIdFormat::Persistent, "pairwise-alice"),
        attributes: vec![
            ReleasedAttribute::of("email", &["alice@acme.com"]),
            ReleasedAttribute::of("displayName", &["Alice Smith"]),
            ReleasedAttribute::of("department", &["Engineering"]),
        ],
        lifetime: Lifetime::seconds(300).unwrap(),
        session_index: SessionIndex::new("_session_1").unwrap(),
        in_response_to: Some(SamlRequestId::new("_authn_req_1").unwrap()),
    }
}
