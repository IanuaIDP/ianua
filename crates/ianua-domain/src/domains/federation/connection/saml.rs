//! What only a SAML connection does: take its provider's metadata, roll
//! over to the provider's next certificate, insist on encrypted
//! assertions, and log people out with the provider both ways.

use crate::domains::federation::connection::FederatedIdpConnection;
use crate::domains::federation::connection::config::{ConnectionConfig, SamlConfig};
use crate::domains::federation::connection::metadata::ImportedIdpMetadata;
use crate::domains::federation::connection::saml_keys::AssertionDecryption;
use crate::domains::federation::control::{FederationControl, FederationRight};
use crate::domains::federation::saml::assertion::{AssertionDelivery, SamlAssertion};
use crate::domains::federation::saml::logout::{
    LogoutAnswer, LogoutPeer, LogoutSubject, SamlLogoutRequest, SentLogoutRequest,
};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{FederatedSubject, HttpsUrl, SamlEntityId, SessionIndex, Setting};

/// A logout the provider asked for: whom to log out, which of their
/// sessions, and where the answer goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderLogout {
    subject: FederatedSubject,
    session_indexes: Vec<SessionIndex>,
    answer: LogoutAnswer,
}

impl ProviderLogout {
    /// Who the provider names, as the connection's links know them.
    #[must_use]
    pub fn subject(&self) -> &FederatedSubject {
        &self.subject
    }

    /// The provider's sessions to end. Empty asks for every session of the
    /// person begun through this connection.
    #[must_use]
    pub fn session_indexes(&self) -> &[SessionIndex] {
        &self.session_indexes
    }

    /// Where the answer goes, and what it answers.
    #[must_use]
    pub fn answer(&self) -> &LogoutAnswer {
        &self.answer
    }
}

impl<T: TenantScope> FederatedIdpConnection<T> {
    /// Takes the provider's endpoints and certificates from its metadata,
    /// keeping this connection's choices of format, signing and
    /// encryption.
    ///
    /// The metadata must name the provider this connection already signs
    /// in through. A certificate it brings that the connection did not take
    /// re-keys the connection, as [`update_config`](Self::update_config)
    /// says. Raises `federation.connection_updated`, once per save however
    /// many settings change.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not manage
    ///   federation.
    /// - [`DomainError::Conflict`] when this is not a SAML connection, or
    ///   the metadata names another provider.
    pub fn import_metadata(
        &mut self,
        metadata: ImportedIdpMetadata,
        control: &FederationControl<'_>,
    ) -> Result<(), DomainError> {
        control.ensure_may(FederationRight::TrustConnection)?;
        let saml = self.saml()?.clone();
        self.update_config(
            ConnectionConfig::Saml(Box::new(metadata.applied_to(saml))),
            control,
        )
    }

    /// Takes the provider's endpoints and certificates from the metadata it
    /// publishes at the address this connection follows, for the
    /// platform's scheduled refresh. Nobody acts: the admin chose to trust
    /// that address when they made the connection from it.
    ///
    /// The metadata must come from that address and name the provider this
    /// connection already signs in through. A certificate it brings that
    /// the connection did not take re-keys the connection, as
    /// [`update_config`](Self::update_config) says. Metadata that changes
    /// nothing raises nothing; one that does raises
    /// `federation.connection_updated`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when this is not a SAML connection, it
    ///   follows no address or another one, or the metadata names another
    ///   provider.
    pub fn refresh_metadata(&mut self, metadata: ImportedIdpMetadata) -> Result<(), DomainError> {
        let saml = self.saml()?.clone();
        let Setting::Set(followed) = &saml.metadata_url else {
            return Err(DomainError::conflict(message!(
                "federation-the-connection-follows-no-metadata-address",
                "the connection follows no metadata address"
            )));
        };
        if metadata.source() != &Setting::Set(followed.clone()) {
            return Err(DomainError::conflict(message!(
                "federation-the-metadata-came-from-another-address",
                "the metadata came from another address than the connection follows"
            )));
        }
        if metadata.entity_id() != &saml.entity_id {
            return Err(DomainError::conflict(message!(
                "federation-the-published-metadata-names-another-provider",
                "the published metadata names another provider"
            )));
        }
        let config = ConnectionConfig::Saml(Box::new(metadata.applied_to(saml)));
        if config == self.config {
            return Ok(());
        }
        if config.brings_new_signer(&self.config) {
            self.keyed_at = crate::shared::clock::now();
        }
        self.config = config;
        self.settings_changed();
        Ok(())
    }

    /// Takes the provider's next certificate as its only one, once the
    /// provider switched to it. The old one is no longer taken.
    ///
    /// Nobody new may sign answers, so it needs only the update right and
    /// re-keys nothing. Raises `federation.connection_updated`, once per
    /// save however many settings change.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not update
    ///   connections.
    /// - [`DomainError::Conflict`] when this is not a SAML connection, or no
    ///   next certificate is set.
    pub fn roll_over_certificate(
        &mut self,
        control: &FederationControl<'_>,
    ) -> Result<(), DomainError> {
        control.ensure_may(FederationRight::EditConnection)?;
        let ConnectionConfig::Saml(saml) = &mut self.config else {
            return Err(not_saml());
        };
        saml.certificates = saml.certificates.rolled_over()?;
        self.settings_changed();
        Ok(())
    }

    /// Refuses a readable assertion when this connection requires them
    /// encrypted.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when this is not a SAML connection.
    /// - [`DomainError::Forbidden`] when the assertion came readable and the
    ///   connection requires it encrypted.
    pub fn ensure_delivered_as_required(
        &self,
        assertion: &SamlAssertion,
    ) -> Result<(), DomainError> {
        match (&self.saml()?.assertion_decryption, assertion.delivery()) {
            (AssertionDecryption::Required(_), AssertionDelivery::Readable) => {
                Err(DomainError::forbidden(message!(
                    "federation-this-connection-takes-only-encrypted-assertions",
                    "this connection takes only encrypted assertions"
                )))
            }
            (AssertionDecryption::Required(_), AssertionDelivery::Encrypted)
            | (AssertionDecryption::NotExpected, _) => Ok(()),
        }
    }

    /// The logout the provider's `request` asks for, once it came from this
    /// connection's provider.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when this is not a SAML connection, or it
    ///   has no logout endpoint to answer at.
    /// - [`DomainError::Forbidden`] when the request names another issuer
    ///   than the provider.
    /// - [`DomainError::Validation`] when the `NameID` cannot name a
    ///   subject.
    pub fn accept_logout(
        &self,
        request: &SamlLogoutRequest,
    ) -> Result<ProviderLogout, DomainError> {
        let saml = self.saml()?;
        if request.issuer().as_str() != saml.entity_id.as_str() {
            return Err(DomainError::forbidden(message!(
                "federation-this-logout-request-does-not-come",
                "this logout request does not come from the connection's provider"
            )));
        }
        Ok(ProviderLogout {
            subject: FederatedSubject::new(request.name_id().as_str())?,
            session_indexes: request.session_indexes().to_vec(),
            answer: request.answered_at(logout_endpoint(saml)?.clone()),
        })
    }

    /// A logout request asking the provider to end `subject`'s session, to
    /// keep until the provider answers.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when this is not a SAML connection, or it
    ///   has no logout endpoint.
    pub fn logout_request(&self, subject: LogoutSubject) -> Result<SentLogoutRequest, DomainError> {
        let saml = self.saml()?;
        let to = LogoutPeer {
            peer: SamlEntityId::new(saml.entity_id.as_str())?,
            destination: logout_endpoint(saml)?.clone(),
            name_id_format: saml.name_id_format.clone(),
        };
        Ok(SentLogoutRequest::sent(to, subject))
    }

    /// The SAML configuration.
    fn saml(&self) -> Result<&SamlConfig, DomainError> {
        let ConnectionConfig::Saml(saml) = &self.config else {
            return Err(not_saml());
        };
        Ok(saml)
    }
}

/// The provider's logout endpoint.
fn logout_endpoint(saml: &SamlConfig) -> Result<&HttpsUrl, DomainError> {
    saml.slo_url.value().ok_or_else(|| {
        DomainError::conflict(message!(
            "federation-the-provider-has-no-logout-endpoint",
            "the provider has no logout endpoint"
        ))
    })
}

fn not_saml() -> DomainError {
    DomainError::conflict(message!(
        "federation-this-is-not-a-saml-connection",
        "this is not a SAML connection"
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::domains::authorization::permission::{FederationAction, SystemPermission};
    use crate::domains::federation::connection::metadata::IdpMetadataFacts;
    use crate::domains::federation::connection::saml_keys::{IdpCertificates, SpEncryptionKey};
    use crate::domains::federation::fixtures::{federation_admin, holding, saml_config};
    use crate::domains::federation::provider_values::ProviderValues;
    use crate::domains::federation::saml::assertion::AssertionFacts;
    use crate::domains::federation::saml::logout::LogoutRequestParts;
    use crate::domains::federation::saml::name_id::SamlNameIdValue;
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::builders::label;
    use crate::test_support::events::raised_names;
    use crate::types::{
        CertificatePem, ConnectionId, Email, Fact, SamlAssertionId, SamlRequestId, SealedSecret,
        Setting,
    };

    const EDITOR: [SystemPermission; 1] = [SystemPermission::Federation(FederationAction::Update)];

    fn certificate(body: &str) -> CertificatePem {
        CertificatePem::new(format!(
            "-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----"
        ))
        .unwrap()
    }

    fn url(s: &str) -> HttpsUrl {
        HttpsUrl::new(s).unwrap()
    }

    fn okta_with(edit: impl FnOnce(&mut SamlConfig)) -> FederatedIdpConnection<ResolvedTenant> {
        let ConnectionConfig::Saml(mut saml) = saml_config() else {
            panic!("a SAML configuration");
        };
        edit(&mut saml);
        let mut conn = FederatedIdpConnection::create(
            ConnectionId::new(),
            label("Okta"),
            ConnectionConfig::Saml(saml),
            &federation_admin(),
        )
        .unwrap();
        raised_names(&mut conn);
        conn
    }

    fn okta() -> FederatedIdpConnection<ResolvedTenant> {
        okta_with(|saml| saml.slo_url = Setting::Set(url("https://idp.acme.com/slo")))
    }

    fn metadata(entity_id: &str, certificates: Vec<CertificatePem>) -> ImportedIdpMetadata {
        ImportedIdpMetadata::new(IdpMetadataFacts {
            entity_id: url(entity_id),
            sso_url: url("https://idp.acme.com/sso/v2"),
            slo_url: Setting::Set(url("https://idp.acme.com/slo/v2")),
            signing_certificates: certificates,
        })
        .unwrap()
    }

    fn saml_of(conn: &FederatedIdpConnection<ResolvedTenant>) -> &SamlConfig {
        conn.saml().unwrap()
    }

    /// Okta's metadata now lists a new SSO endpoint and its next
    /// certificate. Importing it takes both, keeps the connection's own
    /// choices, re-keys it for the new certificate and raises one update.
    #[test]
    fn importing_metadata_replaces_the_endpoints_and_certificates() {
        let start = crate::shared::clock::now();
        let _then = crate::shared::clock::freeze(start);
        let mut conn = okta();
        let _later = crate::shared::clock::freeze(start + time::Duration::minutes(1));

        conn.import_metadata(
            metadata(
                "https://idp.acme.com",
                vec![certificate("MIIC"), certificate("MIID")],
            ),
            &federation_admin(),
        )
        .unwrap();

        let saml = saml_of(&conn);
        assert_eq!(saml.sso_url.as_str(), "https://idp.acme.com/sso/v2");
        assert!(saml.certificates.accepts(&certificate("MIID")));
        assert!(saml.name_id_format.names_one_person_for_good());
        assert_eq!(conn.keyed_at(), start + time::Duration::minutes(1));
        assert_eq!(raised_names(&mut conn), ["federation.connection_updated"]);
    }

    const OKTA_METADATA: &str = "https://idp.acme.com/metadata";

    fn published_by_okta(certificates: Vec<CertificatePem>) -> ImportedIdpMetadata {
        metadata("https://idp.acme.com", certificates)
            .published_at(crate::types::PublicHttpsUrl::new(OKTA_METADATA).unwrap())
    }

    /// Acme's Okta connection, made from the metadata Okta publishes.
    fn following_okta() -> FederatedIdpConnection<ResolvedTenant> {
        okta_with(|saml| {
            saml.metadata_url =
                Setting::Set(crate::types::PublicHttpsUrl::new(OKTA_METADATA).unwrap());
        })
    }

    /// Okta rolls its key over and publishes the next certificate. The
    /// scheduled refresh takes it, with nobody acting, re-keys the
    /// connection, and raises one update.
    #[test]
    fn a_refresh_takes_the_published_certificates() {
        let mut conn = following_okta();

        conn.refresh_metadata(published_by_okta(vec![
            certificate("MIIC"),
            certificate("MIID"),
        ]))
        .unwrap();

        assert!(saml_of(&conn).certificates.accepts(&certificate("MIID")));
        assert_eq!(raised_names(&mut conn), ["federation.connection_updated"]);
    }

    /// Okta's metadata says what it said before, so nothing changes and
    /// nothing is raised.
    #[test]
    fn a_refresh_that_changes_nothing_raises_nothing() {
        let mut conn = following_okta();
        conn.refresh_metadata(published_by_okta(vec![certificate("MIIC")]))
            .unwrap();
        raised_names(&mut conn);

        conn.refresh_metadata(published_by_okta(vec![certificate("MIIC")]))
            .unwrap();

        assert!(raised_names(&mut conn).is_empty());
    }

    /// Refreshing metadata conflicts with a connection that follows no
    /// metadata address.
    #[test]
    fn a_connection_following_no_address_is_not_refreshed() {
        let mut conn = okta();

        let result = conn.refresh_metadata(published_by_okta(vec![certificate("MIIE")]));

        assert!(matches!(result, Err(DomainError::Conflict(_))));
    }

    /// Metadata from the followed address naming another provider is
    /// refused, and its certificate is not accepted by the connection.
    #[test]
    fn a_refresh_naming_another_provider_is_refused() {
        let mut conn = following_okta();
        let evil = metadata("https://idp.evil.example.com", vec![certificate("MIIE")])
            .published_at(crate::types::PublicHttpsUrl::new(OKTA_METADATA).unwrap());

        let result = conn.refresh_metadata(evil);

        assert!(matches!(result, Err(DomainError::Conflict(_))));
        assert!(!saml_of(&conn).certificates.accepts(&certificate("MIIE")));
    }

    /// Importing another provider's metadata into Okta conflicts even for
    /// a federation administrator, and its certificate is not accepted.
    #[test]
    fn metadata_naming_another_provider_is_refused() {
        let mut conn = okta();

        let result = conn.import_metadata(
            metadata("https://idp.evil.example.com", vec![certificate("MIIE")]),
            &federation_admin(),
        );

        assert!(matches!(result, Err(DomainError::Conflict(_))));
        assert!(!saml_of(&conn).certificates.accepts(&certificate("MIIE")));
    }

    /// A connection editor is forbidden from importing metadata with a new
    /// signing certificate.
    #[test]
    fn importing_metadata_needs_the_full_right() {
        let mut conn = okta();

        let result = conn.import_metadata(
            metadata("https://idp.acme.com", vec![certificate("MIIE")]),
            &holding(&EDITOR),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Okta switched to its next certificate. An editor rolls the
    /// connection over: the old one is no longer taken, and nobody is asked
    /// to confirm their link again.
    #[test]
    fn rolling_over_takes_only_the_next_certificate() {
        let mut conn = okta_with(|saml| {
            saml.certificates =
                IdpCertificates::rolling_over(certificate("MIIC"), certificate("MIID")).unwrap();
        });
        let keyed_at = conn.keyed_at();

        conn.roll_over_certificate(&holding(&EDITOR)).unwrap();

        let saml = saml_of(&conn);
        assert!(!saml.certificates.accepts(&certificate("MIIC")));
        assert!(saml.certificates.accepts(&certificate("MIID")));
        assert_eq!(conn.keyed_at(), keyed_at);
    }

    fn assertion_delivered(delivery: AssertionDelivery) -> SamlAssertion {
        SamlAssertion::new(AssertionFacts {
            connection_id: ConnectionId::new(),
            assertion_id: SamlAssertionId::new("_a1").unwrap(),
            email: Email::new("ann@acme.com").unwrap(),
            name_id: FederatedSubject::new("00u1").unwrap(),
            session_index: Setting::Unset,
            delivery,
            authn_context: Fact::Unknown,
            attributes: ProviderValues::new(HashMap::new()),
        })
    }

    /// A connection requiring encryption forbids a readable assertion and
    /// accepts one delivered encrypted.
    #[test]
    fn a_readable_assertion_is_refused_where_encryption_is_required() {
        let conn = okta_with(|saml| {
            saml.assertion_decryption = AssertionDecryption::Required(SpEncryptionKey::new(
                certificate("MIIK"),
                SealedSecret::new("v1.key").unwrap(),
            ));
        });

        let readable =
            conn.ensure_delivered_as_required(&assertion_delivered(AssertionDelivery::Readable));
        let encrypted =
            conn.ensure_delivered_as_required(&assertion_delivered(AssertionDelivery::Encrypted));

        assert!(matches!(readable, Err(DomainError::Forbidden(_))));
        assert!(encrypted.is_ok());
    }

    fn logout_from(issuer: &str) -> SamlLogoutRequest {
        SamlLogoutRequest::new(LogoutRequestParts {
            id: SamlRequestId::new("_idp_logout").unwrap(),
            issuer: SamlEntityId::new(issuer).unwrap(),
            issued_at: crate::shared::clock::now(),
            name_id: SamlNameIdValue::new("00u1").unwrap(),
            session_indexes: vec![SessionIndex::new("_s1").unwrap()],
        })
    }

    /// Okta asks to log out `00u1` from session `_s1`. The logout names
    /// that subject and session, and the answer goes to Okta's endpoint.
    #[test]
    fn the_providers_logout_request_names_the_subject_and_session() {
        let logout = okta()
            .accept_logout(&logout_from("https://idp.acme.com"))
            .unwrap();

        assert_eq!(logout.subject().as_str(), "00u1");
        assert_eq!(logout.session_indexes().len(), 1);
        assert_eq!(
            logout.answer().destination().as_str(),
            "https://idp.acme.com/slo"
        );
    }

    /// Okta's connection forbids a logout request naming another provider
    /// as its issuer.
    #[test]
    fn a_logout_request_from_another_provider_is_refused() {
        let result = okta().accept_logout(&logout_from("https://idp.evil.example.com"));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A connection with no logout endpoint neither sends nor answers
    /// logout requests.
    #[test]
    fn a_connection_without_a_logout_endpoint_takes_no_logout() {
        let conn = okta_with(|_| {});

        let answered = conn.accept_logout(&logout_from("https://idp.acme.com"));
        let asked = conn.logout_request(LogoutSubject {
            request_id: SamlRequestId::new("_sp_logout").unwrap(),
            name_id: SamlNameIdValue::new("00u1").unwrap(),
            session_index: SessionIndex::new("_s1").unwrap(),
        });

        assert!(matches!(answered, Err(DomainError::Conflict(_))));
        assert!(matches!(asked, Err(DomainError::Conflict(_))));
    }

    /// A logout request to Okta goes to its endpoint, names Okta as the
    /// peer and waits for Okta's answer.
    #[test]
    fn a_logout_request_to_the_provider_waits_for_it() {
        let sent = okta()
            .logout_request(LogoutSubject {
                request_id: SamlRequestId::new("_sp_logout").unwrap(),
                name_id: SamlNameIdValue::new("00u1").unwrap(),
                session_index: SessionIndex::new("_s1").unwrap(),
            })
            .unwrap();

        assert_eq!(sent.peer().as_str(), "https://idp.acme.com");
        assert_eq!(sent.destination().as_str(), "https://idp.acme.com/slo");
    }
}
