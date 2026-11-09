//! The SAML messages this platform sends as a connection's service
//! provider: sign-in requests by HTTP-Redirect, signed on the query when
//! the connection says so, and the metadata a provider imports to trust it.
//!
//! Each request carries a fresh random id, which also rides along as the
//! `RelayState`, so the answer names the request it is for. The metadata
//! asks for signed assertions, names the certificate requests are signed
//! with, and lists only the ciphers this platform opens sealed assertions
//! with.

use ianua_app::ports::federation::{
    RequestSigningCertificate, RequestSigningKey, SamlRedirect, SamlServiceProviderMessages,
    ServiceProvider, SpMetadataTerms,
};
use ianua_domain::domains::federation::connection::{AssertionDecryption, SamlConfig};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{CertificatePem, HttpsUrl, SamlRequestId};
use time::format_description::well_known::Iso8601;

use crate::saml::encryption::{AES128_GCM, AES256_GCM, RSA_OAEP, RSA_OAEP_MGF1P};
use crate::saml::metadata::POST_BINDING;
use crate::saml::redirect::request_query;
use crate::saml::xml::document::{ASSERTION, DSIG, METADATA, PROTOCOL, escaped};
use crate::saml::xml::keys::{PrivateKey, random_bytes};

/// Builds sign-in requests for the HTTP-Redirect binding, and the
/// service provider's metadata.
#[derive(Debug, Clone, Copy, Default)]
pub struct RedirectSamlServiceProviderMessages;

impl SamlServiceProviderMessages for RedirectSamlServiceProviderMessages {
    fn sign_in_request(
        &self,
        config: &SamlConfig,
        service_provider: &ServiceProvider,
        key: RequestSigningKey<'_>,
    ) -> Result<SamlRedirect, DomainError> {
        let request_id = fresh_request_id()?;
        let xml = authn_request(&request_id, config, service_provider)?;
        let signer = match key {
            RequestSigningKey::Unsigned => None,
            RequestSigningKey::SignedWith(key) => Some(PrivateKey::of(&key)?),
        };
        let query = request_query(&xml, request_id.as_str(), signer.as_ref())?;
        let address = config.sso_url.as_str();
        let separator = if address.contains('?') { '&' } else { '?' };
        let url =
            HttpsUrl::new(format!("{address}{separator}{query}")).map_err(DomainError::infra)?;
        Ok(SamlRedirect { url, request_id })
    }

    fn metadata(&self, service_provider: &ServiceProvider, terms: &SpMetadataTerms<'_>) -> String {
        let signs_requests = matches!(
            terms.request_signing,
            RequestSigningCertificate::SignedBy(_)
        );
        let mut keys = String::new();
        if let RequestSigningCertificate::SignedBy(certificate) = &terms.request_signing {
            keys.push_str(&key_descriptor("signing", certificate, ""));
        }
        if let AssertionDecryption::Required(key) = terms.decryption {
            keys.push_str(&key_descriptor(
                "encryption",
                key.certificate(),
                &encryption_methods(),
            ));
        }
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="{METADATA}" xmlns:ds="{DSIG}" entityID="{entity_id}"><md:SPSSODescriptor AuthnRequestsSigned="{signs_requests}" WantAssertionsSigned="true" protocolSupportEnumeration="{PROTOCOL}">{keys}<md:SingleLogoutService Binding="{POST_BINDING}" Location="{slo}"/><md:NameIDFormat>{format}</md:NameIDFormat><md:AssertionConsumerService Binding="{POST_BINDING}" Location="{acs}" index="0" isDefault="true"/></md:SPSSODescriptor></md:EntityDescriptor>"#,
            entity_id = escaped(service_provider.entity_id.as_str()),
            slo = escaped(terms.slo_url.as_str()),
            format = escaped(terms.name_id_format.as_str()),
            acs = escaped(service_provider.acs_url.as_str()),
        )
    }
}

/// A new request id: `_` and 128 random bits in hex.
fn fresh_request_id() -> Result<SamlRequestId, DomainError> {
    let bits = random_bytes::<16>()?;
    SamlRequestId::new(format!("_{}", data_encoding::HEXLOWER.encode(&bits)))
        .map_err(DomainError::infra)
}

/// The `AuthnRequest` asking `config`'s provider to answer
/// `service_provider` under `request_id`, by HTTP-POST, now. Every value
/// written into it is escaped.
fn authn_request(
    request_id: &SamlRequestId,
    config: &SamlConfig,
    service_provider: &ServiceProvider,
) -> Result<String, DomainError> {
    let now = clock::now()
        .format(&Iso8601::DEFAULT)
        .map_err(DomainError::infra)?;
    Ok(format!(
        r#"<samlp:AuthnRequest xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}" ID="{id}" Version="2.0" IssueInstant="{now}" Destination="{destination}" AssertionConsumerServiceURL="{acs}" ProtocolBinding="{POST_BINDING}"><saml:Issuer>{issuer}</saml:Issuer><samlp:NameIDPolicy Format="{format}" AllowCreate="true"/></samlp:AuthnRequest>"#,
        id = escaped(request_id.as_str()),
        destination = escaped(config.sso_url.as_str()),
        acs = escaped(service_provider.acs_url.as_str()),
        issuer = escaped(service_provider.entity_id.as_str()),
        format = escaped(config.name_id_format.as_str()),
    ))
}

/// A `KeyDescriptor` for `purpose` carrying `certificate`, `methods`
/// after it.
fn key_descriptor(purpose: &str, certificate: &CertificatePem, methods: &str) -> String {
    format!(
        r#"<md:KeyDescriptor use="{purpose}"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>{methods}</md:KeyDescriptor>"#,
        certificate.base64_body()
    )
}

/// The ciphers a provider may seal assertions with, as metadata lists
/// them: only those this platform opens.
fn encryption_methods() -> String {
    [AES256_GCM, AES128_GCM, RSA_OAEP_MGF1P, RSA_OAEP]
        .iter()
        .map(|method| format!(r#"<md:EncryptionMethod Algorithm="{method}"/>"#))
        .collect()
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
    use ianua_domain::domains::federation::connection::{
        AuthnRequestSigning, IdpCertificates, SpEncryptionKey,
    };
    use ianua_domain::types::{SamlEntityId, SamlNameIdFormat, SealedSecret, Setting};
    use roxmltree::{Document, Node};

    use super::*;
    use crate::saml::redirect::{SignedQuery, checked};
    use crate::saml::xml::document::from_deflated_base64;
    use crate::saml::xml::keys::tests::TestKey;
    use crate::saml::xml::signature::SignatureCheck;

    const PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

    fn config(sso: &str) -> SamlConfig {
        let idp = TestKey::new(SigningAlgorithm::Es256);
        SamlConfig {
            entity_id: HttpsUrl::new("https://idp.acme.com").unwrap(),
            sso_url: HttpsUrl::new(sso).unwrap(),
            slo_url: Setting::Unset,
            certificates: IdpCertificates::single(idp.certificate),
            name_id_format: SamlNameIdFormat::new(PERSISTENT).unwrap(),
            request_signing: AuthnRequestSigning::Unsigned,
            assertion_decryption: AssertionDecryption::NotExpected,
            metadata_url: Setting::Unset,
        }
    }

    fn service_provider() -> ServiceProvider {
        ServiceProvider {
            entity_id: SamlEntityId::new("https://ianua.example.com").unwrap(),
            acs_url: HttpsUrl::new("https://ianua.example.com/acs?tenant=a&b=c").unwrap(),
        }
    }

    fn parameter(url: &HttpsUrl, name: &str) -> String {
        url::Url::parse(url.as_str())
            .unwrap()
            .query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
            .unwrap_or_default()
    }

    /// A sign-in request goes to the provider's endpoint, its id riding
    /// along as the relay state, and asks for an answer at this platform's
    /// address in the connection's `NameID` format.
    #[test]
    fn a_sign_in_request_names_this_platform_and_its_id() {
        let redirect = RedirectSamlServiceProviderMessages
            .sign_in_request(
                &config("https://idp.acme.com/sso"),
                &service_provider(),
                RequestSigningKey::Unsigned,
            )
            .unwrap();

        let xml = from_deflated_base64(&parameter(&redirect.url, "SAMLRequest")).unwrap();
        let document = Document::parse(&xml).unwrap();
        let root = document.root_element();
        assert!(
            redirect
                .url
                .as_str()
                .starts_with("https://idp.acme.com/sso?SAMLRequest=")
        );
        assert_eq!(
            parameter(&redirect.url, "RelayState"),
            redirect.request_id.as_str()
        );
        assert_eq!(root.attribute("ID"), Some(redirect.request_id.as_str()));
        assert_eq!(
            root.attribute("AssertionConsumerServiceURL"),
            Some("https://ianua.example.com/acs?tenant=a&b=c")
        );
        assert!(xml.contains(PERSISTENT));
    }

    /// Ampersands in the issuer and destination survive an XML round trip;
    /// the request also retains its POST binding, version and persistent-name format.
    #[test]
    fn a_request_holds_each_value_as_given() {
        let asking = ServiceProvider {
            entity_id: SamlEntityId::new("https://ianua.example.com/sp?a=1&b=2").unwrap(),
            acs_url: HttpsUrl::new("https://ianua.example.com/acs?tenant=a&b=c").unwrap(),
        };
        let redirect = RedirectSamlServiceProviderMessages
            .sign_in_request(
                &config("https://idp.acme.com/sso?x=1&y=2"),
                &asking,
                RequestSigningKey::Unsigned,
            )
            .unwrap();

        let xml = from_deflated_base64(&parameter(&redirect.url, "SAMLRequest")).unwrap();
        let document = Document::parse(&xml).unwrap();
        let root = document.root_element();
        assert_request_values(root);
    }

    /// Checks escaped addresses and the protocol fields of the parsed request.
    fn assert_request_values(root: Node<'_, '_>) {
        let issuer = root
            .children()
            .find(|node| node.has_tag_name((ASSERTION, "Issuer")))
            .and_then(|node| node.text());
        let policy = root
            .children()
            .find(|node| node.has_tag_name((PROTOCOL, "NameIDPolicy")))
            .and_then(|node| node.attribute("Format"));
        assert_eq!(
            root.attribute("Destination"),
            Some("https://idp.acme.com/sso?x=1&y=2")
        );
        assert_eq!(root.attribute("ProtocolBinding"), Some(POST_BINDING));
        assert_eq!(root.attribute("Version"), Some("2.0"));
        assert!(
            root.attribute("IssueInstant")
                .is_some_and(|at| at.ends_with('Z'))
        );
        assert_eq!(issuer, Some("https://ianua.example.com/sp?a=1&b=2"));
        assert_eq!(policy, Some(PERSISTENT));
    }

    /// Two requests never share an id, so one answer cannot finish both.
    #[test]
    fn every_request_has_its_own_id() {
        let messages = RedirectSamlServiceProviderMessages;
        let config = config("https://idp.acme.com/sso");

        let first = messages
            .sign_in_request(&config, &service_provider(), RequestSigningKey::Unsigned)
            .unwrap();
        let second = messages
            .sign_in_request(&config, &service_provider(), RequestSigningKey::Unsigned)
            .unwrap();

        assert_ne!(first.request_id, second.request_id);
    }

    /// A signed request carries a query signature the provider checks
    /// against the tenant's certificate.
    #[test]
    fn a_signed_request_verifies_against_the_tenants_key() {
        let key = TestKey::new(SigningAlgorithm::Rs256);

        let redirect = RedirectSamlServiceProviderMessages
            .sign_in_request(
                &config("https://idp.acme.com/sso?app=1"),
                &service_provider(),
                RequestSigningKey::SignedWith(key.signing()),
            )
            .unwrap();

        let address = url::Url::parse(redirect.url.as_str()).unwrap();
        let algorithm = parameter(&redirect.url, "SigAlg");
        let signature = parameter(&redirect.url, "Signature");
        let signed = SignedQuery {
            algorithm: &algorithm,
            signature: &signature,
            query: address.query().unwrap(),
        };
        let message = parameter(&redirect.url, "SAMLRequest");
        assert_eq!(
            checked(&signed, &message, &[key.trusted()]),
            Ok(SignatureCheck::Verified)
        );
        assert!(redirect.url.as_str().contains("?app=1&SAMLRequest="));
    }

    /// The metadata names this platform and where answers and logouts go,
    /// asks for signed assertions, names the request signing certificate,
    /// and lists only the ciphers sealed assertions are opened with.
    #[test]
    fn the_metadata_says_how_to_answer_this_platform() {
        let signing = TestKey::new(SigningAlgorithm::Rs256).certificate;
        let sealing = TestKey::new(SigningAlgorithm::Rs256).certificate;
        let xml = metadata_with_keys(&signing, &sealing);

        let document = Document::parse(&xml).unwrap();
        let acs = document
            .descendants()
            .find(|node| node.has_tag_name((METADATA, "AssertionConsumerService")))
            .unwrap();
        assert_eq!(
            acs.attribute("Location"),
            Some("https://ianua.example.com/acs?tenant=a&b=c")
        );
        assert!(xml.contains(r#"AuthnRequestsSigned="true""#));
        assert!(xml.contains(r#"WantAssertionsSigned="true""#));
        assert!(xml.contains(&signing.base64_body()));
        assert!(xml.contains(&sealing.base64_body()));
        assert!(xml.contains(AES256_GCM));
        assert!(!xml.contains("cbc"));
    }

    /// Builds metadata requiring signed requests and assertions encrypted to the given key.
    fn metadata_with_keys(signing: &CertificatePem, sealing: &CertificatePem) -> String {
        let decryption = AssertionDecryption::Required(SpEncryptionKey::new(
            sealing.clone(),
            SealedSecret::new("v1.sealed").unwrap(),
        ));
        let format = SamlNameIdFormat::new(PERSISTENT).unwrap();
        let slo = HttpsUrl::new("https://ianua.example.com/slo").unwrap();

        RedirectSamlServiceProviderMessages.metadata(
            &service_provider(),
            &SpMetadataTerms {
                name_id_format: &format,
                request_signing: RequestSigningCertificate::SignedBy(signing.clone()),
                decryption: &decryption,
                slo_url: &slo,
            },
        )
    }
}
