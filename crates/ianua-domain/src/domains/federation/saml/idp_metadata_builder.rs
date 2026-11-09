//! Writes the IdP's SAML metadata, the `<EntityDescriptor>` SPs import.
//!
//! A Service Provider imports this document to trust this Identity
//! Provider. It holds the SSO endpoint, the signing certificate and the
//! supported bindings.

use crate::domains::federation::saml::name_id::NameIdFormat;
use crate::domains::federation::saml::xml::xml_escape;
use crate::types::{CertificatePem, HttpsUrl, SamlEntityId};

/// Parameters for building IdP SAML metadata.
pub struct IdpMetadataParams {
    /// The IdP's entity ID.
    pub entity_id: SamlEntityId,
    /// The SSO endpoint URL, advertised for both the HTTP-POST and
    /// HTTP-Redirect bindings.
    pub sso_url: HttpsUrl,
    /// The Single Logout endpoint URL, for the HTTP-POST binding only.
    /// `None` leaves logout out of the metadata.
    pub slo_url: Option<HttpsUrl>,
    /// The X.509 signing certificate, as PEM. The metadata carries only its
    /// base64 body, without the armour lines.
    pub signing_certificate: CertificatePem,
}

/// A built IdP SAML metadata XML document.
pub struct BuiltIdpMetadata {
    /// The metadata XML string.
    pub xml: String,
}

/// Builds an IdP SAML 2.0 metadata document (`<EntityDescriptor>`).
///
/// Follows the SAML 2.0 Metadata specification, saml-metadata-2.0-os. It
/// tells SPs the IdP does not need every AuthnRequest signed: each SAML
/// app's own settings say whether its requests must be.
///
/// It offers the persistent, email-address and transient `NameID` formats,
/// the ones a SAML app may be set up for. Each app is sent only its own.
#[must_use]
pub fn build_idp_metadata(params: &IdpMetadataParams) -> BuiltIdpMetadata {
    let slo_descriptor = params
        .slo_url
        .as_ref()
        .map(|url| {
            format!(
                r#"<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{url}"/>"#,
                url = xml_escape(url.as_str())
            )
        })
        .unwrap_or_default();
    let name_id_formats: String = NameIdFormat::ALL
        .into_iter()
        .map(|format| format!("<md:NameIDFormat>{}</md:NameIDFormat>", format.urn()))
        .collect();

    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="{entity_id}"><md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>{name_id_formats}{slo}<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{sso_url}"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{sso_url}"/></md:IDPSSODescriptor></md:EntityDescriptor>"#,
        entity_id = xml_escape(params.entity_id.as_str()),
        cert = xml_escape(&params.signing_certificate.base64_body()),
        slo = slo_descriptor,
        sso_url = xml_escape(params.sso_url.as_str()),
    );

    BuiltIdpMetadata { xml }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> IdpMetadataParams {
        IdpMetadataParams {
            entity_id: SamlEntityId::new("https://auth.acme.com").unwrap(),
            sso_url: HttpsUrl::new("https://auth.acme.com/saml/sso").unwrap(),
            slo_url: Some(HttpsUrl::new("https://auth.acme.com/saml/slo").unwrap()),
            signing_certificate: CertificatePem::new(
                "-----BEGIN CERTIFICATE-----\nMIIBxTCCAW\n-----END CERTIFICATE-----",
            )
            .unwrap(),
        }
    }

    /// Acme's admin downloads the metadata to import into an app. It is an
    /// `EntityDescriptor` holding an IdP SSO descriptor.
    #[test]
    fn builds_valid_entity_descriptor() {
        let result = build_idp_metadata(&params());
        assert!(result.xml.contains("EntityDescriptor"));
        assert!(result.xml.contains("IDPSSODescriptor"));
    }

    /// The metadata names `https://auth.acme.com` as its `entityID`, which the
    /// app then expects as the issuer of every assertion.
    #[test]
    fn includes_entity_id() {
        let result = build_idp_metadata(&params());
        assert!(result.xml.contains(r#"entityID="https://auth.acme.com""#));
    }

    /// The metadata carries the signing certificate's body, so the app can
    /// check the signature on each assertion.
    #[test]
    fn includes_signing_certificate() {
        let result = build_idp_metadata(&params());
        assert!(result.xml.contains("X509Certificate"));
        assert!(result.xml.contains("MIIBxTCCAW"));
    }

    /// Certificate text containing a closing XML tag and an injected
    /// element fails certificate construction.
    #[test]
    fn a_certificate_cannot_add_markup_to_the_metadata() {
        let forged = CertificatePem::new(
            "-----BEGIN CERTIFICATE-----\nMII</ds:X509Certificate><md:Injected/>\n-----END CERTIFICATE-----",
        );

        assert!(forged.is_err());
    }

    /// The certificate is given as PEM with its `BEGIN CERTIFICATE` lines.
    /// The metadata leaves those lines out, as `X509Certificate` expects.
    #[test]
    fn the_metadata_carries_the_certificate_body_only() {
        let result = build_idp_metadata(&params());

        assert!(!result.xml.contains("BEGIN CERTIFICATE"));
    }

    /// The metadata lists the SSO URL once for HTTP-POST and once for
    /// HTTP-Redirect, so an app may use either binding.
    #[test]
    fn includes_sso_endpoints() {
        let result = build_idp_metadata(&params());
        assert!(result.xml.contains("SingleSignOnService"));
        assert!(result.xml.contains("HTTP-POST"));
        assert!(result.xml.contains("HTTP-Redirect"));
        assert!(result.xml.contains("https://auth.acme.com/saml/sso"));
    }

    /// A logout URL is set. The metadata lists it as the single logout
    /// service.
    #[test]
    fn includes_slo_when_present() {
        let result = build_idp_metadata(&params());
        assert!(result.xml.contains("SingleLogoutService"));
        assert!(result.xml.contains("https://auth.acme.com/saml/slo"));
    }

    /// No logout URL is set. The metadata lists no logout service, so an app
    /// never sends logouts to an address that does not exist.
    #[test]
    fn omits_slo_when_none() {
        let mut p = params();
        p.slo_url = None;
        let result = build_idp_metadata(&p);
        assert!(!result.xml.contains("SingleLogoutService"));
    }

    /// The metadata offers the persistent, email-address and transient
    /// formats, each once: the formats a SAML app may be set up for.
    #[test]
    fn the_metadata_offers_every_format_an_app_may_be_set_up_for() {
        let result = build_idp_metadata(&params());

        for format in NameIdFormat::ALL {
            assert!(result.xml.contains(&format!(
                "<md:NameIDFormat>{}</md:NameIDFormat>",
                format.urn()
            )));
        }
        assert_eq!(result.xml.matches("<md:NameIDFormat>").count(), 3);
    }

    /// The IdP descriptor names the SAML 2.0 protocol it supports, which the
    /// metadata specification requires.
    #[test]
    fn includes_protocol_support() {
        let result = build_idp_metadata(&params());
        assert!(result.xml.contains("protocolSupportEnumeration"));
    }
}
