//! Reading an identity provider's SAML metadata: fetched from the address
//! an admin chose through the screened client, then read for the provider's
//! entity id, endpoints and signing certificates.
//!
//! The address is a tenant's choice, so the fetch never reaches inside the
//! deployment, follows no redirect, gives up after a few seconds and stops
//! reading past a megabyte. The document is read by namespace and name, and
//! only for what this platform uses: the HTTP-Redirect sign-in endpoint its
//! requests go to, the HTTP-POST logout endpoint its logout messages are
//! posted to, and the certificates marked for signing.

use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::federation::SamlMetadataReader;
use ianua_domain::domains::federation::connection::IdpMetadataFacts;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use ianua_domain::types::{CertificatePem, HttpsUrl, PublicHttpsUrl, Setting};
use roxmltree::Node;

use crate::http::client::{NameLookup, Trust, body_within, ensure_reachable, screened_through};
use crate::saml::xml::document::{
    Comments, DSIG, METADATA, MOST_MESSAGE_BYTES, PROTOCOL, children, is, parse, refused,
    required_attribute, text_of,
};
use crate::saml::xml::keys::TrustedKey;

/// How long a fetch may take.
const FETCH_TIME: Duration = Duration::from_secs(10);

/// The largest metadata document fetched, which is the largest any SAML
/// document is parsed at. A larger fetch limit would only read a document
/// in full to refuse it.
const MOST_METADATA_BYTES: usize = MOST_MESSAGE_BYTES;

/// The HTTP-Redirect binding, which sign-in requests go out by.
pub(crate) const REDIRECT_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

/// The HTTP-POST binding, which logout messages go out by.
pub(crate) const POST_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

/// Fetches and reads identity provider metadata, reaching only the
/// networks a tenant's address may name.
pub struct ScreenedSamlMetadataReader {
    client: reqwest::Client,
    networks: UpstreamNetworks,
}

impl ScreenedSamlMetadataReader {
    /// A reader whose fetches reach only `networks`, looking names up as
    /// `lookup` says and trusting as `trust` says.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the client cannot be
    /// built.
    pub fn new(
        networks: UpstreamNetworks,
        lookup: NameLookup,
        trust: Trust,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            client: screened_through(FETCH_TIME, networks.clone(), lookup, trust)?,
            networks,
        })
    }

    /// The document served at `url`, any address the screen allows.
    async fn fetched(&self, url: &url::Url) -> Result<String, DomainError> {
        ensure_reachable(url, &self.networks)?;
        let response = self.client.get(url.clone()).send().await.map_err(|error| {
            tracing::warn!(%error, "SAML metadata could not be fetched");
            refused("the metadata address could not be reached")
        })?;
        if !response.status().is_success() {
            return Err(refused("the metadata address answered with an error"));
        }
        let body = body_within(response, MOST_METADATA_BYTES)
            .await
            .map_err(|error| {
                tracing::warn!(%error, "SAML metadata could not be read");
                refused("the metadata could not be read in full, or is larger than allowed")
            })?;
        String::from_utf8(body).map_err(|_| refused("the metadata is not UTF-8"))
    }
}

#[async_trait]
impl SamlMetadataReader for ScreenedSamlMetadataReader {
    async fn fetch(&self, url: &PublicHttpsUrl) -> Result<String, DomainError> {
        let parsed = url::Url::parse(url.as_str())
            .map_err(|_| refused("the metadata address cannot be read"))?;
        self.fetched(&parsed).await
    }

    fn read(&self, document: &str) -> Result<IdpMetadataFacts, DomainError> {
        let parsed = parse(document, Comments::Skipped)?;
        let entity = entity_of(parsed.root_element())?;
        let provider = identity_provider(entity)?;
        let entity_id = required_attribute(entity, "entityID", "the metadata names no entity id")?;
        let sign_in = endpoint(provider, "SingleSignOnService", REDIRECT_BINDING)
            .ok_or_else(|| refused("the metadata names no HTTP-Redirect sign-in endpoint"))?;
        let logout = endpoint(provider, "SingleLogoutService", POST_BINDING)
            .map(|location| https("logout endpoint", location))
            .transpose()?;
        Ok(IdpMetadataFacts {
            entity_id: https("entity id", entity_id)?,
            sso_url: https("sign-in endpoint", sign_in)?,
            slo_url: logout.map_or(Setting::Unset, Setting::Set),
            signing_certificates: signing_certificates(provider)?,
        })
    }
}

/// The one entity a document describes: its root, or the only entity of
/// a group.
fn entity_of<'a, 'input>(root: Node<'a, 'input>) -> Result<Node<'a, 'input>, DomainError> {
    if is(root, METADATA, "EntityDescriptor") {
        return Ok(root);
    }
    if !is(root, METADATA, "EntitiesDescriptor") {
        return Err(refused("this is not SAML metadata"));
    }
    let mut entities = children(root, METADATA, "EntityDescriptor");
    let (Some(entity), None) = (entities.next(), entities.next()) else {
        return Err(refused(
            "the metadata describes more or fewer than one provider",
        ));
    };
    Ok(entity)
}

/// The entity's identity provider role, speaking SAML 2.0.
fn identity_provider<'a, 'input>(
    entity: Node<'a, 'input>,
) -> Result<Node<'a, 'input>, DomainError> {
    let mut roles = children(entity, METADATA, "IDPSSODescriptor");
    let (Some(role), None) = (roles.next(), roles.next()) else {
        return Err(refused(
            "the metadata does not describe one identity provider",
        ));
    };
    let speaks_saml2 = role
        .attribute("protocolSupportEnumeration")
        .is_some_and(|protocols| {
            protocols
                .split_whitespace()
                .any(|protocol| protocol == PROTOCOL)
        });
    if !speaks_saml2 {
        return Err(refused("the identity provider does not speak SAML 2.0"));
    }
    Ok(role)
}

/// The location of the first `service` endpoint of `binding`.
fn endpoint<'a>(provider: Node<'a, '_>, service: &'static str, binding: &str) -> Option<&'a str> {
    children(provider, METADATA, service)
        .find(|endpoint| endpoint.attribute("Binding") == Some(binding))
        .and_then(|endpoint| endpoint.attribute("Location"))
}

/// `location` as an HTTPS address, `what` naming it in the refusal.
fn https(what: &'static str, location: &str) -> Result<HttpsUrl, DomainError> {
    HttpsUrl::new(location).map_err(|_| {
        DomainError::invalid(message!(
            "infra-the-metadata-s-is-not-an",
            format!("the metadata's {what} is not an HTTPS address")
        ))
    })
}

/// The certificates the provider signs with, in the order listed, each
/// once. A key descriptor for encryption alone is left out.
fn signing_certificates(provider: Node<'_, '_>) -> Result<Vec<CertificatePem>, DomainError> {
    let mut certificates: Vec<CertificatePem> = Vec::new();
    let descriptors = children(provider, METADATA, "KeyDescriptor").filter(|descriptor| {
        descriptor
            .attribute("use")
            .is_none_or(|purpose| purpose == "signing")
    });
    for descriptor in descriptors {
        let bodies = descriptor
            .descendants()
            .filter(|node| is(*node, DSIG, "X509Certificate"));
        for body in bodies {
            let certificate = certificate_from(&text_of(body)?)?;
            if !certificates.contains(&certificate) {
                certificates.push(certificate);
            }
        }
    }
    Ok(certificates)
}

/// The certificate whose base64 body is `body`, once it can be read and
/// carries a key signatures can be checked with.
fn certificate_from(body: &str) -> Result<CertificatePem, DomainError> {
    let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    let lines: Vec<String> = compact
        .as_bytes()
        .chunks(64)
        .map(|line| String::from_utf8_lossy(line).into_owned())
        .collect();
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        lines.join("\n")
    );
    let unusable = || refused("the metadata lists a signing certificate this platform cannot use");
    let certificate = CertificatePem::new(pem).map_err(|_| unusable())?;
    TrustedKey::from_certificate(&certificate).map_err(|_| unusable())?;
    Ok(certificate)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
    use ianua_domain::types::CidrRange;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::saml::xml::keys::tests::TestKey;

    fn loopback() -> UpstreamNetworks {
        UpstreamNetworks::new(vec![
            CidrRange::new("127.0.0.0/8").unwrap(),
            CidrRange::new("::1/128").unwrap(),
        ])
    }

    fn body_of(certificate: &CertificatePem) -> String {
        certificate.base64_body()
    }

    /// Okta's metadata, listing `certificates` for signing and one for
    /// encryption alone.
    fn metadata(certificates: &[&CertificatePem]) -> String {
        let signing: String = certificates
            .iter()
            .map(|certificate| {
                format!(
                    r#"<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"#,
                    body_of(certificate)
                )
            })
            .collect();
        let encryption = TestKey::new(SigningAlgorithm::Es256).certificate;
        format!(
            r#"<?xml version="1.0"?><!-- published by Okta --><md:EntityDescriptor xmlns:md="{METADATA}" xmlns:ds="{DSIG}" entityID="https://idp.acme.com"><md:IDPSSODescriptor protocolSupportEnumeration="{PROTOCOL}">{signing}<md:KeyDescriptor use="encryption"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding="{REDIRECT_BINDING}" Location="https://idp.acme.com/slo/redirect"/><md:SingleLogoutService Binding="{POST_BINDING}" Location="https://idp.acme.com/slo/post"/><md:SingleSignOnService Binding="{POST_BINDING}" Location="https://idp.acme.com/sso/post"/><md:SingleSignOnService Binding="{REDIRECT_BINDING}" Location="https://idp.acme.com/sso/redirect"/></md:IDPSSODescriptor></md:EntityDescriptor>"#,
            body_of(&encryption)
        )
    }

    fn reader() -> ScreenedSamlMetadataReader {
        ScreenedSamlMetadataReader::new(loopback(), NameLookup::Host, Trust::PublicRoots).unwrap()
    }

    /// Okta's metadata gives its entity id, the endpoints of the bindings
    /// this platform sends by, and its signing certificates in order, the
    /// encryption certificate left out.
    #[test]
    fn metadata_gives_the_provider_and_its_signing_certificates() {
        let current = TestKey::new(SigningAlgorithm::Es256).certificate;
        let next = TestKey::new(SigningAlgorithm::Es256).certificate;

        let facts = reader().read(&metadata(&[&current, &next])).unwrap();

        assert_eq!(facts.entity_id.as_str(), "https://idp.acme.com");
        assert_eq!(facts.sso_url.as_str(), "https://idp.acme.com/sso/redirect");
        assert_eq!(
            facts.slo_url.value().map(HttpsUrl::as_str),
            Some("https://idp.acme.com/slo/post")
        );
        assert_eq!(facts.signing_certificates.len(), 2);
        assert_eq!(body_of(&facts.signing_certificates[0]), body_of(&current));
    }

    /// A certificate listed twice, as some providers do for signing and
    /// for no use given, is taken once.
    #[test]
    fn a_certificate_listed_twice_is_taken_once() {
        let current = TestKey::new(SigningAlgorithm::Es256).certificate;

        let facts = reader().read(&metadata(&[&current, &current])).unwrap();

        assert_eq!(facts.signing_certificates.len(), 1);
    }

    /// Metadata with a plain HTTP sign-in endpoint fails validation.
    #[test]
    fn an_endpoint_that_is_not_https_is_refused() {
        let current = TestKey::new(SigningAlgorithm::Es256).certificate;
        let plain = metadata(&[&current]).replace(
            "https://idp.acme.com/sso/redirect",
            "http://idp.acme.com/sso/redirect",
        );

        assert!(matches!(
            reader().read(&plain),
            Err(DomainError::Validation(_))
        ));
    }

    /// Unrelated HTML and metadata containing an unreadable certificate are both rejected.
    #[test]
    fn a_document_that_is_not_usable_metadata_is_refused() {
        let current = TestKey::new(SigningAlgorithm::Es256).certificate;
        let broken = metadata(&[&current]).replacen(&body_of(&current), "MIIBbroken", 1);

        assert!(reader().read("<html/>").is_err());
        assert!(reader().read(&broken).is_err());
    }

    async fn serving(response: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/metadata"))
            .respond_with(response)
            .mount(&server)
            .await;
        server
    }

    fn address(server: &MockServer) -> url::Url {
        url::Url::parse(&format!(
            "{}/metadata",
            server.uri().replace("127.0.0.1", "localhost")
        ))
        .unwrap()
    }

    /// The document an allowed address serves is fetched as it is.
    #[tokio::test]
    async fn the_document_is_fetched() {
        let server = serving(ResponseTemplate::new(200).set_body_string("<md/>")).await;

        let fetched = reader().fetched(&address(&server)).await.unwrap();

        assert_eq!(fetched, "<md/>");
    }

    /// A loopback metadata address fails public-address screening without receiving a request.
    #[tokio::test]
    async fn an_address_inside_the_deployment_is_not_reached() {
        let server = serving(ResponseTemplate::new(200).set_body_string("<md/>")).await;
        let public_only = ScreenedSamlMetadataReader::new(
            UpstreamNetworks::public_only(),
            NameLookup::Host,
            Trust::PublicRoots,
        )
        .unwrap();

        let fetched = public_only.fetched(&address(&server)).await;

        assert!(matches!(fetched, Err(DomainError::Validation(_))));
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// A response larger than the fetch limit produces a validation error.
    #[tokio::test]
    async fn a_document_past_its_limit_is_refused() {
        let huge = vec![b'x'; MOST_METADATA_BYTES + 1];
        let server = serving(ResponseTemplate::new(200).set_body_bytes(huge)).await;

        let fetched = reader().fetched(&address(&server)).await;

        assert!(matches!(fetched, Err(DomainError::Validation(_))));
    }

    /// Both fetching and directly parsing a 600 KiB document enforce the metadata size limit.
    #[tokio::test]
    async fn the_fetch_and_the_parse_share_one_limit() {
        let between = vec![b'x'; 600 * 1024];
        let server = serving(ResponseTemplate::new(200).set_body_bytes(between.clone())).await;
        let pasted = String::from_utf8(between).unwrap();

        let fetched = reader().fetched(&address(&server)).await;
        let read = reader().read(&pasted);

        assert!(matches!(fetched, Err(DomainError::Validation(_))));
        assert!(matches!(read, Err(DomainError::Validation(_))));
    }

    /// A redirect response naming the cloud metadata address is treated as a validation error.
    #[tokio::test]
    async fn a_redirect_is_not_followed() {
        let server = serving(
            ResponseTemplate::new(302).insert_header("location", "http://169.254.169.254/latest/"),
        )
        .await;

        let fetched = reader().fetched(&address(&server)).await;

        assert!(matches!(fetched, Err(DomainError::Validation(_))));
    }
}
