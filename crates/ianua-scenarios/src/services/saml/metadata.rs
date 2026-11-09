//! The identity provider an outside app trusts, as it learns it from the
//! metadata the provider publishes: who it is, where sign-in requests and
//! logouts go, and the certificates its messages are signed with.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use roxmltree::{Document, Node};

/// The SAML metadata namespace.
const METADATA: &str = "urn:oasis:names:tc:SAML:2.0:metadata";

/// The HTTP-POST binding.
pub(super) const POST_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

/// What an app knows of the provider from its metadata.
#[derive(Debug, Clone)]
pub struct IdentityProvider {
    entity_id: String,
    sso_url: String,
    slo_url: Option<String>,
    certificates: Vec<Vec<u8>>,
}

impl IdentityProvider {
    /// The provider `xml` describes.
    ///
    /// # Panics
    ///
    /// When the document is not metadata naming an entity id, a sign-in
    /// service over HTTP-POST and at least one signing certificate.
    /// This fixture asserts that successful metadata publication can configure an outside app.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn from_metadata(xml: &str) -> Self {
        let document = Document::parse(xml).expect("the metadata is XML");
        let root = document.root_element();
        let entity_id = root
            .attribute("entityID")
            .expect("the metadata names its entity id")
            .to_owned();
        let provider = descendant(root, "IDPSSODescriptor")
            .expect("the metadata describes an identity provider");
        let sso_url = posted_to(provider, "SingleSignOnService")
            .expect("the provider takes sign-in requests over HTTP-POST");
        let slo_url = posted_to(provider, "SingleLogoutService");
        let certificates = signing_certificates(provider);
        Self {
            entity_id,
            sso_url,
            slo_url,
            certificates,
        }
    }

    /// Its entity id, which its answers name as their issuer.
    #[must_use]
    pub fn entity_id(&self) -> &str {
        &self.entity_id
    }

    /// Where sign-in requests are posted.
    #[must_use]
    pub fn sso_url(&self) -> &str {
        &self.sso_url
    }

    /// Where logout requests and answers are posted, when it takes them.
    #[must_use]
    pub fn slo_url(&self) -> Option<&str> {
        self.slo_url.as_deref()
    }

    /// The certificates its answers may be signed with, DER-encoded.
    #[must_use]
    pub fn certificates(&self) -> &[Vec<u8>] {
        &self.certificates
    }
}

/// Reads the signing certificates advertised by the provider's metadata.
/// Malformed or missing certificates fail the metadata assertion before sign-in tests proceed.
#[allow(clippy::expect_used)]
fn signing_certificates(provider: Node<'_, '_>) -> Vec<Vec<u8>> {
    let certificates: Vec<Vec<u8>> = provider
        .children()
        .filter(|key| is(*key, "KeyDescriptor") && key.attribute("use") != Some("encryption"))
        .filter_map(|key| {
            key.descendants()
                .find(|node| node.has_tag_name("X509Certificate"))
        })
        .filter_map(|certificate| certificate.text())
        .map(|text| {
            let text: String = text.split_whitespace().collect();
            STANDARD.decode(text).expect("a certificate in base64")
        })
        .collect();
    assert!(
        !certificates.is_empty(),
        "the metadata publishes a signing certificate"
    );
    certificates
}

/// Where the provider's service `name` takes messages posted over
/// HTTP-POST.
fn posted_to(provider: Node<'_, '_>, name: &str) -> Option<String> {
    provider
        .children()
        .find(|service| is(*service, name) && service.attribute("Binding") == Some(POST_BINDING))
        .and_then(|service| service.attribute("Location"))
        .map(str::to_owned)
}

/// Whether `node` is the metadata element `name`.
fn is(node: Node<'_, '_>, name: &str) -> bool {
    node.tag_name().namespace() == Some(METADATA) && node.tag_name().name() == name
}

/// The first element under `node` that is the metadata element `name`.
fn descendant<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Option<Node<'a, 'input>> {
    node.descendants().find(|found| is(*found, name))
}
