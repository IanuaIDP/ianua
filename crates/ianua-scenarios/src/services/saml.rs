//! An outside SAML app whose people sign in with a tenant as their
//! identity provider. It learns the provider from its published metadata,
//! sends requests of its own, and takes a message from the provider only
//! once it has checked it as a real app does: the signature against the
//! published certificates, then who issued it, where it was sent, what it
//! answers and when it holds.
//!
//! - [`sign_in`]: asking the provider to sign someone in, and accepting
//!   its answer.
//! - [`logout`]: single logout, asked by the app or by the provider.

pub mod logout;
mod metadata;
pub mod sign_in;
pub mod signature;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ianua_infra::test_support::clock;
pub use metadata::IdentityProvider;
use p256::ecdsa::SigningKey;
use p256::pkcs8::DecodePrivateKey as _;
use rcgen::{CertificateParams, KeyPair};
use roxmltree::Node;
use signature::{Broken, child, enveloped, verify};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

/// The SAML assertion namespace.
const ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

/// The SAML protocol namespace.
const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";

/// The status of a message that did what was asked.
const SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";

/// The persistent `NameID` format the app asks for.
pub const PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

/// An outside app, known by its entity id and the addresses the provider
/// sends it answers and logouts at, with a key of its own when it signs
/// its requests. `Debug` shows no key.
#[derive(Clone)]
pub struct App {
    entity_id: String,
    acs_url: String,
    logout_url: String,
    signer: Option<Signer>,
}

/// The key an app signs its requests with, and the certificate the tenant
/// registers for it.
#[derive(Clone)]
struct Signer {
    key: SigningKey,
    certificate: String,
}

impl std::fmt::Debug for App {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("App")
            .field("entity_id", &self.entity_id)
            .field("signs_requests", &self.signer.is_some())
            .finish_non_exhaustive()
    }
}

/// Why the app refused a message from the provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The message is not the SAML message expected.
    Unreadable(&'static str),
    /// The answer does not do what was asked.
    NotSuccess(String),
    /// A signature does not hold.
    Signature(Broken),
    /// Another provider issued it.
    Issuer,
    /// It is meant for another app.
    Audience,
    /// It was addressed to another place.
    Recipient,
    /// It answers another request.
    Request,
    /// It names someone the app does not know as signed in.
    Person,
    /// It is not valid now.
    Lapsed,
}

impl App {
    /// The app at `host`, taking answers at `/saml/acs` and logouts at
    /// `/saml/slo` there.
    #[must_use]
    pub fn at(host: &str) -> Self {
        Self {
            entity_id: format!("https://{host}/saml"),
            acs_url: format!("https://{host}/saml/acs"),
            logout_url: format!("https://{host}/saml/slo"),
            signer: None,
        }
    }

    /// The app at `host`, signing every request it sends with a fresh key
    /// of its own.
    ///
    /// # Panics
    ///
    /// When the key or its certificate cannot be made.
    /// Signed-request scenarios require a generated app key and matching certificate.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn signing_at(host: &str) -> Self {
        let pair = KeyPair::generate().expect("an app key");
        let certificate = CertificateParams::new(vec![host.to_owned()])
            .expect("certificate parameters")
            .self_signed(&pair)
            .expect("a certificate");
        let signer = Signer {
            key: SigningKey::from_pkcs8_der(&pair.serialize_der()).expect("a P-256 key"),
            certificate: certificate.pem(),
        };
        Self {
            signer: Some(signer),
            ..Self::at(host)
        }
    }

    /// The certificate its requests are signed with, PEM, for the tenant
    /// to register, when it signs them.
    #[must_use]
    pub fn certificate(&self) -> Option<&str> {
        self.signer
            .as_ref()
            .map(|signer| signer.certificate.as_str())
    }

    /// SAML identifier used as request issuer and expected assertion audience.
    #[must_use]
    pub fn entity_id(&self) -> &str {
        &self.entity_id
    }

    /// Where its sign-in answers are posted.
    #[must_use]
    pub fn acs_url(&self) -> &str {
        &self.acs_url
    }

    /// Where logout requests and answers to it are posted.
    #[must_use]
    pub fn logout_url(&self) -> &str {
        &self.logout_url
    }

    /// The site its pages are served from, which a form it posts comes
    /// from.
    /// App addresses are fixture inputs; an invalid host must fail before any request is made.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn site(&self) -> String {
        let url = url::Url::parse(&self.acs_url).expect("the app's address");
        url.origin().ascii_serialization()
    }

    /// The request `xml`, signed when the app signs its requests, as the
    /// message `id` posted as `SAMLRequest` with `relay_state` beside it.
    fn request(&self, id: String, xml: &str, relay_state: &str) -> Sent {
        let Some(signer) = &self.signer else {
            return Sent::of(id, "SAMLRequest", xml, relay_state);
        };
        Sent::of(id, "SAMLRequest", &enveloped(xml, &signer.key), relay_state)
    }
}

/// A message the app sent, which only an answer naming its id answers.
#[derive(Debug, Clone)]
pub struct Sent {
    id: String,
    field: &'static str,
    message: String,
    relay_state: String,
}

impl Sent {
    /// `xml`, the message `id` posted in the form field `field` with
    /// `relay_state` beside it.
    fn of(id: String, field: &'static str, xml: &str, relay_state: &str) -> Self {
        Self {
            id,
            field,
            message: STANDARD.encode(xml),
            relay_state: relay_state.to_owned(),
        }
    }

    /// Its id, which the answer must name.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The form a browser posts to the provider, without a `RelayState`
    /// when there is none to bring back.
    #[must_use]
    pub fn form(&self) -> String {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair(self.field, &self.message);
        if !self.relay_state.is_empty() {
            form.append_pair("RelayState", &self.relay_state);
        }
        form.finish()
    }

    /// The relay state the answer must bring back.
    #[must_use]
    pub fn relay_state(&self) -> &str {
        &self.relay_state
    }
}

/// A fresh message id.
fn fresh_id() -> String {
    format!("_{}", Uuid::new_v4().simple())
}

/// The XML of the base64 `message`.
fn decoded(message: &str) -> Result<String, Refusal> {
    STANDARD
        .decode(message)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or(Refusal::Unreadable("not base64 text"))
}

/// Checks `root` is the protocol message `name`.
fn ensure_message(root: Node<'_, '_>, name: &'static str) -> Result<(), Refusal> {
    if !root.has_tag_name((PROTOCOL, name)) {
        return Err(Refusal::Unreadable(name));
    }
    Ok(())
}

/// Checks `node` carries a signature that holds against `provider`'s
/// published certificates.
fn ensure_signed(node: Node<'_, '_>, provider: &IdentityProvider) -> Result<(), Refusal> {
    verify(node, provider.certificates()).map_err(Refusal::Signature)
}

/// Checks `node` names `provider` as its issuer.
fn ensure_issued_by(node: Node<'_, '_>, provider: &IdentityProvider) -> Result<(), Refusal> {
    let issuer = child(node, ASSERTION, "Issuer").and_then(|issuer| issuer.text());
    if issuer != Some(provider.entity_id()) {
        return Err(Refusal::Issuer);
    }
    Ok(())
}

/// The element reached from `node` through the assertion or protocol
/// children named `names`, in turn.
fn path<'a, 'input>(node: Node<'a, 'input>, names: &[&str]) -> Option<Node<'a, 'input>> {
    names.iter().try_fold(node, |at, name| {
        at.children().find(|found| {
            found.is_element()
                && found.tag_name().name() == *name
                && matches!(found.tag_name().namespace(), Some(ASSERTION | PROTOCOL))
        })
    })
}

/// The time `written` names, in the form SAML writes it.
fn instant(written: Option<&str>) -> Option<OffsetDateTime> {
    written.and_then(|written| OffsetDateTime::parse(written, &Rfc3339).ok())
}

/// The time now, in the form SAML writes it.
/// The scenario clock must remain within RFC 3339's representable year range.
#[allow(clippy::expect_used)]
fn written_now() -> String {
    now().format(&Rfc3339).expect("a time")
}

/// The time now on the application clock, which the platform shares and a
/// scenario may move forward.
fn now() -> OffsetDateTime {
    clock::now()
}
