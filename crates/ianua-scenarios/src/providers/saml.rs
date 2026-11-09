//! A SAML identity provider independent of the platform: its own P-256
//! key, a self-signed certificate the organization registers, and signed
//! assertions answering the request the platform sent. Each answer is
//! built as a real provider builds it, the assertion in exclusive
//! canonical form with an enveloped signature, inside an unsigned
//! response, so the platform's verifier checks real bytes. It also checks
//! the signature on the sign-in requests the service sends it, and logs
//! Ann out either way, signing its own logout messages.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ianua_infra::test_support::clock;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey as _;
use rcgen::{CertificateParams, KeyPair};
use sha2::{Digest as _, Sha256};
use time::Duration;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::providers::parameter;
use crate::services::saml::signature;
use crate::stack::Stack;
use crate::wire::federation::{Begun, Callback, ProviderAnswer};
use crate::wire::organization::IdentityProviderConfig;

/// The provider's entity id, which its assertions name as their issuer.
const ISSUER: &str = "https://identity.acme.example";

/// The host its certificate is made out to.
const HOST: &str = "identity.acme.example";

/// The SAML assertion namespace.
const ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

/// The SAML protocol namespace.
const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";

/// The XML signature namespace.
const DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";

/// Exclusive XML canonicalization, the form the signature covers.
const C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

/// The persistent `NameID` format, the only one a sign-in provider takes.
const PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

/// The subject the provider names Ann by.
const SUBJECT: &str = "ann-at-provider";

/// Ann's session at the provider, which its sign-ins and logouts name.
const SESSION: &str = "_ann";

/// How long an assertion is valid, and how far ahead a future-dated one
/// is issued: five minutes.
const WINDOW_MINUTES: i64 = 5;

/// What differs in an assertion from the request the platform sent. Every
/// change is made before signing, so a refusal shows the platform checked
/// the signed claim, not the unsigned envelope.
#[derive(Clone, Copy)]
pub enum Claim {
    /// Every claim answers the request.
    Correct,
    /// The assertion names another provider as its issuer.
    WrongIssuer,
    /// The assertion is meant for another service provider.
    WrongAudience,
    /// The signed recipient is another address, while the envelope names
    /// the platform's.
    WrongRecipient,
    /// The signed assertion answers another request, while the envelope
    /// names this one.
    WrongRequest,
    /// The assertion's validity ended five minutes ago.
    Expired,
    /// The assertion is issued five minutes in the future.
    FutureIssued,
    /// The assertion is signed with a key the organization never
    /// registered.
    WrongSignature,
    /// The assertion carries no signature.
    Unsigned,
}

/// The pending sign-in, its subject and the signed claim variation to exercise.
pub struct SignIn<'a> {
    /// The subject's email address asserted by this provider.
    pub email: &'a str,
    /// The platform's redirect and browser binding for this sign-in.
    pub begun: Begun,
    /// The single claim or signature condition changed for the scenario.
    pub claim: Claim,
}

/// The service an answer is addressed to, as its published settings name
/// it: who the assertion is meant for, and where the browser posts it.
#[derive(Debug, Clone)]
pub struct ServiceProvider {
    /// The service's entity id, which the assertion's audience names.
    pub audience: String,
    /// The address the answer is posted to, which the assertion's
    /// recipient and the response's destination name.
    pub recipient: String,
}

/// How a sign-in request sent by HTTP-Redirect was signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestSignature {
    /// It carries no signature.
    Unsigned,
    /// Its signature holds against a certificate the service publishes.
    Verified,
    /// It carries a signature no published certificate made.
    Broken,
}

/// A message the provider has the browser post to the service.
#[derive(Debug, Clone)]
pub struct Sent {
    /// Its id, which an answer names.
    pub id: String,
    /// The message, base64.
    pub message: String,
}

/// The provider's signing key and the certificate the organization
/// registers. `Debug` shows no key.
pub struct Provider {
    key: SigningKey,
    certificate: String,
}

impl std::fmt::Debug for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Provider").finish_non_exhaustive()
    }
}

impl Provider {
    /// A provider with a fresh key of its own, made apart from the
    /// platform, so the platform's verifier must check assertions this
    /// key signed against the certificate registered through the API.
    ///
    /// # Panics
    ///
    /// When the key or its certificate cannot be made.
    /// Federation scenarios require a generated signing identity before they start.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn new() -> Self {
        let key = KeyPair::generate().expect("a provider key");
        let certificate = CertificateParams::new(vec![HOST.to_owned()])
            .expect("certificate parameters")
            .self_signed(&key)
            .expect("a certificate");
        Self {
            key: SigningKey::from_pkcs8_der(&key.serialize_der()).expect("a P-256 key"),
            certificate: certificate.pem(),
        }
    }

    /// The settings the organization registers for it: its entity id and
    /// sign-in address, its certificate, and the persistent subject format.
    #[must_use]
    pub fn config(&self) -> IdentityProviderConfig {
        IdentityProviderConfig::Saml {
            entity_id: ISSUER.to_owned(),
            sso_url: format!("{ISSUER}/sso"),
            certificate: self.certificate.clone(),
            name_id_format: PERSISTENT.to_owned(),
        }
    }

    /// Its entity id, which its answers name as their issuer.
    #[must_use]
    pub fn entity_id(&self) -> &'static str {
        ISSUER
    }

    /// The certificate its messages are signed with, PEM.
    #[must_use]
    pub fn certificate(&self) -> &str {
        &self.certificate
    }

    /// The metadata it publishes: its entity id, where sign-in requests and
    /// logouts go, and the certificate it signs with, followed by `next`'s
    /// while it rolls its key over to `next`'s.
    #[must_use]
    pub fn metadata(&self, next: Option<&Self>) -> String {
        let keys: String = std::iter::once(self)
            .chain(next)
            .map(|provider| {
                format!(
                    r#"<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"#,
                    provider.certificate_body()
                )
            })
            .collect();
        format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="{DSIG}" entityID="{ISSUER}"><md:IDPSSODescriptor protocolSupportEnumeration="{PROTOCOL}">{keys}<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{slo}"/><md:NameIDFormat>{PERSISTENT}</md:NameIDFormat><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{ISSUER}/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>"#,
            slo = self.slo_url(),
        )
    }

    /// The base64 body of its certificate, without the PEM lines around it.
    fn certificate_body(&self) -> String {
        self.certificate
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect()
    }

    /// Where it takes logout requests and answers.
    #[must_use]
    pub fn slo_url(&self) -> String {
        format!("{ISSUER}/slo")
    }

    /// How the sign-in request in `redirect`, sent by HTTP-Redirect, was
    /// signed, checked against the signing certificate the service's
    /// metadata `sp_metadata` publishes: the signature covers the query's
    /// parameters exactly as they travel.
    ///
    /// # Panics
    ///
    /// When `redirect` is not an address with a query.
    /// A redirect without its protocol query fails the scenario's request assertion.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn request_signature(redirect: &str, sp_metadata: &str) -> RequestSignature {
        let query = redirect
            .split_once('?')
            .map(|(_, query)| query)
            .expect("a redirect with a query");
        let (Some(algorithm), Some(signature)) = (
            raw_parameter(query, "SigAlg"),
            raw_parameter(query, "Signature"),
        ) else {
            return RequestSignature::Unsigned;
        };
        let signed: Vec<String> = ["SAMLRequest", "RelayState", "SigAlg"]
            .into_iter()
            .filter_map(|name| raw_parameter(query, name).map(|value| format!("{name}={value}")))
            .collect();
        let value = STANDARD
            .decode(decoded_parameter(signature))
            .unwrap_or_default();
        let verified = signing_certificates(sp_metadata).iter().any(|certificate| {
            signature::made_by(
                certificate,
                &decoded_parameter(algorithm),
                signed.join("&").as_bytes(),
                &value,
            )
        });
        match verified {
            true => RequestSignature::Verified,
            false => RequestSignature::Broken,
        }
    }

    /// A logout request for Ann's session here, signed by this provider,
    /// for the browser to post to the service's logout address `to`.
    #[must_use]
    pub fn logout_request(&self, to: &str) -> Sent {
        let id = format!("_{}", Uuid::new_v4().simple());
        let xml = format!(
            r#"<p:LogoutRequest xmlns:p="{PROTOCOL}" xmlns:s="{ASSERTION}" Destination="{to}" ID="{id}" IssueInstant="{now}" Version="2.0"><s:Issuer>{ISSUER}</s:Issuer><s:NameID Format="{PERSISTENT}">{SUBJECT}</s:NameID><p:SessionIndex>{SESSION}</p:SessionIndex></p:LogoutRequest>"#,
            now = instant(Duration::ZERO),
        );
        Sent {
            id,
            message: STANDARD.encode(signature::enveloped(&xml, &self.key)),
        }
    }

    /// The service's logout request `message`, base64 as posted, once it
    /// is checked: signed with a certificate `sp_metadata` publishes, sent
    /// to this provider's logout address, naming Ann's subject and session
    /// here. Answers its id.
    ///
    /// # Errors
    ///
    /// Why the request does not hold, in words.
    pub fn logout_asked(&self, message: &str, sp_metadata: &str) -> Result<String, String> {
        let xml = String::from_utf8(STANDARD.decode(message).map_err(|_| "not base64")?)
            .map_err(|_| "not text")?;
        let document = roxmltree::Document::parse(&xml).map_err(|_| "not XML")?;
        let root = document.root_element();
        signature::verify(root, &signing_certificates(sp_metadata))
            .map_err(|broken| format!("the signature does not hold: {broken:?}"))?;
        if root.attribute("Destination") != Some(self.slo_url().as_str()) {
            return Err("sent to another address".to_owned());
        }
        let text = |name: &str| {
            root.children()
                .find(|node| node.tag_name().name() == name)
                .and_then(|node| node.text())
        };
        if text("NameID") != Some(SUBJECT) || text("SessionIndex") != Some(SESSION) {
            return Err("names someone else, or another session".to_owned());
        }
        root.attribute("ID")
            .map(str::to_owned)
            .ok_or_else(|| "no ID".to_owned())
    }

    /// Checks the service's answer `response`, base64 as posted, to this
    /// provider's logout request `asked`: signed with a certificate
    /// `sp_metadata` publishes, sent to this provider's logout address,
    /// answering `asked`, and a success.
    ///
    /// # Errors
    ///
    /// Why the answer does not hold, in words.
    pub fn logout_answered(
        &self,
        response: &str,
        sp_metadata: &str,
        asked: &Sent,
    ) -> Result<(), String> {
        let xml = String::from_utf8(STANDARD.decode(response).map_err(|_| "not base64")?)
            .map_err(|_| "not text")?;
        let document = roxmltree::Document::parse(&xml).map_err(|_| "not XML")?;
        let root = document.root_element();
        signature::verify(root, &signing_certificates(sp_metadata))
            .map_err(|broken| format!("the signature does not hold: {broken:?}"))?;
        if root.attribute("Destination") != Some(self.slo_url().as_str()) {
            return Err("sent to another address".to_owned());
        }
        if root.attribute("InResponseTo") != Some(asked.id.as_str()) {
            return Err("answers another request".to_owned());
        }
        let status = root
            .descendants()
            .find(|node| node.tag_name().name() == "StatusCode")
            .and_then(|code| code.attribute("Value"));
        if status != Some("urn:oasis:names:tc:SAML:2.0:status:Success") {
            return Err(format!("the logout did not succeed: {status:?}"));
        }
        Ok(())
    }

    /// This provider's signed answer to the logout request `asked`: Ann is
    /// logged out here. Base64, for the browser to post to the service's
    /// logout address `to`.
    #[must_use]
    pub fn logged_out(&self, asked: &str, to: &str) -> String {
        let xml = format!(
            r#"<p:LogoutResponse xmlns:p="{PROTOCOL}" xmlns:s="{ASSERTION}" Destination="{to}" ID="_{id}" InResponseTo="{asked}" IssueInstant="{now}" Version="2.0"><s:Issuer>{ISSUER}</s:Issuer><p:Status><p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></p:StatusCode></p:Status></p:LogoutResponse>"#,
            id = Uuid::new_v4().simple(),
            now = instant(Duration::ZERO),
        );
        STANDARD.encode(signature::enveloped(&xml, &self.key))
    }

    /// The answer the browser hands back for the organization `sign_in`:
    /// an assertion about its email address for the request in its
    /// `RelayState`, addressed to `stack`'s organization sign-in page,
    /// changed as its claim says before it is signed, with the browser's
    /// binding kept.
    ///
    /// # Panics
    ///
    /// When the redirect carries no `RelayState`.
    #[must_use]
    pub fn callback(&self, stack: &Stack, sign_in: SignIn<'_>) -> Callback {
        let audience = stack.app_url().as_str().trim_end_matches('/').to_owned();
        let to = ServiceProvider {
            recipient: format!("{audience}/login/sso/saml"),
            audience,
        };
        self.answer(&to, sign_in)
    }

    /// The answer for `sign_in`, addressed to the service provider `to`:
    /// an assertion about its email address for the request in the
    /// redirect's `RelayState`, changed as its claim says before it is
    /// signed, with the browser's binding kept.
    ///
    /// # Panics
    ///
    /// When the redirect carries no `RelayState`.
    #[must_use]
    pub fn answer(&self, to: &ServiceProvider, sign_in: SignIn<'_>) -> Callback {
        let SignIn {
            email,
            begun,
            claim,
        } = sign_in;
        let request = parameter(&begun.redirect_url, "RelayState");
        let ServiceProvider {
            audience,
            recipient,
        } = to;
        let assertion = Assertion {
            id: format!("_{}", Uuid::new_v4().simple()),
            request: claim.request(&request),
            recipient: claim.recipient(recipient),
            audience: claim.audience(audience),
            issuer: claim.issuer(),
            email,
            issued: claim.issued(),
            expires: claim.expires(),
        };
        let signed = self.sealed(&assertion, claim);
        let response = response(recipient, &request, &signed);
        Callback {
            binding: begun.binding,
            answer: ProviderAnswer::Saml {
                relay_state: request,
                saml_response: STANDARD.encode(response),
            },
        }
    }

    /// `assertion` as `claim` sends it: unsigned, signed by a stranger's
    /// key, or signed by this provider.
    fn sealed(&self, assertion: &Assertion<'_>, claim: Claim) -> String {
        match claim {
            Claim::Unsigned => assertion.xml(),
            Claim::WrongSignature => Self::new().signed(assertion),
            Claim::Correct
            | Claim::WrongIssuer
            | Claim::WrongAudience
            | Claim::WrongRecipient
            | Claim::WrongRequest
            | Claim::Expired
            | Claim::FutureIssued => self.signed(assertion),
        }
    }

    /// `assertion` with its enveloped signature after its issuer. The
    /// assertion and `SignedInfo` are written in exclusive canonical form,
    /// attributes sorted, closing tags explicit, only the namespaces used,
    /// so the bytes signed are the bytes the verifier canonicalizes.
    fn signed(&self, assertion: &Assertion<'_>) -> String {
        let plain = assertion.xml();
        let digest = STANDARD.encode(Sha256::digest(plain.as_bytes()));
        let info = format!(
            r##"<ds:SignedInfo xmlns:ds="{DSIG}"><ds:CanonicalizationMethod Algorithm="{C14N}"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"></ds:SignatureMethod><ds:Reference URI="#{}"><ds:Transforms><ds:Transform Algorithm="{DSIG}enveloped-signature"></ds:Transform><ds:Transform Algorithm="{C14N}"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##,
            assertion.id
        );
        let signature: Signature = self.key.sign(info.as_bytes());
        let signature = format!(
            r#"<ds:Signature xmlns:ds="{DSIG}">{info}<ds:SignatureValue>{}</ds:SignatureValue></ds:Signature>"#,
            STANDARD.encode(signature.to_bytes())
        );
        plain.replacen("</s:Issuer>", &format!("</s:Issuer>{signature}"), 1)
    }
}

impl Default for Provider {
    fn default() -> Self {
        Self::new()
    }
}

impl Claim {
    /// The request the signed assertion answers.
    fn request(self, request: &str) -> &str {
        match self {
            Self::WrongRequest => "_another_request",
            _ => request,
        }
    }

    /// The recipient the signed assertion names.
    fn recipient(self, recipient: &str) -> &str {
        match self {
            Self::WrongRecipient => "https://elsewhere.example/acs",
            _ => recipient,
        }
    }

    /// The audience the signed assertion is meant for.
    fn audience(self, audience: &str) -> &str {
        match self {
            Self::WrongAudience => "https://elsewhere.example",
            _ => audience,
        }
    }

    /// The issuer the signed assertion names.
    fn issuer(self) -> &'static str {
        match self {
            Self::WrongIssuer => "https://other-idp.example",
            _ => ISSUER,
        }
    }

    /// How far from now the assertion says it was issued.
    fn issued(self) -> Duration {
        match self {
            Self::FutureIssued => Duration::minutes(WINDOW_MINUTES),
            _ => Duration::ZERO,
        }
    }

    /// How far from now the assertion stops being valid.
    fn expires(self) -> Duration {
        match self {
            Self::Expired => -Duration::minutes(WINDOW_MINUTES),
            _ => Duration::minutes(WINDOW_MINUTES),
        }
    }
}

/// The facts the provider signs, apart from the unsigned response around
/// them.
struct Assertion<'a> {
    id: String,
    request: &'a str,
    recipient: &'a str,
    audience: &'a str,
    issuer: &'a str,
    email: &'a str,
    issued: Duration,
    expires: Duration,
}

impl Assertion<'_> {
    /// The assertion before its signature goes in: Ann's persistent
    /// subject, her address, and its window, in the canonical form the
    /// signature covers. Every value comes from this provider, none from
    /// outside XML.
    fn xml(&self) -> String {
        let Self {
            id,
            request,
            recipient,
            audience,
            issuer,
            email,
            issued,
            expires,
        } = self;
        let now = instant(*issued);
        let end = instant(*expires);
        format!(
            r#"<s:Assertion xmlns:s="{ASSERTION}" ID="{id}" IssueInstant="{now}" Version="2.0"><s:Issuer>{issuer}</s:Issuer><s:Subject><s:NameID Format="{PERSISTENT}">{SUBJECT}</s:NameID><s:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><s:SubjectConfirmationData InResponseTo="{request}" NotOnOrAfter="{end}" Recipient="{recipient}"></s:SubjectConfirmationData></s:SubjectConfirmation></s:Subject><s:Conditions NotOnOrAfter="{end}"><s:AudienceRestriction><s:Audience>{audience}</s:Audience></s:AudienceRestriction></s:Conditions><s:AuthnStatement AuthnInstant="{now}" SessionIndex="{SESSION}"><s:AuthnContext><s:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</s:AuthnContextClassRef></s:AuthnContext></s:AuthnStatement><s:AttributeStatement><s:Attribute Name="email"><s:AttributeValue>{email}</s:AttributeValue></s:Attribute></s:AttributeStatement></s:Assertion>"#
        )
    }
}

/// Wraps the signed assertion in the response for the original request and destination.
fn response(recipient: &str, request: &str, signed: &str) -> String {
    format!(
        r#"<p:Response xmlns:p="{PROTOCOL}" Destination="{recipient}" ID="_{}" InResponseTo="{request}" IssueInstant="{}" Version="2.0"><s:Issuer xmlns:s="{ASSERTION}">{ISSUER}</s:Issuer><p:Status><p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></p:StatusCode></p:Status>{signed}</p:Response>"#,
        Uuid::new_v4().simple(),
        instant(Duration::ZERO)
    )
}

/// Reads a query value without decoding the bytes covered by the redirect signature.
fn raw_parameter<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix(name)?.strip_prefix('='))
}

/// The signing certificates the service's metadata `sp_metadata`
/// publishes, DER-encoded.
fn signing_certificates(sp_metadata: &str) -> Vec<Vec<u8>> {
    let Ok(document) = roxmltree::Document::parse(sp_metadata) else {
        return Vec::new();
    };
    document
        .descendants()
        .filter(|key| key.has_tag_name("KeyDescriptor") && key.attribute("use") == Some("signing"))
        .filter_map(|key| {
            key.descendants()
                .find(|node| node.has_tag_name("X509Certificate"))
        })
        .filter_map(|certificate| certificate.text())
        .filter_map(|text| {
            let text: String = text.split_whitespace().collect();
            STANDARD.decode(text).ok()
        })
        .collect()
}

/// An XML timestamp `offset` from now on the application clock, which the
/// platform shares and a scenario may move forward, so issue times and
/// validity windows are judged as a real provider's would be.
/// The fixture clock must stay within the year range required by RFC 3339.
#[allow(clippy::expect_used)]
fn instant(offset: Duration) -> String {
    (clock::now() + offset)
        .format(&Rfc3339)
        .expect("an XML dateTime")
}

/// Decodes one redirect query value without changing the raw bytes used for signature checks.
fn decoded_parameter(value: &str) -> String {
    url::form_urlencoded::parse(format!("v={value}").as_bytes())
        .next()
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default()
}
