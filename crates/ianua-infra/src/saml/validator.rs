//! Checking a SAML provider's answer to a sign-in this platform asked for.
//!
//! Everything is refused unless it holds: the response is posted where it
//! arrived and answers the request sent, carries exactly one assertion in
//! the one place a response carries it, and that assertion is covered by a
//! signature from a certificate the connection takes, its own or the
//! response's around it. The assertion must name the provider, be meant
//! for this platform, confirm this very sign-in and be inside its window.
//! A sealed assertion is opened with the connection's own key, unsealed
//! only for the call, and a connection that takes only sealed assertions
//! refuses a readable one. Spending the assertion, so it is never taken twice,
//! is the ledger's, which the use case asks right after.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::authentication::SecretEncryptor;
use ianua_app::ports::federation::{SamlAnswer, SamlConnection, SamlValidator, ServiceProvider};
use ianua_domain::domains::federation::connection::{AssertionDecryption, SamlConfig};
use ianua_domain::domains::federation::provider_values::ProviderValues;
use ianua_domain::domains::federation::saml::assertion::{
    AssertionDelivery, AssertionFacts, SamlAssertion,
};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    ConnectionId, Email, Fact, FederatedSubject, SamlAssertionId, SamlRequestId, SessionIndex,
    Setting,
};
use roxmltree::Node;
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::saml::conditions::{
    Expected, ensure_bearer, ensure_conditions, ensure_issued, ensure_session_current,
};
use crate::saml::encryption::{DecryptionKey, opened};
use crate::saml::xml::document::{
    ASSERTION, Comments, PROTOCOL, children, elements, ensure_version, from_base64, is, only_child,
    parse, refused, required_attribute, required_child, text_of,
};
use crate::saml::xml::keys::TrustedKey;
use crate::saml::xml::signature::{SignatureCheck, SignatureRefused, checked, ensure_placed};

/// The status of a response that signed the person in.
const SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";

/// The format of an issuer named as an entity.
const ENTITY: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";

/// The format a `NameID` has when it states none.
const UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";

/// The format of a `NameID` that is an email address.
const EMAIL_FORMAT: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

/// The attributes providers carry the person's address in, the first one
/// found taken, compared without case.
const EMAIL_ATTRIBUTES: [&str; 4] = [
    "email",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "urn:oid:0.9.2342.19200300.100.1.3",
    "mail",
];

/// Checks SAML responses with XML Signature against the certificates a
/// connection takes, opening sealed assertions with the connection's key.
pub struct DsigSamlValidator {
    encryptor: Arc<dyn SecretEncryptor>,
}

impl DsigSamlValidator {
    /// A validator opening connections' sealed private keys with
    /// `encryptor`.
    #[must_use]
    pub fn new(encryptor: Arc<dyn SecretEncryptor>) -> Self {
        Self { encryptor }
    }

    /// The private key `connection` takes sealed assertions with, unsealed,
    /// when it takes them.
    async fn decryption_key(
        &self,
        decryption: &AssertionDecryption,
        connection: &SamlConnection,
    ) -> Result<Option<DecryptionKey>, DomainError> {
        let AssertionDecryption::Required(key) = decryption else {
            return Ok(None);
        };
        let place = connection.decryption_key_place();
        let opened = Zeroizing::new(
            self.encryptor
                .decrypt(key.sealed_private_key(), &place)
                .await?,
        );
        let unreadable = || DomainError::infra_msg("the connection's private key cannot be read");
        let pem = std::str::from_utf8(&opened).map_err(|_| unreadable())?;
        DecryptionKey::from_pkcs8_pem(pem)
            .map(Some)
            .map_err(|_| unreadable())
    }
}

#[async_trait]
impl SamlValidator for DsigSamlValidator {
    async fn validate(
        &self,
        answer: &SamlAnswer<'_>,
        config: &SamlConfig,
        connection: &SamlConnection,
        service_provider: &ServiceProvider,
    ) -> Result<SamlAssertion, DomainError> {
        let decryption = self
            .decryption_key(&config.assertion_decryption, connection)
            .await?;
        let answered = Answered {
            response: answer.response,
            request: answer.in_response_to,
            config,
            connection_id: connection.id,
            service_provider,
            now: clock::now(),
        };
        checked_answer(&answered, decryption.as_ref())
    }
}

/// A response and everything it is checked against.
struct Answered<'a> {
    response: &'a str,
    request: &'a SamlRequestId,
    config: &'a SamlConfig,
    connection_id: ConnectionId,
    service_provider: &'a ServiceProvider,
    now: OffsetDateTime,
}

impl Answered<'_> {
    fn expected(&self) -> Expected<'_> {
        Expected {
            now: self.now,
            audience: self.service_provider.entity_id.as_str(),
            recipient: self.service_provider.acs_url.as_str(),
            request: self.request.as_str(),
        }
    }
}

/// How the assertion reached this platform: under the response's own
/// signature or not, and sealed or readable.
#[derive(Debug, Clone, Copy)]
struct Carriage {
    response: SignatureCheck,
    delivery: AssertionDelivery,
}

/// The assertion `answered` carries, once every check holds.
fn checked_answer(
    answered: &Answered<'_>,
    decryption: Option<&DecryptionKey>,
) -> Result<SamlAssertion, DomainError> {
    let xml = from_base64(answered.response)?;
    let document = parse(&xml, Comments::Refused)?;
    let root = document.root_element();
    ensure_response(root, answered)?;
    ensure_placed(&document, |parent| {
        parent == root || is_carried(parent, root)
    })?;
    let keys = TrustedKey::all(answered.config.certificates.accepted());
    let response = checked(root, &keys).map_err(SignatureRefused::as_invalid)?;
    let carried = carried_assertion(root)?;
    if !is(carried, ASSERTION, "EncryptedAssertion") {
        ensure_readable_taken(answered.config)?;
        let carriage = Carriage {
            response,
            delivery: AssertionDelivery::Readable,
        };
        return read_assertion(carried, carriage, answered, &keys);
    }
    let key = decryption.ok_or_else(|| {
        refused("the assertion came sealed, and the connection holds no key to open it")
    })?;
    let plain = opened(carried, key)?;
    let inner = parse(&plain, Comments::Refused)?;
    let assertion = inner.root_element();
    ensure_placed(&inner, |parent| parent == assertion)?;
    let carriage = Carriage {
        response,
        delivery: AssertionDelivery::Encrypted,
    };
    read_assertion(assertion, carriage, answered, &keys)
}

/// Refuses a response that is not a successful answer to the request
/// sent, posted where it arrived, from the connection's provider.
fn ensure_response(root: Node<'_, '_>, answered: &Answered<'_>) -> Result<(), DomainError> {
    if !is(root, PROTOCOL, "Response") {
        return Err(refused("the message is not a SAML response"));
    }
    ensure_version(root)?;
    if root.attribute("Destination") != Some(answered.service_provider.acs_url.as_str()) {
        return Err(refused("the response was sent to another address"));
    }
    if root.attribute("InResponseTo") != Some(answered.request.as_str()) {
        return Err(refused("the response answers another request"));
    }
    if let Some(issuer) = only_child(root, ASSERTION, "Issuer")? {
        ensure_issuer(issuer, answered.config)?;
    }
    let status = required_child(root, PROTOCOL, "Status", "the response carries no status")?;
    let code = required_child(
        status,
        PROTOCOL,
        "StatusCode",
        "the response carries no status",
    )?;
    if code.attribute("Value") != Some(SUCCESS) {
        return Err(refused("the provider did not sign the person in"));
    }
    Ok(())
}

/// Refuses a readable assertion on a connection that takes only sealed
/// ones, here where the assertion is read, so no caller has to remember
/// the rule for the check to hold.
fn ensure_readable_taken(config: &SamlConfig) -> Result<(), DomainError> {
    match &config.assertion_decryption {
        AssertionDecryption::Required(_) => Err(refused(
            "the assertion came readable, and the connection takes only sealed ones",
        )),
        AssertionDecryption::NotExpected => Ok(()),
    }
}

/// Refuses an `Issuer` naming anyone but the connection's provider.
fn ensure_issuer(issuer: Node<'_, '_>, config: &SamlConfig) -> Result<(), DomainError> {
    let as_entity = issuer
        .attribute("Format")
        .is_none_or(|format| format == ENTITY);
    if !as_entity || text_of(issuer)? != config.entity_id.as_str() {
        return Err(refused("the message comes from another provider"));
    }
    Ok(())
}

/// Whether `parent` is the assertion a response carries, which may hold a
/// signature of its own.
fn is_carried<'a, 'input>(parent: Node<'a, 'input>, root: Node<'a, 'input>) -> bool {
    is(parent, ASSERTION, "Assertion") && parent.parent_element() == Some(root)
}

/// The one assertion, readable or sealed, the response carries as its own
/// child. A second anywhere in the document, inside another element or as
/// a sibling, is refused: it is how a forged assertion is slipped beside a
/// signed one.
fn carried_assertion<'a, 'input>(root: Node<'a, 'input>) -> Result<Node<'a, 'input>, DomainError> {
    let is_assertion = |node: &Node<'_, '_>| {
        is(*node, ASSERTION, "Assertion") || is(*node, ASSERTION, "EncryptedAssertion")
    };
    if root.document().descendants().filter(is_assertion).count() != 1 {
        return Err(refused("the response does not carry exactly one assertion"));
    }
    elements(root)
        .into_iter()
        .find(is_assertion)
        .ok_or_else(|| refused("the assertion is not where a response carries it"))
}

/// The assertion `assertion` says, once it is signed, from the provider,
/// and holds for this sign-in.
fn read_assertion(
    assertion: Node<'_, '_>,
    carriage: Carriage,
    answered: &Answered<'_>,
    keys: &[TrustedKey],
) -> Result<SamlAssertion, DomainError> {
    if !is(assertion, ASSERTION, "Assertion") {
        return Err(refused("the sealed element is not an assertion"));
    }
    ensure_version(assertion)?;
    let own = checked(assertion, keys).map_err(SignatureRefused::as_invalid)?;
    if own == SignatureCheck::Absent && carriage.response == SignatureCheck::Absent {
        return Err(refused("the assertion is not signed"));
    }
    let assertion_id = SamlAssertionId::new(required_attribute(
        assertion,
        "ID",
        "the assertion has no ID",
    )?)?;
    let subject = confirmed_subject(assertion, answered)?;
    let named = Named::read(subject, answered.config)?;
    let attributes = attributes_of(assertion);
    let statement = only_child(assertion, ASSERTION, "AuthnStatement")?;
    Ok(SamlAssertion::new(AssertionFacts {
        connection_id: answered.connection_id,
        assertion_id,
        email: email_of(&attributes, &named)?,
        name_id: named.subject,
        session_index: session_index(statement)?,
        delivery: carriage.delivery,
        authn_context: authn_context(statement),
        attributes: ProviderValues::new(attributes),
    }))
}

/// Reads the subject after checking the provider, validity window and bearer confirmation.
fn confirmed_subject<'a, 'input>(
    assertion: Node<'a, 'input>,
    answered: &Answered<'_>,
) -> Result<Node<'a, 'input>, DomainError> {
    ensure_issuer(
        required_child(
            assertion,
            ASSERTION,
            "Issuer",
            "the assertion names no issuer",
        )?,
        answered.config,
    )?;
    let expected = answered.expected();
    ensure_issued(assertion, answered.now)?;
    ensure_conditions(assertion, &expected)?;
    let subject = required_child(
        assertion,
        ASSERTION,
        "Subject",
        "the assertion names nobody",
    )?;
    ensure_bearer(subject, &expected)?;
    ensure_session_current(assertion, answered.now)?;
    Ok(subject)
}

/// Whom an assertion's `NameID` names, and the address it is when its
/// format says so.
struct Named {
    subject: FederatedSubject,
    address: Option<String>,
}

impl Named {
    /// The `NameID` of `subject`, in the format the connection takes.
    fn read(subject: Node<'_, '_>, config: &SamlConfig) -> Result<Self, DomainError> {
        let hidden = only_child(subject, ASSERTION, "EncryptedID")?.is_some()
            || only_child(subject, ASSERTION, "BaseID")?.is_some();
        if hidden {
            return Err(refused(
                "the assertion names the person in a form this platform does not read",
            ));
        }
        let name_id = required_child(subject, ASSERTION, "NameID", "the assertion names nobody")?;
        let format = name_id.attribute("Format").unwrap_or(UNSPECIFIED);
        if format != config.name_id_format.as_str() {
            return Err(refused(
                "the assertion names the person in another format than the connection takes",
            ));
        }
        let value = text_of(name_id)?;
        Ok(Self {
            subject: FederatedSubject::new(value.as_str())?,
            address: (format == EMAIL_FORMAT).then_some(value),
        })
    }
}

/// Every attribute the assertion carries, each with its values, those
/// holding markup or nothing left out.
fn attributes_of(assertion: Node<'_, '_>) -> HashMap<String, Vec<String>> {
    let mut by_name: HashMap<String, Vec<String>> = HashMap::new();
    let attributes = children(assertion, ASSERTION, "AttributeStatement")
        .flat_map(|statement| children(statement, ASSERTION, "Attribute"));
    for attribute in attributes {
        let Some(name) = attribute.attribute("Name") else {
            continue;
        };
        let values = children(attribute, ASSERTION, "AttributeValue")
            .filter_map(|value| text_of(value).ok())
            .filter(|value| !value.is_empty());
        by_name.entry(name.to_owned()).or_default().extend(values);
    }
    by_name.retain(|_, values| !values.is_empty());
    by_name
}

/// The person's address: from the first address attribute carried, or
/// the `NameID` when its format says it is one.
fn email_of(
    attributes: &HashMap<String, Vec<String>>,
    named: &Named,
) -> Result<Email, DomainError> {
    let carried = EMAIL_ATTRIBUTES.iter().find_map(|known| {
        attributes
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(known))
            .and_then(|(_, values)| values.first())
    });
    let address = carried
        .or(named.address.as_ref())
        .ok_or_else(|| refused("the assertion names no email address"))?;
    Ok(Email::new(address.as_str())?)
}

fn session_index(statement: Option<Node<'_, '_>>) -> Result<Setting<SessionIndex>, DomainError> {
    let index = statement
        .and_then(|statement| statement.attribute("SessionIndex"))
        .map(SessionIndex::new)
        .transpose()?;
    Ok(Setting::from_stored(index))
}

fn authn_context(statement: Option<Node<'_, '_>>) -> Fact<String> {
    statement
        .and_then(|statement| {
            only_child(statement, ASSERTION, "AuthnContext")
                .ok()
                .flatten()
        })
        .and_then(|context| {
            only_child(context, ASSERTION, "AuthnContextClassRef")
                .ok()
                .flatten()
        })
        .and_then(|class| text_of(class).ok())
        .filter(|class| !class.is_empty())
        .map_or(Fact::Unknown, Fact::Known)
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use ianua_app::ports::authentication::SealOwner;
    use ianua_app::ports::federation::SamlAssertionLedger as _;
    use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
    use ianua_domain::domains::federation::connection::{
        AuthnRequestSigning, IdpCertificates, SpEncryptionKey,
    };
    use ianua_domain::types::{HttpsUrl, SamlEntityId, SamlNameIdFormat, TenantId};
    use time::Duration;
    use time::format_description::well_known::Iso8601;

    use super::*;
    use crate::crypto::{AesGcmSecretEncryptor, SealingKey};
    use crate::postgres::federation::PgSamlAssertionLedger;
    use crate::saml::encryption::tests::{sealed, sp_key};
    use crate::saml::signer::tests::signed;
    use crate::saml::xml::keys::tests::TestKey;
    use crate::test_support::TestDb;
    use crate::test_support::rows::authorization::tenant;

    const IDP: &str = "https://idp.acme.com";
    const SP: &str = "https://ianua.example.com";
    const ACS: &str = "https://ianua.example.com/acs";
    const REQUEST: &str = "_req1";
    const PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

    /// Okta, as Acme's connection trusts it, and this platform as its
    /// service provider.
    struct Fixture {
        idp: TestKey,
        config: SamlConfig,
        service_provider: ServiceProvider,
        validator: DsigSamlValidator,
        encryptor: Arc<AesGcmSecretEncryptor>,
        connection: SamlConnection,
    }

    impl Fixture {
        fn new() -> Self {
            let idp = TestKey::new(SigningAlgorithm::Es256);
            let encryptor = Arc::new(AesGcmSecretEncryptor::new(
                SealingKey::new("k1", [7; 32]).unwrap(),
                Vec::new(),
            ));
            Self {
                config: SamlConfig {
                    entity_id: HttpsUrl::new(IDP).unwrap(),
                    sso_url: HttpsUrl::new("https://idp.acme.com/sso").unwrap(),
                    slo_url: Setting::Unset,
                    certificates: IdpCertificates::single(idp.certificate.clone()),
                    name_id_format: SamlNameIdFormat::new(PERSISTENT).unwrap(),
                    request_signing: AuthnRequestSigning::Unsigned,
                    assertion_decryption: AssertionDecryption::NotExpected,
                    metadata_url: Setting::Unset,
                },
                service_provider: ServiceProvider {
                    entity_id: SamlEntityId::new(SP).unwrap(),
                    acs_url: HttpsUrl::new(ACS).unwrap(),
                },
                validator: DsigSamlValidator::new(encryptor.clone()),
                encryptor,
                idp,
                connection: SamlConnection {
                    owner: SealOwner::Tenant(TenantId::new()),
                    id: ConnectionId::new(),
                },
            }
        }

        /// Acme's connection taking only sealed assertions, with the SP
        /// key `sp` sealed for `sealed_for`.
        async fn requiring_sealed(&mut self, sp: &TestKey, sealed_for: &SamlConnection) {
            let sealed_key = self
                .encryptor
                .encrypt(
                    sp.private_key.expose().as_bytes(),
                    &sealed_for.decryption_key_place(),
                )
                .await
                .unwrap();
            self.config.assertion_decryption = AssertionDecryption::Required(SpEncryptionKey::new(
                sp.certificate.clone(),
                sealed_key,
            ));
        }

        async fn validate(&self, response: &str) -> Result<SamlAssertion, DomainError> {
            let encoded = STANDARD.encode(response);
            let request = SamlRequestId::new(REQUEST).unwrap();
            let answer = SamlAnswer {
                response: &encoded,
                in_response_to: &request,
            };
            self.validator
                .validate(
                    &answer,
                    &self.config,
                    &self.connection,
                    &self.service_provider,
                )
                .await
        }

        /// A response carrying Ann's assertion, signed by Okta.
        fn signed_response(&self) -> String {
            response(&signed(
                &assertion("_a1", SP, Duration::minutes(5)),
                &self.idp,
            ))
        }
    }

    fn instant(offset: Duration) -> String {
        (OffsetDateTime::now_utc() + offset)
            .format(&Iso8601::DEFAULT)
            .unwrap()
    }

    /// Ann's assertion as Okta writes it, for `audience`, ending `ends`
    /// from now.
    fn assertion(id: &str, audience: &str, ends: Duration) -> String {
        format!(
            r#"<saml:Assertion xmlns:saml="{ASSERTION}" ID="{id}" Version="2.0" IssueInstant="{now}"><saml:Issuer>{IDP}</saml:Issuer><saml:Subject><saml:NameID Format="{PERSISTENT}">00u1</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="{ACS}" InResponseTo="{REQUEST}" NotOnOrAfter="{end}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{start}" NotOnOrAfter="{end}"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="{now}" SessionIndex="_s1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>ann@acme.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name="groups"><saml:AttributeValue>eng</saml:AttributeValue><saml:AttributeValue>ops</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>"#,
            now = instant(Duration::ZERO),
            start = instant(-Duration::minutes(1)),
            end = instant(ends),
        )
    }

    /// A response from Okta answering the request, carrying `carried`.
    fn response(carried: &str) -> String {
        format!(
            r#"<samlp:Response xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}" ID="_r1" Version="2.0" IssueInstant="{now}" Destination="{ACS}" InResponseTo="{REQUEST}"><saml:Issuer>{IDP}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{SUCCESS}"/></samlp:Status>{carried}</samlp:Response>"#,
            now = instant(Duration::ZERO),
        )
    }

    fn refused_as_invalid(result: &Result<SamlAssertion, DomainError>) -> bool {
        matches!(result, Err(DomainError::Validation(_)))
    }

    /// Ann's response signed by Okta is taken: her `NameID`, address,
    /// provider session, sign-in method and attributes come through.
    #[tokio::test]
    async fn a_signed_response_signs_the_person_in() {
        let fx = Fixture::new();

        let assertion = fx.validate(&fx.signed_response()).await.unwrap();

        assert_eq!(assertion.name_id().as_str(), "00u1");
        assert_eq!(assertion.email().as_str(), "ann@acme.com");
        assert_eq!(assertion.assertion_id().as_str(), "_a1");
        assert_eq!(
            assertion.session_index().map(SessionIndex::as_str),
            Some("_s1")
        );
        assert_eq!(assertion.delivery(), AssertionDelivery::Readable);
        assert_eq!(assertion.attributes().values("groups"), ["eng", "ops"]);
    }

    /// An assertion signed only through the response around it is taken:
    /// the response's signature covers it.
    #[tokio::test]
    async fn an_assertion_signed_through_its_response_is_taken() {
        let fx = Fixture::new();
        let whole = signed(
            &response(&assertion("_a1", SP, Duration::minutes(5))),
            &fx.idp,
        );

        assert!(fx.validate(&whole).await.is_ok());
    }

    /// An unsigned assertion naming Ann fails response validation.
    #[tokio::test]
    async fn an_unsigned_response_is_refused() {
        let fx = Fixture::new();
        let unsigned = response(&assertion("_a1", SP, Duration::minutes(5)));

        assert!(refused_as_invalid(&fx.validate(&unsigned).await));
    }

    /// Replacing the subject of Okta's signed assertion makes validation fail.
    #[tokio::test]
    async fn a_tampered_assertion_is_refused() {
        let fx = Fixture::new();
        let tampered = fx.signed_response().replace(">00u1<", ">00u2<");

        assert!(refused_as_invalid(&fx.validate(&tampered).await));
    }

    /// An assertion signed by another key is invalid even when it carries that key's certificate.
    #[tokio::test]
    async fn an_assertion_signed_by_another_key_is_refused() {
        let fx = Fixture::new();
        let mallory = TestKey::new(SigningAlgorithm::Es256);
        let forged = response(&signed(
            &assertion("_a1", SP, Duration::minutes(5)),
            &mallory,
        ));

        assert!(refused_as_invalid(&fx.validate(&forged).await));
    }

    /// An extra assertion invalidates the response whether placed beside the signed
    /// assertion, around it, or inside extensions.
    #[tokio::test]
    async fn a_wrapped_assertion_is_refused() {
        let fx = Fixture::new();
        let genuine = signed(&assertion("_a1", SP, Duration::minutes(5)), &fx.idp);
        let forged = assertion("_evil", SP, Duration::minutes(5)).replace(">00u1<", ">admin<");
        let beside = response(&format!("{forged}{genuine}"));
        let inside = response(&forged.replace(
            "</saml:Assertion>",
            &format!("<saml:Advice>{genuine}</saml:Advice></saml:Assertion>"),
        ));
        let extension = response(&forged).replace(
            "<samlp:Status>",
            &format!("<samlp:Extensions>{genuine}</samlp:Extensions><samlp:Status>"),
        );

        assert!(refused_as_invalid(&fx.validate(&beside).await));
        assert!(refused_as_invalid(&fx.validate(&inside).await));
        assert!(refused_as_invalid(&fx.validate(&extension).await));
    }

    /// Reusing the signed assertion's ID and signature cannot validate a different body.
    #[tokio::test]
    async fn a_signature_moved_to_another_assertion_is_refused() {
        let fx = Fixture::new();
        let genuine = signed(&assertion("_a1", SP, Duration::minutes(5)), &fx.idp);
        let start = genuine.find("<ds:Signature").unwrap();
        let end = genuine.find("</ds:Signature>").unwrap() + "</ds:Signature>".len();
        let forged = assertion("_a1", SP, Duration::minutes(5))
            .replace(">00u1<", ">admin<")
            .replacen(
                "</saml:Issuer>",
                &format!("</saml:Issuer>{}", &genuine[start..end]),
                1,
            );

        assert!(refused_as_invalid(&fx.validate(&response(&forged)).await));
    }

    /// Okta's valid signature does not make an assertion for another audience acceptable.
    #[tokio::test]
    async fn an_assertion_for_another_audience_is_refused() {
        let fx = Fixture::new();
        let elsewhere = signed(
            &assertion("_a1", "https://other.example.com", Duration::minutes(5)),
            &fx.idp,
        );

        assert!(refused_as_invalid(
            &fx.validate(&response(&elsewhere)).await
        ));
    }

    /// An expired assertion fails validation even inside a readable response.
    #[tokio::test]
    async fn an_expired_assertion_is_refused() {
        let fx = Fixture::new();
        let expired = signed(&assertion("_a1", SP, -Duration::minutes(10)), &fx.idp);

        assert!(refused_as_invalid(&fx.validate(&response(&expired)).await));
    }

    /// Changing the request reference in a signed response makes it invalid.
    #[tokio::test]
    async fn a_response_to_another_request_is_refused() {
        let fx = Fixture::new();
        let other = fx.signed_response().replace(
            &format!(r#"InResponseTo="{REQUEST}""#),
            r#"InResponseTo="_other""#,
        );

        assert!(refused_as_invalid(&fx.validate(&other).await));
    }

    /// A trusted signing key cannot substitute another issuer for the configured provider.
    #[tokio::test]
    async fn an_assertion_from_another_issuer_is_refused() {
        let fx = Fixture::new();
        let other = signed(
            &assertion("_a1", SP, Duration::minutes(5))
                .replace(&format!(">{IDP}<"), ">https://idp.evil.example.com<"),
            &fx.idp,
        );

        assert!(refused_as_invalid(&fx.validate(&response(&other)).await));
    }

    /// The same response validates twice, but its assertion can be spent only once
    /// in the replay ledger.
    #[tokio::test]
    async fn a_replayed_assertion_is_spent_once() {
        let fx = Fixture::new();
        let db = TestDb::fresh().await;
        let ledger = PgSamlAssertionLedger::new(Arc::clone(&db.databases));
        let tenant = tenant();
        let captured = fx.signed_response();
        let remembered = clock::now() + Duration::days(1);

        let first = fx.validate(&captured).await.unwrap();
        let again = fx.validate(&captured).await.unwrap();

        let spent = ledger
            .spend(&tenant, first.assertion_id(), remembered)
            .await
            .unwrap();
        let spent_again = ledger
            .spend(&tenant, again.assertion_id(), remembered)
            .await
            .unwrap();
        assert!(spent);
        assert!(!spent_again);
    }

    /// A connection taking only sealed assertions opens one sealed to its
    /// key, and reports it came sealed.
    #[tokio::test]
    async fn a_sealed_assertion_opens_with_the_connections_key() {
        let mut fx = Fixture::new();
        let (sp, _) = sp_key();
        let own = fx.connection;
        fx.requiring_sealed(&sp, &own).await;
        let genuine = signed(&assertion("_a1", SP, Duration::minutes(5)), &fx.idp);

        let opened = fx
            .validate(&response(&sealed(&genuine, &sp.certificate)))
            .await
            .unwrap();

        assert_eq!(opened.delivery(), AssertionDelivery::Encrypted);
        assert_eq!(opened.name_id().as_str(), "00u1");
    }

    /// Requiring encryption rejects a plaintext assertion even when Okta signed it.
    #[tokio::test]
    async fn a_readable_assertion_is_refused_where_only_sealed_ones_are_taken() {
        let mut fx = Fixture::new();
        let (sp, _) = sp_key();
        let own = fx.connection;
        fx.requiring_sealed(&sp, &own).await;

        let result = fx.validate(&fx.signed_response()).await;

        assert!(refused_as_invalid(&result));
    }

    /// A decryption key sealed for another tenant fails to open in Acme's connection,
    /// producing an infrastructure error rather than a validated assertion.
    #[tokio::test]
    async fn a_key_sealed_for_another_connection_does_not_open() {
        let mut fx = Fixture::new();
        let (sp, _) = sp_key();
        let elsewhere = SamlConnection {
            owner: SealOwner::Tenant(TenantId::new()),
            id: fx.connection.id,
        };
        fx.requiring_sealed(&sp, &elsewhere).await;
        let genuine = signed(&assertion("_a1", SP, Duration::minutes(5)), &fx.idp);

        let result = fx
            .validate(&response(&sealed(&genuine, &sp.certificate)))
            .await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// An encrypted assertion is invalid when the connection has no decryption key.
    #[tokio::test]
    async fn a_sealed_assertion_without_a_key_is_refused() {
        let fx = Fixture::new();
        let (sp, _) = sp_key();
        let genuine = signed(&assertion("_a1", SP, Duration::minutes(5)), &fx.idp);

        let result = fx
            .validate(&response(&sealed(&genuine, &sp.certificate)))
            .await;

        assert!(refused_as_invalid(&result));
    }
}
