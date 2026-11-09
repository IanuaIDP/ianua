//! Reading the SAML messages peers send: an app's sign-in request, and
//! single logout requests and answers, each by the binding it came on.
//!
//! A message posted in a form carries its signature inside the XML, on its
//! root; one sent by redirect carries it on the query. Either way it is
//! checked against the certificates the caller trusts for that peer, and a
//! signature that does not verify is refused outright. Whether an unsigned
//! message may do anything is the domain's to say, except for a logout,
//! whose port asks the signature of it.

use ianua_app::ports::federation::{
    InboundSamlMessage, RedirectSignature, SamlBinding, SamlMessageReader, SignatureTrust,
};
use ianua_domain::domains::federation::saml::authn_request::{
    InboundAuthnRequest, InboundAuthnRequestRow, NameIdAsked, Reauthentication, RequestSignature,
};
use ianua_domain::domains::federation::saml::logout::{
    LogoutRequestParts, LogoutResponseParts, LogoutStatus, SamlLogoutRequest, SamlLogoutResponse,
};
use ianua_domain::domains::federation::saml::name_id::SamlNameIdValue;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    HttpsUrl, SamlEntityId, SamlNameIdFormat, SamlRequestId, SamlResponseId, SessionIndex,
};
use roxmltree::{Document, Node};
use time::OffsetDateTime;
use time::format_description::well_known::Iso8601;

use crate::saml::conditions::ALLOWED_SKEW;
use crate::saml::redirect::{SignedQuery, checked as query_checked};
use crate::saml::xml::document::{
    ASSERTION, Comments, PROTOCOL, children, ensure_version, from_base64, from_deflated_base64, is,
    only_child, parse, refused, required_attribute, required_child, text_of,
};
use crate::saml::xml::keys::TrustedKey;
use crate::saml::xml::signature::{SignatureCheck, SignatureRefused, checked, ensure_placed};

/// Reads SAML messages from peers, checking XML and query signatures.
#[derive(Debug, Clone, Copy, Default)]
pub struct DsigSamlMessageReader;

impl SamlMessageReader for DsigSamlMessageReader {
    fn issuer(&self, message: &InboundSamlMessage) -> Result<SamlEntityId, DomainError> {
        let xml = received(message)?;
        let document = parse(&xml, Comments::Refused)?;
        issuer_of(document.root_element())
    }

    fn authn_request(
        &self,
        message: &InboundSamlMessage,
        trust: &SignatureTrust,
    ) -> Result<InboundAuthnRequest, DomainError> {
        let xml = received(message)?;
        let document = parse(&xml, Comments::Refused)?;
        let root = message_root(&document, "AuthnRequest")?;
        let signature = match signature_of(message, root, trust)? {
            SignatureCheck::Absent => RequestSignature::Absent,
            SignatureCheck::Verified => RequestSignature::Verified,
        };
        authn_request_of(root, signature)
    }

    fn logout_request(
        &self,
        message: &InboundSamlMessage,
        trust: &SignatureTrust,
    ) -> Result<SamlLogoutRequest, DomainError> {
        let xml = received(message)?;
        let document = parse(&xml, Comments::Refused)?;
        let root = message_root(&document, "LogoutRequest")?;
        ensure_signed_as_asked(signature_of(message, root, trust)?, trust)?;
        logout_request_of(root)
    }

    fn logout_response(
        &self,
        message: &InboundSamlMessage,
        trust: &SignatureTrust,
    ) -> Result<SamlLogoutResponse, DomainError> {
        let xml = received(message)?;
        let document = parse(&xml, Comments::Refused)?;
        let root = message_root(&document, "LogoutResponse")?;
        ensure_signed_as_asked(signature_of(message, root, trust)?, trust)?;
        logout_response_of(root)
    }
}

/// The XML of `message`, decoded as its binding carries it.
fn received(message: &InboundSamlMessage) -> Result<String, DomainError> {
    match message.binding {
        SamlBinding::Post => from_base64(&message.message),
        SamlBinding::Redirect(_) => from_deflated_base64(&message.message),
    }
}

/// The root of `document`, once it is the protocol message `name` of SAML
/// 2.0 and holds no signature but on itself.
fn message_root<'a, 'input>(
    document: &'a Document<'input>,
    name: &'static str,
) -> Result<Node<'a, 'input>, DomainError> {
    let root = document.root_element();
    if !is(root, PROTOCOL, name) {
        return Err(refused("the message is not the kind expected here"));
    }
    ensure_version(root)?;
    ensure_placed(document, |parent| parent == root)?;
    Ok(root)
}

/// Whether `root` came signed by a key `trust` names, by the binding it
/// came on. With no signature required, none is checked.
fn signature_of(
    message: &InboundSamlMessage,
    root: Node<'_, '_>,
    trust: &SignatureTrust,
) -> Result<SignatureCheck, DomainError> {
    let SignatureTrust::SignedBy(certificates) = trust else {
        return Ok(SignatureCheck::Absent);
    };
    let keys = TrustedKey::all(certificates);
    let checked_by_binding = match &message.binding {
        SamlBinding::Post => checked(root, &keys),
        SamlBinding::Redirect(RedirectSignature::Absent) => Ok(SignatureCheck::Absent),
        SamlBinding::Redirect(RedirectSignature::Present {
            algorithm,
            signature,
            signed_query,
        }) => query_checked(
            &SignedQuery {
                algorithm,
                signature,
                query: signed_query,
            },
            &message.message,
            &keys,
        ),
    };
    checked_by_binding.map_err(SignatureRefused::as_forbidden)
}

/// Refuses an unsigned message where `trust` asks for a signature.
fn ensure_signed_as_asked(
    check: SignatureCheck,
    trust: &SignatureTrust,
) -> Result<(), DomainError> {
    let asked = matches!(trust, SignatureTrust::SignedBy(_));
    if asked && check == SignatureCheck::Absent {
        return Err(DomainError::forbidden(message!(
            "infra-the-message-is-not-signed",
            "the message is not signed"
        )));
    }
    Ok(())
}

/// The peer `root` names as its issuer.
fn issuer_of(root: Node<'_, '_>) -> Result<SamlEntityId, DomainError> {
    entity_named(required_child(
        root,
        ASSERTION,
        "Issuer",
        "the message names no issuer",
    )?)
}

/// The entity id `issuer` holds.
fn entity_named(issuer: Node<'_, '_>) -> Result<SamlEntityId, DomainError> {
    Ok(SamlEntityId::new(text_of(issuer)?)?)
}

/// The sign-in request `root` holds.
fn authn_request_of(
    root: Node<'_, '_>,
    signature: RequestSignature,
) -> Result<InboundAuthnRequest, DomainError> {
    let id = SamlRequestId::new(required_attribute(root, "ID", "the request has no ID")?)?;
    let issuer = only_child(root, ASSERTION, "Issuer")?
        .map(entity_named)
        .transpose()?;
    let acs_url = root
        .attribute("AssertionConsumerServiceURL")
        .map(|address| {
            HttpsUrl::new(address).map_err(|_| {
                refused("the request asks for an answer at an address that is not HTTPS")
            })
        })
        .transpose()?;
    InboundAuthnRequest::reconstitute(InboundAuthnRequestRow {
        id,
        issuer,
        acs_url,
        force_authn: reauthentication(root.attribute("ForceAuthn"))?,
        name_id_policy: name_id_asked(root)?,
        signature,
    })
}

/// Whether the request forces a fresh sign-in, as `xs:boolean` writes it.
fn reauthentication(written: Option<&str>) -> Result<Reauthentication, DomainError> {
    match written {
        Some("true" | "1") => Ok(Reauthentication::Forced),
        None | Some("false" | "0") => Ok(Reauthentication::NotForced),
        Some(_) => Err(refused("the request's ForceAuthn is not a boolean")),
    }
}

/// The `NameID` format the request's policy asks for.
fn name_id_asked(root: Node<'_, '_>) -> Result<NameIdAsked, DomainError> {
    let format =
        only_child(root, PROTOCOL, "NameIDPolicy")?.and_then(|policy| policy.attribute("Format"));
    let Some(format) = format else {
        return Ok(NameIdAsked::AnyFormat);
    };
    Ok(NameIdAsked::Format(SamlNameIdFormat::new(format)?))
}

/// The logout request `root` holds, once it has not lapsed, with the time
/// it was issued, which bounds it when it carries no `NotOnOrAfter`.
fn logout_request_of(root: Node<'_, '_>) -> Result<SamlLogoutRequest, DomainError> {
    ensure_not_lapsed(root.attribute("NotOnOrAfter"), clock::now())?;
    let issued_at = instant_of(required_attribute(
        root,
        "IssueInstant",
        "the request carries no issue time",
    )?)?;
    let hidden = only_child(root, ASSERTION, "EncryptedID")?.is_some()
        || only_child(root, ASSERTION, "BaseID")?.is_some();
    if hidden {
        return Err(refused(
            "the request names the person in a form this platform does not read",
        ));
    }
    let name_id = required_child(root, ASSERTION, "NameID", "the request names nobody")?;
    let session_indexes = children(root, PROTOCOL, "SessionIndex")
        .map(|index| Ok(SessionIndex::new(text_of(index)?)?))
        .collect::<Result<Vec<_>, DomainError>>()?;
    Ok(SamlLogoutRequest::new(LogoutRequestParts {
        id: SamlRequestId::new(required_attribute(root, "ID", "the request has no ID")?)?,
        issuer: issuer_of(root)?,
        issued_at,
        name_id: SamlNameIdValue::new(text_of(name_id)?)?,
        session_indexes,
    }))
}

/// The logout answer `root` holds.
fn logout_response_of(root: Node<'_, '_>) -> Result<SamlLogoutResponse, DomainError> {
    let status = required_child(root, PROTOCOL, "Status", "the answer carries no status")?;
    let top = required_child(
        status,
        PROTOCOL,
        "StatusCode",
        "the answer carries no status",
    )?;
    let sub = only_child(top, PROTOCOL, "StatusCode")?
        .and_then(|code| code.attribute("Value"))
        .unwrap_or_default();
    Ok(SamlLogoutResponse::new(LogoutResponseParts {
        id: SamlResponseId::new(required_attribute(root, "ID", "the answer has no ID")?)?,
        issuer: issuer_of(root)?,
        in_response_to: SamlRequestId::new(required_attribute(
            root,
            "InResponseTo",
            "the answer names no request",
        )?)?,
        status: LogoutStatus::from_codes(top.attribute("Value").unwrap_or_default(), sub),
    }))
}

/// Refuses a request whose `NotOnOrAfter` has passed, by more than the
/// skew allowed.
fn ensure_not_lapsed(ends: Option<&str>, now: OffsetDateTime) -> Result<(), DomainError> {
    let Some(ends) = ends else {
        return Ok(());
    };
    if instant_of(ends)? <= now.saturating_sub(ALLOWED_SKEW) {
        return Err(refused("the request has lapsed"));
    }
    Ok(())
}

/// The moment `written` names.
fn instant_of(written: &str) -> Result<OffsetDateTime, DomainError> {
    OffsetDateTime::parse(written, &Iso8601::DEFAULT)
        .map_err(|_| refused("a time in the request cannot be read"))
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use flate2::Compression;
    use flate2::write::DeflateEncoder;
    use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;

    use super::*;
    use crate::saml::redirect::request_query;
    use crate::saml::signer::tests::signed;
    use crate::saml::xml::keys::PrivateKey;
    use crate::saml::xml::keys::tests::TestKey;

    const APP: &str = "https://app.acme.com";

    fn authn_xml() -> String {
        format!(
            r#"<samlp:AuthnRequest xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}" ID="_req1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" AssertionConsumerServiceURL="https://app.acme.com/acs" ForceAuthn="true"><saml:Issuer>{APP}</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"/></samlp:AuthnRequest>"#
        )
    }

    fn logout_xml(ends: &str) -> String {
        format!(
            r#"<samlp:LogoutRequest xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}" ID="_l1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" NotOnOrAfter="{ends}"><saml:Issuer>{APP}</saml:Issuer><saml:NameID>00u1</saml:NameID><samlp:SessionIndex>_s1</samlp:SessionIndex><samlp:SessionIndex>_s2</samlp:SessionIndex></samlp:LogoutRequest>"#
        )
    }

    fn later() -> String {
        (OffsetDateTime::now_utc() + time::Duration::minutes(5))
            .format(&Iso8601::DEFAULT)
            .unwrap()
    }

    fn posted(xml: &str) -> InboundSamlMessage {
        InboundSamlMessage {
            binding: SamlBinding::Post,
            message: STANDARD.encode(xml),
        }
    }

    fn redirected(xml: &str) -> InboundSamlMessage {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(xml.as_bytes()).unwrap();
        InboundSamlMessage {
            binding: SamlBinding::Redirect(RedirectSignature::Absent),
            message: STANDARD.encode(encoder.finish().unwrap()),
        }
    }

    /// A request the app signed by redirect, as the browser brings it.
    fn redirected_signed_by(key: &TestKey) -> InboundSamlMessage {
        let signer = PrivateKey::of(&key.signing()).unwrap();
        let query = request_query(&authn_xml(), "_req1", Some(&signer)).unwrap();
        let value = |name: &str| {
            url::form_urlencoded::parse(query.as_bytes())
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.into_owned())
                .unwrap()
        };
        InboundSamlMessage {
            message: value("SAMLRequest"),
            binding: SamlBinding::Redirect(RedirectSignature::Present {
                algorithm: value("SigAlg"),
                signature: value("Signature"),
                signed_query: query.clone(),
            }),
        }
    }

    fn trusting(key: &TestKey) -> SignatureTrust {
        SignatureTrust::SignedBy(vec![key.certificate.clone()])
    }

    /// The app's issuer is read before anything is trusted, so its keys
    /// can be found.
    #[test]
    fn the_issuer_is_read_first() {
        let issuer = DsigSamlMessageReader
            .issuer(&redirected(&authn_xml()))
            .unwrap();

        assert_eq!(issuer.as_str(), APP);
    }

    /// A sign-in request names its id, app, answer address, fresh sign-in
    /// and format, and reads as unsigned when it is.
    #[test]
    fn a_sign_in_request_reads_as_sent() {
        let request = DsigSamlMessageReader
            .authn_request(&redirected(&authn_xml()), &SignatureTrust::NotRequired)
            .unwrap();

        assert_eq!(request.id().as_str(), "_req1");
        assert_eq!(
            request.acs_url().map(HttpsUrl::as_str),
            Some("https://app.acme.com/acs")
        );
        assert_eq!(request.force_authn(), Reauthentication::Forced);
        assert_eq!(request.signature(), RequestSignature::Absent);
    }

    /// A request the app signed, by redirect or in a form, reads as
    /// verified against the app's certificate.
    #[test]
    fn a_signed_request_reads_as_verified_by_either_binding() {
        let key = TestKey::new(SigningAlgorithm::Es256);
        let reader = DsigSamlMessageReader;

        let by_redirect = reader
            .authn_request(&redirected_signed_by(&key), &trusting(&key))
            .unwrap();
        let by_form = reader
            .authn_request(&posted(&signed(&authn_xml(), &key)), &trusting(&key))
            .unwrap();

        assert_eq!(by_redirect.signature(), RequestSignature::Verified);
        assert_eq!(by_form.signature(), RequestSignature::Verified);
    }

    /// Requests signed by another key are forbidden in both redirect and form bindings.
    #[test]
    fn a_request_signed_by_another_key_is_refused() {
        let app = TestKey::new(SigningAlgorithm::Es256);
        let mallory = TestKey::new(SigningAlgorithm::Es256);
        let reader = DsigSamlMessageReader;

        let by_redirect = reader.authn_request(&redirected_signed_by(&mallory), &trusting(&app));
        let by_form =
            reader.authn_request(&posted(&signed(&authn_xml(), &mallory)), &trusting(&app));

        assert!(matches!(by_redirect, Err(DomainError::Forbidden(_))));
        assert!(matches!(by_form, Err(DomainError::Forbidden(_))));
    }

    /// Changing the response address after signing makes the request forbidden.
    #[test]
    fn a_tampered_signed_request_is_refused() {
        let key = TestKey::new(SigningAlgorithm::Es256);
        let tampered =
            signed(&authn_xml(), &key).replace("app.acme.com/acs", "evil.example.com/acs");

        let result = DsigSamlMessageReader.authn_request(&posted(&tampered), &trusting(&key));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A logout request from the provider names whom to log out and every
    /// session index it lists, once its signature verifies.
    #[test]
    fn a_signed_logout_request_names_the_person_and_sessions() {
        let key = TestKey::new(SigningAlgorithm::Es256);

        let request = DsigSamlMessageReader
            .logout_request(
                &posted(&signed(&logout_xml(&later()), &key)),
                &trusting(&key),
            )
            .unwrap();

        assert_eq!(request.name_id().as_str(), "00u1");
        assert_eq!(request.session_indexes().len(), 2);
        assert_eq!(request.issuer().as_str(), APP);
    }

    /// When signatures are required, an unsigned logout request is forbidden.
    #[test]
    fn an_unsigned_logout_request_is_refused_where_signing_is_asked() {
        let key = TestKey::new(SigningAlgorithm::Es256);

        let result =
            DsigSamlMessageReader.logout_request(&posted(&logout_xml(&later())), &trusting(&key));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A logout request past its expiry produces a validation error.
    #[test]
    fn a_lapsed_logout_request_is_refused() {
        let key = TestKey::new(SigningAlgorithm::Es256);
        let lapsed = signed(&logout_xml("2020-01-01T00:00:00Z"), &key);

        let result = DsigSamlMessageReader.logout_request(&posted(&lapsed), &trusting(&key));

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A logout request needs an expiry or issue time. Missing both is invalid,
    /// while a supplied issue time survives parsing.
    #[test]
    fn a_logout_request_without_its_issue_time_is_refused() {
        let key = TestKey::new(SigningAlgorithm::Es256);
        let timeless = format!(
            r#"<samlp:LogoutRequest xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}" ID="_l2" Version="2.0"><saml:Issuer>{APP}</saml:Issuer><saml:NameID>00u1</saml:NameID></samlp:LogoutRequest>"#
        );

        let refused = DsigSamlMessageReader
            .logout_request(&posted(&signed(&timeless, &key)), &trusting(&key));
        let read = DsigSamlMessageReader
            .logout_request(
                &posted(&signed(&logout_xml(&later()), &key)),
                &trusting(&key),
            )
            .unwrap();

        assert!(matches!(refused, Err(DomainError::Validation(_))));
        assert_eq!(read.issued_at().unix_timestamp(), 1_767_225_600);
    }

    /// A logout answer names the request it answers and how it went, a
    /// partial logout read from its second-level code.
    #[test]
    fn a_logout_answer_reads_its_status() {
        let key = TestKey::new(SigningAlgorithm::Es256);
        let answer = format!(
            r#"<samlp:LogoutResponse xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}" ID="_lr1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" InResponseTo="_l9"><saml:Issuer>{APP}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:PartialLogout"/></samlp:StatusCode></samlp:Status></samlp:LogoutResponse>"#
        );

        let response = DsigSamlMessageReader
            .logout_response(&posted(&signed(&answer, &key)), &trusting(&key))
            .unwrap();

        assert_eq!(response.in_response_to().as_str(), "_l9");
        assert_eq!(response.status(), LogoutStatus::Partial);
    }

    /// An authentication request cannot be parsed as a logout response.
    #[test]
    fn a_message_of_another_kind_is_refused() {
        let result = DsigSamlMessageReader
            .logout_response(&posted(&authn_xml()), &SignatureTrust::NotRequired);

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }
}
