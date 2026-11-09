//! Wraps an assertion in a SAML `<Response>` for the SP.
//!
//! The unsigned `<samlp:Response>` holds the status code, issuer,
//! destination and the assertion itself. The infrastructure layer signs it
//! afterwards.

use crate::domains::federation::saml::assertion_builder::SignedAssertion;
use crate::domains::federation::saml::xml::{xml_date_time, xml_escape};
use crate::shared::errors::DomainError;
use crate::types::{HttpsUrl, SamlEntityId, SamlRequestId, SamlResponseId};

/// Parameters for building a SAML Response envelope.
pub struct SamlResponseParams {
    /// The response's unique ID. The caller makes it.
    pub response_id: SamlResponseId,
    /// The IdP's entity ID, written as the issuer.
    pub issuer: SamlEntityId,
    /// The SP's ACS URL, written as the destination.
    pub destination: HttpsUrl,
    /// The AuthnRequest ID this answers. `None` leaves out `InResponseTo`.
    pub in_response_to: Option<SamlRequestId>,
    /// The signed assertion. Its XML goes in as it is, without escaping.
    pub assertion: SignedAssertion,
}

/// An unsigned SAML Response.
#[derive(Debug)]
pub struct BuiltSamlResponse {
    xml: String,
    id: SamlResponseId,
}

impl BuiltSamlResponse {
    /// The whole Response XML, ready to sign or base64-encode.
    #[must_use]
    pub fn xml(&self) -> &str {
        &self.xml
    }

    /// The response ID.
    #[must_use]
    pub fn id(&self) -> &SamlResponseId {
        &self.id
    }
}

/// Builds an unsigned SAML 2.0 Response around a signed assertion.
///
/// The status is always Success. The caller can sign the Response element
/// too, or send it with only the assertion inside signed.
///
/// # Errors
///
/// - [`DomainError::Validation`] when the clock reads a time that cannot be
///   written as a SAML time. The response is never written with an empty
///   `IssueInstant`.
pub fn build_response(params: &SamlResponseParams) -> Result<BuiltSamlResponse, DomainError> {
    let now_str = xml_date_time("issue time", crate::shared::clock::now())?;

    let in_response_to_attr = params
        .in_response_to
        .as_ref()
        .map(SamlRequestId::as_str)
        .map(|irt| format!(r#" InResponseTo="{irt}""#))
        .unwrap_or_default();

    let xml = format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{now_str}" Destination="{destination}"{in_response_to}><saml:Issuer>{issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>{assertion}</samlp:Response>"#,
        id = xml_escape(params.response_id.as_str()),
        destination = xml_escape(params.destination.as_str()),
        in_response_to = in_response_to_attr,
        issuer = xml_escape(params.issuer.as_str()),
        assertion = params.assertion.xml(),
    );

    Ok(BuiltSamlResponse {
        xml,
        id: params.response_id.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::federation::fixtures::alice_assertion;
    use crate::domains::federation::saml::assertion_builder::build_assertion;

    fn params() -> SamlResponseParams {
        SamlResponseParams {
            response_id: SamlResponseId::new("_resp_1").unwrap(),
            issuer: SamlEntityId::new("https://auth.acme.com").unwrap(),
            destination: HttpsUrl::new("https://app.acme.com/saml/acs").unwrap(),
            in_response_to: Some(SamlRequestId::new("_authn_req_1").unwrap()),
            assertion: build_assertion(&alice_assertion())
                .unwrap()
                .signed("<saml:Assertion>test</saml:Assertion>".to_owned()),
        }
    }

    /// Alice's assertion is wrapped for `app.acme.com`. The response has a
    /// Success status and keeps the caller's id.
    #[test]
    fn builds_valid_response_envelope() {
        let result = build_response(&params()).unwrap();
        assert!(result.xml().contains("samlp:Response"));
        assert!(result.xml().contains("samlp:Status"));
        assert!(result.xml().contains("Success"));
        assert_eq!(result.id().as_str(), "_resp_1");
    }

    /// The response names `https://auth.acme.com` as its issuer, so the app
    /// can tell which IdP sent it.
    #[test]
    fn a_response_names_its_issuer() {
        let result = build_response(&params()).unwrap();
        assert!(result.xml().contains("https://auth.acme.com"));
    }

    /// The response's `Destination` is the app's ACS URL. An app that receives
    /// it anywhere else must refuse it.
    #[test]
    fn a_response_names_the_acs_url_it_is_for() {
        let result = build_response(&params()).unwrap();
        assert!(
            result
                .xml()
                .contains(r#"Destination="https://app.acme.com/saml/acs""#)
        );
    }

    /// The app sent request `_authn_req_1`. The response carries that id as
    /// `InResponseTo`.
    #[test]
    fn includes_in_response_to() {
        let result = build_response(&params()).unwrap();
        assert!(result.xml().contains(r#"InResponseTo="_authn_req_1""#));
    }

    /// The signed assertion goes into the response unchanged. Escaping it
    /// would break its signature.
    #[test]
    fn a_response_carries_its_assertion() {
        let result = build_response(&params()).unwrap();
        assert!(
            result
                .xml()
                .contains("<saml:Assertion>test</saml:Assertion>")
        );
    }

    /// An IdP-initiated sign-in answers no request. The response then has no
    /// `InResponseTo` at all.
    #[test]
    fn omits_in_response_to_when_none() {
        let mut p = params();
        p.in_response_to = None;
        let result = build_response(&p).unwrap();
        assert!(!result.xml().contains("InResponseTo"));
    }

    /// An issuer of `auth&co` is written as `auth&amp;co`, so the response
    /// stays well-formed XML.
    #[test]
    fn escapes_special_characters_in_issuer() {
        let mut p = params();
        p.issuer = SamlEntityId::new("auth&co").unwrap();
        let result = build_response(&p).unwrap();
        assert!(result.xml().contains("auth&amp;co"));
    }
}
