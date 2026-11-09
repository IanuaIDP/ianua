//! The parts of an SP's SAML AuthnRequest that the IdP needs to answer it.

use crate::shared::errors::DomainError;
use crate::shared::model::two_cases::two_cases;
use crate::types::{HttpsUrl, SamlEntityId, SamlNameIdFormat, SamlRequestId};

two_cases! {
    /// Whether an SP asked for a fresh sign-in, the request's `ForceAuthn`.
    pub enum Reauthentication {
        /// The person signs in again, even with a session open.
        Forced => true,
        /// An open session answers the request.
        NotForced => false,
    }
}

/// The `NameID` format a request's `NameIDPolicy` asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameIdAsked {
    /// The request carries no `NameIDPolicy` format, so the app's own
    /// format answers it.
    AnyFormat,
    /// The request asks for this format.
    Format(SamlNameIdFormat),
}

/// Whether a request came signed by the key the app registered.
///
/// The adapter checks a signature against the certificate the app
/// registered for its requests, and refuses a request whose signature does
/// not verify. So only these two cases reach the domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestSignature {
    /// The request carried no signature.
    Absent,
    /// The request was signed, and the signature verified against the
    /// app's registered certificate.
    Verified,
}

/// A parsed SAML AuthnRequest from a Service Provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundAuthnRequest {
    /// The request ID. The Response sends it back as `InResponseTo`.
    id: SamlRequestId,
    /// The SP's entity ID, from the Issuer element.
    issuer: Option<SamlEntityId>,
    /// The SP's Assertion Consumer Service URL.
    acs_url: Option<HttpsUrl>,
    /// Whether re-authentication was requested.
    force_authn: Reauthentication,
    /// The `NameID` format it asks for.
    name_id_policy: NameIdAsked,
    /// Whether it came signed.
    signature: RequestSignature,
}

/// The parsed fields of an [`InboundAuthnRequest`].
pub struct InboundAuthnRequestRow {
    /// The AuthnRequest ID.
    pub id: SamlRequestId,
    /// The SP's entity ID.
    pub issuer: Option<SamlEntityId>,
    /// The SP's ACS URL.
    pub acs_url: Option<HttpsUrl>,
    /// Whether re-authentication was requested.
    pub force_authn: Reauthentication,
    /// The `NameID` format it asks for.
    pub name_id_policy: NameIdAsked,
    /// Whether it came signed by the app's registered key.
    pub signature: RequestSignature,
}

impl InboundAuthnRequest {
    /// Builds an inbound SAML request from its parsed fields.
    ///
    /// # Errors
    ///
    /// - Never fails. No part of the row can contradict another, and each part
    ///   was read through its own checked type.
    pub fn reconstitute(row: InboundAuthnRequestRow) -> Result<Self, DomainError> {
        Ok(Self {
            id: row.id,
            issuer: row.issuer,
            acs_url: row.acs_url,
            force_authn: row.force_authn,
            name_id_policy: row.name_id_policy,
            signature: row.signature,
        })
    }

    /// The request ID, sent back as `InResponseTo`.
    #[must_use]
    pub fn id(&self) -> &SamlRequestId {
        &self.id
    }

    /// The SP's entity ID, from the Issuer element.
    #[must_use]
    pub fn issuer(&self) -> Option<&SamlEntityId> {
        self.issuer.as_ref()
    }

    /// The SP's Assertion Consumer Service URL.
    #[must_use]
    pub fn acs_url(&self) -> Option<&HttpsUrl> {
        self.acs_url.as_ref()
    }

    /// Whether re-authentication was requested.
    #[must_use]
    pub fn force_authn(&self) -> Reauthentication {
        self.force_authn
    }

    /// The `NameID` format it asks for.
    #[must_use]
    pub fn name_id_policy(&self) -> &NameIdAsked {
        &self.name_id_policy
    }

    /// Whether it came signed by the app's registered key.
    #[must_use]
    pub fn signature(&self) -> RequestSignature {
        self.signature
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str) -> InboundAuthnRequestRow {
        InboundAuthnRequestRow {
            id: SamlRequestId::new(id).unwrap(),
            issuer: None,
            acs_url: None,
            force_authn: Reauthentication::NotForced,
            name_id_policy: NameIdAsked::AnyFormat,
            signature: RequestSignature::Absent,
        }
    }

    /// The ACS URL is where the assertion is posted. A swapped value sends
    /// Ann's assertion to a place she never asked for.
    #[test]
    fn a_request_reports_the_id_issuer_and_acs_url_it_carried() {
        let request = InboundAuthnRequest::reconstitute(InboundAuthnRequestRow {
            issuer: Some(SamlEntityId::new("https://app.acme.com").unwrap()),
            acs_url: Some(HttpsUrl::new("https://app.acme.com/saml/acs").unwrap()),
            ..row("_authn_req_1")
        })
        .unwrap();

        assert_eq!(request.id().as_str(), "_authn_req_1");
        assert_eq!(
            request.issuer().map(SamlEntityId::as_str),
            Some("https://app.acme.com")
        );
        assert_eq!(
            request.acs_url().map(HttpsUrl::as_str),
            Some("https://app.acme.com/saml/acs")
        );
    }

    /// Absent values let the connection's configured ones apply, rather than
    /// an invented one.
    #[test]
    fn an_omitted_issuer_or_acs_url_stays_absent() {
        let request = InboundAuthnRequest::reconstitute(row("_authn_req_1")).unwrap();

        assert_eq!(request.issuer(), None);
        assert_eq!(request.acs_url(), None);
    }

    /// `ForceAuthn` asks for a fresh sign-in instead of the user's session.
    /// Read as always set, everybody signs in on every request. Read as never
    /// set, an SP that wants a fresh sign-in before a payment does not get one.
    #[test]
    fn re_authentication_is_only_forced_when_the_request_asked_for_it() {
        let asked = InboundAuthnRequest::reconstitute(InboundAuthnRequestRow {
            force_authn: Reauthentication::Forced,
            ..row("_authn_req_1")
        })
        .unwrap();
        let did_not = InboundAuthnRequest::reconstitute(row("_authn_req_2")).unwrap();

        assert_eq!(asked.force_authn(), Reauthentication::Forced);
        assert_eq!(did_not.force_authn(), Reauthentication::NotForced);
    }

    /// A request asking for the address format, signed with the app's key,
    /// reports both, so the app's settings can be checked against them.
    #[test]
    fn a_request_reports_the_format_it_asks_for_and_its_signature() {
        let format =
            SamlNameIdFormat::new("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
                .unwrap();

        let request = InboundAuthnRequest::reconstitute(InboundAuthnRequestRow {
            name_id_policy: NameIdAsked::Format(format.clone()),
            signature: RequestSignature::Verified,
            ..row("_authn_req_1")
        })
        .unwrap();

        assert_eq!(request.name_id_policy(), &NameIdAsked::Format(format));
        assert_eq!(request.signature(), RequestSignature::Verified);
    }
}
