//! Writes the single logout messages this platform sends: a
//! `<LogoutRequest>` to a peer, and a `<LogoutResponse>` answering one.
//!
//! Both are written unsigned. The infrastructure layer signs them with the
//! tenant's signing key, in the document or on the redirect binding.

use crate::domains::federation::saml::logout::{LogoutAnswer, LogoutStatus, SentLogoutRequest};
use crate::domains::federation::saml::xml::{xml_date_time, xml_escape};
use crate::shared::errors::DomainError;
use crate::types::{SamlEntityId, SamlResponseId};

/// A logout message, written and ready to sign.
#[derive(Debug)]
pub struct BuiltLogoutMessage {
    xml: String,
}

impl BuiltLogoutMessage {
    /// The message XML.
    #[must_use]
    pub fn xml(&self) -> &str {
        &self.xml
    }
}

/// Writes `sent` as a `<LogoutRequest>` from `issuer`, this platform's
/// entity id.
///
/// # Errors
///
/// - [`DomainError::Validation`] when its times cannot be written as SAML
///   times. A request is never written without its end.
pub fn build_logout_request(
    sent: &SentLogoutRequest,
    issuer: &SamlEntityId,
) -> Result<BuiltLogoutMessage, DomainError> {
    let issued = xml_date_time("issue time", sent.sent_at())?;
    let ends = xml_date_time("end time", sent.expires_at())?;
    let xml = format!(
        r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{issued}" NotOnOrAfter="{ends}" Destination="{destination}"><saml:Issuer>{issuer}</saml:Issuer><saml:NameID Format="{format}">{name_id}</saml:NameID><samlp:SessionIndex>{session_index}</samlp:SessionIndex></samlp:LogoutRequest>"#,
        id = xml_escape(sent.id().as_str()),
        destination = xml_escape(sent.destination().as_str()),
        issuer = xml_escape(issuer.as_str()),
        format = xml_escape(sent.name_id_format().as_str()),
        name_id = xml_escape(sent.name_id().as_str()),
        session_index = xml_escape(sent.session_index().as_str()),
    );
    Ok(BuiltLogoutMessage { xml })
}

/// What a `<LogoutResponse>` answering a peer says.
#[derive(Debug)]
pub struct LogoutResponseParams {
    /// The response's `ID`. The caller makes it.
    pub response_id: SamlResponseId,
    /// This platform's entity id, written as the issuer.
    pub issuer: SamlEntityId,
    /// The request it answers, and where it goes.
    pub answer: LogoutAnswer,
    /// How the logout went here.
    pub status: LogoutStatus,
}

/// Writes the `<LogoutResponse>` `params` describe.
///
/// # Errors
///
/// - [`DomainError::Validation`] when the clock reads a time that cannot be
///   written as a SAML time.
pub fn build_logout_response(
    params: &LogoutResponseParams,
) -> Result<BuiltLogoutMessage, DomainError> {
    let issued = xml_date_time("issue time", crate::shared::clock::now())?;
    let sub_code = params
        .status
        .sub_code()
        .map(|code| format!(r#"<samlp:StatusCode Value="{code}"/>"#))
        .unwrap_or_default();
    let xml = format!(
        r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{issued}" Destination="{destination}" InResponseTo="{in_response_to}"><saml:Issuer>{issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{code}">{sub_code}</samlp:StatusCode></samlp:Status></samlp:LogoutResponse>"#,
        id = xml_escape(params.response_id.as_str()),
        destination = xml_escape(params.answer.destination().as_str()),
        in_response_to = xml_escape(params.answer.in_response_to().as_str()),
        issuer = xml_escape(params.issuer.as_str()),
        code = params.status.status_code(),
    );
    Ok(BuiltLogoutMessage { xml })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::federation::saml::logout::{
        LogoutPeer, LogoutRequestParts, LogoutSubject, SamlLogoutRequest,
    };
    use crate::domains::federation::saml::name_id::SamlNameIdValue;
    use crate::types::{HttpsUrl, SamlNameIdFormat, SamlRequestId, SessionIndex};

    fn sent() -> SentLogoutRequest {
        SentLogoutRequest::sent(
            LogoutPeer {
                peer: SamlEntityId::new("https://app.acme.com").unwrap(),
                destination: HttpsUrl::new("https://app.acme.com/slo").unwrap(),
                name_id_format: SamlNameIdFormat::new(SamlNameIdFormat::PERSISTENT).unwrap(),
            },
            LogoutSubject {
                request_id: SamlRequestId::new("_logout_1").unwrap(),
                name_id: SamlNameIdValue::new("p-<123>").unwrap(),
                session_index: SessionIndex::new("_session_1").unwrap(),
            },
        )
    }

    fn issuer() -> SamlEntityId {
        SamlEntityId::new("https://auth.acme.com").unwrap()
    }

    /// The request to `app.acme.com` names the person, the session and the
    /// app's logout address, with the `NameID` escaped.
    #[test]
    fn a_logout_request_names_the_person_the_session_and_the_peer() {
        let built = build_logout_request(&sent(), &issuer()).unwrap();

        assert!(built.xml().contains(r#"ID="_logout_1""#));
        assert!(
            built
                .xml()
                .contains(r#"Destination="https://app.acme.com/slo""#)
        );
        assert!(built.xml().contains(">p-&lt;123&gt;</saml:NameID>"));
        assert!(
            built
                .xml()
                .contains("<samlp:SessionIndex>_session_1</samlp:SessionIndex>")
        );
        assert!(built.xml().contains("NotOnOrAfter="));
    }

    fn answer() -> LogoutAnswer {
        SamlLogoutRequest::new(LogoutRequestParts {
            id: SamlRequestId::new("_their_logout").unwrap(),
            issuer: SamlEntityId::new("https://app.acme.com").unwrap(),
            issued_at: crate::shared::clock::now(),
            name_id: SamlNameIdValue::new("p-123").unwrap(),
            session_indexes: Vec::new(),
        })
        .answered_at(HttpsUrl::new("https://app.acme.com/slo").unwrap())
    }

    /// The answer to the app's request names it as `InResponseTo` and goes
    /// to the app's logout address.
    #[test]
    fn a_logout_response_answers_the_request() {
        let built = build_logout_response(&LogoutResponseParams {
            response_id: SamlResponseId::new("_resp_1").unwrap(),
            issuer: issuer(),
            answer: answer(),
            status: LogoutStatus::Success,
        })
        .unwrap();

        assert!(built.xml().contains(r#"InResponseTo="_their_logout""#));
        assert!(
            built
                .xml()
                .contains(r#"Destination="https://app.acme.com/slo""#)
        );
        assert!(built.xml().contains("status:Success"));
        assert!(!built.xml().contains("PartialLogout"));
    }

    /// A partial logout is written as success with the partial sub-code,
    /// as SAML writes it.
    #[test]
    fn a_partial_logout_carries_its_sub_code() {
        let built = build_logout_response(&LogoutResponseParams {
            response_id: SamlResponseId::new("_resp_1").unwrap(),
            issuer: issuer(),
            answer: answer(),
            status: LogoutStatus::Partial,
        })
        .unwrap();

        assert!(built.xml().contains("status:Success"));
        assert!(built.xml().contains("status:PartialLogout"));
    }
}
