//! A sign-in a SAML app may be answered for: the request it sent, checked
//! against how the app was set up, or a sign-in it never asked for.

use crate::domains::federation::saml::authn_request::Reauthentication;
use crate::domains::federation::saml::name_id::NameIdFormat;
use crate::types::{HttpsUrl, SamlRequestId, SamlServiceProviderId};

/// What an answer answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answering {
    /// The app's request with this id, written back as `InResponseTo`.
    Request(SamlRequestId),
    /// A sign-in started here, which no request asked for.
    Unsolicited,
}

/// A sign-in to a SAML app this platform may answer: where the assertion
/// goes, how the person is named, and what it answers.
///
/// Only [`SamlServiceProvider`](crate::domains::federation::service_provider::SamlServiceProvider)
/// makes one, once the request passed the app's rules. So the address is
/// one the app registered and the format one it was set up for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedAuthnRequest {
    pub(crate) provider: SamlServiceProviderId,
    pub(crate) acs_url: HttpsUrl,
    pub(crate) name_id_format: NameIdFormat,
    pub(crate) answering: Answering,
    pub(crate) reauthentication: Reauthentication,
}

impl AcceptedAuthnRequest {
    /// The app it is for.
    #[must_use]
    pub fn provider(&self) -> &SamlServiceProviderId {
        &self.provider
    }

    /// Where the assertion is posted, written as its recipient.
    #[must_use]
    pub fn acs_url(&self) -> &HttpsUrl {
        &self.acs_url
    }

    /// How the person is named.
    #[must_use]
    pub fn name_id_format(&self) -> NameIdFormat {
        self.name_id_format
    }

    /// What it answers.
    #[must_use]
    pub fn answering(&self) -> &Answering {
        &self.answering
    }

    /// The request id to write as `InResponseTo`, for an answer to a
    /// request.
    #[must_use]
    pub fn in_response_to(&self) -> Option<&SamlRequestId> {
        match &self.answering {
            Answering::Request(id) => Some(id),
            Answering::Unsolicited => None,
        }
    }

    /// Whether the app asked for a fresh sign-in.
    #[must_use]
    pub fn reauthentication(&self) -> Reauthentication {
        self.reauthentication
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepted(answering: Answering) -> AcceptedAuthnRequest {
        AcceptedAuthnRequest {
            provider: SamlServiceProviderId::new(),
            acs_url: HttpsUrl::new("https://app.acme.com/acs").unwrap(),
            name_id_format: NameIdFormat::Persistent,
            answering,
            reauthentication: Reauthentication::NotForced,
        }
    }

    /// An answer to request `_r1` names it as `InResponseTo`. A sign-in no
    /// request asked for names none, as SAML wants.
    #[test]
    fn only_an_answer_to_a_request_names_it() {
        let id = SamlRequestId::new("_r1").unwrap();

        assert_eq!(
            accepted(Answering::Request(id.clone())).in_response_to(),
            Some(&id)
        );
        assert_eq!(accepted(Answering::Unsolicited).in_response_to(), None);
    }
}
