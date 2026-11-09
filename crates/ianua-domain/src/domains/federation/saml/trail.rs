//! What this platform's SAML exchanges with its peers leave on the record:
//! a person signed in to an app, a logout request sent to a peer, and the
//! peer's answer to it.
//!
//! None of them changes anything the tenant keeps, but each is a person's
//! access crossing a trust boundary, so each is recorded. A trail raises
//! its records as the exchange goes, and is dropped once they are taken,
//! stamped with the tenant they happened in.

use std::marker::PhantomData;

use crate::domains::federation::events::{
    LogoutRequestSent, LogoutResponseTaken, SamlAssertionIssued,
};
use crate::domains::federation::saml::logout::{
    LogoutStatus, SamlLogoutResponse, SentLogoutRequest,
};
use crate::domains::federation::service_provider::SamlServiceProvider;
use crate::domains::identity::account::user::User;
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};

/// The records one SAML exchange raised and has not handed over yet.
#[derive(Debug)]
pub struct SamlTrail<T: TenantScope> {
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> SamlTrail<T> {
    /// `account` was signed in to `app`, with an assertion about them.
    /// Raises `federation.saml_assertion_issued`, naming the app and the
    /// person.
    pub fn assertion_issued(&mut self, app: &SamlServiceProvider<T>, account: &User<T>) {
        self.raised.raise(SamlAssertionIssued {
            provider_id: *app.id(),
            provider_name: app.name().clone(),
            user_id: *account.id(),
            user_label: account.label(),
            occurred_at: crate::shared::clock::now(),
        });
    }

    /// `sent` went to its peer. Raises `federation.logout_request_sent`,
    /// naming the peer and where it went.
    pub fn logout_sent(&mut self, sent: &SentLogoutRequest) {
        self.raised.raise(LogoutRequestSent {
            request_id: sent.id().clone(),
            peer: sent.peer().clone(),
            destination: sent.destination().clone(),
            occurred_at: sent.sent_at(),
        });
    }

    /// How the logout went, by `response`, once it is the answer to `sent`
    /// from the peer it went to. Raises `federation.logout_response_taken`
    /// with the status.
    ///
    /// # Errors
    ///
    /// - As [`SentLogoutRequest::accept_response`]; nothing is raised.
    pub fn logout_answered(
        &mut self,
        sent: &SentLogoutRequest,
        response: &SamlLogoutResponse,
    ) -> Result<LogoutStatus, DomainError> {
        let status = sent.accept_response(response)?;
        self.raised.raise(LogoutResponseTaken {
            request_id: sent.id().clone(),
            peer: sent.peer().clone(),
            status,
            occurred_at: crate::shared::clock::now(),
        });
        Ok(status)
    }
}

impl<T: TenantScope> Default for SamlTrail<T> {
    fn default() -> Self {
        Self {
            raised: Raised::default(),
            _scope: PhantomData,
        }
    }
}

impl<T: TenantScope> Raises for SamlTrail<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::federation::fixtures::federation_admin;
    use crate::domains::federation::saml::logout::{LogoutResponseParts, SentLogoutRequestRow};
    use crate::domains::federation::saml::name_id::{NameIdFormat, SamlNameIdValue};
    use crate::domains::federation::service_provider::{
        AcsUrls, AssertionEncryption, AttributeStatements, NewSamlServiceProvider,
        RequestSigningRule, SamlServiceProviderSettings, SignedParts,
    };
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::builders::{label, user};
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{
        HttpsUrl, SamlEntityId, SamlNameIdFormat, SamlRequestId, SamlResponseId,
        SamlServiceProviderId, SessionIndex, Setting, UserId,
    };

    fn entity(value: &str) -> SamlEntityId {
        SamlEntityId::new(value).unwrap()
    }

    /// A request asking Salesforce to end Ann's session, sent just now.
    fn sent_to_salesforce() -> SentLogoutRequest {
        let now = crate::shared::clock::now();
        SentLogoutRequest::reconstitute(SentLogoutRequestRow {
            id: SamlRequestId::new("_l1").unwrap(),
            peer: entity("https://salesforce.example"),
            destination: HttpsUrl::new("https://salesforce.example/slo").unwrap(),
            name_id_format: SamlNameIdFormat::new(SamlNameIdFormat::PERSISTENT).unwrap(),
            name_id: SamlNameIdValue::new("pairwise-ann").unwrap(),
            session_index: SessionIndex::new("_s1").unwrap(),
            sent_at: now,
            expires_at: now + Duration::minutes(10),
        })
        .unwrap()
    }

    fn answer(issuer: &str) -> SamlLogoutResponse {
        SamlLogoutResponse::new(LogoutResponseParts {
            id: SamlResponseId::new("_r1").unwrap(),
            issuer: entity(issuer),
            in_response_to: SamlRequestId::new("_l1").unwrap(),
            status: LogoutStatus::Success,
        })
    }

    /// Salesforce, set up to be signed in to from here.
    fn salesforce() -> SamlServiceProvider<ResolvedTenant> {
        let acs = HttpsUrl::new("https://salesforce.example/acs").unwrap();
        SamlServiceProvider::create(
            NewSamlServiceProvider {
                id: SamlServiceProviderId::new(),
                name: label("Salesforce"),
                entity_id: entity("https://salesforce.example"),
                settings: SamlServiceProviderSettings {
                    acs_urls: AcsUrls::new(acs, Vec::new()).unwrap(),
                    logout_url: Setting::Unset,
                    name_id_format: NameIdFormat::Persistent,
                    attributes: AttributeStatements::standard().unwrap(),
                    signing: SignedParts::Assertion,
                    encryption: AssertionEncryption::Plain,
                    request_signing: RequestSigningRule::NotRequired,
                },
            },
            &federation_admin(),
        )
        .unwrap()
    }

    /// Ann is signed in to Salesforce from here. The record names the app
    /// and Ann by her address.
    #[test]
    fn signing_a_person_in_to_an_app_is_recorded() {
        let mut trail = SamlTrail::<ResolvedTenant>::default();
        let ann = user(UserId::new(), "ann@acme.test");

        trail.assertion_issued(&salesforce(), &ann);

        let events = raised(&mut trail);
        assert_eq!(
            events[0].event_type().as_str(),
            "federation.saml_assertion_issued"
        );
        assert_eq!(
            events[0].payload().get("user"),
            Some(ann.id().to_string().as_str())
        );
    }

    /// Ann signs out after using Salesforce. The request sent to it is
    /// recorded, naming where it went.
    #[test]
    fn a_logout_request_sent_is_recorded() {
        let mut trail = SamlTrail::<ResolvedTenant>::default();

        trail.logout_sent(&sent_to_salesforce());

        let events = raised(&mut trail);
        assert_eq!(
            events[0].event_type().as_str(),
            "federation.logout_request_sent"
        );
        assert_eq!(
            events[0].payload().get("destination"),
            Some("https://salesforce.example/slo")
        );
    }

    /// Salesforce answers that Ann is logged out. The answer is recorded
    /// with how it went.
    #[test]
    fn a_peers_answer_is_recorded_with_its_status() {
        let mut trail = SamlTrail::<ResolvedTenant>::default();

        let status = trail
            .logout_answered(&sent_to_salesforce(), &answer("https://salesforce.example"))
            .unwrap();

        assert_eq!(status, LogoutStatus::Success);
        assert_eq!(
            raised(&mut trail)[0].payload().get("status"),
            Some("success")
        );
    }

    /// Mallory's app cannot answer a logout request sent to Salesforce;
    /// the forbidden response raises no event.
    #[test]
    fn an_answer_from_another_peer_records_nothing() {
        let mut trail = SamlTrail::<ResolvedTenant>::default();

        let refused =
            trail.logout_answered(&sent_to_salesforce(), &answer("https://mallory.example"));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert!(raised_names(&mut trail).is_empty());
    }
}
