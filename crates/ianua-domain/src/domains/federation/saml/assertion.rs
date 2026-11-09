//! The identity claims read from a validated SAML response.
//!
//! The infrastructure layer parses the XML and checks the signature, behind
//! the `SamlValidator` port. This module only holds the result.

use crate::domains::federation::provider_values::ProviderValues;
use crate::domains::federation::vouched_identity::{
    ProviderEmailVerification, ProviderFactor, VouchedFacts, VouchedIdentity,
};
use crate::types::{
    ConnectionId, Email, Fact, FederatedSubject, SamlAssertionId, SessionIndex, Setting,
};

/// How an assertion reached this platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssertionDelivery {
    /// Signed but readable, by the browser it passed through too.
    Readable,
    /// Encrypted to this platform's key, and opened here.
    Encrypted,
}

/// Identity claims extracted from a validated SAML assertion.
#[derive(Debug, Clone)]
pub struct SamlAssertion {
    connection_id: ConnectionId,
    assertion_id: SamlAssertionId,
    email: Email,
    name_id: FederatedSubject,
    session_index: Setting<SessionIndex>,
    delivery: AssertionDelivery,
    factor: ProviderFactor,
    attributes: ProviderValues,
}

/// What a validated SAML assertion says about the person.
pub struct AssertionFacts {
    /// The connection it arrived on.
    pub connection_id: ConnectionId,
    /// The assertion's own id.
    pub assertion_id: SamlAssertionId,
    /// The person's address.
    pub email: Email,
    /// The identity provider's name for them.
    pub name_id: FederatedSubject,
    /// The session the provider keeps for them, which its logout requests
    /// name. Unset when the assertion carries none.
    pub session_index: Setting<SessionIndex>,
    /// Whether it came encrypted.
    pub delivery: AssertionDelivery,
    /// The `AuthnContextClassRef`, which says how the person signed in at the
    /// provider. Unknown when the assertion carries none.
    pub authn_context: Fact<String>,
    /// Any further attributes it carried, each with every value it
    /// carried.
    pub attributes: ProviderValues,
}

impl SamlAssertion {
    /// Builds an assertion from validated data. The sign-in factor is read
    /// from `authn_context`.
    #[must_use]
    pub fn new(facts: AssertionFacts) -> Self {
        let AssertionFacts {
            connection_id,
            assertion_id,
            email,
            name_id,
            session_index,
            delivery,
            authn_context,
            attributes,
        } = facts;
        Self {
            connection_id,
            assertion_id,
            email,
            name_id,
            session_index,
            delivery,
            factor: ProviderFactor::from_saml_context(authn_context.as_ref().map(String::as_str)),
            attributes,
        }
    }

    /// What the provider vouched for. SAML has no claim for whether the
    /// address was verified, so that stays unstated.
    #[must_use]
    pub fn vouched(&self) -> VouchedIdentity {
        VouchedIdentity::new(VouchedFacts {
            connection_id: self.connection_id,
            subject: self.name_id.clone(),
            email: self.email.clone(),
            email_verification: ProviderEmailVerification::Unstated,
            factor: self.factor,
        })
    }

    /// The `ID` the identity provider gave this assertion.
    ///
    /// The SAML specification makes it unique per assertion, so it is the key
    /// that marks an assertion as used. An assertion stays valid for its whole
    /// window. Only a record of having seen its id stops it being used twice.
    #[must_use]
    pub fn assertion_id(&self) -> &SamlAssertionId {
        &self.assertion_id
    }

    /// The connection this assertion came from.
    #[must_use]
    pub fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }

    /// The authenticated user's email.
    #[must_use]
    pub fn email(&self) -> &Email {
        &self.email
    }

    /// The SAML `NameID` value.
    #[must_use]
    pub fn name_id(&self) -> &FederatedSubject {
        &self.name_id
    }

    /// The session the provider keeps for the person, which its logout
    /// requests name.
    #[must_use]
    pub fn session_index(&self) -> Option<&SessionIndex> {
        self.session_index.value()
    }

    /// Whether it came encrypted.
    #[must_use]
    pub fn delivery(&self) -> AssertionDelivery {
        self.delivery
    }

    /// The attributes the assertion carried, such as `given_name`,
    /// `department` or `groups`, each with every value it carried.
    #[must_use]
    pub fn attributes(&self) -> &ProviderValues {
        &self.attributes
    }

    /// The first value of the attribute under `key`, if the assertion
    /// carried one.
    #[must_use]
    pub fn attribute(&self, key: &str) -> Option<&str> {
        self.attributes.first(key)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn name_id() -> FederatedSubject {
        FederatedSubject::new("alice@acme.com").unwrap()
    }

    fn assertion() -> SamlAssertion {
        SamlAssertion::new(AssertionFacts {
            connection_id: ConnectionId::new(),
            assertion_id: SamlAssertionId::new("_a1b2c3").unwrap(),
            email: Email::new("alice@acme.com").unwrap(),
            name_id: name_id(),
            session_index: Setting::Set(SessionIndex::new("_session_1").unwrap()),
            delivery: AssertionDelivery::Encrypted,
            authn_context: Fact::Known(
                "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport".to_owned(),
            ),
            attributes: ProviderValues::new(HashMap::from([
                ("department".to_owned(), vec!["Engineering".to_owned()]),
                ("employee_id".to_owned(), vec!["E-42".to_owned()]),
                (
                    "groups".to_owned(),
                    vec!["engineering".to_owned(), "ops".to_owned()],
                ),
            ])),
        })
    }

    /// An assertion exposes its original identifier for the caller's
    /// replay check.
    #[test]
    fn an_assertion_reports_the_id_a_replay_check_spends() {
        assert_eq!(assertion().assertion_id().as_str(), "_a1b2c3");
    }

    /// The connection says which provider vouched for the user. The `NameID`
    /// says who they are there. Either one read wrongly admits a user that
    /// another provider vouched for.
    #[test]
    fn an_assertion_names_the_connection_it_came_from_and_the_subject() {
        let connection = ConnectionId::new();

        let assertion = SamlAssertion::new(AssertionFacts {
            connection_id: connection,
            assertion_id: SamlAssertionId::new("_a1b2c3").unwrap(),
            email: Email::new("alice@acme.com").unwrap(),
            name_id: name_id(),
            session_index: Setting::Unset,
            delivery: AssertionDelivery::Readable,
            authn_context: Fact::Unknown,
            attributes: ProviderValues::default(),
        });

        assert_eq!(*assertion.connection_id(), connection);
        assert_eq!(assertion.name_id(), &name_id());
        assert_eq!(assertion.session_index(), None);
    }

    /// The provider's session index and the encryption are kept as they
    /// came, so a later logout names the right session and a connection
    /// that requires encryption can tell.
    #[test]
    fn an_assertion_keeps_its_session_and_how_it_came() {
        let assertion = assertion();

        assert_eq!(
            assertion.session_index().map(SessionIndex::as_str),
            Some("_session_1")
        );
        assert_eq!(assertion.delivery(), AssertionDelivery::Encrypted);
    }

    /// Alice signs in at the provider with a password. What the assertion
    /// vouches for leaves her address unstated, since SAML has no such claim,
    /// and records no second factor.
    #[test]
    fn the_vouched_identity_leaves_verification_unstated_and_reads_the_factor() {
        let vouched = assertion().vouched();

        assert_eq!(vouched.subject(), &name_id());
        assert_eq!(
            vouched.email_verification(),
            ProviderEmailVerification::Unstated
        );
        assert_eq!(vouched.factor(), ProviderFactor::NotPerformed);
    }

    /// Attributes fill Ann's profile through the connection's mapping. An
    /// invented entry gives her a name nobody gave her. A missing one drops
    /// the mapping.
    #[test]
    fn the_attributes_are_the_ones_the_provider_sent() {
        let assertion = assertion();

        assert_eq!(assertion.attributes().len(), 3);
        assert_eq!(assertion.attribute("department"), Some("Engineering"));
        assert_eq!(assertion.attribute("employee_id"), Some("E-42"));
        assert_eq!(
            assertion.attribute("manager"),
            None,
            "an attribute nobody sent must not appear"
        );
    }

    /// Okta sends Ann's groups as two values of one attribute. Both are
    /// kept, so the second still maps to what it brings.
    #[test]
    fn a_multi_valued_attribute_keeps_every_value() {
        let assertion = assertion();

        assert_eq!(
            assertion.attributes().values("groups"),
            ["engineering", "ops"]
        );
    }
}
