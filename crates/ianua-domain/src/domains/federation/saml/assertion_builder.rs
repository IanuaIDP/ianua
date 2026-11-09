//! Writes the SAML assertions this IdP issues to SPs.
//!
//! A SAML 2.0 assertion here holds:
//! - Subject: the `NameID` the app was set up for.
//! - Conditions: the audience and the time window.
//! - AuthnStatement: the session and how the person signed in.
//! - AttributeStatement: the attributes the app's statements release.
//!
//! The XML is unsigned. The infrastructure layer signs it with the tenant's
//! signing key, and encrypts it for an app that asks for that.

use time::OffsetDateTime;

use crate::domains::authentication::risk_engine::assurance::AssuranceLevel;
use crate::domains::federation::saml::name_id::IssuedNameId;
use crate::domains::federation::saml::xml::{xml_date_time, xml_escape};
use crate::domains::federation::service_provider::ReleasedAttribute;
use crate::shared::errors::DomainError;
use crate::types::{HttpsUrl, SamlAssertionId, SamlEntityId, SamlRequestId, SessionIndex};

/// The SAML 2.0 class for a sign-in that proved one factor over TLS.
const PASSWORD_PROTECTED_TRANSPORT: &str =
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";

/// The REFEDS profile service providers read as "signed in with more than
/// one factor".
const REFEDS_MFA: &str = "https://refeds.org/profile/mfa";

/// Parameters for building a SAML assertion.
pub struct AssertionParams {
    /// The assertion's unique ID. The caller makes it.
    pub assertion_id: SamlAssertionId,
    /// The IdP's entity ID, written as the issuer.
    pub issuer: SamlEntityId,
    /// The SP's entity ID, written as the only audience.
    pub sp_entity_id: SamlEntityId,
    /// The SP's ACS URL, written as the recipient.
    pub acs_url: HttpsUrl,
    /// When the person signed in, which is what `AuthnInstant` reports.
    pub authenticated_at: OffsetDateTime,
    /// How strongly they signed in, which picks the `AuthnContextClassRef`.
    pub assurance: AssuranceLevel,
    /// The `NameID` the app names the person by, in its format.
    pub name_id: IssuedNameId,
    /// The attributes the app's statements release, in order.
    pub attributes: Vec<ReleasedAttribute>,
    /// How long the assertion is valid, counted from when it is built.
    pub lifetime: crate::types::Lifetime,
    /// The login correlation value used by the peer for single logout.
    pub session_index: SessionIndex,
    /// The ID of the SP's AuthnRequest, written as `InResponseTo`. `None`
    /// leaves it out, as for an IdP-initiated sign-in.
    pub in_response_to: Option<SamlRequestId>,
}

/// An unsigned SAML assertion, as [`build_assertion`] wrote it.
///
/// It cannot go into a response. Only [`BuiltAssertion::signed`] turns it
/// into the [`SignedAssertion`] a response takes, so an unsigned assertion
/// never reaches a service provider.
#[derive(Debug)]
pub struct BuiltAssertion {
    xml: String,
    id: SamlAssertionId,
}

impl BuiltAssertion {
    /// The assertion XML, ready to sign.
    #[must_use]
    pub fn xml(&self) -> &str {
        &self.xml
    }

    /// The assertion ID.
    #[must_use]
    pub fn id(&self) -> &SamlAssertionId {
        &self.id
    }

    /// The same assertion, as the tenant's signing key signed it.
    ///
    /// `signed_xml` is what the signer returned for [`xml`](Self::xml). It
    /// keeps this assertion's ID.
    #[must_use]
    pub fn signed(self, signed_xml: String) -> SignedAssertion {
        SignedAssertion {
            xml: signed_xml,
            id: self.id,
        }
    }
}

/// A SAML assertion signed with the tenant's signing key, ready to go into a
/// response.
#[derive(Debug)]
pub struct SignedAssertion {
    xml: String,
    id: SamlAssertionId,
}

impl SignedAssertion {
    /// The signed assertion XML. It goes into a response as it is, since
    /// escaping it would break its signature.
    #[must_use]
    pub fn xml(&self) -> &str {
        &self.xml
    }

    /// The assertion ID.
    #[must_use]
    pub fn id(&self) -> &SamlAssertionId {
        &self.id
    }

    /// The same signed assertion, sealed for an app that set up an
    /// encryption key.
    ///
    /// `encrypted_xml` is the `<saml:EncryptedAssertion>` the encrypter
    /// returned for [`xml`](Self::xml). It keeps this assertion's ID, and
    /// goes into the response in its place.
    #[must_use]
    pub fn sealed(self, encrypted_xml: String) -> Self {
        Self {
            xml: encrypted_xml,
            id: self.id,
        }
    }
}

/// Builds an unsigned SAML 2.0 assertion.
///
/// The caller signs it with the tenant's signing key before sending it to
/// the SP.
///
/// # Errors
///
/// - [`DomainError::Validation`] when the sign-in time, or the window the
///   assertion is good for, cannot be written as a SAML time. It is never
///   written with an empty time, which some service providers read as no
///   limit at all.
pub fn build_assertion(params: &AssertionParams) -> Result<BuiltAssertion, DomainError> {
    let now = crate::shared::clock::now();
    let now_str = xml_date_time("issue time", now)?;
    let not_on_or_after = xml_date_time("end time", params.lifetime.ends_after(now))?;

    let in_response_to_attr = params
        .in_response_to
        .as_ref()
        .map(SamlRequestId::as_str)
        .map(|irt| format!(r#" InResponseTo="{irt}""#))
        .unwrap_or_default();

    let authn_stmt = authn_statement(params)?;
    let attr_stmts = attribute_statement(&params.attributes);

    let xml = format!(
        r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" IssueInstant="{now_str}" Version="2.0"><saml:Issuer>{issuer}</saml:Issuer><saml:Subject><saml:NameID Format="{name_id_format}">{subject}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData{in_response_to_attr} NotOnOrAfter="{not_on_or_after}" Recipient="{acs}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{now_str}" NotOnOrAfter="{not_on_or_after}"><saml:AudienceRestriction><saml:Audience>{sp_entity_id}</saml:Audience></saml:AudienceRestriction></saml:Conditions>{authn_stmt}{attr_stmts}</saml:Assertion>"#,
        id = params.assertion_id,
        issuer = xml_escape(params.issuer.as_str()),
        name_id_format = params.name_id.format().urn(),
        subject = xml_escape(params.name_id.value().as_str()),
        acs = xml_escape(params.acs_url.as_str()),
        sp_entity_id = xml_escape(params.sp_entity_id.as_str()),
    );

    Ok(BuiltAssertion {
        xml,
        id: params.assertion_id.clone(),
    })
}

/// The `AuthnStatement`, which says when and how strongly the person signed in.
fn authn_statement(params: &AssertionParams) -> Result<String, DomainError> {
    let instant = xml_date_time("sign-in time", params.authenticated_at)?;
    Ok(format!(
        r#"<saml:AuthnStatement AuthnInstant="{instant}" SessionIndex="{session_index}"><saml:AuthnContext><saml:AuthnContextClassRef>{class}</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>"#,
        session_index = xml_escape(params.session_index.as_str()),
        class = authn_context_class(params.assurance),
    ))
}

/// The `AuthnContextClassRef` for a sign-in of this strength.
///
/// One factor reads as a password over TLS. A second factor or a hardware
/// key reads as multi-factor, so an SP that asks for MFA can tell.
fn authn_context_class(assurance: AssuranceLevel) -> &'static str {
    match assurance {
        AssuranceLevel::Aal1 => PASSWORD_PROTECTED_TRANSPORT,
        AssuranceLevel::Aal2 | AssuranceLevel::Aal3 => REFEDS_MFA,
    }
}

/// The `AttributeStatement` carrying the released attributes. An app
/// released nothing gets none, since SAML allows no empty statement.
fn attribute_statement(released: &[ReleasedAttribute]) -> String {
    let attributes: String = released.iter().map(attribute).collect();
    match released {
        [] => attributes,
        [_, ..] => format!("<saml:AttributeStatement>{attributes}</saml:AttributeStatement>"),
    }
}

fn attribute(released: &ReleasedAttribute) -> String {
    let values: String = released
        .values()
        .iter()
        .map(|value| {
            format!(
                "<saml:AttributeValue>{}</saml:AttributeValue>",
                xml_escape(value)
            )
        })
        .collect();
    format!(
        r#"<saml:Attribute Name="{}" NameFormat="{}">{values}</saml:Attribute>"#,
        xml_escape(released.name().as_str()),
        released.name_format().urn(),
    )
}

#[cfg(test)]
mod tests {
    use time::format_description::well_known::Iso8601;

    use super::*;
    use crate::domains::federation::fixtures::alice_assertion as params;
    use crate::domains::federation::saml::name_id::NameIdFormat;
    use crate::types::Lifetime;

    /// Alice signs in to `app.acme.com` through this IdP. The assertion names
    /// her address, the IdP as issuer and the app, and keeps the caller's id.
    #[test]
    fn builds_valid_assertion_xml() {
        let result = build_assertion(&params()).unwrap();
        assert!(result.xml().contains("saml:Assertion"));
        assert!(result.xml().contains("alice@acme.com"));
        assert!(result.xml().contains("https://auth.acme.com"));
        assert!(result.xml().contains("https://app.acme.com"));
        assert_eq!(result.id().as_str(), "_assertion_1");
    }

    /// The assertion carries a bearer confirmation whose recipient is the
    /// app's ACS URL, so it is good only when posted there.
    #[test]
    fn includes_subject_confirmation() {
        let result = build_assertion(&params()).unwrap();
        assert!(result.xml().contains("SubjectConfirmation"));
        assert!(result.xml().contains("bearer"));
        assert!(
            result
                .xml()
                .contains("Recipient=\"https://app.acme.com/saml/acs\"")
        );
    }

    /// The assertion limits its audience to `app.acme.com`, so another
    /// service provider must refuse it.
    #[test]
    fn includes_audience_restriction() {
        let result = build_assertion(&params()).unwrap();
        assert!(result.xml().contains("AudienceRestriction"));
        assert!(result.xml().contains("https://app.acme.com"));
    }

    /// Alice's display name and her `department` are released. Both are
    /// written into the assertion with their values.
    #[test]
    fn an_assertion_carries_the_released_attributes() {
        let result = build_assertion(&params()).unwrap();
        assert!(result.xml().contains("displayName"));
        assert!(result.xml().contains("Alice Smith"));
        assert!(result.xml().contains("department"));
        assert!(result.xml().contains("Engineering"));
    }

    /// Alice holds two roles, released under `roles`. Both are written as
    /// values of one attribute.
    #[test]
    fn a_many_valued_attribute_is_written_once_with_each_value() {
        let p = AssertionParams {
            attributes: vec![ReleasedAttribute::of("roles", &["editor", "billing"])],
            ..params()
        };

        let result = build_assertion(&p).unwrap();

        assert_eq!(result.xml().matches(r#"Name="roles""#).count(), 1);
        assert!(result.xml().contains(
            "<saml:AttributeValue>editor</saml:AttributeValue><saml:AttributeValue>billing</saml:AttributeValue>"
        ));
    }

    /// An app released nothing gets no attribute statement at all, which
    /// SAML would refuse as empty.
    #[test]
    fn an_app_released_nothing_gets_no_attribute_statement() {
        let p = AssertionParams {
            attributes: Vec::new(),
            ..params()
        };

        let result = build_assertion(&p).unwrap();

        assert!(!result.xml().contains("AttributeStatement"));
    }

    /// The app sent request `_authn_req_1`. The assertion answers it with
    /// that id as `InResponseTo`, so the app can match it to its request.
    #[test]
    fn includes_in_response_to() {
        let result = build_assertion(&params()).unwrap();
        assert!(result.xml().contains("InResponseTo=\"_authn_req_1\""));
    }

    /// Every assertion carries both a start and an end time, so none is
    /// valid forever.
    #[test]
    fn includes_time_bounds() {
        let result = build_assertion(&params()).unwrap();
        assert!(result.xml().contains("NotBefore="));
        assert!(result.xml().contains("NotOnOrAfter="));
    }

    /// An assertion with the maximum lifetime writes its exact expiry
    /// after issue time and never an empty NotOnOrAfter value.
    #[test]
    fn the_longest_lifetime_writes_a_full_end_time() {
        let issued_at = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let _frozen = crate::shared::clock::freeze(issued_at);
        let p = AssertionParams {
            lifetime: Lifetime::MAX,
            ..params()
        };

        let result = build_assertion(&p).unwrap();

        let ends = (issued_at + Lifetime::MAX.duration())
            .format(&Iso8601::DEFAULT)
            .unwrap();
        assert!(
            result.xml().contains(&format!("NotOnOrAfter=\"{ends}\"")),
            "{}",
            result.xml()
        );
        assert!(!result.xml().contains("NotOnOrAfter=\"\""));
    }

    /// An assertion with a sign-in date before year zero fails construction
    /// with a validation error.
    #[test]
    fn an_assertion_with_a_time_saml_cannot_write_is_refused() {
        let p = AssertionParams {
            authenticated_at: time::Date::from_calendar_date(-1, time::Month::January, 1)
                .unwrap()
                .midnight()
                .assume_utc(),
            ..params()
        };

        let result = build_assertion(&p);

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// Alice signed in hours ago and the assertion is built now. `AuthnInstant`
    /// carries her sign-in time, so an SP that limits sign-in age sees it.
    #[test]
    fn the_authn_instant_is_when_the_person_signed_in() {
        let p = params();
        let signed_in = p.authenticated_at.format(&Iso8601::DEFAULT).unwrap();

        let result = build_assertion(&p).unwrap();

        assert!(
            result
                .xml()
                .contains(&format!(r#"AuthnInstant="{signed_in}""#))
        );
    }

    /// Alice signed in with a password only. The assertion reports password
    /// over TLS and never claims MFA.
    #[test]
    fn a_single_factor_sign_in_is_reported_as_password_over_tls() {
        let result = build_assertion(&params()).unwrap();

        assert!(result.xml().contains(PASSWORD_PROTECTED_TRANSPORT));
        assert!(!result.xml().contains(REFEDS_MFA));
    }

    /// Alice signed in with a second factor or a hardware key. The assertion
    /// reports the REFEDS MFA profile, so an app that requires MFA lets her in.
    #[test]
    fn a_multi_factor_sign_in_is_reported_as_mfa() {
        for assurance in [AssuranceLevel::Aal2, AssuranceLevel::Aal3] {
            let p = AssertionParams {
                assurance,
                ..params()
            };

            let result = build_assertion(&p).unwrap();

            assert!(result.xml().contains(REFEDS_MFA), "{assurance:?}");
            assert!(!result.xml().contains(PASSWORD_PROTECTED_TRANSPORT));
        }
    }

    /// A value of `Alice & Bob <Co>` is written with `&`, `<` and `>`
    /// escaped, so it stays text and the XML stays well formed.
    #[test]
    fn escapes_special_characters() {
        let p = AssertionParams {
            attributes: vec![ReleasedAttribute::of("displayName", &["Alice & Bob <Co>"])],
            ..params()
        };

        let result = build_assertion(&p).unwrap();

        assert!(result.xml().contains("Alice &amp; Bob &lt;Co&gt;"));
    }

    /// Quotes and markup in an attribute name are escaped in the assertion,
    /// leaving no injected element in its XML.
    #[test]
    fn an_attribute_name_cannot_break_out_of_its_xml_attribute() {
        let p = AssertionParams {
            attributes: vec![ReleasedAttribute::of(r#"x"><saml:Injected/>"#, &["v"])],
            ..params()
        };

        let result = build_assertion(&p).unwrap();

        assert!(!result.xml().contains("<saml:Injected/>"));
        assert!(result.xml().contains("x&quot;&gt;&lt;saml:Injected/&gt;"));
    }

    /// An assertion with a five-minute lifetime is built at a frozen time.
    /// It starts at that time and ends five minutes later, never before it starts.
    #[test]
    fn the_window_runs_forward_from_the_moment_of_issue() {
        let issued_at = time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let _frozen = crate::shared::clock::freeze(issued_at);

        let result = build_assertion(&params()).unwrap();

        let expires_at = (issued_at + time::Duration::seconds(300))
            .format(&Iso8601::DEFAULT)
            .unwrap();
        let issued = issued_at.format(&Iso8601::DEFAULT).unwrap();

        assert!(
            result.xml().contains(&format!("NotBefore=\"{issued}\"")),
            "{}",
            result.xml()
        );
        assert!(
            result
                .xml()
                .contains(&format!("NotOnOrAfter=\"{expires_at}\"")),
            "{}",
            result.xml()
        );
    }

    /// Alice signs in to an app set up for pairwise ids. The `NameID` is the
    /// pairwise value in the persistent format.
    #[test]
    fn the_name_id_is_written_in_its_format() {
        let result = build_assertion(&params()).unwrap();

        assert!(result.xml().contains(&format!(
            r#"<saml:NameID Format="{}">pairwise-alice</saml:NameID>"#,
            NameIdFormat::Persistent.urn()
        )));
    }

    /// An app set up for addresses gets Alice's address in the address
    /// format.
    #[test]
    fn an_address_name_id_is_written_in_the_address_format() {
        let p = AssertionParams {
            name_id: IssuedNameId::of(NameIdFormat::EmailAddress, "alice@acme.com"),
            ..params()
        };

        let result = build_assertion(&p).unwrap();

        assert!(result.xml().contains(&format!(
            r#"<saml:NameID Format="{}">alice@acme.com</saml:NameID>"#,
            NameIdFormat::EmailAddress.urn()
        )));
    }

    /// Alice's assertion comes back from the signer. The signed one keeps
    /// her assertion's ID and carries exactly what the signer returned.
    #[test]
    fn a_signed_assertion_keeps_its_id_and_the_signers_xml() {
        let signed = build_assertion(&params())
            .unwrap()
            .signed("<saml:Assertion>signed</saml:Assertion>".to_owned());

        assert_eq!(signed.id().as_str(), "_assertion_1");
        assert_eq!(signed.xml(), "<saml:Assertion>signed</saml:Assertion>");
    }

    /// A signed assertion sealed for an app carries the encrypted form in
    /// its place, under the same ID.
    #[test]
    fn a_sealed_assertion_carries_the_encrypted_form() {
        let sealed = build_assertion(&params())
            .unwrap()
            .signed("<saml:Assertion>signed</saml:Assertion>".to_owned())
            .sealed("<saml:EncryptedAssertion>x</saml:EncryptedAssertion>".to_owned());

        assert_eq!(sealed.id().as_str(), "_assertion_1");
        assert!(sealed.xml().starts_with("<saml:EncryptedAssertion>"));
    }
}
