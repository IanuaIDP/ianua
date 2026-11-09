//! The app asking its provider to sign someone in, and accepting the
//! answer only once it is signed by the provider, for this app, posted to
//! its address, in answer to its own request, and holds now.

use std::collections::BTreeMap;

use roxmltree::{Document, Node};

use super::metadata::POST_BINDING;
use super::signature::{Broken, child, verify};
use super::{
    ASSERTION, App, IdentityProvider, PERSISTENT, PROTOCOL, Refusal, SUCCESS, Sent, decoded,
    ensure_issued_by, ensure_message, ensure_signed, fresh_id, instant, now, path, written_now,
};

/// What the app learned from an answer it accepted.
#[derive(Debug, Clone)]
pub struct Accepted {
    /// The id the person is named by.
    pub name_id: String,
    /// SAML URI describing how the provider represents the subject identifier.
    pub name_id_format: String,
    /// The provider's session the sign-in belongs to, which a logout
    /// names.
    pub session_index: Option<String>,
    /// The attributes sent, by name.
    pub attributes: BTreeMap<String, Vec<String>>,
}

impl App {
    /// A fresh request to `provider` to sign someone in, its answer to be
    /// posted to the app's own address and to bring `relay_state` back.
    #[must_use]
    pub fn sign_in_request(&self, provider: &IdentityProvider, relay_state: &str) -> Sent {
        self.request_to(provider, self.acs_url(), relay_state)
    }

    /// A fresh request to `provider` asking for its answer at `acs_url`,
    /// whether or not the app takes answers there.
    #[must_use]
    pub fn request_to(
        &self,
        provider: &IdentityProvider,
        acs_url: &str,
        relay_state: &str,
    ) -> Sent {
        let id = fresh_id();
        let xml = format!(
            r#"<samlp:AuthnRequest xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}" ID="{id}" Version="2.0" IssueInstant="{now}" Destination="{destination}" AssertionConsumerServiceURL="{acs_url}" ProtocolBinding="{POST_BINDING}"><saml:Issuer>{issuer}</saml:Issuer><samlp:NameIDPolicy Format="{PERSISTENT}" AllowCreate="true"/></samlp:AuthnRequest>"#,
            now = written_now(),
            destination = provider.sso_url(),
            issuer = self.entity_id(),
        );
        self.request(id, &xml, relay_state)
    }

    /// The answer `response`, base64 as posted, once the app has checked
    /// it was signed by `provider` for this app, posted to its address, in
    /// answer to `request`, and holds now.
    ///
    /// # Errors
    ///
    /// [`Refusal`] says what does not hold.
    pub fn accepted(
        &self,
        provider: &IdentityProvider,
        request: &Sent,
        response: &str,
    ) -> Result<Accepted, Refusal> {
        self.checked(provider, response, Some(request.id()))
    }

    /// The answer `response`, base64 as posted, sent without the app
    /// asking, as a sign-in started at the provider is: checked as
    /// [`accepted`](Self::accepted) checks one, except that it must answer
    /// no request at all.
    ///
    /// # Errors
    ///
    /// [`Refusal`] says what does not hold.
    pub fn accepted_unsolicited(
        &self,
        provider: &IdentityProvider,
        response: &str,
    ) -> Result<Accepted, Refusal> {
        self.checked(provider, response, None)
    }

    /// What `response` says, once it is checked as signed by `provider`
    /// for this app, posted to its address, in answer to the request
    /// `answering` names or to none, and holding now.
    fn checked(
        &self,
        provider: &IdentityProvider,
        response: &str,
        answering: Option<&str>,
    ) -> Result<Accepted, Refusal> {
        let xml = decoded(response)?;
        let document = Document::parse(&xml).map_err(|_| Refusal::Unreadable("not XML"))?;
        let root = document.root_element();
        ensure_message(root, "Response")?;
        ensure_success(root)?;
        let assertion = only_assertion(root)?;
        ensure_signed(assertion, provider)?;
        ensure_signed_if_signed(root, provider)?;
        ensure_issued_by(assertion, provider)?;
        self.ensure_for_this_app(root, assertion, answering)?;
        ensure_holds_now(assertion)?;
        accepted_of(assertion)
    }

    /// Checks the answer is meant for this app, at its address, in answer
    /// to the request `answering` names, or to none.
    fn ensure_for_this_app(
        &self,
        root: Node<'_, '_>,
        assertion: Node<'_, '_>,
        answering: Option<&str>,
    ) -> Result<(), Refusal> {
        let audience = path(
            assertion,
            &["Conditions", "AudienceRestriction", "Audience"],
        )
        .and_then(|audience| audience.text());
        if audience != Some(self.entity_id()) {
            return Err(Refusal::Audience);
        }
        let confirmation = confirmation(assertion)?;
        let addressed = [
            root.attribute("Destination"),
            confirmation.attribute("Recipient"),
        ];
        if addressed.iter().any(|to| *to != Some(self.acs_url())) {
            return Err(Refusal::Recipient);
        }
        let answers = [
            root.attribute("InResponseTo"),
            confirmation.attribute("InResponseTo"),
        ];
        if answers.iter().any(|to| *to != answering) {
            return Err(Refusal::Request);
        }
        Ok(())
    }
}

/// Checks the answer signs the person in.
fn ensure_success(root: Node<'_, '_>) -> Result<(), Refusal> {
    let status = path(root, &["Status", "StatusCode"])
        .and_then(|code| code.attribute("Value"))
        .unwrap_or_default();
    if status != SUCCESS {
        return Err(Refusal::NotSuccess(status.to_owned()));
    }
    Ok(())
}

/// Checks the response's own signature too, when it carries one.
fn ensure_signed_if_signed(root: Node<'_, '_>, provider: &IdentityProvider) -> Result<(), Refusal> {
    match verify(root, provider.certificates()) {
        Ok(()) | Err(Broken::Unsigned) => Ok(()),
        Err(broken) => Err(Refusal::Signature(broken)),
    }
}

/// Checks the assertion's conditions and confirmation hold now.
fn ensure_holds_now(assertion: Node<'_, '_>) -> Result<(), Refusal> {
    let conditions =
        child(assertion, ASSERTION, "Conditions").ok_or(Refusal::Unreadable("no conditions"))?;
    let confirmation = confirmation(assertion)?;
    let now = now();
    let started = instant(conditions.attribute("NotBefore")).is_none_or(|start| start <= now);
    let ends = [
        instant(conditions.attribute("NotOnOrAfter")),
        instant(confirmation.attribute("NotOnOrAfter")),
    ];
    let unended = ends.iter().all(|end| end.is_some_and(|end| now < end));
    if !(started && unended) {
        return Err(Refusal::Lapsed);
    }
    Ok(())
}

/// What the assertion says of the person.
fn accepted_of(assertion: Node<'_, '_>) -> Result<Accepted, Refusal> {
    let name_id =
        path(assertion, &["Subject", "NameID"]).ok_or(Refusal::Unreadable("no NameID"))?;
    let session_index = child(assertion, ASSERTION, "AuthnStatement")
        .and_then(|statement| statement.attribute("SessionIndex"))
        .map(str::to_owned);
    Ok(Accepted {
        name_id: name_id.text().unwrap_or_default().to_owned(),
        name_id_format: name_id.attribute("Format").unwrap_or_default().to_owned(),
        session_index,
        attributes: attributes_of(assertion),
    })
}

/// The attributes the assertion sends, by name.
fn attributes_of(assertion: Node<'_, '_>) -> BTreeMap<String, Vec<String>> {
    let Some(statement) = child(assertion, ASSERTION, "AttributeStatement") else {
        return BTreeMap::new();
    };
    statement
        .children()
        .filter(|attribute| attribute.has_tag_name((ASSERTION, "Attribute")))
        .filter_map(|attribute| {
            let values = attribute
                .children()
                .filter_map(|value| value.text())
                .map(str::to_owned)
                .collect();
            Some((attribute.attribute("Name")?.to_owned(), values))
        })
        .collect()
}

/// The assertion's bearer confirmation.
fn confirmation<'a, 'input>(assertion: Node<'a, 'input>) -> Result<Node<'a, 'input>, Refusal> {
    path(
        assertion,
        &["Subject", "SubjectConfirmation", "SubjectConfirmationData"],
    )
    .ok_or(Refusal::Unreadable("no subject confirmation"))
}

/// The response's one assertion.
fn only_assertion<'a, 'input>(root: Node<'a, 'input>) -> Result<Node<'a, 'input>, Refusal> {
    let mut found = root
        .children()
        .filter(|found| found.has_tag_name((ASSERTION, "Assertion")));
    match (found.next(), found.next()) {
        (Some(only), None) => Ok(only),
        (None, _) => Err(Refusal::Unreadable("no readable assertion")),
        (Some(_), Some(_)) => Err(Refusal::Unreadable("more than one assertion")),
    }
}
