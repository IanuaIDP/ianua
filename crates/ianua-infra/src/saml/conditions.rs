//! What an assertion must say before anyone is signed in by it: that it
//! is meant for this platform, posted where it arrived, in answer to the
//! request sent, and inside its time window.
//!
//! Each check reads only the signed assertion. The response around it may
//! be unsigned, so its `Destination` and `InResponseTo` bind nothing: a
//! stolen assertion wrapped in a fresh response would pass them. The
//! assertion's own audience, recipient and answered request do bind it.

use ianua_domain::shared::errors::DomainError;
use roxmltree::Node;
use time::format_description::well_known::Iso8601;
use time::{Duration, OffsetDateTime};

use crate::saml::xml::document::{
    ASSERTION, children, elements, is, refused, required_child, text_of,
};

/// How far the provider's clock may run from this one, either way.
pub(crate) const ALLOWED_SKEW: Duration = Duration::seconds(60);

/// The furthest ahead an assertion's window may end. A spent assertion is
/// remembered for a day, so a longer window would outlive the memory that
/// stops it being used twice.
pub(crate) const LONGEST_WINDOW: Duration = Duration::hours(12);

/// The confirmation method of a bearer assertion, the only one taken.
const BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

/// What this sign-in expects an assertion to name.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Expected<'a> {
    /// The time it is checked at.
    pub(crate) now: OffsetDateTime,
    /// This platform's entity id, which its audience must name.
    pub(crate) audience: &'a str,
    /// The address it was posted to, which its recipient must name.
    pub(crate) recipient: &'a str,
    /// The request it must answer.
    pub(crate) request: &'a str,
}

/// Refuses an assertion whose conditions do not hold now, or that is not
/// meant for this platform.
///
/// # Errors
///
/// Returns `DomainError::Validation` when it has no conditions, is not yet
/// valid, has expired, has a window ending too far ahead, names another
/// audience or none, or carries a condition this platform does not know.
pub(crate) fn ensure_conditions(
    assertion: Node<'_, '_>,
    expected: &Expected<'_>,
) -> Result<(), DomainError> {
    let conditions = required_child(
        assertion,
        ASSERTION,
        "Conditions",
        "the assertion carries no conditions",
    )?;
    if let Some(not_before) = conditions.attribute("NotBefore") {
        ensure_started(instant(not_before)?, expected.now)?;
    }
    let ends = conditions
        .attribute("NotOnOrAfter")
        .ok_or_else(|| refused("the assertion carries no end"))?;
    ensure_window(instant(ends)?, expected.now)?;
    ensure_known_conditions(conditions)?;
    ensure_audience(conditions, expected.audience)
}

/// Refuses an assertion with no bearer confirmation for this sign-in: one
/// for the address it was posted to, answering the request sent, and not
/// yet lapsed.
///
/// # Errors
///
/// Returns `DomainError::Validation` when none of its confirmations fits.
pub(crate) fn ensure_bearer(
    subject: Node<'_, '_>,
    expected: &Expected<'_>,
) -> Result<(), DomainError> {
    let fits = children(subject, ASSERTION, "SubjectConfirmation")
        .filter(|confirmation| confirmation.attribute("Method") == Some(BEARER))
        .any(|confirmation| confirms(confirmation, expected).is_ok());
    if !fits {
        return Err(refused("the assertion is not confirmed for this sign-in"));
    }
    Ok(())
}

/// Refuses an assertion whose provider session ended already.
///
/// # Errors
///
/// Returns `DomainError::Validation` when an authentication statement's
/// `SessionNotOnOrAfter` has passed.
pub(crate) fn ensure_session_current(
    assertion: Node<'_, '_>,
    now: OffsetDateTime,
) -> Result<(), DomainError> {
    for statement in children(assertion, ASSERTION, "AuthnStatement") {
        let Some(ends) = statement.attribute("SessionNotOnOrAfter") else {
            continue;
        };
        if instant(ends)? <= now.saturating_sub(ALLOWED_SKEW) {
            return Err(refused("the provider's session has ended"));
        }
    }
    Ok(())
}

/// Refuses an assertion issued in the future, past the skew allowed.
///
/// # Errors
///
/// Returns `DomainError::Validation` when its `IssueInstant` is missing,
/// unreadable or ahead.
pub(crate) fn ensure_issued(
    assertion: Node<'_, '_>,
    now: OffsetDateTime,
) -> Result<(), DomainError> {
    let issued = assertion
        .attribute("IssueInstant")
        .ok_or_else(|| refused("the assertion carries no issue time"))?;
    ensure_started(instant(issued)?, now)
}

/// Whether `confirmation` confirms this sign-in.
fn confirms(confirmation: Node<'_, '_>, expected: &Expected<'_>) -> Result<(), DomainError> {
    let data = required_child(
        confirmation,
        ASSERTION,
        "SubjectConfirmationData",
        "a confirmation carries no data",
    )?;
    if data.attribute("Recipient") != Some(expected.recipient) {
        return Err(refused("the assertion is meant for another address"));
    }
    if data.attribute("InResponseTo") != Some(expected.request) {
        return Err(refused("the assertion answers another request"));
    }
    if let Some(not_before) = data.attribute("NotBefore") {
        ensure_started(instant(not_before)?, expected.now)?;
    }
    let ends = data
        .attribute("NotOnOrAfter")
        .ok_or_else(|| refused("a confirmation carries no end"))?;
    ensure_window(instant(ends)?, expected.now)
}

/// Refuses conditions holding anything but audiences, one-time use and
/// proxying limits: an unknown condition cannot be held to.
fn ensure_known_conditions(conditions: Node<'_, '_>) -> Result<(), DomainError> {
    let known = |node: &Node<'_, '_>| {
        ["AudienceRestriction", "OneTimeUse", "ProxyRestriction"]
            .iter()
            .any(|name| is(*node, ASSERTION, name))
    };
    if !elements(conditions).iter().all(known) {
        return Err(refused(
            "the assertion carries a condition this platform does not know",
        ));
    }
    Ok(())
}

/// Refuses conditions that do not restrict the assertion to this
/// platform: there must be an audience restriction, and every one must
/// name it.
fn ensure_audience(conditions: Node<'_, '_>, audience: &str) -> Result<(), DomainError> {
    let restrictions: Vec<Node<'_, '_>> =
        children(conditions, ASSERTION, "AudienceRestriction").collect();
    let names_us = |restriction: &Node<'_, '_>| {
        children(*restriction, ASSERTION, "Audience")
            .any(|named| text_of(named).is_ok_and(|text| text == audience))
    };
    if restrictions.is_empty() || !restrictions.iter().all(names_us) {
        return Err(refused(
            "the assertion is meant for another service provider",
        ));
    }
    Ok(())
}

fn ensure_started(starts: OffsetDateTime, now: OffsetDateTime) -> Result<(), DomainError> {
    if starts > now.saturating_add(ALLOWED_SKEW) {
        return Err(refused("the assertion is not valid yet"));
    }
    Ok(())
}

fn ensure_window(ends: OffsetDateTime, now: OffsetDateTime) -> Result<(), DomainError> {
    if ends <= now.saturating_sub(ALLOWED_SKEW) {
        return Err(refused("the assertion has expired"));
    }
    if ends > now.saturating_add(LONGEST_WINDOW) {
        return Err(refused("the assertion stays valid for longer than allowed"));
    }
    Ok(())
}

/// The `xs:dateTime` `text` writes.
fn instant(text: &str) -> Result<OffsetDateTime, DomainError> {
    OffsetDateTime::parse(text, &Iso8601::DEFAULT)
        .map_err(|_| refused("a time in the assertion cannot be read"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::saml::xml::document::{Comments, parse};

    const AUDIENCE: &str = "https://ianua.example.com";
    const RECIPIENT: &str = "https://ianua.example.com/acs";
    const REQUEST: &str = "_req1";

    fn at(offset: Duration) -> String {
        (OffsetDateTime::now_utc() + offset)
            .format(&Iso8601::DEFAULT)
            .unwrap()
    }

    fn expected() -> Expected<'static> {
        Expected {
            now: OffsetDateTime::now_utc(),
            audience: AUDIENCE,
            recipient: RECIPIENT,
            request: REQUEST,
        }
    }

    fn assertion(conditions: &str, confirmation: &str) -> String {
        format!(
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" IssueInstant="{}"><saml:Subject>{confirmation}</saml:Subject>{conditions}</saml:Assertion>"#,
            at(Duration::ZERO)
        )
    }

    fn conditions(audience: &str, ends: Duration) -> String {
        format!(
            r#"<saml:Conditions NotBefore="{}" NotOnOrAfter="{}"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>"#,
            at(-Duration::minutes(1)),
            at(ends)
        )
    }

    fn bearer(recipient: &str, request: &str, ends: Duration) -> String {
        format!(
            r#"<saml:SubjectConfirmation Method="{BEARER}"><saml:SubjectConfirmationData Recipient="{recipient}" InResponseTo="{request}" NotOnOrAfter="{}"/></saml:SubjectConfirmation>"#,
            at(ends)
        )
    }

    fn checks(xml: &str) -> Result<(), DomainError> {
        let document = parse(xml, Comments::Refused).unwrap();
        let root = document.root_element();
        let subject = root.first_element_child().unwrap();
        ensure_issued(root, expected().now)?;
        ensure_conditions(root, &expected())?;
        ensure_bearer(subject, &expected())
    }

    fn five_minutes() -> Duration {
        Duration::minutes(5)
    }

    /// An assertion for this platform, posted where it arrived, answering
    /// the request sent and inside its window, holds.
    #[test]
    fn an_assertion_for_this_sign_in_holds() {
        let xml = assertion(
            &conditions(AUDIENCE, five_minutes()),
            &bearer(RECIPIENT, REQUEST, five_minutes()),
        );

        assert!(checks(&xml).is_ok());
    }

    /// An assertion naming another service provider fails the audience check.
    #[test]
    fn an_assertion_for_another_audience_is_refused() {
        let xml = assertion(
            &conditions("https://other.example.com", five_minutes()),
            &bearer(RECIPIENT, REQUEST, five_minutes()),
        );

        assert!(checks(&xml).is_err());
    }

    /// Omitting the audience fails validation rather than granting an unrestricted audience.
    #[test]
    fn an_assertion_without_an_audience_is_refused() {
        let unrestricted = format!(
            r#"<saml:Conditions NotOnOrAfter="{}"/>"#,
            at(five_minutes())
        );
        let xml = assertion(&unrestricted, &bearer(RECIPIENT, REQUEST, five_minutes()));

        assert!(checks(&xml).is_err());
    }

    /// An assertion expired beyond the allowed clock skew fails validation.
    #[test]
    fn an_expired_assertion_is_refused() {
        let gone = -Duration::minutes(10);
        let xml = assertion(
            &conditions(AUDIENCE, gone),
            &bearer(RECIPIENT, REQUEST, gone),
        );

        assert!(checks(&xml).is_err());
    }

    /// A provider's clock running half a minute behind does not refuse an
    /// assertion that just ended by its own reckoning.
    #[test]
    fn a_clock_a_little_behind_is_forgiven() {
        let just = -Duration::seconds(30);
        let xml = assertion(
            &conditions(AUDIENCE, just),
            &bearer(RECIPIENT, REQUEST, just),
        );

        assert!(checks(&xml).is_ok());
    }

    /// A week-long validity window exceeds the accepted assertion lifetime.
    #[test]
    fn a_window_too_long_is_refused() {
        let week = Duration::days(7);
        let xml = assertion(
            &conditions(AUDIENCE, week),
            &bearer(RECIPIENT, REQUEST, week),
        );

        assert!(checks(&xml).is_err());
    }

    /// Subject confirmation must match both the pending request and its recipient;
    /// changing either makes the assertion invalid.
    #[test]
    fn an_assertion_for_another_request_or_address_is_refused() {
        let other_request = assertion(
            &conditions(AUDIENCE, five_minutes()),
            &bearer(RECIPIENT, "_other", five_minutes()),
        );
        let other_address = assertion(
            &conditions(AUDIENCE, five_minutes()),
            &bearer("https://evil.example.com/acs", REQUEST, five_minutes()),
        );

        assert!(checks(&other_request).is_err());
        assert!(checks(&other_address).is_err());
    }

    /// An unsupported condition fails validation instead of being ignored.
    #[test]
    fn an_unknown_condition_is_refused() {
        let strange = conditions(AUDIENCE, five_minutes())
            .replace("</saml:Conditions>", "<saml:Condition/></saml:Conditions>");
        let xml = assertion(&strange, &bearer(RECIPIENT, REQUEST, five_minutes()));

        assert!(checks(&xml).is_err());
    }

    /// An issue time far in the future is invalid despite an otherwise readable assertion.
    #[test]
    fn an_assertion_issued_in_the_future_is_refused() {
        let xml = assertion(
            &conditions(AUDIENCE, five_minutes()),
            &bearer(RECIPIENT, REQUEST, five_minutes()),
        )
        .replacen(&at(Duration::ZERO)[..10], "2999-01-01", 1);

        assert!(checks(&xml).is_err());
    }
}
