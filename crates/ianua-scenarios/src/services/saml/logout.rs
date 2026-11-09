//! Single logout between the app and its provider, either way: the app
//! asking the provider to end the person's session and checking the
//! signed answer, and the provider asking the app, which checks the
//! signed request names the person it signed in, and answers.

use roxmltree::Document;

use super::sign_in::Accepted;
use super::signature::child;
use super::{
    ASSERTION, App, IdentityProvider, PROTOCOL, Refusal, SUCCESS, Sent, decoded, ensure_issued_by,
    ensure_message, ensure_signed, fresh_id, instant, now, path, written_now,
};

/// The second-level status of a logout that ended only some sessions.
const PARTIAL: &str = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout";

/// How a logout went, as its answer says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoggedOut {
    /// Every session ended.
    Success,
    /// Some sessions ended.
    Partial,
    /// It failed, with this status.
    Failed(String),
}

/// A logout request the provider sent the app, checked.
#[derive(Debug, Clone)]
pub struct LogoutAsked {
    id: String,
}

impl App {
    /// A fresh request to `provider` to log out the person the app knows
    /// from `signed_in`, bringing `relay_state` back.
    ///
    /// # Panics
    ///
    /// When the provider publishes no logout address.
    #[must_use]
    pub fn logout_request(
        &self,
        provider: &IdentityProvider,
        signed_in: &Accepted,
        relay_state: &str,
    ) -> Sent {
        let id = fresh_id();
        let session = signed_in
            .session_index
            .as_ref()
            .map(|index| format!("<samlp:SessionIndex>{index}</samlp:SessionIndex>"))
            .unwrap_or_default();
        let xml = format!(
            r#"<samlp:LogoutRequest xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}" ID="{id}" Version="2.0" IssueInstant="{now}" Destination="{destination}"><saml:Issuer>{issuer}</saml:Issuer><saml:NameID Format="{format}">{name_id}</saml:NameID>{session}</samlp:LogoutRequest>"#,
            now = written_now(),
            destination = slo_url(provider),
            issuer = self.entity_id(),
            format = signed_in.name_id_format,
            name_id = signed_in.name_id,
        );
        self.request(id, &xml, relay_state)
    }

    /// How the logout `request` went, once the app has checked the answer
    /// `response`, base64 as posted, was signed and issued by `provider`,
    /// sent to the app's logout address, and answers `request`.
    ///
    /// # Errors
    ///
    /// [`Refusal`] says what does not hold.
    pub fn logout_answered(
        &self,
        provider: &IdentityProvider,
        request: &Sent,
        response: &str,
    ) -> Result<LoggedOut, Refusal> {
        let xml = decoded(response)?;
        let document = Document::parse(&xml).map_err(|_| Refusal::Unreadable("not XML"))?;
        let root = document.root_element();
        ensure_message(root, "LogoutResponse")?;
        ensure_signed(root, provider)?;
        ensure_issued_by(root, provider)?;
        if root.attribute("Destination") != Some(self.logout_url()) {
            return Err(Refusal::Recipient);
        }
        if root.attribute("InResponseTo") != Some(request.id()) {
            return Err(Refusal::Request);
        }
        let top = path(root, &["Status", "StatusCode"]).ok_or(Refusal::Unreadable("no status"))?;
        let second = child(top, PROTOCOL, "StatusCode").and_then(|code| code.attribute("Value"));
        Ok(match (top.attribute("Value"), second) {
            (Some(SUCCESS), Some(PARTIAL)) => LoggedOut::Partial,
            (Some(SUCCESS), _) => LoggedOut::Success,
            (other, _) => LoggedOut::Failed(other.unwrap_or_default().to_owned()),
        })
    }

    /// The provider's logout request `message`, base64 as posted, once the
    /// app has checked it was signed and issued by `provider`, sent to the
    /// app's logout address, holds now, and names the person and session
    /// the app knows from `signed_in`.
    ///
    /// # Errors
    ///
    /// [`Refusal`] says what does not hold.
    pub fn logout_asked(
        &self,
        provider: &IdentityProvider,
        message: &str,
        signed_in: &Accepted,
    ) -> Result<LogoutAsked, Refusal> {
        let xml = decoded(message)?;
        let document = Document::parse(&xml).map_err(|_| Refusal::Unreadable("not XML"))?;
        let root = document.root_element();
        ensure_message(root, "LogoutRequest")?;
        ensure_signed(root, provider)?;
        ensure_issued_by(root, provider)?;
        if root.attribute("Destination") != Some(self.logout_url()) {
            return Err(Refusal::Recipient);
        }
        let lapsed = instant(root.attribute("NotOnOrAfter")).is_some_and(|end| end <= now());
        if lapsed {
            return Err(Refusal::Lapsed);
        }
        let named = child(root, ASSERTION, "NameID").and_then(|name_id| name_id.text());
        let session = child(root, PROTOCOL, "SessionIndex").and_then(|index| index.text());
        if named != Some(signed_in.name_id.as_str())
            || session != signed_in.session_index.as_deref()
        {
            return Err(Refusal::Person);
        }
        let id = root
            .attribute("ID")
            .ok_or(Refusal::Unreadable("no ID"))?
            .to_owned();
        Ok(LogoutAsked { id })
    }

    /// The app's answer to the provider's request `asked`, which came with
    /// `relay_state`: the person is logged out here. For the browser to
    /// post to `provider`'s logout address.
    ///
    /// # Panics
    ///
    /// When the provider publishes no logout address.
    #[must_use]
    pub fn logged_out(
        &self,
        provider: &IdentityProvider,
        asked: &LogoutAsked,
        relay_state: &str,
    ) -> Sent {
        let id = fresh_id();
        let xml = format!(
            r#"<samlp:LogoutResponse xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}" ID="{id}" Version="2.0" IssueInstant="{now}" Destination="{destination}" InResponseTo="{asked}"><saml:Issuer>{issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{SUCCESS}"/></samlp:Status></samlp:LogoutResponse>"#,
            now = written_now(),
            destination = slo_url(provider),
            asked = asked.id,
            issuer = self.entity_id(),
        );
        Sent::of(id, "SAMLResponse", &xml, relay_state)
    }
}

/// Where `provider` takes logouts.
/// Logout scenarios require the provider metadata to advertise this endpoint.
#[allow(clippy::expect_used)]
fn slo_url(provider: &IdentityProvider) -> &str {
    provider
        .slo_url()
        .expect("the provider publishes where it takes logouts")
}
