//! How an app's server took the logout token it was sent.
//!
//! Ann signs out and the apps she signed in to are told. An app whose server
//! never answered may still hold her session, so each posting is recorded:
//! which app, and whether its server took the token. The token itself is
//! never recorded.

use crate::domains::oauth::clients::client::OAuthClient;
use crate::domains::oauth::events::grants::BackChannelLogoutSent;
use crate::isolation::scope::TenantScope;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::types::EventLabel;

/// How an app's server took a logout token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogoutDelivery {
    /// The server took it.
    Taken,
    /// No server took it in time.
    Unreachable,
}

impl LogoutDelivery {
    /// The name the audit trail records it by.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Taken => "taken",
            Self::Unreachable => "unreachable",
        }
    }
}

/// A logout token posted to one app's server, and how it was taken.
#[derive(Debug)]
pub struct LogoutTold<T: TenantScope> {
    delivery: LogoutDelivery,
    raised: Raised<T>,
}

impl<T: TenantScope> LogoutTold<T> {
    /// Records that `client`'s server was sent a logout token and took it
    /// as `delivery` says, raising `oauth.back_channel_logout_sent`.
    #[must_use]
    pub fn record(client: &OAuthClient<T>, delivery: LogoutDelivery) -> Self {
        let mut raised = Raised::default();
        raised.raise(BackChannelLogoutSent {
            client_id: *client.id(),
            client_label: EventLabel::of(client.name().as_str()),
            delivery,
            occurred_at: crate::shared::clock::now(),
        });
        Self { delivery, raised }
    }

    /// How the server took the token.
    #[must_use]
    pub fn delivery(&self) -> LogoutDelivery {
        self.delivery
    }
}

impl<T: TenantScope> Raises for LogoutTold<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::oauth::clients::client::{GrantType, NewOAuthClient};
    use crate::domains::oauth::clients::credential::ClientCredential;
    use crate::domains::oauth::clients::settings::ClientSettings;
    use crate::domains::oauth::control::tests::key_admin;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::test_support::builders::label;
    use crate::test_support::events::raised;
    use crate::types::{ClientId, OAuthClientId, RedirectUri, TokenHash};

    /// The web app Ann signed in to.
    fn web_app() -> OAuthClient<ResolvedTenant> {
        OAuthClient::create(
            NewOAuthClient {
                id: OAuthClientId::new(),
                client_id_value: ClientId::new("web_app").unwrap(),
                credential: ClientCredential::secret(TokenHash::from_stored("s".to_owned())),
                name: label("Web app"),
                redirect_uris: vec![RedirectUri::new("https://app.acme.com/cb").unwrap()],
                post_logout_redirect_uris: Vec::new(),
                grant_types: vec![GrantType::AuthorizationCode],
                scopes: Vec::new(),
                settings: ClientSettings::platform_defaults(),
            },
            &key_admin(),
        )
        .unwrap()
    }

    /// Ann signs out and the web app's server never answers. The posting is
    /// recorded as unreachable, naming the app, so an administrator sees it
    /// may still hold her session.
    #[test]
    fn an_unreachable_server_is_recorded() {
        let app = web_app();
        let mut told = LogoutTold::record(&app, LogoutDelivery::Unreachable);

        let events = raised(&mut told);

        assert_eq!(told.delivery(), LogoutDelivery::Unreachable);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().to_string(),
            "oauth.back_channel_logout_sent"
        );
        assert_eq!(events[0].payload().get("delivery"), Some("unreachable"));
        assert!(matches!(
            events[0].payload().value("client"),
            Some(FieldValue::Reference(_))
        ));
    }

    /// A successful logout-delivery record has only two payload fields,
    /// including the taken delivery status, leaving the token out.
    #[test]
    fn the_record_carries_no_token() {
        let mut told = LogoutTold::record(&web_app(), LogoutDelivery::Taken);

        let payload = raised(&mut told)[0].payload();

        assert_eq!(payload.len(), 2);
        assert_eq!(payload.get("delivery"), Some("taken"));
    }
}
