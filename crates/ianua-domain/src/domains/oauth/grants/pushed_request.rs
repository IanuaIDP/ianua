//! Pushed authorization requests (RFC 9126): a client sends its
//! authorization request straight to the server, proving itself, and sends
//! the browser on with only a `request_uri`.
//!
//! The parameters never pass through the browser, so nobody can change the
//! scopes or redirect on the way. A pushed request is screened as a
//! browser's would be, lives sixty seconds, is used once, and only by the
//! client that pushed it: Mallory's app cannot send a browser on with a
//! `request_uri` the portal pushed.

use std::fmt;

use time::{Duration, OffsetDateTime};

use crate::domains::oauth::clients::client::OAuthClient;
use crate::domains::oauth::events::grants::AuthorizationRequestPushed;
use crate::domains::oauth::grants::authorization_code::{CodeChallenge, NonceSent};
use crate::domains::oauth::grants::authorization_request::{
    AskedRequest, AuthorizeRefusal, MaxAge, RequestScreen, RequestedAcr, screen,
};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::{EventLabel, OAuthClientId, PushedRequestId, RedirectUri, Usage};

/// How long a pushed request may be used: sixty seconds (RFC 9126 2.2).
const LIFETIME: Duration = Duration::seconds(60);

/// The prefix of every `request_uri` this server hands out.
const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

/// The `request_uri` a pushed request is found by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestUri(PushedRequestId);

impl RequestUri {
    /// The `request_uri` of the request `id` names.
    #[must_use]
    pub fn of(id: PushedRequestId) -> Self {
        Self(id)
    }

    /// Reads a `request_uri` a browser brought.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when it is not one this server hands
    ///   out.
    pub fn parse(text: &str) -> Result<Self, DomainError> {
        let unknown = || {
            DomainError::invalid(message!(
                "oauth-this-request-uri-was-not-issued",
                "this request_uri was not issued here"
            ))
        };
        let id = text.strip_prefix(REQUEST_URI_PREFIX).ok_or_else(unknown)?;
        let uuid = uuid::Uuid::parse_str(id).map_err(|_| unknown())?;
        Ok(Self(PushedRequestId::from_uuid(uuid)))
    }

    /// The pushed request it names.
    #[must_use]
    pub fn id(&self) -> &PushedRequestId {
        &self.0
    }
}

impl fmt::Display for RequestUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{REQUEST_URI_PREFIX}{}", self.0)
    }
}

text_value! {
    /// The `state` a client sends to tie the answer to its own request. It
    /// is handed back as it came; nothing here reads it. At most 1024
    /// bytes.
    pub struct ClientState;
}

impl TextValue for ClientState {
    const FIELD: &'static str = "state";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.not_empty().max_bytes(1024).no_control_chars()
    }
}

/// The `state` a request carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateSent {
    /// None.
    NotSent,
    /// The opaque client value echoed to correlate the authorization response.
    Sent(ClientState),
}

/// The authorization parameters a client pushed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedParameters {
    /// Where the answer goes.
    pub redirect_uri: RedirectUri,
    /// What it asks: the flow, scopes, prompts and response mode.
    pub asked: AskedRequest,
    /// The oldest acceptable sign-in, used to decide whether fresh authentication is required.
    pub max_age: MaxAge,
    /// Its `acr_values`.
    pub acr: RequestedAcr,
    /// Its PKCE challenge.
    pub code_challenge: CodeChallenge,
    /// Its nonce, if it sent one.
    pub nonce: NonceSent,
    /// Its `state`, if it sent one.
    pub state: StateSent,
}

/// Why a pushed request could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PushedRefusal {
    /// Another client pushed it.
    #[error("this request_uri was pushed by another client")]
    OtherClient,
    /// Its sixty seconds are over.
    #[error("this request_uri has expired")]
    Expired,
    /// It was used already.
    #[error("this request_uri was used already")]
    Used,
}

impl From<PushedRefusal> for DomainError {
    fn from(refusal: PushedRefusal) -> Self {
        Self::invalid(refusal.to_string())
    }
}

/// An authorization request a client pushed, waiting for the browser.
#[derive(Debug)]
pub struct PushedRequest<T: TenantScope> {
    id: PushedRequestId,
    client_id: OAuthClientId,
    parameters: PushedParameters,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    usage: Usage,
    raised: Raised<T>,
}

/// A pushed request as storage keeps it, checked again by
/// [`PushedRequest::reconstitute`].
pub struct PushedRequestRow {
    /// The stored identity encoded into the browser's request URI.
    pub id: PushedRequestId,
    /// The client that pushed it.
    pub client_id: OAuthClientId,
    /// What it asks.
    pub parameters: PushedParameters,
    /// When it was pushed.
    pub created_at: OffsetDateTime,
    /// When it stops being usable.
    pub expires_at: OffsetDateTime,
    /// Whether it was used, and when.
    pub usage: Usage,
}

impl<T: TenantScope> PushedRequest<T> {
    /// Takes the request `client` pushed, as `id`, once it passes the
    /// screen a browser's request would, and raises
    /// `oauth.authorization_request_pushed`.
    ///
    /// # Errors
    ///
    /// - The [`AuthorizeRefusal`] the screen answers. A redirect the client
    ///   did not register is `InvalidRequest`: the client proved itself, so
    ///   it is told.
    pub fn push(
        id: PushedRequestId,
        client: &OAuthClient<T>,
        parameters: PushedParameters,
    ) -> Result<Self, AuthorizeRefusal> {
        match screen(Some(client), &parameters.redirect_uri, &parameters.asked) {
            RequestScreen::Proceed => {}
            RequestScreen::TellClient(refused) => return Err(refused),
            RequestScreen::TellBrowser => return Err(AuthorizeRefusal::InvalidRequest),
        }
        let now = crate::shared::clock::now();
        let mut raised = Raised::default();
        raised.raise(AuthorizationRequestPushed {
            client_id: *client.id(),
            client_label: EventLabel::of(client.name().as_str()),
            occurred_at: now,
        });
        Ok(Self {
            id,
            client_id: *client.id(),
            parameters,
            created_at: now,
            expires_at: now.saturating_add(LIFETIME),
            usage: Usage::Unused,
            raised,
        })
    }

    /// Rebuilds a pushed request from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row expires before it was
    ///   pushed or lives longer than sixty seconds, or was used before it
    ///   was pushed.
    pub fn reconstitute(row: PushedRequestRow) -> Result<Self, DomainError> {
        RowCheck::of("pushed authorization request")
            .holds(
                row.created_at < row.expires_at,
                "expires before it was pushed",
            )
            .holds(
                row.expires_at <= row.created_at.saturating_add(LIFETIME),
                "lives longer than sixty seconds",
            )
            .in_order_if(
                row.created_at,
                row.usage.used_at(),
                "used before it was pushed",
            )
            .finish()?;
        Ok(Self {
            id: row.id,
            client_id: row.client_id,
            parameters: row.parameters,
            created_at: row.created_at,
            expires_at: row.expires_at,
            usage: row.usage,
            raised: Raised::default(),
        })
    }

    /// The stable identity encoded into the browser's request URI.
    #[must_use]
    pub fn id(&self) -> &PushedRequestId {
        &self.id
    }

    /// The `request_uri` the client sends the browser on with.
    #[must_use]
    pub fn request_uri(&self) -> RequestUri {
        RequestUri::of(self.id)
    }

    /// The client that pushed it.
    #[must_use]
    pub fn client_id(&self) -> &OAuthClientId {
        &self.client_id
    }

    /// When it was pushed.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When it stops being usable.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// Whether it was used, and when.
    #[must_use]
    pub fn usage(&self) -> Usage {
        self.usage
    }

    /// What was pushed, for storage to keep. A browser's request reads
    /// them through [`Self::ensure_usable_by`] or [`Self::redeem`], which
    /// check who may use them first.
    #[must_use]
    pub fn parameters(&self) -> &PushedParameters {
        &self.parameters
    }

    /// Refuses the request at `now` unless a browser naming `client` may
    /// use it, leaving it unused: screening a browser's request checks it
    /// here, and only the consent step spends it.
    ///
    /// # Errors
    ///
    /// - The cases [`PushedRefusal`] names.
    pub fn ensure_usable_by(
        &self,
        client: &OAuthClient<T>,
        now: OffsetDateTime,
    ) -> Result<(), PushedRefusal> {
        if self.client_id != *client.id() {
            return Err(PushedRefusal::OtherClient);
        }
        if self.usage.is_used() {
            return Err(PushedRefusal::Used);
        }
        if now >= self.expires_at {
            return Err(PushedRefusal::Expired);
        }
        Ok(())
    }

    /// Uses the request at `now`, for a browser that came with its
    /// `request_uri` naming `client`, and hands back what was pushed.
    ///
    /// # Errors
    ///
    /// - The cases [`PushedRefusal`] names.
    pub fn redeem(
        &mut self,
        client: &OAuthClient<T>,
        now: OffsetDateTime,
    ) -> Result<PushedParameters, PushedRefusal> {
        self.ensure_usable_by(client, now)?;
        self.usage = Usage::Used { at: now };
        Ok(self.parameters.clone())
    }
}

impl<T: TenantScope> Raises for PushedRequest<T> {
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
    use crate::domains::oauth::grants::authorization_request::{
        AskedFlow, AskedPrompts, AskedScopes, ResponseMode,
    };
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::builders::label;
    use crate::test_support::events::raised_names;
    use crate::types::{ClientId, Scope, TokenHash};

    /// Where the portal sends its answers.
    const REDIRECT: &str = "https://portal.acme.com/callback";

    /// A client registered as `client_id`, with the portal's redirect.
    fn client(client_id: &str) -> OAuthClient<ResolvedTenant> {
        OAuthClient::create(
            NewOAuthClient {
                id: OAuthClientId::new(),
                client_id_value: ClientId::new(client_id).unwrap(),
                credential: ClientCredential::secret(TokenHash::from_stored("s".to_owned())),
                name: label(client_id),
                redirect_uris: vec![RedirectUri::new(REDIRECT).unwrap()],
                post_logout_redirect_uris: Vec::new(),
                grant_types: vec![GrantType::AuthorizationCode],
                scopes: vec![Scope::new("openid").unwrap()],
                settings: ClientSettings::platform_defaults(),
            },
            &key_admin(),
        )
        .unwrap()
    }

    /// A code request for `openid`, answered at `redirect`.
    fn parameters(redirect: &str) -> PushedParameters {
        PushedParameters {
            redirect_uri: RedirectUri::new(redirect).unwrap(),
            asked: AskedRequest {
                flow: AskedFlow::CodeWithS256Challenge,
                scopes: AskedScopes::Named(vec![Scope::new("openid").unwrap()]),
                prompts: AskedPrompts::Named(Vec::new()),
                response_mode: ResponseMode::Query,
            },
            max_age: MaxAge::Any,
            acr: RequestedAcr::Any,
            code_challenge: CodeChallenge::new("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                .unwrap(),
            nonce: NonceSent::NotSent,
            state: StateSent::Sent(ClientState::new("af0ifjsldkj").unwrap()),
        }
    }

    /// The portal's request, pushed.
    fn pushed(portal: &OAuthClient<ResolvedTenant>) -> PushedRequest<ResolvedTenant> {
        PushedRequest::push(PushedRequestId::new(), portal, parameters(REDIRECT)).unwrap()
    }

    /// The row `request` is stored as.
    fn row_of(request: &PushedRequest<ResolvedTenant>) -> PushedRequestRow {
        PushedRequestRow {
            id: request.id,
            client_id: request.client_id,
            parameters: request.parameters.clone(),
            created_at: request.created_at,
            expires_at: request.expires_at,
            usage: request.usage,
        }
    }

    /// The portal pushes its request and the browser comes back with the
    /// `request_uri`. The pushed parameters are handed back, once.
    #[test]
    fn a_pushed_request_is_used_once_by_its_client() {
        let portal = client("portal");
        let mut request = pushed(&portal);
        let now = crate::shared::clock::now();

        let first = request.redeem(&portal, now);
        let again = request.redeem(&portal, now);

        assert_eq!(first.unwrap(), parameters(REDIRECT));
        assert_eq!(again.unwrap_err(), PushedRefusal::Used);
    }

    /// The browser comes back with the portal's `request_uri` and is
    /// screened. The check leaves the request unused, so the consent step
    /// can still spend it once.
    #[test]
    fn checking_a_pushed_request_leaves_it_unused() {
        let portal = client("portal");
        let mut request = pushed(&portal);
        let now = crate::shared::clock::now();

        let checked = request.ensure_usable_by(&portal, now);

        assert_eq!(checked, Ok(()));
        assert_eq!(request.usage(), Usage::Unused);
        assert_eq!(request.parameters(), &parameters(REDIRECT));
        assert!(request.redeem(&portal, now).is_ok());
    }

    /// Checking a redeemed request reports the wrong client for Mallory and
    /// prior use for the portal that pushed it.
    #[test]
    fn the_check_refuses_what_redeeming_would() {
        let portal = client("portal");
        let mut request = pushed(&portal);
        let now = crate::shared::clock::now();
        request.redeem(&portal, now).unwrap();

        let mallorys = request.ensure_usable_by(&client("mallory"), now);
        let spent = request.ensure_usable_by(&portal, now);

        assert_eq!(mallorys, Err(PushedRefusal::OtherClient));
        assert_eq!(spent, Err(PushedRefusal::Used));
    }

    /// The portal pushes a request. It is recorded, naming the portal, and
    /// a request read back from storage raises nothing again.
    #[test]
    fn pushing_raises_oauth_authorization_request_pushed() {
        let mut request = pushed(&client("portal"));
        let mut read_back =
            PushedRequest::<ResolvedTenant>::reconstitute(row_of(&request)).unwrap();

        assert_eq!(
            raised_names(&mut request),
            ["oauth.authorization_request_pushed"]
        );
        assert!(raised_names(&mut read_back).is_empty());
    }

    /// Mallory's client cannot redeem the portal's pushed request. Redemption
    /// returns the other-client refusal.
    #[test]
    fn another_client_cannot_use_a_pushed_request() {
        let mut request = pushed(&client("portal"));

        let result = request.redeem(&client("mallory"), crate::shared::clock::now());

        assert_eq!(result.unwrap_err(), PushedRefusal::OtherClient);
    }

    /// A browser that comes back after sixty seconds is refused.
    #[test]
    fn a_pushed_request_lives_sixty_seconds() {
        let portal = client("portal");
        let mut request = pushed(&portal);

        let late = request.redeem(&portal, request.expires_at());

        assert_eq!(late.unwrap_err(), PushedRefusal::Expired);
        assert_eq!(request.expires_at() - request.created_at(), LIFETIME);
    }

    /// Pushing a request with an unregistered redirect fails the request
    /// screen and returns an invalid-request refusal.
    #[test]
    fn a_pushed_request_is_screened() {
        let result = PushedRequest::push(
            PushedRequestId::new(),
            &client("portal"),
            parameters("https://mallory.example/cb"),
        );

        assert_eq!(result.unwrap_err(), AuthorizeRefusal::InvalidRequest);
    }

    /// A `request_uri` reads back to the request it names; one not issued
    /// here is refused.
    #[test]
    fn a_request_uri_reads_back_to_its_request() {
        let uri = RequestUri::of(PushedRequestId::new());

        assert_eq!(RequestUri::parse(&uri.to_string()).unwrap(), uri);
        assert!(RequestUri::parse("urn:example:other").is_err());
    }

    /// A stored request living longer than sixty seconds is refused as
    /// corrupt.
    #[test]
    fn a_stored_request_living_too_long_is_refused() {
        let request = pushed(&client("portal"));
        let row = PushedRequestRow {
            expires_at: request.created_at + Duration::hours(1),
            ..row_of(&request)
        };

        assert!(refused_as_corrupt(
            &PushedRequest::<ResolvedTenant>::reconstitute(row)
        ));
    }
}
