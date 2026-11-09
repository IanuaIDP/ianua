//! What a person's token is asked to be meant for at the token endpoint
//! (RFC 8707), and whether a client's token may open a stream route's
//! signed-in tunnel.

use crate::domains::oauth::clients::client::OAuthClient;
use crate::domains::oauth::clients::settings::AccessTokenFormat;
use crate::domains::routing::stream::{StreamPolicy, StreamRoute, TUNNEL_AUDIENCE_PREFIX};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::StreamRouteId;

/// What a person's token is asked to be meant for at the token endpoint,
/// by its resource indicator (RFC 8707 `resource`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenResource {
    /// No resource named: its client, and the APIs that client calls.
    Holder,
    /// The stream route a `urn:ianua:stream-route:` indicator names.
    StreamRoute(StreamRouteId),
}

impl TokenResource {
    /// The resource `indicator` names: a stream route's signed-in tunnel,
    /// written `urn:ianua:stream-route:` and the route's id, as its
    /// tunnel's audience is.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `indicator` names anything else.
    ///   Only a stream route's tunnel is a resource a token is asked for.
    pub fn from_indicator(indicator: &str) -> Result<Self, DomainError> {
        indicator
            .strip_prefix(TUNNEL_AUDIENCE_PREFIX)
            .and_then(|id| uuid::Uuid::parse_str(id).ok())
            .map(|id| Self::StreamRoute(StreamRouteId::from_uuid(id)))
            .ok_or_else(|| {
                DomainError::invalid(message!(
                    "oauth-the-resource-names-no-stream-route",
                    "the resource names no stream route of this tenant"
                ))
            })
    }
}

/// Refuses a tunnel token `client` could not use at `route`, so a token
/// endpoint can check a resource before its grant spends anything.
///
/// # Errors
///
/// - [`DomainError::Validation`] when `client` takes opaque tokens, or
///   `route` opens no signed-in tunnel or is not active.
pub fn ensure_tunnel_for<T: TenantScope>(
    client: &OAuthClient<T>,
    route: &StreamRoute<T>,
) -> Result<(), DomainError> {
    if client.settings().token_format != AccessTokenFormat::Jwt {
        return Err(DomainError::invalid(message!(
            "oauth-this-client-takes-opaque-tokens-which",
            "this client takes opaque tokens, which a tunnel cannot read"
        )));
    }
    if route.policy() != StreamPolicy::Tunnel {
        return Err(DomainError::invalid(message!(
            "oauth-the-stream-route-opens-no-signed",
            "the stream route opens no signed-in tunnel"
        )));
    }
    if !route.is_active() {
        return Err(DomainError::invalid(message!(
            "oauth-the-stream-route-is-not-active",
            "the stream route is not active"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::routing::stream::tunnel_audience_of;

    /// A stream route's resource indicator names that route; anything else
    /// is no resource a token is asked for.
    #[test]
    fn a_resource_indicator_names_a_stream_route() {
        let route = StreamRouteId::new();
        let indicator = tunnel_audience_of(&route).unwrap();

        let named = TokenResource::from_indicator(indicator.as_str()).unwrap();

        assert_eq!(named, TokenResource::StreamRoute(route));
        for other in [
            "https://api.acme.example",
            "urn:ianua:stream-route:",
            "urn:ianua:stream-route:not-an-id",
            "urn:ianua:route:019f0000-0000-7000-8000-0000000000a6",
        ] {
            assert!(
                matches!(
                    TokenResource::from_indicator(other),
                    Err(DomainError::Validation(_))
                ),
                "{other}"
            );
        }
    }
}
