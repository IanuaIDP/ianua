//! What a request at the gateway presents, as the gateway extracted it.

use ianua_domain::domains::proxy::request::cross_site::{CsrfEcho, PageOrigin};
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Audience, DomainName, HttpMethod, HttpUrl, ServiceId};

/// The one credential a request presents, picked by the gateway in this
/// order: a bearer token, an API key header, an app session cookie on a
/// host with app sign-in, the session cookie elsewhere.
///
/// A bearer token is not sorted by kind: the gateway cannot tell an access
/// token from a task token or a consumer's key without reading it, and it
/// never does.
#[derive(Clone)]
pub enum Presented {
    /// Nothing but, perhaps, a client certificate.
    Nothing,
    /// The `Authorization: Bearer` value: an access token, a task token, a
    /// consumer's own token, or a consumer's API key.
    Bearer(Secret),
    /// The value of an API key header (`apikey`, `x-api-key`).
    ApiKey(Secret),
    /// The session cookie, carrying a token the tenant signed, read where
    /// the host has no app sign-in, with the CSRF pair beside it.
    SessionCookie {
        /// The cookie's token.
        token: Secret,
        /// The CSRF cookie and header.
        csrf: CsrfEcho,
    },
    /// The app session cookie of a host with app sign-in, for a route that
    /// takes that host's sign-in.
    AppSession(AppSessionCookie),
    /// The `Authorization: Bearer` value on the gateway's workflow
    /// listener: a run pass, read as nothing else. Elsewhere a bearer is
    /// never read as a pass.
    RunPass(Secret),
}

/// An app session cookie, with what it must say to be taken on its host.
#[derive(Clone)]
pub struct AppSessionCookie {
    /// The cookie's token.
    pub token: Secret,
    /// The host it arrived on, without a port.
    pub host: DomainName,
    /// The service whose sign-in must have opened the session.
    pub owner: ServiceId,
    /// The audience the session must name: the owner's, or on a host of a
    /// service's own cookie, that service's.
    pub audience: Audience,
    /// The page that sent the request: the host's own, or one it trusts.
    pub origin: PageOrigin,
    /// The app's CSRF cookie and header.
    pub csrf: CsrfEcho,
}

/// Where a request was sent, as the client framed it, which a `DPoP` proof
/// must name.
#[derive(Clone)]
pub struct RequestTarget {
    /// The HTTP verb that must match the sender proof.
    pub method: HttpMethod,
    /// The scheme, host and normalized path the client addressed, without
    /// query or fragment.
    pub url: HttpUrl,
}
