//! Which route a live request takes, the way the gateway picks it.

use crate::domains::routing::matching::path_match::{Captures, captures};
use crate::domains::routing::matching::path_rewrite::ForwardedPath;
use crate::domains::routing::matching::request_match::RequestValues;
use crate::domains::routing::route::Route;
use crate::isolation::scope::TenantScope;
use crate::types::{CanonicalPath, Fact, HttpMethod, ServiceId};

/// The order routes are tried in: lowest priority number first, then the
/// most specific pattern. The gateway sorts its table by this, so every
/// caller agrees on which route takes a request.
#[must_use]
pub fn evaluation_order<T: TenantScope>(a: &Route<T>, b: &Route<T>) -> std::cmp::Ordering {
    a.priority()
        .cmp(&b.priority())
        .then_with(|| b.specificity().cmp(&a.specificity()))
}

/// A request as the gateway routes it.
#[derive(Clone, Copy)]
pub struct RouteRequest<'a> {
    /// The HTTP verb used to select eligible forwarding rules.
    pub method: HttpMethod,
    /// The path, in its canonical spelling.
    pub path: &'a CanonicalPath,
    /// The host the request was sent to. When it is unknown only a route
    /// on every host matches.
    pub host: Fact<&'a str>,
    /// The headers and cookies the request carries. When they are unknown
    /// only a route without header or cookie conditions matches.
    pub values: Fact<&'a dyn RequestValues>,
}

impl std::fmt::Debug for RouteRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("host", &self.host)
            .field("values", &self.values.map(|_| "carried"))
            .finish()
    }
}

impl<T: TenantScope> Route<T> {
    /// Whether this route takes `request`: its hosts accept the host, it
    /// matches the method, its header and cookie conditions hold, and its
    /// pattern fits the path.
    ///
    /// An unknown host is taken only by a route on every host, and unknown
    /// headers and cookies only by a route with no conditions. Otherwise a
    /// route bound to one host, or to a blue/green header, would judge a
    /// request by a rule the gateway applies to another.
    ///
    /// Whether the route is active, and its service serving, is asked
    /// apart: see [`resolve_route`].
    #[must_use]
    pub fn takes(&self, request: &RouteRequest<'_>) -> bool {
        let on_host = match request.host {
            Fact::Known(host) => self.hosts().accepts(host),
            Fact::Unknown => self.hosts().is_any(),
        };
        on_host && self.takes_once_named(request)
    }

    /// Whether this route takes `request` once something other than the
    /// host named it, as a run pass names its route: the host plays no
    /// part, and the method, the header and cookie conditions and the path
    /// must still fit, as [`takes`](Self::takes) holds them.
    #[must_use]
    pub fn takes_once_named(&self, request: &RouteRequest<'_>) -> bool {
        let conditions_hold = match request.values {
            Fact::Known(values) => self.conditions().hold_for(values),
            Fact::Unknown => self.conditions().is_empty(),
        };
        self.matches_method(request.method) && conditions_hold && self.matches_path(request.path)
    }

    /// The path the upstream is sent for `path` on this route, after its
    /// rewrite, spelled for the wire and without a query. See
    /// [`PathRewrite::forwarded`](crate::domains::routing::matching::path_rewrite::PathRewrite::forwarded)
    /// for the rules.
    ///
    /// `None` when the pattern does not fit `path`, or the rewrite cannot
    /// make a canonical path of it. The caller refuses the request: nothing
    /// is forwarded with a literal `{name}` in it.
    #[must_use]
    pub fn forwarding_path(&self, path: &CanonicalPath) -> Option<ForwardedPath> {
        self.forwarding(path).map(Forwarding::into_path)
    }

    /// What this route makes of `path`: what its pattern captured, which
    /// the route's parameter rules read, and the path the upstream is sent,
    /// as [`forwarding_path`](Self::forwarding_path) gives it.
    ///
    /// `None` exactly when `forwarding_path` is.
    #[must_use]
    pub fn forwarding(&self, path: &CanonicalPath) -> Option<Forwarding> {
        let captures = captures(self.path_pattern().as_str(), path)?;
        let path = self.path_rewrite().forwarded(path, &captures)?;
        Some(Forwarding { captures, path })
    }
}

/// What a route makes of the path a request matched on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forwarding {
    captures: Captures,
    path: ForwardedPath,
}

impl Forwarding {
    /// What the route's pattern captured from the path, by name.
    #[must_use]
    pub fn captures(&self) -> &Captures {
        &self.captures
    }

    /// The path the upstream is sent, spelled for the wire and without a
    /// query.
    #[must_use]
    pub fn path(&self) -> &ForwardedPath {
        &self.path
    }

    /// The path the upstream is sent, owned.
    #[must_use]
    pub fn into_path(self) -> ForwardedPath {
        self.path
    }
}

impl<T: TenantScope> AsRef<Self> for Route<T> {
    fn as_ref(&self) -> &Self {
        self
    }
}

/// The route a live request takes, picked the way the gateway picks it.
///
/// It is the first in [`evaluation_order`] of the routes that are active,
/// whose service is serving, and that [`Route::takes`] the request. On a
/// tie, the one first in `routes` wins, so a table already sorted by
/// [`evaluation_order`] gives its first match.
///
/// `routes` may be routes or anything holding one, such as the gateway's
/// compiled table entries, and the match is handed back as given.
///
/// With no host known, only a route on every host can match, and with no
/// headers or cookies known only a route without conditions. A route whose
/// service is not serving is skipped, as the gateway skips it. So its policy
/// never stands in for the one enforced.
///
/// `None` when no active route matches. The caller should deny, as the proxy
/// does for an unmatched path.
#[must_use]
pub fn resolve_route<'a, T, R>(
    routes: impl IntoIterator<Item = &'a R>,
    request: &RouteRequest<'_>,
    serving: impl Fn(&ServiceId) -> bool,
) -> Option<&'a R>
where
    T: TenantScope,
    R: AsRef<Route<T>> + 'a,
{
    routes
        .into_iter()
        .filter(|held| {
            let route = route_of(*held);
            route.is_active() && serving(route.service_id()) && route.takes(request)
        })
        .reduce(|best, held| {
            if evaluation_order(route_of(held), route_of(best)).is_lt() {
                held
            } else {
                best
            }
        })
}

/// The route `held` holds.
fn route_of<T: TenantScope, R: AsRef<Route<T>>>(held: &R) -> &Route<T> {
    held.as_ref()
}
