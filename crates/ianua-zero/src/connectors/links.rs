//! The live links of every connector, and the enrolled connectors they are
//! judged against.
//!
//! The follower hands in each tenant's enrolled connectors whenever it
//! reads the tenant, and every link of that tenant is judged again then: a
//! link whose connector was revoked, removed or enrolled again with another
//! key is closed at once. A tenant withdrawn loses every link. A link is let
//! in only while its connector's key is the one its certificate carries,
//! checked again under the same lock it is added under, so a revocation
//! read between the handshake and the adding still closes it.
//!
//! Links are bounded twice: per connector, and across the gateway. One past
//! either bound is refused, never queued.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use http_body_util::Empty;
use hyper::body::Bytes;
use hyper::client::conn::http2::SendRequest;
use ianua_domain::domains::routing::connector::tunnel::ConnectorTunnel;
use ianua_domain::shared::validation::UrlHost;
use ianua_domain::types::{ConnectorId, PublicKeyPin, TenantId};
use ianua_infra::crypto::ConnectorIdentity;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use super::LinkLimits;

/// Why a link was not let in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum LinkRefusal {
    /// The tenant has no enrolled connector by that id: unknown, another
    /// tenant's, or not enrolled yet.
    #[error("the tenant has no such enrolled connector")]
    UnknownConnector,
    /// The connector is revoked, or its key is not the one the certificate
    /// carries.
    #[error("the connector does not admit this key")]
    NotAdmitted,
    /// The connector holds as many links as it may.
    #[error("the connector holds as many links as it may")]
    ConnectorFull,
    /// The gateway holds as many links as it may.
    #[error("the gateway holds as many connector links as it may")]
    GatewayFull,
}

/// One live link: the HTTP/2 connection a connector holds open, down which
/// connections to its backends are opened.
pub(super) struct Link {
    id: u64,
    key: PublicKeyPin,
    sender: SendRequest<Empty<Bytes>>,
    streams: Arc<Semaphore>,
    closed: CancellationToken,
}

impl Link {
    /// A sender for one more request down the link.
    pub(super) fn sender(&self) -> SendRequest<Empty<Bytes>> {
        self.sender.clone()
    }

    /// The streams the link may still carry.
    pub(super) fn streams(&self) -> Arc<Semaphore> {
        Arc::clone(&self.streams)
    }

    /// Fires when the link is closed by the gateway.
    pub(super) fn closed(&self) -> CancellationToken {
        self.closed.clone()
    }

    /// Whether the link is still taking requests.
    fn is_live(&self) -> bool {
        !self.closed.is_cancelled() && !self.sender.is_closed()
    }
}

/// A link to add: whose it is, and how requests go down it.
pub(super) struct NewLink {
    /// Who its certificate names.
    pub(super) identity: ConnectorIdentity,
    /// How requests are sent down it.
    pub(super) sender: SendRequest<Empty<Bytes>>,
    /// Closed when the gateway closes it.
    pub(super) closed: CancellationToken,
}

/// Every tenant's enrolled connectors and every connector's live links.
pub(crate) struct ConnectorLinks {
    limits: LinkLimits,
    state: RwLock<State>,
    next_id: AtomicU64,
    turn: AtomicUsize,
}

/// What the registry holds, behind one lock.
#[derive(Default)]
struct State {
    tunnels: HashMap<TenantId, HashMap<ConnectorId, ConnectorTunnel>>,
    links: HashMap<(TenantId, ConnectorId), Vec<Arc<Link>>>,
    total: usize,
}

impl ConnectorLinks {
    /// An empty registry held to `limits`: no connector is enrolled until
    /// the follower hands one in.
    #[must_use]
    pub(crate) fn new(limits: LinkLimits) -> Self {
        Self {
            limits,
            state: RwLock::new(State::default()),
            next_id: AtomicU64::new(0),
            turn: AtomicUsize::new(0),
        }
    }

    /// The longest opening one connection down a link may take.
    #[must_use]
    pub(crate) fn open_timeout(&self) -> std::time::Duration {
        self.limits.open
    }

    /// Holds `tunnels` as `tenant`'s enrolled connectors from now on, and
    /// closes every link of the tenant none of them admits.
    pub(crate) fn install(&self, tenant: TenantId, tunnels: Vec<ConnectorTunnel>) {
        let by_id: HashMap<ConnectorId, ConnectorTunnel> = tunnels
            .into_iter()
            .map(|tunnel| (*tunnel.id(), tunnel))
            .collect();
        let mut state = self.write();
        state.tunnels.insert(tenant, by_id);
        state.close_unadmitted(tenant);
    }

    /// Forgets `tenant`'s connectors and closes every link it holds.
    pub(crate) fn withdraw(&self, tenant: &TenantId) {
        let mut state = self.write();
        state.tunnels.remove(tenant);
        state.close_unadmitted(*tenant);
    }

    /// Whether a link held with a certificate naming `identity` would be
    /// let in now.
    ///
    /// # Errors
    ///
    /// [`LinkRefusal::UnknownConnector`] or [`LinkRefusal::NotAdmitted`].
    pub(crate) fn admits(&self, identity: &ConnectorIdentity) -> Result<(), LinkRefusal> {
        self.read().admission(identity)
    }

    /// Adds `link`, once it is still let in and both bounds leave room.
    ///
    /// # Errors
    ///
    /// Any [`LinkRefusal`].
    pub(super) fn register(
        &self,
        link: NewLink,
        streams_per_link: usize,
    ) -> Result<Arc<Link>, LinkRefusal> {
        let identity = link.identity;
        let mut state = self.write();
        state.admission(&identity)?;
        if state.total >= self.limits.max_links {
            return Err(LinkRefusal::GatewayFull);
        }
        let held = state
            .links
            .entry((identity.tenant, identity.connector))
            .or_default();
        if held.len() >= self.limits.links_per_connector {
            return Err(LinkRefusal::ConnectorFull);
        }
        let added = Arc::new(Link {
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            key: identity.key,
            sender: link.sender,
            streams: Arc::new(Semaphore::new(streams_per_link)),
            closed: link.closed,
        });
        held.push(Arc::clone(&added));
        state.total = state.total.saturating_add(1);
        Ok(added)
    }

    /// Removes `link` of `tenant`'s `connector`, closing it. Removing one
    /// already gone is no error.
    pub(super) fn remove(&self, tenant: TenantId, connector: ConnectorId, link: &Link) {
        let mut state = self.write();
        state.drop_link(tenant, connector, link.id);
        link.closed.cancel();
    }

    /// A live link of `tenant`'s `connector`, taking turns between them.
    pub(super) fn pick(&self, tenant: TenantId, connector: ConnectorId) -> Option<Arc<Link>> {
        let state = self.read();
        let live: Vec<&Arc<Link>> = state
            .links
            .get(&(tenant, connector))?
            .iter()
            .filter(|link| link.is_live())
            .collect();
        if live.is_empty() {
            return None;
        }
        let turn = self.turn.fetch_add(1, Ordering::Relaxed);
        live.get(turn % live.len()).map(|link| Arc::clone(link))
    }

    /// Whether `tenant`'s `connector` may be asked to dial `host`: it is
    /// enrolled and its scope names the host. A revoked one holds no link,
    /// so nothing is sent through it either way.
    pub(super) fn may_dial(
        &self,
        tenant: TenantId,
        connector: ConnectorId,
        host: UrlHost<'_>,
    ) -> bool {
        self.read()
            .tunnels
            .get(&tenant)
            .and_then(|tunnels| tunnels.get(&connector))
            .is_some_and(|tunnel| tunnel.scope().permits(host))
    }

    /// How many live links `tenant`'s `connector` holds.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn live(&self, tenant: TenantId, connector: ConnectorId) -> usize {
        self.read()
            .links
            .get(&(tenant, connector))
            .map_or(0, |links| {
                links.iter().filter(|link| link.is_live()).count()
            })
    }

    fn read(&self) -> RwLockReadGuard<'_, State> {
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, State> {
        self.state.write().unwrap_or_else(PoisonError::into_inner)
    }
}

impl State {
    /// Whether a link naming `identity` is let in against the connectors
    /// held now.
    fn admission(&self, identity: &ConnectorIdentity) -> Result<(), LinkRefusal> {
        let Some(tunnel) = self
            .tunnels
            .get(&identity.tenant)
            .and_then(|tunnels| tunnels.get(&identity.connector))
        else {
            return Err(LinkRefusal::UnknownConnector);
        };
        if !tunnel.admits(&identity.key) {
            return Err(LinkRefusal::NotAdmitted);
        }
        Ok(())
    }

    /// Closes and drops every link of `tenant` its connector no longer
    /// admits.
    fn close_unadmitted(&mut self, tenant: TenantId) {
        let tunnels = self.tunnels.get(&tenant);
        let closed: usize = self
            .links
            .iter_mut()
            .filter(|((owner, _), _)| *owner == tenant)
            .map(|((_, connector), links)| {
                keep_admitted(links, tunnels.and_then(|held| held.get(connector)))
            })
            .sum();
        self.links.retain(|_, links| !links.is_empty());
        self.total = self.total.saturating_sub(closed);
        if closed > 0 {
            tracing::info!(%tenant, closed, "connector links no longer admitted were closed");
        }
    }

    /// Drops the link `id` of `tenant`'s `connector`.
    fn drop_link(&mut self, tenant: TenantId, connector: ConnectorId, id: u64) {
        let key = (tenant, connector);
        let Some(links) = self.links.get_mut(&key) else {
            return;
        };
        let before = links.len();
        links.retain(|link| link.id != id);
        let dropped = before.saturating_sub(links.len());
        self.total = self.total.saturating_sub(dropped);
        if links.is_empty() {
            self.links.remove(&key);
        }
    }
}

/// Closes and drops every one of `links` that `tunnel` does not admit,
/// answering how many were closed. No tunnel admits none of them.
fn keep_admitted(links: &mut Vec<Arc<Link>>, tunnel: Option<&ConnectorTunnel>) -> usize {
    let (kept, refused): (Vec<Arc<Link>>, Vec<Arc<Link>>) = links
        .drain(..)
        .partition(|link| tunnel.is_some_and(|tunnel| tunnel.admits(&link.key)));
    refused.iter().for_each(|link| link.closed.cancel());
    *links = kept;
    refused.len()
}

impl std::fmt::Debug for ConnectorLinks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectorLinks")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}
