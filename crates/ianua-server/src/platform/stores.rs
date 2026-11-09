//! The store caches in front of the hottest reads, and the unit of work
//! and the event dispatcher every use case is given, wrapped so a change
//! drops what it touched on this node once it settles.

use std::sync::Arc;
use std::time::Duration;

use ianua_app::ports::authorization::AccessRecordStore;
use ianua_app::ports::runtime::UnitOfWork;
use ianua_app::ports::shared::{EventDispatcher, TokenLookup};
use ianua_boot::foundation::CacheConfig;
use ianua_infra::cache::{
    CacheAccessRecordStore, CacheEventDispatcher, CacheTokenLookup, CacheUnitOfWork, SharedState,
    StoreCaches,
};
use ianua_infra::crypto::HmacTokenResolver;
use ianua_infra::postgres::audit::PgEventDispatcher;
use ianua_infra::postgres::authorization::PgAccessRecordStore;
use ianua_infra::postgres::shared::PgTokenLookup;
use ianua_infra::postgres::{Databases, PgUnitOfWork};

use crate::platform::Keys;

/// How long a store cache's version is kept past its last raise.
const VERSIONS_KEPT: Duration = Duration::from_secs(86_400);

/// The store caches and what goes through them.
pub(super) struct StoreParts {
    /// The caches of this node, under versions every node shares.
    pub(super) caches: Arc<StoreCaches>,
    /// The unit of work every use case runs in.
    pub(super) unit_of_work: Arc<dyn UnitOfWork>,
    /// The event dispatcher every use case records through: the audit
    /// trail and its outbox.
    pub(super) event_dispatcher: Arc<dyn EventDispatcher>,
    /// The bearer lookup, its callers kept. The token resolver and every
    /// port that looks a bearer up take this one.
    pub(super) token_lookup: Arc<dyn TokenLookup>,
    /// The access record store, each holder's records kept.
    pub(super) access_records: Arc<dyn AccessRecordStore>,
    /// The resolver of every bearer the API is shown, over the cached
    /// lookup.
    pub(super) token_resolver: Arc<HmacTokenResolver>,
}

/// The store caches over `state`, and the stores, unit of work and
/// dispatcher wrapped by them.
#[must_use]
pub(super) fn stores(
    databases: &Arc<Databases>,
    state: Arc<dyn SharedState>,
    config: &CacheConfig,
    keys: &Keys,
) -> StoreParts {
    let caches = Arc::new(StoreCaches::new(state, VERSIONS_KEPT));
    let trail: Arc<dyn EventDispatcher> = Arc::new(PgEventDispatcher::new(
        Arc::clone(databases),
        keys.audit_chain_seals.clone(),
    ));
    let lookup: Arc<dyn TokenLookup> = Arc::new(CacheTokenLookup::new(
        Arc::new(PgTokenLookup::new(Arc::clone(databases))),
        Arc::clone(&caches),
        config.callers,
    ));
    let records: Arc<dyn AccessRecordStore> = Arc::new(CacheAccessRecordStore::new(
        Arc::new(PgAccessRecordStore::new(Arc::clone(databases))),
        Arc::clone(&caches),
        config.holdings,
    ));
    StoreParts {
        unit_of_work: Arc::new(CacheUnitOfWork::new(
            Arc::new(PgUnitOfWork),
            Arc::clone(&caches),
        )),
        event_dispatcher: Arc::new(CacheEventDispatcher::new(trail, Arc::clone(&caches))),
        token_resolver: Arc::new(HmacTokenResolver::new(
            &keys.shared_root,
            Arc::clone(&lookup),
        )),
        token_lookup: lookup,
        access_records: records,
        caches,
    }
}
