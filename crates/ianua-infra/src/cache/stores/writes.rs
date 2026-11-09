//! How the node that makes a change drops its own entries at once: the
//! event dispatcher notes every event it kept, and the unit of work applies
//! them once it has settled.
//!
//! Dropping while the change is still being written would be too early: a
//! request reading in between would find the old rows, still uncommitted
//! over, and keep them under the fresh version. So a dispatch inside a
//! unit only notes its events, and the unit applies them after it commits
//! or rolls back; a rolled-back change dropping its entries costs store
//! reads, never a wrong answer. A dispatch outside any unit has committed
//! by the time it answers, so it applies at once.
//!
//! Inside a unit, a holdings read for a tenant whose grants the unit holds
//! or whose links it changed goes to the store: such a read decides a
//! write and must see every commit before the hold, and the unit's own
//! writes.
//!
//! Both decorators must wrap the one unit of work and the one dispatcher
//! the node hands out. A dispatch inside a Postgres unit run outside the
//! cache's own is caught: nothing is dropped before it commits, the
//! mistake is logged, and the events follower applies the change once the
//! event goes out; holdings inside such a unit are read from the store.

use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use ianua_app::ports::runtime::{UnitOfWork, UnitWork};
use ianua_app::ports::shared::EventDispatcher;
use ianua_domain::domains::audit::builder::AuditContext;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::event::DomainEvent;

use crate::cache::stores::invalidation::{Change, StoreCaches};
use crate::cache::stores::owners::Owner;
use crate::postgres::foundation::unit::in_unit;

tokio::task_local! {
    static SETTLING: Arc<Settling>;
}

/// What the running unit noted, to apply once it settles.
#[derive(Default)]
struct Settling {
    changes: Mutex<Vec<Change>>,
    held: Mutex<Vec<Owner>>,
}

impl Settling {
    /// The changes noted, taken out.
    fn taken(&self) -> Vec<Change> {
        std::mem::take(&mut *self.changes.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

/// `change`, when no unit runs, so it is committed and applies now; `None`
/// when the running unit took it, or when a unit runs that this cache does
/// not settle.
///
/// The last is a wiring mistake: the unit's writes are not committed yet,
/// and dropping now would let a read in between keep the old rows under
/// the fresh version. So nothing is dropped here, the mistake is logged,
/// and the change is left to the events follower, which applies it once
/// the unit committed and its event went out.
pub(crate) fn applicable_now(change: Change) -> Option<Change> {
    let noted = SETTLING.try_with(|settling| {
        settling
            .changes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(change);
    });
    if noted.is_ok() {
        return None;
    }
    if in_unit() {
        tracing::error!(
            "an event was kept inside a unit of work the store caches do not settle; wrap the unit of work in CacheUnitOfWork. Its drops are left to the events follower"
        );
        return None;
    }
    Some(change)
}

/// Notes that the running unit holds `owner`'s grants, so its holdings are
/// read from the store for the rest of the unit.
pub(crate) fn note_held(owner: Owner) {
    let _ = SETTLING.try_with(|settling| {
        settling
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(owner);
    });
}

/// Whether the running unit holds `owner`'s grants or changed its links,
/// so its holdings must be read from the store. Inside a unit this cache
/// does not settle, which no hold can be noted in, every read must.
pub(crate) fn settling_holdings_of(owner: Owner) -> bool {
    SETTLING
        .try_with(|settling| {
            let held = settling
                .held
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(&owner);
            held || settling
                .changes
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .any(|change| change.touches_holdings_of(owner))
        })
        .unwrap_or_else(|_| in_unit())
}

/// The unit of work, applying the changes it kept to the store caches once
/// it has settled.
pub struct CacheUnitOfWork {
    inner: Arc<dyn UnitOfWork>,
    caches: Arc<StoreCaches>,
}

impl CacheUnitOfWork {
    /// `inner`, applying what its units kept to `caches` after each.
    #[must_use]
    pub fn new(inner: Arc<dyn UnitOfWork>, caches: Arc<StoreCaches>) -> Self {
        Self { inner, caches }
    }

    /// Applies to the caches every change `settling` kept.
    async fn apply(&self, settling: &Settling) {
        for change in settling.taken() {
            self.caches.apply(change).await;
        }
    }
}

#[async_trait]
impl UnitOfWork for CacheUnitOfWork {
    async fn run<'a>(&'a self, work: UnitWork<'a>) -> Result<(), DomainError> {
        if SETTLING.try_with(|_| ()).is_ok() {
            return self.inner.run(work).await;
        }
        let settling = Arc::new(Settling::default());
        let settled = SETTLING
            .scope(Arc::clone(&settling), self.inner.run(work))
            .await;
        self.apply(&settling).await;
        settled
    }

    async fn run_apart<'a>(&'a self, work: UnitWork<'a>) -> Result<(), DomainError> {
        let settling = Arc::new(Settling::default());
        let settled = SETTLING
            .scope(Arc::clone(&settling), self.inner.run_apart(work))
            .await;
        self.apply(&settling).await;
        settled
    }
}

/// The event dispatcher, noting every event it kept for the store caches.
pub struct CacheEventDispatcher {
    inner: Arc<dyn EventDispatcher>,
    caches: Arc<StoreCaches>,
}

impl CacheEventDispatcher {
    /// `inner`, applying every event it keeps to `caches`, at once or once
    /// the running unit settles.
    #[must_use]
    pub fn new(inner: Arc<dyn EventDispatcher>, caches: Arc<StoreCaches>) -> Self {
        Self { inner, caches }
    }
}

#[async_trait]
impl EventDispatcher for CacheEventDispatcher {
    // A decorator of the sink forwards the context `RequestAuditor` already
    // bound at the boundary; it makes no dispatch of its own. See
    // clippy.toml's `disallowed-methods`.
    #[allow(clippy::disallowed_methods)]
    async fn dispatch(
        &self,
        events: &[DomainEvent],
        ctx: &AuditContext,
    ) -> Result<(), DomainError> {
        self.inner.dispatch(events, ctx).await?;
        for event in events {
            let change = Change::of(event.event_type(), Owner::of_event(event));
            if let Some(now) = applicable_now(change) {
                self.caches.apply(now).await;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // The dispatcher's own tests call the raw sink they test; use cases
    // reach it only through `RequestAuditor`.
    #![allow(clippy::disallowed_methods)]

    use std::time::Duration;

    use ianua_app::ports::runtime::Settlement;
    use ianua_domain::test_support::events::{sample_role_assigned, sample_tenant_event};
    use ianua_domain::types::{PrincipalRef, RoleId, TenantId, UserId};

    use super::*;
    use crate::cache::MemoryState;
    use crate::cache::stores::entries::{Entries, EntryKeeping};
    use crate::cache::stores::owners::Owners;
    use crate::cache::stores::versions::Cached;
    use crate::postgres::foundation::unit::PgUnitOfWork;

    /// A dispatcher that keeps every event, as the audit trail does.
    struct Keeping;

    #[async_trait]
    impl EventDispatcher for Keeping {
        async fn dispatch(&self, _: &[DomainEvent], _: &AuditContext) -> Result<(), DomainError> {
            Ok(())
        }
    }

    /// A unit of work that runs its work and settles nothing.
    struct Running;

    #[async_trait]
    impl UnitOfWork for Running {
        async fn run<'a>(&'a self, work: UnitWork<'a>) -> Result<(), DomainError> {
            let _: Settlement = work.await;
            Ok(())
        }

        async fn run_apart<'a>(&'a self, work: UnitWork<'a>) -> Result<(), DomainError> {
            self.run(work).await
        }
    }

    struct Node {
        holdings: Arc<Entries<&'static str, u8>>,
        unit: CacheUnitOfWork,
        dispatcher: CacheEventDispatcher,
    }

    fn node() -> Node {
        let caches = Arc::new(StoreCaches::new(
            Arc::new(MemoryState::new(100)),
            Duration::from_secs(60),
        ));
        let holdings = caches.entries(
            Cached::Holdings,
            EntryKeeping {
                lifetime: Duration::from_secs(60),
                capacity: 100,
            },
        );
        Node {
            unit: CacheUnitOfWork::new(Arc::new(Running), Arc::clone(&caches)),
            dispatcher: CacheEventDispatcher::new(Arc::new(Keeping), caches),
            holdings,
        }
    }

    fn role_given_in(tenant: TenantId) -> DomainEvent {
        sample_role_assigned(tenant, PrincipalRef::User(UserId::new()), RoleId::new())
    }

    /// An event dispatched outside any unit has been kept when the
    /// dispatch answers, so its entries go at once.
    #[tokio::test]
    async fn a_dispatch_outside_a_unit_drops_at_once() {
        let node = node();
        let acme = TenantId::new();
        node.holdings
            .put("ann", 1, Owners::only(Owner::Tenant(*acme.as_uuid())));

        node.dispatcher
            .dispatch(&[role_given_in(acme)], &AuditContext::system())
            .await
            .unwrap();

        assert!(node.holdings.get(&"ann").is_none());
    }

    /// An event inside a cache-wrapped unit leaves its entry present while the unit settles;
    /// the entry is removed after settlement.
    #[tokio::test]
    async fn a_dispatch_inside_a_unit_drops_once_it_settles() {
        let node = node();
        let acme = TenantId::new();
        let owner = Owner::Tenant(*acme.as_uuid());
        node.holdings.put("ann", 1, Owners::only(owner));
        let during = Arc::new(Mutex::new(None));

        let seen = Arc::clone(&during);
        let holdings = Arc::clone(&node.holdings);
        let dispatcher = &node.dispatcher;
        node.unit
            .run(Box::pin(async move {
                dispatcher
                    .dispatch(&[role_given_in(acme)], &AuditContext::system())
                    .await
                    .unwrap();
                *seen.lock().unwrap() =
                    Some((holdings.get(&"ann").is_some(), settling_holdings_of(owner)));
                Settlement::Commit
            }))
            .await
            .unwrap();

        assert_eq!(*during.lock().unwrap(), Some((true, true)));
        assert!(node.holdings.get(&"ann").is_none());
        assert!(!settling_holdings_of(owner));
    }

    /// An event inside an unwrapped Postgres unit leaves the cache entry present
    /// and marks the tenant as settling.
    #[tokio::test]
    async fn a_dispatch_inside_an_unwrapped_unit_drops_nothing_early() {
        let node = node();
        let acme = TenantId::new();
        let owner = Owner::Tenant(*acme.as_uuid());
        node.holdings.put("ann", 1, Owners::only(owner));
        let during = Arc::new(Mutex::new(None));

        let seen = Arc::clone(&during);
        let holdings = Arc::clone(&node.holdings);
        let dispatcher = &node.dispatcher;
        PgUnitOfWork
            .run(Box::pin(async move {
                dispatcher
                    .dispatch(&[role_given_in(acme)], &AuditContext::system())
                    .await
                    .unwrap();
                *seen.lock().unwrap() =
                    Some((holdings.get(&"ann").is_some(), settling_holdings_of(owner)));
                Settlement::Commit
            }))
            .await
            .unwrap();

        assert_eq!(*during.lock().unwrap(), Some((true, true)));
    }

    /// A unit that changed nothing a cache holds leaves the entries alone.
    #[tokio::test]
    async fn an_unrelated_event_leaves_the_entries() {
        let node = node();
        let acme = TenantId::new();
        node.holdings
            .put("ann", 1, Owners::only(Owner::Tenant(*acme.as_uuid())));

        node.dispatcher
            .dispatch(&[sample_tenant_event(acme)], &AuditContext::system())
            .await
            .unwrap();

        assert!(node.holdings.get(&"ann").is_some());
    }
}
