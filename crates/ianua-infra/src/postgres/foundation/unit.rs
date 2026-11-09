//! The unit of work, and the one way a store reaches the database.
//!
//! A store runs its statements through [`scoped`], and nothing else: it
//! never holds a pool or a transaction. Inside a running unit the call joins
//! the unit's transaction on its database; outside one it gets a short
//! transaction of its own. Either way the call runs in a transaction, with
//! row-level security set for its scope, so no path forgets the tenant.
//!
//! Inside a unit each call runs in a savepoint of its own. Postgres refuses
//! every statement after a failed one until the transaction rolls back, so
//! without it one refused insert, such as a name already taken, would sink
//! every write of the request, though the use case meant only to report it.
//!
//! When the work ends the unit commits or rolls back every transaction it
//! opened, so a change and the audit record of it are kept or dropped
//! together. A unit holds one transaction per database and per role: the
//! audit purge signs in as a role of its own, so its work never joins a
//! transaction the app's role opened, nor the app's work one of the
//! purge's.
//!
//! The transactions commit one after another, so a lock must outlive the
//! writes it guards. A store taking a transaction-level lock, such as a
//! plan count, a domain claim's site or a tenant's grants, takes it
//! through [`scoped_holding`], and the transaction holding the lock
//! commits after the unit's others of its role: a request waiting on the
//! lock then sees every write it guards, though the writes went to a
//! tenant's own database and the lock to the platform's.
//!
//! A unit started inside a running one is nested in it: in every
//! transaction it touches, those opened inside it included, it writes
//! after a savepoint of its own. When it succeeds the savepoints are
//! released and its writes become the outer unit's; when it fails, on any
//! error it returns, they are rolled back to, and nothing it wrote is
//! kept, though the outer unit goes on and commits the rest. So work kept
//! together inside a request is all or nothing whatever the request ends
//! up answering. Nested units of one task run one after another, or one
//! inside another: savepoints of one transaction can only be ended latest
//! first. A nested unit started beside another still running, as two
//! joined futures would, is refused before it runs, and so is a store call
//! made beside a running nested unit outside it, which its rollback would
//! otherwise undo.
//!
//! The unit travels with the task, so neither use cases nor stores pass it
//! around. A task spawned from inside a unit does not inherit it.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::runtime::{Settlement, UnitOfWork, UnitWork};
use ianua_domain::shared::errors::DomainError;
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use tokio::sync::Mutex as AsyncMutex;

use crate::postgres::foundation::errors::unanswered;
use crate::postgres::foundation::pool::{Database, Databases, Login};
use crate::postgres::foundation::security::{self, RowScope};

tokio::task_local! {
    static UNIT: Arc<Unit>;
    static NEST: u32;
}

/// Whether the running code is part of a unit of work, so its writes are
/// not committed until the unit settles.
pub(crate) fn in_unit() -> bool {
    UNIT.try_with(|_| ()).is_ok()
}

/// The depth of the nested unit the running code is part of, or `0` when
/// it is part of no nested unit.
fn current_nest() -> u32 {
    NEST.try_with(|depth| *depth).unwrap_or(0)
}

/// How long a store call waits for its unit's transaction while another
/// call of the same unit holds it. Calls of one unit run one after another,
/// so a wait this long means one holds it across another: failing beats
/// hanging.
const JOIN_TIMEOUT: Duration = Duration::from_secs(10);

/// A unit's transaction on one database, opened on first use, whether the
/// last store call on it still has its savepoint open, and how many nested
/// units have a savepoint open on it.
#[derive(Default)]
struct Slot {
    transaction: Option<Transaction<'static, Postgres>>,
    call: Call,
    nests: u32,
}

/// Whether a store call's savepoint is waiting to be settled.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum Call {
    /// No call has run since the last one was settled.
    #[default]
    Settled,
    /// A call ran inside its savepoint; the next call or the commit settles
    /// it.
    Open,
}

type SharedSlot = Arc<AsyncMutex<Slot>>;

/// Which transaction of a unit a store call joins: one per database and
/// per role signed in to it.
type SlotKey = (Login, Database);

/// The transactions a unit has open, those of them holding a lock that
/// guards the unit's writes, and how deep the nested units now running
/// inside it go.
#[derive(Default)]
struct Unit {
    transactions: Mutex<Vec<(SlotKey, SharedSlot)>>,
    locking: Mutex<Vec<SlotKey>>,
    depth: Mutex<u32>,
}

impl Unit {
    /// Notes that the transaction for `key` holds a lock guarding the
    /// unit's writes, so it commits after the ones holding the writes.
    fn holds_lock(&self, key: SlotKey) {
        let mut locking = self.locking.lock().unwrap_or_else(PoisonError::into_inner);
        if !locking.contains(&key) {
            locking.push(key);
        }
    }

    /// Starts a nested unit inside the one at depth `enclosing`, and answers
    /// its depth; `None` when another nested unit, not one it runs inside,
    /// is still running, as two run side by side would be.
    fn enter(&self, enclosing: u32) -> Option<u32> {
        let mut depth = self.depth.lock().unwrap_or_else(PoisonError::into_inner);
        if *depth != enclosing {
            return None;
        }
        *depth = depth.saturating_add(1);
        Some(*depth)
    }

    /// Ends the nested unit at `depth` as `settlement` says: in every
    /// transaction it touched, its savepoint is released, or rolled back to
    /// first.
    async fn leave(&self, depth: u32, settlement: Settlement) -> Result<(), DomainError> {
        *self.depth.lock().unwrap_or_else(PoisonError::into_inner) = depth.saturating_sub(1);
        let slots: Vec<SharedSlot> = self
            .transactions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(_, slot)| Arc::clone(slot))
            .collect();
        for slot in slots {
            let mut held = tokio::time::timeout(JOIN_TIMEOUT, slot.lock())
                .await
                .map_err(|_| unanswered(sqlx::Error::PoolTimedOut))?;
            settle_nest(&mut held, depth, settlement)
                .await
                .map_err(unanswered)?;
        }
        Ok(())
    }

    /// The unit's slot for `key`, made on first use.
    fn slot(&self, key: SlotKey) -> SharedSlot {
        let mut open = self
            .transactions
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some((_, slot)) = open.iter().find(|(held, _)| *held == key) {
            return Arc::clone(slot);
        }
        let slot = SharedSlot::default();
        open.push((key, Arc::clone(&slot)));
        slot
    }

    /// Commits or rolls back every transaction.
    async fn settle(&self, settlement: Settlement) -> Result<(), DomainError> {
        let open = std::mem::take(
            &mut *self
                .transactions
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
        if settlement == Settlement::Rollback {
            roll_back(open).await;
            return Ok(());
        }
        let locking =
            std::mem::take(&mut *self.locking.lock().unwrap_or_else(PoisonError::into_inner));
        commit_all(commit_order(open, &locking)).await
    }
}

/// Orders commits with audit purges last, after their audit records are durable.
/// Within each role, `locking` transactions follow the writes they guard.
/// This keeps plan-count and domain-claim locks until separate tenant-database
/// writes are visible, so waiting requests cannot act on stale counts or claims.
/// A failure before a purge leaves recorded work to retry, never an unaudited deletion.
fn commit_order(
    mut open: Vec<(SlotKey, SharedSlot)>,
    locking: &[SlotKey],
) -> Vec<(SlotKey, SharedSlot)> {
    open.sort_by_key(|(key, _)| (key.0 == Login::AuditPurge, locking.contains(key)));
    open
}

/// Runs `call` on a connection whose transaction sees the rows of `scope`:
/// the running unit's transaction when there is one, or a transaction of
/// its own that commits when `call` succeeds.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure`, with the cause kept, when the
/// database cannot be reached in time or a statement fails.
pub(crate) async fn scoped<T>(
    databases: &Databases,
    scope: RowScope,
    call: impl AsyncFnOnce(&mut PgConnection) -> Result<T, sqlx::Error>,
) -> Result<T, DomainError> {
    let (database, pool) = databases.for_scope(scope);
    let Ok(unit) = UNIT.try_with(Arc::clone) else {
        return alone(&pool, scope, call).await.map_err(unanswered);
    };
    let slot = unit.slot((databases.login(), database));
    joined(&slot, &pool, scope, call).await.map_err(unanswered)
}

/// Runs `call`, which takes a transaction-level lock guarding writes the
/// unit makes, as [`scoped`] does. Inside a unit, the transaction it joins
/// commits after the unit's other transactions of its role, so the lock
/// holds until every write it guards is committed, in whichever database.
///
/// # Errors
///
/// As [`scoped`].
pub(crate) async fn scoped_holding<T>(
    databases: &Databases,
    scope: RowScope,
    call: impl AsyncFnOnce(&mut PgConnection) -> Result<T, sqlx::Error>,
) -> Result<T, DomainError> {
    if let Ok(unit) = UNIT.try_with(Arc::clone) {
        let (database, _) = databases.for_scope(scope);
        unit.holds_lock((databases.login(), database));
    }
    scoped(databases, scope, call).await
}

/// Runs `call` in a transaction of its own even inside a unit, committed
/// when it ends, for what others must see while the unit still runs.
///
/// # Errors
///
/// As [`scoped`].
pub(crate) async fn scoped_alone<T>(
    databases: &Databases,
    scope: RowScope,
    call: impl AsyncFnOnce(&mut PgConnection) -> Result<T, sqlx::Error>,
) -> Result<T, DomainError> {
    let (_, pool) = databases.for_scope(scope);
    alone(&pool, scope, call).await.map_err(unanswered)
}

/// Runs `call` in a transaction of its own, committed when it succeeds.
async fn alone<T>(
    pool: &PgPool,
    scope: RowScope,
    call: impl AsyncFnOnce(&mut PgConnection) -> Result<T, sqlx::Error>,
) -> Result<T, sqlx::Error> {
    let mut transaction = pool.begin().await?;
    security::apply(&mut transaction, scope).await?;
    let answer = call(&mut transaction).await?;
    transaction.commit().await?;
    Ok(answer)
}

/// Runs `call` in a savepoint of the unit's selected transaction slot.
async fn joined<T>(
    slot: &AsyncMutex<Slot>,
    pool: &PgPool,
    scope: RowScope,
    call: impl AsyncFnOnce(&mut PgConnection) -> Result<T, sqlx::Error>,
) -> Result<T, sqlx::Error> {
    let mut held = tokio::time::timeout(JOIN_TIMEOUT, slot.lock())
        .await
        .map_err(|_| sqlx::Error::PoolTimedOut)?;
    let transaction = open_call(&mut held, pool, current_nest()).await?;
    security::apply(transaction, scope).await?;
    call(transaction).await
}

/// Starts a store call, made inside the nested unit at `depth` or `0` for
/// none, on the unit's transaction: opens the transaction on first use,
/// settles the previous call, opens a savepoint for each nested unit the
/// call runs inside that has none on it yet, and opens this call's
/// savepoint.
///
/// A call outside a nested unit whose savepoint is open on the slot runs
/// beside it, and would be undone with it: it is refused instead.
async fn open_call<'s>(
    slot: &'s mut Slot,
    pool: &PgPool,
    depth: u32,
) -> Result<&'s mut PgConnection, sqlx::Error> {
    ensure_nesting(slot.nests, depth)?;
    if slot.transaction.is_none() {
        slot.transaction = Some(pool.begin().await?);
    }
    let previous = slot.call;
    let Some(transaction) = slot.transaction.as_mut() else {
        return Err(sqlx::Error::Protocol(
            "the unit's transaction is gone".to_owned(),
        ));
    };
    if previous == Call::Open {
        settle_call(transaction).await?;
        slot.call = Call::Settled;
    }
    while slot.nests < depth {
        sqlx::query("SAVEPOINT unit_nest")
            .execute(&mut **transaction)
            .await?;
        slot.nests = slot.nests.saturating_add(1);
    }
    sqlx::query("SAVEPOINT unit_call")
        .execute(&mut **transaction)
        .await?;
    slot.call = Call::Open;
    Ok(&mut **transaction)
}

/// Refuses a call whose rollback would be controlled by a sibling nested unit.
fn ensure_nesting(open_depth: u32, depth: u32) -> Result<(), sqlx::Error> {
    if open_depth > depth {
        return Err(sqlx::Error::Protocol(
            "a store call ran beside a nested unit still running in the same unit".to_owned(),
        ));
    }
    Ok(())
}

/// Keeps what the last store call wrote, or, when one of its statements
/// failed, undoes that call alone so the transaction can go on.
async fn settle_call(connection: &mut PgConnection) -> Result<(), sqlx::Error> {
    if sqlx::query("RELEASE SAVEPOINT unit_call")
        .execute(&mut *connection)
        .await
        .is_ok()
    {
        return Ok(());
    }
    sqlx::query("ROLLBACK TO SAVEPOINT unit_call")
        .execute(&mut *connection)
        .await?;
    sqlx::query("RELEASE SAVEPOINT unit_call")
        .execute(connection)
        .await?;
    Ok(())
}

/// Ends, on `slot`, the nested unit at `depth`, when it touched the slot:
/// settles the last store call, then releases the nested unit's savepoint,
/// rolling back to it first when `settlement` drops its writes. Nested
/// units end innermost first, so the savepoint of the latest name is this
/// unit's.
async fn settle_nest(
    slot: &mut Slot,
    depth: u32,
    settlement: Settlement,
) -> Result<(), sqlx::Error> {
    if slot.nests != depth {
        return Ok(());
    }
    let Some(transaction) = slot.transaction.as_mut() else {
        slot.nests = slot.nests.saturating_sub(1);
        return Ok(());
    };
    if slot.call == Call::Open {
        settle_call(transaction).await?;
        slot.call = Call::Settled;
    }
    if settlement == Settlement::Rollback {
        sqlx::query("ROLLBACK TO SAVEPOINT unit_nest")
            .execute(&mut **transaction)
            .await?;
    }
    sqlx::query("RELEASE SAVEPOINT unit_nest")
        .execute(&mut **transaction)
        .await?;
    slot.nests = slot.nests.saturating_sub(1);
    Ok(())
}

/// Commits every transaction in turn. The first that fails rolls back the
/// ones not yet committed.
///
/// One transaction cannot span two databases or two roles, so a unit that
/// wrote to two can be left half committed when the second commit fails.
/// Each database holds its own changes and their outbox rows, so even then
/// no change is kept without its audit record; a purge, written as a role
/// of its own, commits after its record, and a lock after the writes it
/// guards ([`commit_order`]).
async fn commit_all(open: Vec<(SlotKey, SharedSlot)>) -> Result<(), DomainError> {
    let mut remaining = open.into_iter();
    while let Some((_, slot)) = remaining.next() {
        let Slot {
            transaction, call, ..
        } = std::mem::take(&mut *slot.lock().await);
        let Some(transaction) = transaction else {
            continue;
        };
        if let Err(error) = settle_and_commit(transaction, call).await {
            roll_back(remaining.collect()).await;
            return Err(unanswered(error));
        }
    }
    Ok(())
}

/// Settles the last store call, then commits `transaction`.
async fn settle_and_commit(
    mut transaction: Transaction<'static, Postgres>,
    call: Call,
) -> Result<(), sqlx::Error> {
    if call == Call::Open {
        settle_call(&mut transaction).await?;
    }
    transaction.commit().await
}

async fn roll_back(open: Vec<(SlotKey, SharedSlot)>) {
    for (_, slot) in open {
        let Some(transaction) = slot.lock().await.transaction.take() else {
            continue;
        };
        if let Err(error) = transaction.rollback().await {
            tracing::warn!(error = %error, "rolling back a unit of work failed");
        }
    }
}

/// The Postgres unit of work.
#[derive(Debug, Default, Clone, Copy)]
pub struct PgUnitOfWork;

#[async_trait]
impl UnitOfWork for PgUnitOfWork {
    async fn run<'a>(&'a self, work: UnitWork<'a>) -> Result<(), DomainError> {
        if let Ok(running) = UNIT.try_with(Arc::clone) {
            return run_nested(&running, work).await;
        }
        run_alone(work).await
    }

    async fn run_apart<'a>(&'a self, work: UnitWork<'a>) -> Result<(), DomainError> {
        run_alone(work).await
    }
}

/// Runs `work` as a unit of its own, with transactions of its own that it
/// commits or rolls back when it ends, whether or not another unit is
/// running around it. A unit nested in it nests in it, not in the one
/// around.
async fn run_alone(work: UnitWork<'_>) -> Result<(), DomainError> {
    let unit = Arc::new(Unit::default());
    let settlement = UNIT.scope(Arc::clone(&unit), NEST.scope(0, work)).await;
    unit.settle(settlement).await
}

/// Runs `work` nested in the running `unit`: its writes are kept, as the
/// outer unit's, when it settles to commit, and undone alone otherwise.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure`, without running `work`, when
/// another nested unit of the same unit is still running beside this one,
/// and when its savepoints cannot be settled.
async fn run_nested(unit: &Unit, work: UnitWork<'_>) -> Result<(), DomainError> {
    let Some(depth) = unit.enter(current_nest()) else {
        return Err(DomainError::infra_msg(
            "a nested unit was started beside another still running in the same unit",
        ));
    };
    let settlement = NEST.scope(depth, work).await;
    unit.leave(depth, settlement).await
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::runtime::{atomically, atomically_apart};
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::test_support::TestDb;

    /// A test database with a `notes` table under row-level security, as
    /// every tenant table is.
    async fn with_notes() -> TestDb {
        let db = TestDb::fresh().await;
        db.tamper(
            "CREATE TABLE notes (id uuid PRIMARY KEY, tenant_id uuid NOT NULL, body text NOT NULL);
             ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
             ALTER TABLE notes FORCE ROW LEVEL SECURITY;
             CREATE POLICY tenant_rows ON notes
                 USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
                        OR current_setting('app.platform_scope', true) = 'on')
                 WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
                        OR current_setting('app.platform_scope', true) = 'on');
             GRANT SELECT, INSERT, UPDATE, DELETE ON notes TO ianua_app;",
        )
        .await;
        db
    }

    async fn write(db: &TestDb, tenant: TenantId, body: &str) -> Result<(), DomainError> {
        let body = body.to_owned();
        scoped(
            &db.databases,
            RowScope::Tenant(tenant),
            async move |connection| {
                sqlx::query("INSERT INTO notes (id, tenant_id, body) VALUES ($1, $2, $3)")
                    .bind(uuid_now())
                    .bind(tenant.as_uuid())
                    .bind(&body)
                    .execute(connection)
                    .await
                    .map(|_| ())
            },
        )
        .await
    }

    async fn bodies(db: &TestDb, scope: RowScope) -> Vec<String> {
        scoped(&db.databases, scope, async |connection| {
            sqlx::query_scalar("SELECT body FROM notes ORDER BY body")
                .fetch_all(connection)
                .await
        })
        .await
        .expect("the notes read")
    }

    fn uuid_now() -> uuid::Uuid {
        *TenantId::new().as_uuid()
    }

    /// The purge transaction follows the app transaction in commit order,
    /// keeping deletion behind the transaction that records it.
    #[test]
    fn the_purges_transactions_commit_last() {
        let open = vec![
            (
                (Login::AuditPurge, Database::Platform),
                SharedSlot::default(),
            ),
            ((Login::App, Database::Platform), SharedSlot::default()),
        ];

        let order: Vec<Login> = commit_order(open, &[])
            .into_iter()
            .map(|((login, _), _)| login)
            .collect();

        assert_eq!(order, [Login::App, Login::AuditPurge]);
    }

    /// A dedicated database's write commits before the platform transaction
    /// holding its lock; the purge transaction still comes last.
    #[test]
    fn a_lock_commits_after_the_writes_it_guards() {
        let acme = Database::Dedicated(TenantId::new());
        let lock = (Login::App, Database::Platform);
        let open = vec![
            (lock, SharedSlot::default()),
            (
                (Login::AuditPurge, Database::Platform),
                SharedSlot::default(),
            ),
            ((Login::App, acme), SharedSlot::default()),
        ];

        let order: Vec<SlotKey> = commit_order(open, &[lock])
            .into_iter()
            .map(|(key, _)| key)
            .collect();

        assert_eq!(
            order,
            [
                (Login::App, acme),
                lock,
                (Login::AuditPurge, Database::Platform)
            ]
        );
    }

    /// A waiter taking the platform lock reads the guarded write from the
    /// tenant's dedicated database after the writer commits.
    #[tokio::test]
    async fn a_waiter_on_a_lock_sees_the_write_it_guards() {
        let platform = with_notes().await;
        let own = with_notes().await;
        let acme = TenantId::new();
        platform.databases.register(acme, own.as_dedicated());
        let (taken, wait_for_take) = tokio::sync::oneshot::channel::<()>();

        let waiter = spawn_lock_waiter(Arc::clone(&platform.databases), acme, wait_for_take);
        atomically(
            &PgUnitOfWork,
            async {
                scoped_holding(
                    &platform.databases,
                    RowScope::Platform,
                    async |connection| take_test_lock(connection).await,
                )
                .await
                .expect("the unit takes the lock");
                taken.send(()).expect("the waiter listens");
                tokio::time::sleep(Duration::from_millis(50)).await;
                write(&platform, acme, "guarded").await.expect("the write");
            },
            |()| Settlement::Commit,
        )
        .await
        .expect("the unit commits");

        let seen = waiter.await.expect("the waiter finishes");

        assert_eq!(seen, ["guarded"]);
    }

    /// Starts a reader that waits for the writer's lock before reading guarded rows.
    fn spawn_lock_waiter(
        databases: Arc<Databases>,
        tenant: TenantId,
        wait_for_take: tokio::sync::oneshot::Receiver<()>,
    ) -> tokio::task::JoinHandle<Vec<String>> {
        tokio::spawn(async move {
            wait_for_take.await.expect("the lock was taken");
            scoped_holding(&databases, RowScope::Platform, async |connection| {
                take_test_lock(connection).await
            })
            .await
            .expect("the waiter takes the lock");
            scoped(&databases, RowScope::Tenant(tenant), async |connection| {
                sqlx::query_scalar::<_, String>("SELECT body FROM notes")
                    .fetch_all(connection)
                    .await
            })
            .await
            .expect("the waiter reads")
        })
    }

    /// Takes the test's transaction-level lock, waiting while another
    /// transaction holds it.
    async fn take_test_lock(connection: &mut PgConnection) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT pg_advisory_xact_lock(424242)")
            .execute(connection)
            .await
            .map(|_| ())
    }

    /// Ann saves a note and the record of it in one unit: both are kept.
    #[tokio::test]
    async fn a_committed_unit_keeps_every_write() {
        let db = with_notes().await;
        let tenant = TenantId::new();

        atomically(
            &PgUnitOfWork,
            async {
                write(&db, tenant, "first").await.expect("the first write");
                write(&db, tenant, "second")
                    .await
                    .expect("the second write");
            },
            |()| Settlement::Commit,
        )
        .await
        .expect("the unit commits");

        assert_eq!(
            bodies(&db, RowScope::Tenant(tenant)).await,
            ["first", "second"]
        );
    }

    /// A request's unit starts a rule's run apart and waits on a worker to
    /// see it. Another connection sees the run while the request still
    /// runs, and the run stays though the request rolls back.
    #[tokio::test]
    async fn work_run_apart_is_seen_at_once_and_outlives_the_unit_around_it() {
        let db = with_notes().await;
        let tenant = TenantId::new();
        let databases = Arc::clone(&db.databases);

        let seen_meanwhile = atomically(
            &PgUnitOfWork,
            async {
                write(&db, tenant, "request")
                    .await
                    .expect("the request's write");
                atomically_apart(
                    &PgUnitOfWork,
                    async {
                        write(&db, tenant, "rule run")
                            .await
                            .expect("the run's write")
                    },
                    |()| Settlement::Commit,
                )
                .await
                .expect("the run is kept");
                seen_elsewhere(databases, tenant).await
            },
            |_| Settlement::Rollback,
        )
        .await
        .expect("the request rolls back");

        assert_eq!(seen_meanwhile, ["rule run"]);
        assert_eq!(bodies(&db, RowScope::Tenant(tenant)).await, ["rule run"]);
    }

    /// The notes `tenant` has, as a connection outside any running unit
    /// reads them.
    async fn seen_elsewhere(databases: Arc<Databases>, tenant: TenantId) -> Vec<String> {
        tokio::spawn(async move {
            scoped(&databases, RowScope::Tenant(tenant), async |connection| {
                sqlx::query_scalar::<_, String>("SELECT body FROM notes ORDER BY body")
                    .fetch_all(connection)
                    .await
            })
            .await
        })
        .await
        .expect("the other connection reads")
        .expect("the notes read")
    }

    /// Rolling back a unit removes the note it wrote.
    #[tokio::test]
    async fn a_rolled_back_unit_keeps_nothing() {
        let db = with_notes().await;
        let tenant = TenantId::new();

        atomically(
            &PgUnitOfWork,
            async {
                write(&db, tenant, "first").await.expect("the first write");
            },
            |()| Settlement::Rollback,
        )
        .await
        .expect("the unit rolls back");

        assert!(bodies(&db, RowScope::Tenant(tenant)).await.is_empty());
    }

    /// One refused write, such as a name already taken, is undone alone:
    /// the use case reports it, and the unit's other writes are kept.
    #[tokio::test]
    async fn a_failed_call_is_undone_alone() {
        let db = with_notes().await;
        let tenant = TenantId::new();
        let other = TenantId::new();

        atomically(
            &PgUnitOfWork,
            async {
                write(&db, tenant, "kept").await.expect("the first write");
                let refused = write_as(&db, tenant, other, "another tenant's row").await;
                assert!(
                    refused.is_err(),
                    "row-level security refuses another tenant's row"
                );
                write(&db, tenant, "also kept")
                    .await
                    .expect("the unit goes on");
            },
            |()| Settlement::Commit,
        )
        .await
        .expect("the unit commits");

        assert_eq!(
            bodies(&db, RowScope::Tenant(tenant)).await,
            ["also kept", "kept"]
        );
    }

    /// What a nested unit's work settles to: kept when it succeeded, undone
    /// on any error, as the app's helper for keeping work together does.
    fn kept_when_done(outcome: &Result<(), DomainError>) -> Settlement {
        match outcome {
            Ok(()) => Settlement::Commit,
            Err(_) => Settlement::Rollback,
        }
    }

    /// Writes `body` in `tenant`, then refuses the work as a conflict, the
    /// way a use case answers a request decided meanwhile.
    async fn written_then_refused(
        db: &TestDb,
        tenant: TenantId,
        body: &str,
    ) -> Result<(), DomainError> {
        write(db, tenant, body).await?;
        Err(DomainError::conflict("the request was decided meanwhile"))
    }

    /// A conflict rolls back the nested unit's note while the outer unit
    /// commits the notes written before and after it.
    #[tokio::test]
    async fn a_nested_unit_that_returns_a_conflict_leaves_nothing() {
        let db = with_notes().await;
        let tenant = TenantId::new();

        atomically(
            &PgUnitOfWork,
            async {
                write(&db, tenant, "before").await.expect("the outer write");
                let refused = atomically(
                    &PgUnitOfWork,
                    written_then_refused(&db, tenant, "half"),
                    kept_when_done,
                )
                .await
                .expect("the nested unit settles");
                assert!(matches!(refused, Err(DomainError::Conflict(_))));
                write(&db, tenant, "after")
                    .await
                    .expect("the outer goes on");
            },
            |()| Settlement::Commit,
        )
        .await
        .expect("the unit commits");

        assert_eq!(
            bodies(&db, RowScope::Tenant(tenant)).await,
            ["after", "before"]
        );
    }

    /// A nested unit that succeeds keeps its writes in the outer unit, and
    /// they are committed with it.
    #[tokio::test]
    async fn a_nested_unit_that_succeeds_is_kept_with_the_outer() {
        let db = with_notes().await;
        let tenant = TenantId::new();

        atomically(
            &PgUnitOfWork,
            async {
                atomically(&PgUnitOfWork, write(&db, tenant, "nested"), kept_when_done)
                    .await
                    .expect("the nested unit settles")
                    .expect("the nested write");
            },
            |()| Settlement::Commit,
        )
        .await
        .expect("the unit commits");

        assert_eq!(bodies(&db, RowScope::Tenant(tenant)).await, ["nested"]);
    }

    /// An inner rollback leaves the middle unit's note intact; a middle
    /// rollback also removes the successful inner unit's note.
    #[tokio::test]
    async fn units_nested_twice_keep_or_drop_their_own_writes() {
        let db = with_notes().await;
        let tenant = TenantId::new();

        atomically(
            &PgUnitOfWork,
            async {
                let kept = atomically(
                    &PgUnitOfWork,
                    keep_middle_drop_inner(&db, tenant),
                    kept_when_done,
                )
                .await
                .expect("the middle unit settles");
                assert!(kept.is_ok());
                let dropped = atomically(
                    &PgUnitOfWork,
                    drop_middle_keep_inner(&db, tenant),
                    kept_when_done,
                )
                .await
                .expect("the middle unit settles");
                assert!(dropped.is_err());
            },
            |()| Settlement::Commit,
        )
        .await
        .expect("the unit commits");

        assert_eq!(bodies(&db, RowScope::Tenant(tenant)).await, ["middle kept"]);
    }

    /// Writes a middle unit's note and proves an inner unit's refusal reaches it.
    async fn keep_middle_drop_inner(db: &TestDb, tenant: TenantId) -> Result<(), DomainError> {
        write(db, tenant, "middle kept").await?;
        let inner = atomically(
            &PgUnitOfWork,
            written_then_refused(db, tenant, "inner dropped"),
            kept_when_done,
        )
        .await?;
        assert!(inner.is_err());
        Ok(())
    }

    /// Commits an inner unit's write into its parent, then refuses the parent's work.
    async fn drop_middle_keep_inner(db: &TestDb, tenant: TenantId) -> Result<(), DomainError> {
        atomically(
            &PgUnitOfWork,
            write(db, tenant, "inner of dropped"),
            kept_when_done,
        )
        .await??;
        written_then_refused(db, tenant, "middle dropped").await
    }

    /// Writes `body` in `tenant`, then lets anything else on the task run
    /// before the work ends, as a unit waiting on the network would.
    async fn written_then_waiting(
        db: &TestDb,
        tenant: TenantId,
        body: &str,
    ) -> Result<(), DomainError> {
        write(db, tenant, body).await?;
        tokio::task::yield_now().await;
        Ok(())
    }

    /// Of two nested units joined side by side, the second is refused as an
    /// infrastructure error and only the first unit's note is committed.
    #[tokio::test]
    async fn a_nested_unit_beside_another_still_running_is_refused() {
        let db = with_notes().await;
        let tenant = TenantId::new();

        atomically(
            &PgUnitOfWork,
            async {
                let (first, second) = tokio::join!(
                    atomically(
                        &PgUnitOfWork,
                        written_then_waiting(&db, tenant, "first"),
                        kept_when_done,
                    ),
                    atomically(&PgUnitOfWork, write(&db, tenant, "second"), kept_when_done,),
                );
                assert!(matches!(first, Ok(Ok(()))));
                assert!(matches!(second, Err(DomainError::Infrastructure(_))));
            },
            |()| Settlement::Commit,
        )
        .await
        .expect("the unit commits");

        assert_eq!(bodies(&db, RowScope::Tenant(tenant)).await, ["first"]);
    }

    /// A store call beside a running nested unit is refused; when the
    /// nested unit then rolls back, neither note remains.
    #[tokio::test]
    async fn a_store_call_beside_a_running_nested_unit_is_refused() {
        let db = with_notes().await;
        let tenant = TenantId::new();

        atomically(
            &PgUnitOfWork,
            async {
                let (nested, beside) = tokio::join!(
                    atomically(
                        &PgUnitOfWork,
                        async {
                            written_then_waiting(&db, tenant, "nested").await?;
                            Err::<(), DomainError>(DomainError::conflict("decided meanwhile"))
                        },
                        kept_when_done,
                    ),
                    write(&db, tenant, "beside"),
                );
                assert!(matches!(nested, Ok(Err(DomainError::Conflict(_)))));
                assert!(matches!(beside, Err(DomainError::Infrastructure(_))));
            },
            |()| Settlement::Commit,
        )
        .await
        .expect("the unit commits");

        assert!(bodies(&db, RowScope::Tenant(tenant)).await.is_empty());
    }

    /// A nested rollback removes its write even when it opened the dedicated
    /// database transaction; the outer unit's platform write remains.
    #[tokio::test]
    async fn a_transaction_opened_inside_a_nested_unit_is_undone_with_it() {
        let platform = with_notes().await;
        let own = with_notes().await;
        let (acme, globex) = (TenantId::new(), TenantId::new());
        platform.databases.register(acme, own.as_dedicated());

        atomically(
            &PgUnitOfWork,
            async {
                write(&platform, globex, "globex kept")
                    .await
                    .expect("the outer write");
                let refused = atomically(
                    &PgUnitOfWork,
                    written_then_refused(&platform, acme, "acme dropped"),
                    kept_when_done,
                )
                .await
                .expect("the nested unit settles");
                assert!(refused.is_err());
            },
            |()| Settlement::Commit,
        )
        .await
        .expect("the unit commits");

        assert!(bodies(&own, RowScope::Platform).await.is_empty());
        assert_eq!(bodies(&platform, RowScope::Platform).await, ["globex kept"]);
    }

    /// Writes a row for `row_tenant` while scoped to `scope_tenant`.
    async fn write_as(
        db: &TestDb,
        scope_tenant: TenantId,
        row_tenant: TenantId,
        body: &str,
    ) -> Result<(), DomainError> {
        let body = body.to_owned();
        scoped(
            &db.databases,
            RowScope::Tenant(scope_tenant),
            async move |connection| {
                sqlx::query("INSERT INTO notes (id, tenant_id, body) VALUES ($1, $2, $3)")
                    .bind(uuid_now())
                    .bind(row_tenant.as_uuid())
                    .bind(&body)
                    .execute(connection)
                    .await
                    .map(|_| ())
            },
        )
        .await
    }

    /// A store call outside any unit commits on its own.
    #[tokio::test]
    async fn a_call_outside_a_unit_commits_alone() {
        let db = with_notes().await;
        let tenant = TenantId::new();

        write(&db, tenant, "alone").await.expect("the write");

        assert_eq!(bodies(&db, RowScope::Tenant(tenant)).await, ["alone"]);
    }

    /// Acme and Globex each read only their own notes. Platform scope reads
    /// both tenants' notes, while unscoped access reads neither.
    #[tokio::test]
    async fn each_scope_sees_only_its_rows() {
        let db = with_notes().await;
        let (acme, globex) = (TenantId::new(), TenantId::new());
        write(&db, acme, "acme").await.expect("acme writes");
        write(&db, globex, "globex").await.expect("globex writes");

        assert_eq!(bodies(&db, RowScope::Tenant(acme)).await, ["acme"]);
        assert_eq!(bodies(&db, RowScope::Tenant(globex)).await, ["globex"]);
        assert_eq!(bodies(&db, RowScope::Platform).await, ["acme", "globex"]);
        assert!(bodies(&db, RowScope::Unscoped).await.is_empty());
    }

    /// Acme's notes go only to its registered dedicated database; after
    /// deregistration, its next note joins Globex's in the platform database.
    #[tokio::test]
    async fn a_tenant_with_its_own_database_keeps_its_rows_there() {
        let platform = with_notes().await;
        let own = with_notes().await;
        let (acme, globex) = (TenantId::new(), TenantId::new());
        platform.databases.register(acme, own.as_dedicated());

        write(&platform, acme, "acme's own")
            .await
            .expect("acme writes");
        write(&platform, globex, "globex shared")
            .await
            .expect("globex writes");
        platform.databases.deregister(&acme);
        write(&platform, acme, "acme moved back")
            .await
            .expect("acme writes again");

        assert_eq!(bodies(&own, RowScope::Platform).await, ["acme's own"]);
        assert_eq!(
            bodies(&platform, RowScope::Platform).await,
            ["acme moved back", "globex shared"]
        );
    }
}
