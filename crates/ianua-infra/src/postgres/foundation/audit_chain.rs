//! What keeps a tenant's audit chain whole while it is written: the lock
//! every writer of a tenant's chain takes, the lock every purge of it
//! takes, and the seals on its anchor and verdict.
//!
//! Both locks are transaction-level advisory locks under a key made from
//! the tenant alone, the same in every database, held until the
//! transaction ends. The chain lock keeps two appends from linking to the
//! same record. The purge lock keeps two purges, and a purge and a move of
//! the trail, from removing or copying one stretch at once. An append and
//! a purge touch other rows, the newest and the oldest, so they do not
//! wait for each other: a purge runs in one unit with the record of it,
//! which takes the chain lock on another connection, and one lock for both
//! would leave that unit waiting on itself. Whoever takes both takes the
//! purge lock first.
//!
//! Only the audit purge's role may remove an audit record
//! (postgres/foundation/roles.rs); the app's role holds no delete on the
//! table at all. Against whoever holds the purge's role the chain's anchor
//! and the sweep's verdict are sealed here, each under a key of its own, so
//! neither can be moved past records removed unseen.
//!
//! A head's, an anchor's and a verdict's seals are made under three keys
//! derived for those uses alone ([`AuditChainSeals`]), so no seal of one
//! kind is ever one of another, and a head's seal copied into the anchor
//! does not hold there.

use sha2::{Digest as _, Sha256};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::crypto::{AuditChainSeals, ChainLink};

/// What the lock key is made from, before the tenant: no other lock of the
/// platform is made the same way.
const KEY_PREFIX: &[u8] = b"ianua.audit_chain:";

/// What the purge lock key is made from, before the tenant.
const PURGE_KEY_PREFIX: &[u8] = b"ianua.audit_chain.purge:";

/// The seal on `tenant`'s anchor at `seq` with `hash`.
pub(crate) fn anchor_seal(
    seals: &AuditChainSeals,
    tenant: Uuid,
    seq: i64,
    hash: &[u8],
) -> [u8; 32] {
    seals.anchor_seal(&tenant, seq, hash)
}

/// Whether `seal` authenticates the tenant's retained anchor link.
pub(crate) fn anchor_holds(
    seals: &AuditChainSeals,
    tenant: Uuid,
    link: ChainLink<'_>,
    seal: &[u8],
) -> bool {
    seals.anchor_holds(&tenant, link, seal)
}

/// The seal on `tenant`'s verdict whose columns, written out, are `parts`.
pub(crate) fn verdict_seal(seals: &AuditChainSeals, tenant: Uuid, parts: &[&[u8]]) -> [u8; 32] {
    seals.verdict_seal(&tenant, &parts.concat())
}

/// Whether `seal` is the seal on `tenant`'s verdict whose columns, written
/// out, are `parts`.
pub(crate) fn verdict_holds(
    seals: &AuditChainSeals,
    tenant: Uuid,
    parts: &[&[u8]],
    seal: &[u8],
) -> bool {
    seals.verdict_holds(&tenant, &parts.concat(), seal)
}

/// The advisory lock key under `prefix` of `tenant`'s chain: the first
/// eight bytes of a digest of the tenant, so tenants spread over the whole
/// key space.
fn key_of(prefix: &[u8], tenant: Uuid) -> i64 {
    let digest = Sha256::new()
        .chain_update(prefix)
        .chain_update(tenant.as_bytes())
        .finalize();
    let mut key = [0_u8; 8];
    for (to, from) in key.iter_mut().zip(digest.iter()) {
        *to = *from;
    }
    i64::from_be_bytes(key)
}

/// Takes `tenant`'s chain lock for the running transaction, waiting while
/// another writer holds it.
pub(crate) async fn lock(connection: &mut PgConnection, tenant: Uuid) -> Result<(), sqlx::Error> {
    lock_key(connection, key_of(KEY_PREFIX, tenant)).await
}

/// Takes `tenant`'s purge lock for the running transaction, waiting while
/// another purge or a move of the trail holds it.
pub(crate) async fn lock_purges(
    connection: &mut PgConnection,
    tenant: Uuid,
) -> Result<(), sqlx::Error> {
    lock_key(connection, key_of(PURGE_KEY_PREFIX, tenant)).await
}

/// Takes the advisory lock `key` for the running transaction.
async fn lock_key(connection: &mut PgConnection, key: i64) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(key)
        .execute(connection)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::rows::audit::chain_heads;

    /// Each tenant's chain has a lock of its own, the same every time, and
    /// a purge lock apart from it.
    #[test]
    fn each_tenant_has_locks_of_its_own() {
        let acme = Uuid::now_v7();
        let globex = Uuid::now_v7();

        assert_eq!(key_of(KEY_PREFIX, acme), key_of(KEY_PREFIX, acme));
        assert_ne!(key_of(KEY_PREFIX, acme), key_of(KEY_PREFIX, globex));
        assert_ne!(key_of(KEY_PREFIX, acme), key_of(PURGE_KEY_PREFIX, acme));
    }

    /// An anchor's seal verifies only for its tenant and purpose; a head's
    /// seal cannot replace it, and it cannot serve as a verdict's seal.
    #[test]
    fn a_seal_of_one_kind_never_holds_as_another() {
        let seals = chain_heads();
        let tenant = Uuid::now_v7();
        let hash = [7_u8; 32];

        let head = seals.head_seal(&tenant, 3, &hash);
        let anchor = anchor_seal(&seals, tenant, 3, &hash);
        let link = ChainLink {
            seq: 3,
            hash: &hash,
        };

        assert!(anchor_holds(&seals, tenant, link, &anchor));
        assert!(!anchor_holds(&seals, tenant, link, &head));
        assert!(!anchor_holds(&seals, Uuid::now_v7(), link, &anchor));
        assert!(!verdict_holds(&seals, tenant, &[&hash], &anchor));
    }
}
