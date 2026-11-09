//! A tenant's audit trail handed between the platform's tables and the
//! tenant's own schema, in the caller's transaction, under the tenant's
//! purge lock and then its chain lock, so no record is added or purged
//! between the copy and what follows it.
//!
//! When a tenant gets its schema, its trail so far is copied in, so the
//! chain goes on there from the record it ended on; the platform keeps its
//! copy, which nothing reads or purges while the tenant lives apart. A
//! copy run again brings back no record older than the schema's anchor.
//! When
//! the tenant leaves its schema, the trail comes back in two steps. First,
//! when the schema's retention purged further than the platform's copy
//! reaches, the platform's older records go too and its anchor moves with
//! it ([`follow_anchor`]); only the audit purge's role may remove a record,
//! so this step runs as that role. Then, as the app's role, records and
//! outbox entries are added where missing and the newer head and verdict
//! win ([`merge`]), which is refused while the schema's anchor is still
//! ahead of the platform's, so the chain always verifies from its anchor.
//! Each step run again adds nothing.
//!
//! Both sides come from the same migrations, so a row is copied whole, with
//! every column a later migration adds.

use sqlx::postgres::PgRow;
use sqlx::{PgConnection, Row as _};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::audit_chain;
use crate::postgres::foundation::tenant_databases::schemas::TenantSchema;

/// Copies `tenant`'s trail from the platform's tables into `schema`. Run
/// again after the schema's retention purged, it copies none of the
/// records the purge removed back in.
pub(crate) async fn adopt(
    connection: &mut PgConnection,
    tenant: Uuid,
    schema: &TenantSchema,
) -> Result<(), sqlx::Error> {
    audit_chain::lock_purges(&mut *connection, tenant).await?;
    audit_chain::lock(&mut *connection, tenant).await?;
    for statement in adoptions(&schema.quoted()) {
        sqlx::query(&statement)
            .bind(tenant)
            .execute(&mut *connection)
            .await?;
    }
    Ok(())
}

/// The statements that copy a trail into the schema `quoted`, each binding
/// the tenant as `$1`. The anchor goes first, the schema's own kept when it
/// has one, and only records after it follow, so the records a purge in
/// the schema removed never come back from the platform's older copy.
fn adoptions(quoted: &str) -> [String; 3] {
    [
        format!(
            "INSERT INTO {quoted}.audit_chain_anchors SELECT * FROM public.audit_chain_anchors \
             WHERE tenant_id = $1 ON CONFLICT DO NOTHING"
        ),
        format!(
            "INSERT INTO {quoted}.audit_records SELECT * FROM public.audit_records r \
             WHERE r.tenant_id = $1 AND r.seq > coalesce( \
                 (SELECT a.seq FROM {quoted}.audit_chain_anchors a WHERE a.tenant_id = $1), 0) \
             ON CONFLICT DO NOTHING"
        ),
        format!(
            "INSERT INTO {quoted}.audit_chain_heads SELECT * FROM public.audit_chain_heads \
             WHERE tenant_id = $1 ON CONFLICT DO NOTHING"
        ),
    ]
}

/// Brings `tenant`'s trail back from `schema` into the platform's tables,
/// as the app's role, once [`follow_anchor`] moved the platform's anchor as
/// far as the schema's. A schema already gone has nothing to bring.
pub(crate) async fn merge(
    connection: &mut PgConnection,
    tenant: Uuid,
    schema: &TenantSchema,
) -> Result<(), sqlx::Error> {
    if !exists(&mut *connection, schema).await? {
        return Ok(());
    }
    let quoted = schema.quoted();
    audit_chain::lock_purges(&mut *connection, tenant).await?;
    audit_chain::lock(&mut *connection, tenant).await?;
    ensure_anchor_followed(&mut *connection, tenant, &quoted).await?;
    for statement in merges(&quoted) {
        sqlx::query(&statement)
            .bind(tenant)
            .execute(&mut *connection)
            .await?;
    }
    Ok(())
}

/// When `schema`'s retention purged further than the platform's copy of
/// `tenant`'s trail reaches, removes the platform's records up to the
/// schema's anchor and moves the platform's anchor there. Runs as the audit
/// purge's role, scoped to `tenant`. A schema already gone, or never
/// purged, has nothing to follow.
pub(crate) async fn follow_anchor(
    connection: &mut PgConnection,
    tenant: Uuid,
    schema: &TenantSchema,
) -> Result<(), sqlx::Error> {
    if !exists(&mut *connection, schema).await? {
        return Ok(());
    }
    audit_chain::lock_purges(&mut *connection, tenant).await?;
    let read = format!(
        "SELECT seq, entry_hash, purged_before, seal FROM {}.audit_chain_anchors \
         WHERE tenant_id = $1",
        schema.quoted()
    );
    let Some(anchor) = sqlx::query(&read)
        .bind(tenant)
        .fetch_optional(&mut *connection)
        .await?
    else {
        return Ok(());
    };
    advance_anchor(connection, tenant, &anchor).await
}

/// Whether `schema` is still there.
async fn exists(connection: &mut PgConnection, schema: &TenantSchema) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT to_regnamespace($1) IS NOT NULL")
        .bind(schema.name())
        .fetch_one(connection)
        .await
}

/// Refuses the merge while `quoted`'s anchor of `tenant`'s chain is ahead
/// of the platform's: the schema purged records since [`follow_anchor`]
/// ran, and merging now would leave a gap at the start of the platform's
/// chain. The step runs again from [`follow_anchor`].
async fn ensure_anchor_followed(
    connection: &mut PgConnection,
    tenant: Uuid,
    quoted: &str,
) -> Result<(), sqlx::Error> {
    let ahead = format!(
        "SELECT coalesce((SELECT seq FROM {quoted}.audit_chain_anchors WHERE tenant_id = $1), 0) \
         > coalesce((SELECT seq FROM public.audit_chain_anchors WHERE tenant_id = $1), 0)"
    );
    let ahead: bool = sqlx::query_scalar(&ahead)
        .bind(tenant)
        .fetch_one(connection)
        .await?;
    if !ahead {
        return Ok(());
    }
    Err(sqlx::Error::InvalidArgument(
        "the schema purged further than the platform's copy reaches; its anchor is followed first"
            .to_owned(),
    ))
}

/// Removes the platform's records of `tenant` up to the schema's `anchor`,
/// and moves the platform's anchor there unless it is further already.
async fn advance_anchor(
    connection: &mut PgConnection,
    tenant: Uuid,
    anchor: &PgRow,
) -> Result<(), sqlx::Error> {
    let seq: i64 = anchor.try_get("seq")?;
    let hash: Vec<u8> = anchor.try_get("entry_hash")?;
    let cutoff: OffsetDateTime = anchor.try_get("purged_before")?;
    let seal: Vec<u8> = anchor.try_get("seal")?;
    sqlx::query("DELETE FROM public.audit_records WHERE tenant_id = $1 AND seq <= $2")
        .bind(tenant)
        .bind(seq)
        .execute(&mut *connection)
        .await?;
    sqlx::query(
        "INSERT INTO public.audit_chain_anchors \
         (tenant_id, seq, entry_hash, purged_before, seal) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (tenant_id) DO UPDATE SET seq = EXCLUDED.seq, \
         entry_hash = EXCLUDED.entry_hash, purged_before = EXCLUDED.purged_before, \
         seal = EXCLUDED.seal \
         WHERE audit_chain_anchors.seq < EXCLUDED.seq",
    )
    .bind(tenant)
    .bind(seq)
    .bind(hash)
    .bind(cutoff)
    .bind(seal)
    .execute(connection)
    .await?;
    Ok(())
}

/// The statements that bring the rest of the trail back, each binding the
/// tenant as `$1`.
fn merges(quoted: &str) -> [String; 4] {
    [
        format!(
            "INSERT INTO public.audit_records SELECT * FROM {quoted}.audit_records \
             WHERE tenant_id = $1 ON CONFLICT DO NOTHING"
        ),
        format!(
            "INSERT INTO public.event_outbox SELECT * FROM {quoted}.event_outbox \
             WHERE tenant_id = $1 ON CONFLICT DO NOTHING"
        ),
        format!(
            "INSERT INTO public.audit_chain_heads SELECT * FROM {quoted}.audit_chain_heads \
             WHERE tenant_id = $1 \
             ON CONFLICT (tenant_id) DO UPDATE SET seq = EXCLUDED.seq, \
             entry_hash = EXCLUDED.entry_hash, seal = EXCLUDED.seal \
             WHERE audit_chain_heads.seq < EXCLUDED.seq"
        ),
        format!(
            "INSERT INTO public.audit_chain_verdicts SELECT * FROM {quoted}.audit_chain_verdicts \
             WHERE tenant_id = $1 \
             ON CONFLICT (tenant_id) DO UPDATE SET verified_at = EXCLUDED.verified_at, \
             standing = EXCLUDED.standing, broken_at_seq = EXCLUDED.broken_at_seq, \
             checkpoint_seq = EXCLUDED.checkpoint_seq, checkpoint_hash = EXCLUDED.checkpoint_hash \
             WHERE audit_chain_verdicts.verified_at < EXCLUDED.verified_at"
        ),
    ]
}
