//! The walk of a tenant's audit chain: a bounded stretch rehashed record
//! by record, and at the chain's end its sealed head checked.
//!
//! Each record must sit at the next place, name the link before it as its
//! `prev_hash`, and hash, with that link, to its own `entry_hash`. A record
//! removed, reordered or changed breaks the walk there. When no record
//! follows, the head must be sealed by the platform and name the last link,
//! so records cut off the chain's end are a break too. A walk from a
//! checkpoint a retention purge has since passed starts from the anchor the
//! purge left, when the platform sealed it: an anchor whose seal does not
//! hold is no anchor, so records removed in front of it break the walk.

mod record;

use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::audit::AuditChainVerifier;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::audit::checkpoint::{ChainCheckpoint, ChainHash, ChainStart};
use ianua_domain::domains::audit::walk::ChainStretch;
use ianua_domain::shared::errors::DomainError;
use sqlx::PgConnection;
use uuid::Uuid;

use self::record::{AnchorRecord, HeadRecord, LinkRecord, StretchRecord};
use crate::crypto::{AuditChainSeals, ChainLink};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The longest a walk may read before it is given up.
const READ_AT_MOST: Duration = Duration::from_secs(5);

/// The link before the first record of a chain.
const GENESIS: [u8; 32] = [0; 32];

/// What one walk reads: where it starts, the stretch after it, and the
/// sealed head when nothing follows.
struct Read {
    start: LinkRecord,
    stretch: Vec<StretchRecord>,
    head: Option<HeadRecord>,
}

/// Where a walk from `start` begins: the checkpoint, unless a purge left
/// an anchor past it, or the chain's very start.
fn start_link(start: &ChainStart, anchor: Option<LinkRecord>) -> LinkRecord {
    let from_checkpoint = match start {
        ChainStart::Genesis => LinkRecord {
            seq: 0,
            entry_hash: GENESIS.to_vec(),
        },
        ChainStart::After(checkpoint) => LinkRecord {
            seq: checkpoint.seq(),
            entry_hash: checkpoint.hash().as_bytes().to_vec(),
        },
    };
    match anchor {
        Some(anchor) if anchor.seq > from_checkpoint.seq => anchor,
        Some(_) | None => from_checkpoint,
    }
}

/// What `read` says of `tenant_id`'s chain: intact so far, ended at its
/// sealed head, or broken at the first record that does not hold.
fn walked(
    tenant_id: Uuid,
    read: Read,
    heads: &AuditChainSeals,
) -> Result<ChainStretch, DomainError> {
    let Read {
        start,
        stretch,
        head,
    } = read;
    let mut link = start;
    let mut checked: u64 = 0;
    for record in stretch {
        let place = link.seq.saturating_add(1);
        let Some(next) = record.into_link_after(&link, tenant_id) else {
            return Ok(ChainStretch::Broken {
                checked,
                at_seq: place,
            });
        };
        checked = checked.saturating_add(1);
        link = next;
    }
    if checked > 0 {
        let last =
            ChainCheckpoint::from_stored(link.seq, ChainHash::from_stored(&link.entry_hash)?)?;
        return Ok(ChainStretch::Intact { checked, last });
    }
    Ok(at_end(tenant_id, &link, head.as_ref(), heads))
}

/// What the chain's end says once no record follows `link`.
fn at_end(
    tenant_id: Uuid,
    link: &LinkRecord,
    head: Option<&HeadRecord>,
    heads: &AuditChainSeals,
) -> ChainStretch {
    let ended = match head {
        None => link.seq == 0,
        Some(head) => {
            let sealed = ChainLink {
                seq: head.seq,
                hash: &head.entry_hash,
            };
            head.seq == link.seq
                && head.entry_hash == link.entry_hash
                && heads.head_holds(&tenant_id, sealed, &head.seal)
        }
    };
    if ended {
        return ChainStretch::Ended;
    }
    ChainStretch::Broken {
        checked: 0,
        at_seq: link.seq.saturating_add(1),
    }
}

/// Resolves the checkpoint against the tenant's authenticated retention anchor.
async fn read_start(
    connection: &mut PgConnection,
    tenant: Uuid,
    start: &ChainStart,
    heads: &AuditChainSeals,
) -> Result<LinkRecord, sqlx::Error> {
    let anchor = sqlx::query_file_as!(
        AnchorRecord,
        "queries/audit_chain_anchors/of_tenant.sql",
        tenant
    )
    .fetch_optional(connection)
    .await?;
    let sealed = anchor.and_then(|held| held.into_sealed_link(tenant, heads));
    Ok(start_link(start, sealed))
}

/// Reads only the bounded records after the resolved starting link.
async fn read_stretch(
    connection: &mut PgConnection,
    tenant: Uuid,
    start: &LinkRecord,
    limit: NonZeroU32,
) -> Result<Vec<StretchRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        StretchRecord,
        "queries/audit_records/stretch.sql",
        tenant,
        start.seq,
        i64::from(limit.get())
    )
    .fetch_all(connection)
    .await
}

/// Loads the sealed head only after the walk reaches the end of its records.
async fn read_head(
    connection: &mut PgConnection,
    tenant: Uuid,
) -> Result<Option<HeadRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        HeadRecord,
        "queries/audit_chain_heads/of_tenant.sql",
        tenant
    )
    .fetch_optional(connection)
    .await
}

/// The Postgres walk of a tenant's audit chain.
pub struct PgAuditChainVerifier {
    databases: Arc<Databases>,
    heads: AuditChainSeals,
}

impl TenantScoped for PgAuditChainVerifier {}

impl PgAuditChainVerifier {
    /// A walk of the chains in `databases`, their heads checked with
    /// `heads`.
    #[must_use]
    pub fn new(databases: Arc<Databases>, heads: AuditChainSeals) -> Self {
        Self { databases, heads }
    }

    async fn read(
        &self,
        tenant_id: &ScopedTenant,
        start: &ChainStart,
        limit: NonZeroU32,
    ) -> Result<Read, DomainError> {
        let tenant = *tenant_id.as_uuid();
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let start = read_start(&mut *connection, tenant, start, &self.heads).await?;
                let stretch = read_stretch(&mut *connection, tenant, &start, limit).await?;
                let head = match stretch.first() {
                    Some(_) => None,
                    None => read_head(connection, tenant).await?,
                };
                Ok(Read {
                    start,
                    stretch,
                    head,
                })
            },
        )
        .await
    }
}

#[async_trait]
impl AuditChainVerifier for PgAuditChainVerifier {
    async fn verify_stretch(
        &self,
        tenant_id: &ScopedTenant,
        start: &ChainStart,
        limit: NonZeroU32,
    ) -> Result<ChainStretch, DomainError> {
        let read = tokio::time::timeout(READ_AT_MOST, self.read(tenant_id, start, limit))
            .await
            .map_err(DomainError::infra)??;
        walked(*tenant_id.as_uuid(), read, &self.heads)
    }
}

#[cfg(test)]
mod tests {
    // The walk's tests write records through the raw sink, as the trail's
    // own tests do; use cases reach it only through `RequestAuditor`.
    #![allow(clippy::disallowed_methods)]

    use ianua_app::ports::audit::AuditRetentionStore as _;
    use ianua_app::ports::shared::EventDispatcher;
    use ianua_domain::domains::audit::builder::AuditContext;
    use ianua_domain::types::WorkflowExecutionId;

    use super::*;
    use crate::postgres::audit::{PgAuditRetentionStore, PgEventDispatcher};
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::audit::{
        chain_heads, failed_sign_in, saved_organization, saved_tenant_of,
    };

    struct Fixture {
        db: TestDb,
        tenant: ScopedTenant,
        walk: PgAuditChainVerifier,
    }

    async fn fixture(records: i64) -> Fixture {
        fixture_as(records, &AuditContext::system()).await
    }

    /// A tenant with `records` records, each written as `context` says.
    async fn fixture_as(records: i64, context: &AuditContext) -> Fixture {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let tenant = saved_tenant_of(&db.databases, organization).await;
        let events = (1..=records)
            .map(|seconds| failed_sign_in(*tenant, seconds))
            .collect::<Vec<_>>();
        PgEventDispatcher::new(Arc::clone(&db.databases), chain_heads())
            .dispatch(&events, context)
            .await
            .unwrap();
        Fixture {
            walk: PgAuditChainVerifier::new(Arc::clone(&db.databases), chain_heads()),
            tenant,
            db,
        }
    }

    fn most(limit: u32) -> NonZeroU32 {
        NonZeroU32::new(limit).unwrap()
    }

    /// A chain of three walks intact in stretches of two and one, and then
    /// ends at its sealed head.
    #[tokio::test]
    async fn an_untouched_chain_walks_to_its_sealed_head() {
        let fx = fixture(3).await;

        let first = fx
            .walk
            .verify_stretch(&fx.tenant, &ChainStart::Genesis, most(2))
            .await
            .unwrap();
        let ChainStretch::Intact { checked: 2, last } = first else {
            panic!("the first stretch did not hold: {first:?}");
        };
        let second = fx
            .walk
            .verify_stretch(&fx.tenant, &ChainStart::After(last), most(2))
            .await
            .unwrap();
        let ChainStretch::Intact { checked: 1, last } = second else {
            panic!("the second stretch did not hold: {second:?}");
        };
        let end = fx
            .walk
            .verify_stretch(&fx.tenant, &ChainStart::After(last), most(2))
            .await
            .unwrap();

        assert_eq!(end, ChainStretch::Ended);
    }

    /// Changing the second record's stored actor makes verification report a
    /// break at that record after checking the first.
    #[tokio::test]
    async fn a_changed_record_breaks_the_walk() {
        let fx = fixture(3).await;
        fx.db
            .tamper(
                "SET session_replication_role = replica; \
                 UPDATE audit_records SET actor = 'tenant_user:00000000-0000-0000-0000-000000000001' WHERE seq = 2; \
                 SET session_replication_role = origin;",
            )
            .await;

        let walked = fx
            .walk
            .verify_stretch(&fx.tenant, &ChainStart::Genesis, most(10))
            .await
            .unwrap();

        assert_eq!(
            walked,
            ChainStretch::Broken {
                checked: 1,
                at_seq: 2
            }
        );
    }

    /// A workflow run's records chain like any other, and the walk holds.
    #[tokio::test]
    async fn records_made_through_a_run_walk_intact() {
        let run = AuditContext::system().through_run(WorkflowExecutionId::new());
        let fx = fixture_as(2, &run).await;

        let walked = fx
            .walk
            .verify_stretch(&fx.tenant, &ChainStart::Genesis, most(10))
            .await
            .unwrap();

        assert!(matches!(walked, ChainStretch::Intact { checked: 2, .. }));
    }

    /// Changing the second record's workflow run makes verification report a
    /// break at that record after checking the first.
    #[tokio::test]
    async fn a_swapped_run_breaks_the_walk() {
        let run = AuditContext::system().through_run(WorkflowExecutionId::new());
        let fx = fixture_as(2, &run).await;
        fx.db
            .tamper(
                "SET session_replication_role = replica; \
                 UPDATE audit_records SET through_execution_id = '00000000-0000-0000-0000-000000000001' WHERE seq = 2; \
                 SET session_replication_role = origin;",
            )
            .await;

        let walked = fx
            .walk
            .verify_stretch(&fx.tenant, &ChainStart::Genesis, most(10))
            .await
            .unwrap();

        assert_eq!(
            walked,
            ChainStretch::Broken {
                checked: 1,
                at_seq: 2
            }
        );
    }

    /// Removing the last record and moving the head back without resealing it
    /// leaves the first stretch intact but reports a break at the missing end.
    #[tokio::test]
    async fn a_chain_cut_short_breaks_at_its_end() {
        let fx = fixture(2).await;
        fx.db
            .tamper(
                "SET session_replication_role = replica; \
                 DELETE FROM audit_records WHERE seq = 2; \
                 UPDATE audit_chain_heads h SET seq = 1, entry_hash = r.entry_hash \
                 FROM audit_records r WHERE r.tenant_id = h.tenant_id AND r.seq = 1; \
                 SET session_replication_role = origin;",
            )
            .await;
        let first = fx
            .walk
            .verify_stretch(&fx.tenant, &ChainStart::Genesis, most(10))
            .await
            .unwrap();
        let ChainStretch::Intact { last, .. } = first else {
            panic!("the stretch before the cut did not hold: {first:?}");
        };

        let end = fx
            .walk
            .verify_stretch(&fx.tenant, &ChainStart::After(last), most(10))
            .await
            .unwrap();

        assert_eq!(
            end,
            ChainStretch::Broken {
                checked: 0,
                at_seq: 2
            }
        );
    }

    /// A chain a retention purge cut walks from the anchor the purge left
    /// and sealed, so the purge never reads as a break.
    #[tokio::test]
    async fn a_purged_chain_walks_from_its_sealed_anchor() {
        let fx = fixture(3).await;
        PgAuditRetentionStore::new(Arc::clone(&fx.db.audit_purge), chain_heads())
            .purge_before(&fx.tenant, at(3))
            .await
            .unwrap();

        let walked = fx
            .walk
            .verify_stretch(&fx.tenant, &ChainStart::Genesis, most(10))
            .await
            .unwrap();

        assert!(matches!(walked, ChainStretch::Intact { checked: 1, .. }));
    }

    /// Copying the head's seal into an anchor and deleting every record does
    /// not hide the missing chain: verification reports a break at record one.
    #[tokio::test]
    async fn an_anchor_the_platform_did_not_seal_is_not_trusted() {
        let fx = fixture(3).await;
        fx.db
            .tamper(
                "SET session_replication_role = replica; \
                 INSERT INTO audit_chain_anchors (tenant_id, seq, entry_hash, purged_before, seal) \
                 SELECT tenant_id, seq, entry_hash, now(), seal FROM audit_chain_heads; \
                 DELETE FROM audit_records; \
                 SET session_replication_role = origin;",
            )
            .await;

        let walked = fx
            .walk
            .verify_stretch(&fx.tenant, &ChainStart::Genesis, most(10))
            .await
            .unwrap();

        assert_eq!(
            walked,
            ChainStretch::Broken {
                checked: 0,
                at_seq: 1
            }
        );
    }

    /// A tenant that never kept a record has a chain that ended at once.
    #[tokio::test]
    async fn an_empty_chain_has_ended() {
        let fx = fixture(0).await;

        let walked = fx
            .walk
            .verify_stretch(&fx.tenant, &ChainStart::Genesis, most(10))
            .await
            .unwrap();

        assert_eq!(walked, ChainStretch::Ended);
    }
}
