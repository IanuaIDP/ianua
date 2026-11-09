//! The registrations the background sweeps work through, read across every
//! tenant: those of the tenants in the platform database in one query, as
//! platform work, and those of each tenant with a database of its own from
//! that database, all at once. No one query reaches across databases, so
//! one per database is the least there can be.

use futures_util::future::try_join_all;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;
use sqlx::PgConnection;
use time::OffsetDateTime;

use crate::postgres::domain::registrations::record::DomainRecord;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The most claims still to be proved one sweep is handed.
pub(super) const AWAITING_PROOF_AT_MOST: usize = 100;

/// Which registrations a sweep works through.
#[derive(Debug, Clone, Copy)]
pub(super) enum Sweep {
    /// The claims still to be proved and due for a check at this moment.
    AwaitingProof(OffsetDateTime),
    /// The proved domains.
    Proved,
    /// The proved domains still waiting for a certificate, proved before
    /// this moment.
    AwaitingCertificate(OffsetDateTime),
}

/// Which database's registrations a sweep reads.
#[derive(Debug, Clone, Copy)]
enum Place {
    /// Every tenant's in the platform database.
    Shared,
    /// One tenant's, in its own database.
    Own(TenantId),
}

impl Sweep {
    /// The registrations of every tenant `sweep` works through, wherever
    /// they live.
    pub(super) async fn everywhere(
        self,
        databases: &Databases,
    ) -> Result<Vec<DomainRecord>, DomainError> {
        let shared = scoped(databases, RowScope::Platform, async |connection| {
            self.read(connection, Place::Shared).await
        });
        let own = databases.with_own_database().into_iter().map(|tenant| {
            scoped(
                databases,
                RowScope::Tenant(tenant),
                async move |connection| self.read(connection, Place::Own(tenant)).await,
            )
        });
        let (shared, own) = futures_util::try_join!(shared, try_join_all(own))?;
        Ok(shared
            .into_iter()
            .chain(own.into_iter().flatten())
            .collect())
    }

    /// The registrations this sweep works through in `place`.
    async fn read(
        self,
        connection: &mut PgConnection,
        place: Place,
    ) -> Result<Vec<DomainRecord>, sqlx::Error> {
        match (self, place) {
            (Self::AwaitingProof(now), Place::Shared) => awaiting_proof(connection, now).await,
            (Self::AwaitingProof(now), Place::Own(tenant)) => {
                awaiting_proof_of(connection, now, tenant).await
            }
            (Self::Proved, Place::Shared) => proved(connection).await,
            (Self::Proved, Place::Own(tenant)) => proved_of(connection, tenant).await,
            (Self::AwaitingCertificate(cutoff), Place::Shared) => {
                awaiting_certificate(connection, cutoff).await
            }
            (Self::AwaitingCertificate(cutoff), Place::Own(tenant)) => {
                awaiting_certificate_of(connection, cutoff, tenant).await
            }
        }
    }
}

async fn awaiting_proof(
    connection: &mut PgConnection,
    now: OffsetDateTime,
) -> Result<Vec<DomainRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        DomainRecord,
        "queries/registered_domains/awaiting_proof.sql",
        now
    )
    .fetch_all(connection)
    .await
}

async fn awaiting_proof_of(
    connection: &mut PgConnection,
    now: OffsetDateTime,
    tenant: TenantId,
) -> Result<Vec<DomainRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        DomainRecord,
        "queries/registered_domains/awaiting_proof_of_tenant.sql",
        now,
        tenant.as_uuid()
    )
    .fetch_all(connection)
    .await
}

async fn proved(connection: &mut PgConnection) -> Result<Vec<DomainRecord>, sqlx::Error> {
    sqlx::query_file_as!(DomainRecord, "queries/registered_domains/proved.sql")
        .fetch_all(connection)
        .await
}

async fn proved_of(
    connection: &mut PgConnection,
    tenant: TenantId,
) -> Result<Vec<DomainRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        DomainRecord,
        "queries/registered_domains/proved_of_tenant.sql",
        tenant.as_uuid()
    )
    .fetch_all(connection)
    .await
}

async fn awaiting_certificate(
    connection: &mut PgConnection,
    cutoff: OffsetDateTime,
) -> Result<Vec<DomainRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        DomainRecord,
        "queries/registered_domains/awaiting_certificate.sql",
        cutoff
    )
    .fetch_all(connection)
    .await
}

async fn awaiting_certificate_of(
    connection: &mut PgConnection,
    cutoff: OffsetDateTime,
    tenant: TenantId,
) -> Result<Vec<DomainRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        DomainRecord,
        "queries/registered_domains/awaiting_certificate_of_tenant.sql",
        cutoff,
        tenant.as_uuid()
    )
    .fetch_all(connection)
    .await
}
