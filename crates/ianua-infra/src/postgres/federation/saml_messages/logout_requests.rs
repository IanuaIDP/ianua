//! The SAML logout requests a tenant sent its peers, kept until their
//! answer comes back.
//!
//! A request is removed as it is taken, so its answer is taken once.
//! Whether an answer came in time is the request's own rule, so a request
//! is kept for [`LATE_ANSWERS`] past the time its answer stops being taken,
//! for a late answer to be told it came late; after that it is cleared when
//! the tenant's next request is kept.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::federation::SentLogoutRequestStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::federation::saml::logout::SentLogoutRequest;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::SamlRequestId;
use sqlx::PgConnection;
use time::{Duration, OffsetDateTime};

use self::record::{LogoutColumns, LogoutRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// How long a request is kept after its answer stops being taken.
const LATE_ANSWERS: Duration = Duration::hours(1);

/// The Postgres store of sent logout requests.
pub struct PgSentLogoutRequestStore {
    databases: Arc<Databases>,
}

impl PgSentLogoutRequestStore {
    /// A store keeping requests in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgSentLogoutRequestStore {}

/// Removes requests that have outlived even the late-answer retention window.
async fn clear_expired(
    connection: &mut PgConnection,
    tenant: &ScopedTenant,
    before: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    sqlx::query_file!(
        "queries/sent_logout_requests/clear_expired.sql",
        tenant.as_uuid(),
        before
    )
    .execute(connection)
    .await
    .map(|_| ())
}

#[async_trait]
impl SentLogoutRequestStore for PgSentLogoutRequestStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        request: &SentLogoutRequest,
    ) -> Result<(), DomainError> {
        let columns = LogoutColumns::of(request);
        let forgotten_before = clock::now().saturating_sub(LATE_ANSWERS);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                clear_expired(connection, tenant_id, forgotten_before).await?;
                sqlx::query_file!(
                    "queries/sent_logout_requests/keep.sql",
                    tenant_id.as_uuid(),
                    columns.id,
                    columns.peer,
                    columns.destination,
                    columns.name_id_format,
                    columns.name_id,
                    columns.session_index,
                    columns.sent_at,
                    columns.expires_at,
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn take(
        &self,
        tenant_id: &ScopedTenant,
        id: &SamlRequestId,
    ) -> Result<Option<SentLogoutRequest>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    LogoutRecord,
                    "queries/sent_logout_requests/take.sql",
                    tenant_id.as_uuid(),
                    id.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(LogoutRecord::into_request).transpose()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::federation::saml::logout::SentLogoutRequestRow;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::federation::sent_logout_row;

    struct Fixture {
        db: TestDb,
        store: PgSentLogoutRequestStore,
        tenant: ScopedTenant,
    }

    /// A fresh database, the store on it, and one tenant.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        Fixture {
            store: PgSentLogoutRequestStore::new(Arc::clone(&db.databases)),
            tenant: tenant(),
            db,
        }
    }

    fn request(row: SentLogoutRequestRow) -> SentLogoutRequest {
        SentLogoutRequest::reconstitute(row).unwrap()
    }

    fn id(text: &str) -> SamlRequestId {
        SamlRequestId::new(text).unwrap()
    }

    /// A sent request is taken once, as it was kept.
    #[tokio::test]
    async fn a_sent_request_is_taken_once() {
        let fx = fixture().await;
        let sent = request(sent_logout_row("_logout1", "pairwise-ann"));
        fx.store.save(&fx.tenant, &sent).await.unwrap();

        let first = fx.store.take(&fx.tenant, &id("_logout1")).await.unwrap();
        let again = fx.store.take(&fx.tenant, &id("_logout1")).await.unwrap();

        let first = first.unwrap();
        assert_eq!(first.peer(), sent.peer());
        assert_eq!(first.destination(), sent.destination());
        assert_eq!(first.name_id(), sent.name_id());
        assert_eq!(first.session_index(), sent.session_index());
        assert_eq!(first.expires_at(), sent.expires_at());
        assert!(again.is_none());
    }

    /// Taking an unknown logout request returns nothing.
    #[tokio::test]
    async fn a_request_never_sent_takes_nothing() {
        let fx = fixture().await;

        let taken = fx.store.take(&fx.tenant, &id("_never")).await.unwrap();

        assert!(taken.is_none());
    }

    /// Globex cannot take Acme's logout request by its ID.
    #[tokio::test]
    async fn another_tenants_request_is_not_taken() {
        let fx = fixture().await;
        fx.store
            .save(
                &fx.tenant,
                &request(sent_logout_row("_acme1", "pairwise-ann")),
            )
            .await
            .unwrap();

        let taken = fx.store.take(&tenant(), &id("_acme1")).await.unwrap();

        assert!(taken.is_none());
    }

    /// A request long past its answer is forgotten when the next is kept.
    #[tokio::test]
    async fn a_long_expired_request_is_forgotten() {
        let fx = fixture().await;
        fx.store
            .save(
                &fx.tenant,
                &request(sent_logout_row("_old1", "pairwise-ann")),
            )
            .await
            .unwrap();
        fx.db
            .tamper(
                "UPDATE sent_logout_requests \
                 SET sent_at = now() - interval '3 hours', expires_at = now() - interval '2 hours'",
            )
            .await;

        fx.store
            .save(
                &fx.tenant,
                &request(sent_logout_row("_new1", "pairwise-bob")),
            )
            .await
            .unwrap();

        let old = fx.store.take(&fx.tenant, &id("_old1")).await.unwrap();
        assert!(old.is_none());
    }

    /// A stored logout request with a full day to answer fails to load as
    /// corrupt storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_request_is_refused() {
        let fx = fixture().await;
        fx.store
            .save(
                &fx.tenant,
                &request(sent_logout_row("_bad1", "pairwise-ann")),
            )
            .await
            .unwrap();
        fx.db
            .tamper("UPDATE sent_logout_requests SET expires_at = sent_at + interval '1 day'")
            .await;

        let taken = fx.store.take(&fx.tenant, &id("_bad1")).await;

        assert!(matches!(taken, Err(DomainError::Infrastructure(_))));
    }
}
