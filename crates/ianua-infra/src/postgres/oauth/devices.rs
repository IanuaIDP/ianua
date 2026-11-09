//! Device authorization requests, kept and swept through each tenant's
//! current database route. Reads stay bounded, and saves only move pending
//! requests so concurrent answers or redemption cannot be overwritten.

mod record;
mod user_codes;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authentication::SecretEncryptor;
use ianua_app::ports::oauth::{CodeHasher, DEVICE_EXPIRY_BATCH, DeviceAuthStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::oauth::grants::device_authorization::DeviceAuthorization;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DeviceUserCode, TokenHash};
use sqlx::postgres::PgQueryResult;
use time::OffsetDateTime;

use self::record::{DeviceAuthColumns, DeviceAuthRecord};
use self::user_codes::UserCodes;
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a user code to one request of a tenant.
const USER_CODE_KEY: &str = "oauth_device_authorizations_user_code_key";

/// Requires a unique user code and a request still eligible for this write.
fn ensure_written(written: (Uniqueness, u64)) -> Result<(), DomainError> {
    match written {
        (Uniqueness::Taken, _) => Err(DomainError::conflict(message!(
            "infra-another-device-request-of-the-tenant",
            "another device request of the tenant shows this user code"
        ))),
        (Uniqueness::Kept, 0) => Err(DomainError::conflict(message!(
            "infra-the-device-request-was-answered-redeemed",
            "the device request was answered, redeemed or lapsed already"
        ))),
        (Uniqueness::Kept, _) => Ok(()),
    }
}

/// The Postgres store of device authorizations.
pub struct PgDeviceAuthStore {
    databases: Arc<Databases>,
    codes: UserCodes,
}

impl TenantScoped for PgDeviceAuthStore {}

impl PgDeviceAuthStore {
    /// A store keeping device authorizations in `databases`, finding a user
    /// code by its hash from `hasher` and keeping it sealed by `encryptor`.
    #[must_use]
    pub fn new(
        databases: Arc<Databases>,
        hasher: Arc<dyn CodeHasher>,
        encryptor: Arc<dyn SecretEncryptor>,
    ) -> Self {
        Self {
            databases,
            codes: UserCodes::new(hasher, encryptor),
        }
    }

    /// The authorization `record` holds, its user code opened.
    async fn rebuilt(
        &self,
        record: Option<DeviceAuthRecord>,
    ) -> Result<Option<DeviceAuthorization<ResolvedTenant>>, DomainError> {
        let Some(record) = record else {
            return Ok(None);
        };
        let user_code = self.codes.opened(&record).await?;
        record.into_device(user_code).map(Some)
    }

    /// Seals the displayed user code for its tenant and device-code digest.
    async fn sealed_user_code(
        &self,
        tenant: &ScopedTenant,
        auth: &DeviceAuthorization<ResolvedTenant>,
    ) -> Result<String, DomainError> {
        self.codes
            .sealed(**tenant, auth.device_code_hash().as_str(), auth.user_code())
            .await
    }
}

#[async_trait]
impl DeviceAuthStore for PgDeviceAuthStore {
    async fn list_lapsed(
        &self,
        tenant: &ScopedTenant,
        now: OffsetDateTime,
    ) -> Result<Vec<DeviceAuthorization<ResolvedTenant>>, DomainError> {
        let limit = i64::try_from(DEVICE_EXPIRY_BATCH).map_err(DomainError::infra)?;
        let records = scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| {
                sqlx::query_file_as!(
                    DeviceAuthRecord,
                    "queries/oauth_device_authorizations/lapsed_of_tenant.sql",
                    tenant.as_uuid(),
                    now,
                    limit
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        let mut found = Vec::with_capacity(records.len());
        for record in records {
            let user_code = self.codes.opened(&record).await?;
            found.push(record.into_device(user_code)?);
        }
        Ok(found)
    }

    async fn find_by_device_code_hash(
        &self,
        tenant_id: &ScopedTenant,
        device_code_hash: &TokenHash,
    ) -> Result<Option<DeviceAuthorization<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    DeviceAuthRecord,
                    "queries/oauth_device_authorizations/by_device_code.sql",
                    tenant_id.as_uuid(),
                    device_code_hash.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        self.rebuilt(record).await
    }

    async fn find_by_user_code(
        &self,
        tenant_id: &ScopedTenant,
        user_code: &DeviceUserCode,
    ) -> Result<Option<DeviceAuthorization<ResolvedTenant>>, DomainError> {
        let hash = self.codes.hash_of(user_code).await?;
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    DeviceAuthRecord,
                    "queries/oauth_device_authorizations/by_user_code.sql",
                    tenant_id.as_uuid(),
                    hash
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        self.rebuilt(record).await
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        auth: &DeviceAuthorization<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = DeviceAuthColumns::of(auth);
        let user_code_hash = self.codes.hash_of(auth.user_code()).await?;
        let user_code_sealed = self.sealed_user_code(tenant_id, auth).await?;
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let attempt = sqlx::query_file!(
                    "queries/oauth_device_authorizations/save.sql",
                    tenant_id.as_uuid(),
                    columns.device_code_hash,
                    user_code_hash,
                    user_code_sealed,
                    columns.client_id,
                    columns.scopes.as_slice(),
                    columns.status,
                    columns.approved_by,
                    columns.interval_secs,
                    columns.last_polled_at,
                    columns.created_at,
                    columns.expires_at,
                )
                .execute(connection)
                .await;
                let rows = attempt.as_ref().map_or(0, PgQueryResult::rows_affected);
                unique_on(attempt, USER_CODE_KEY).map(|kept| (kept, rows))
            },
        )
        .await?;
        ensure_written(written)
    }

    async fn redeem(
        &self,
        tenant_id: &ScopedTenant,
        device_code_hash: &TokenHash,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let redeemed = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/oauth_device_authorizations/redeem.sql",
                    tenant_id.as_uuid(),
                    device_code_hash.as_str(),
                    now
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        Ok(redeemed.rows_affected() == 1)
    }

    async fn record_poll(
        &self,
        tenant_id: &ScopedTenant,
        auth: &DeviceAuthorization<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = DeviceAuthColumns::of(auth);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/oauth_device_authorizations/record_poll.sql",
                    tenant_id.as_uuid(),
                    columns.device_code_hash,
                    columns.last_polled_at,
                    columns.interval_secs
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::test_support::authentication::FakeEncryptor;
    use ianua_app::test_support::oauth::FakeCodeHasher;
    use ianua_domain::domains::oauth::clients::client::{GrantType, OAuthClient};
    use ianua_domain::domains::oauth::grants::device_authorization::{
        DeviceAuthRow, DeviceAuthState, LastPoll, PollInterval,
    };
    use ianua_domain::types::UserId;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::oauth::{
        a_client, a_person, device_row, hash, oauth_client_row,
    };

    struct Fixture {
        db: TestDb,
        store: PgDeviceAuthStore,
        tenant: ScopedTenant,
        tv: OAuthClient<ResolvedTenant>,
        ann: UserId,
    }

    /// A store on `db`, with the fakes that hash and seal user codes.
    fn store_on(db: &TestDb) -> PgDeviceAuthStore {
        PgDeviceAuthStore::new(
            Arc::clone(&db.databases),
            Arc::new(FakeCodeHasher::new()),
            Arc::new(FakeEncryptor),
        )
    }

    /// A fresh database, the store on it, and a tenant with a device client
    /// and a person to approve its requests.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = tenant();
        let tv = a_client(
            &db,
            &tenant,
            oauth_client_row("tv", &[GrantType::DeviceCode]),
        )
        .await;
        let ann = a_person(&db, &tenant, "ann@acme.example").await;
        Fixture {
            store: store_on(&db),
            db,
            tenant,
            tv,
            ann,
        }
    }

    fn device(row: DeviceAuthRow) -> DeviceAuthorization<ResolvedTenant> {
        DeviceAuthorization::reconstitute(row).unwrap()
    }

    impl Fixture {
        /// Saves a device-flow client in the selected tenant's current database.
        async fn client(&self, owner: &ScopedTenant, name: &str) -> OAuthClient<ResolvedTenant> {
            a_client(
                &self.db,
                owner,
                oauth_client_row(name, &[GrantType::DeviceCode]),
            )
            .await
        }

        /// Verifies that no pending expiry remains in this tenant's current database.
        async fn assert_no_expiry(&self, owner: &ScopedTenant) {
            assert!(
                self.store
                    .list_lapsed(owner, at(600))
                    .await
                    .unwrap()
                    .is_empty()
            );
        }

        /// Checks the only expired request, expires it, and verifies that the batch drains.
        async fn drain_one(&self, owner: &ScopedTenant, code: &str) {
            let found = self.store.list_lapsed(owner, at(600)).await.unwrap();
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].user_code().as_str(), code);
            for mut request in found {
                request.expire().unwrap();
                self.store.save(owner, &request).await.unwrap();
            }
            self.assert_no_expiry(owner).await;
        }

        fn pending(&self, raw: &str, user_code: &str) -> DeviceAuthRow {
            device_row(&self.tv, raw, user_code)
        }

        fn approved(&self, raw: &str, user_code: &str) -> DeviceAuthRow {
            DeviceAuthRow {
                state: DeviceAuthState::Approved { by: self.ann },
                ..self.pending(raw, user_code)
            }
        }

        async fn stored(&self, raw: &str) -> DeviceAuthorization<ResolvedTenant> {
            self.store
                .find_by_device_code_hash(&self.tenant, &hash(raw))
                .await
                .unwrap()
                .unwrap()
        }
    }

    /// A saved request is found by its device code and by its user code,
    /// showing the code it was saved with.
    #[tokio::test]
    async fn a_saved_request_is_found_by_either_code() {
        let db = fixture().await;
        let request = device(db.pending("device-1", "ABCD-1234"));

        db.store.save(&db.tenant, &request).await.unwrap();

        let by_device = db.stored("device-1").await;
        let by_user = db
            .store
            .find_by_user_code(&db.tenant, request.user_code())
            .await
            .unwrap()
            .unwrap();
        for found in [&by_device, &by_user] {
            assert_eq!(found.device_code_hash(), request.device_code_hash());
            assert_eq!(found.user_code(), request.user_code());
            assert_eq!(found.client_id(), db.tv.id());
            assert_eq!(found.scopes(), request.scopes());
            assert_eq!(found.state(), DeviceAuthState::Pending);
            assert_eq!(found.interval(), PollInterval::DEFAULT);
            assert_eq!(found.expires_at(), request.expires_at());
        }
    }

    /// An unknown device-code hash and a user-code lookup from another
    /// tenant both return nothing.
    #[tokio::test]
    async fn a_request_is_found_only_by_its_tenant() {
        let db = fixture().await;
        let request = device(db.pending("device-1", "ABCD-1234"));
        db.store.save(&db.tenant, &request).await.unwrap();
        let globex = tenant();

        let unknown = db
            .store
            .find_by_device_code_hash(&db.tenant, &hash("nobody"))
            .await
            .unwrap();
        let theirs = db
            .store
            .find_by_user_code(&globex, request.user_code())
            .await
            .unwrap();

        assert!(unknown.is_none());
        assert!(theirs.is_none());
    }

    /// Saving a second request with the same tenant's user code returns a
    /// conflict.
    #[tokio::test]
    async fn a_user_code_another_request_shows_is_refused() {
        let db = fixture().await;
        db.store
            .save(&db.tenant, &device(db.pending("device-1", "ABCD-1234")))
            .await
            .unwrap();

        let second = db
            .store
            .save(&db.tenant, &device(db.pending("device-2", "ABCD-1234")))
            .await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
    }

    /// Ann approves the request: saving again keeps who approved it.
    #[tokio::test]
    async fn saving_again_keeps_the_approval() {
        let db = fixture().await;
        db.store
            .save(&db.tenant, &device(db.pending("device-1", "ABCD-1234")))
            .await
            .unwrap();

        db.store
            .save(&db.tenant, &device(db.approved("device-1", "ABCD-1234")))
            .await
            .unwrap();

        assert_eq!(
            db.stored("device-1").await.state(),
            DeviceAuthState::Approved { by: db.ann }
        );
    }

    /// Only the first redemption succeeds; a second attempt returns false
    /// and the request remains redeemed by Ann.
    #[tokio::test]
    async fn an_approval_is_redeemed_once() {
        let db = fixture().await;
        db.store
            .save(&db.tenant, &device(db.approved("device-1", "ABCD-1234")))
            .await
            .unwrap();

        let first = db
            .store
            .redeem(&db.tenant, &hash("device-1"), at(30))
            .await
            .unwrap();
        let second = db
            .store
            .redeem(&db.tenant, &hash("device-1"), at(30))
            .await
            .unwrap();

        assert!(first);
        assert!(!second);
        assert_eq!(
            db.stored("device-1").await.state(),
            DeviceAuthState::Redeemed { by: db.ann }
        );
    }

    /// Saving Bob's approval after Ann's approval was redeemed conflicts.
    /// Another redemption fails, and the request stays redeemed by Ann.
    #[tokio::test]
    async fn a_redeemed_request_is_never_approved_again() {
        let db = fixture().await;
        let bob = a_person(&db.db, &db.tenant, "bob@acme.example").await;
        db.store
            .save(&db.tenant, &device(db.approved("device-1", "ABCD-1234")))
            .await
            .unwrap();
        db.store
            .redeem(&db.tenant, &hash("device-1"), at(30))
            .await
            .unwrap();
        let bobs = device(DeviceAuthRow {
            state: DeviceAuthState::Approved { by: bob },
            ..db.pending("device-1", "ABCD-1234")
        });

        let saved = db.store.save(&db.tenant, &bobs).await;
        let again = db
            .store
            .redeem(&db.tenant, &hash("device-1"), at(30))
            .await
            .unwrap();

        assert!(matches!(saved, Err(DomainError::Conflict(_))));
        assert!(!again);
        assert_eq!(
            db.stored("device-1").await.state(),
            DeviceAuthState::Redeemed { by: db.ann }
        );
    }

    /// Redemption returns false for both a pending request and an expired
    /// approval.
    #[tokio::test]
    async fn a_pending_or_expired_request_is_not_redeemed() {
        let db = fixture().await;
        db.store
            .save(&db.tenant, &device(db.pending("pending", "ABCD-1234")))
            .await
            .unwrap();
        db.store
            .save(&db.tenant, &device(db.approved("late", "WXYZ-9876")))
            .await
            .unwrap();

        let pending = db
            .store
            .redeem(&db.tenant, &hash("pending"), at(30))
            .await
            .unwrap();
        let late = db
            .store
            .redeem(&db.tenant, &hash("late"), at(600))
            .await
            .unwrap();

        assert!(!pending);
        assert!(!late);
    }

    /// Recording a poll from a pending copy updates its time and interval
    /// while preserving Ann's stored approval.
    #[tokio::test]
    async fn a_poll_never_undoes_an_approval() {
        let db = fixture().await;
        db.store
            .save(&db.tenant, &device(db.approved("device-1", "ABCD-1234")))
            .await
            .unwrap();
        let polled = device(DeviceAuthRow {
            last_poll: LastPoll::At(at(20)),
            interval: PollInterval::seconds(10).unwrap(),
            ..db.pending("device-1", "ABCD-1234")
        });

        db.store.record_poll(&db.tenant, &polled).await.unwrap();

        let found = db.stored("device-1").await;
        assert_eq!(found.state(), DeviceAuthState::Approved { by: db.ann });
        assert_eq!(found.last_poll(), LastPoll::At(at(20)));
        assert_eq!(found.interval(), PollInterval::seconds(10).unwrap());
    }

    /// Each tenant's expiry read excludes other tenants, answered requests
    /// and links that still work, including when their expiries are earlier.
    #[tokio::test]
    async fn expiry_reads_only_the_tenants_expired_pending_requests() {
        let db = fixture().await;
        let globex = tenant();
        let theirs = db.client(&globex, "tv").await;
        for request in [
            device(db.pending("lapsed", "ABCD-1234")),
            device(db.approved("answered", "WXYZ-9876")),
            device(DeviceAuthRow {
                expires_at: at(5000),
                ..db.pending("live", "LIVE-0001")
            }),
        ] {
            db.store.save(&db.tenant, &request).await.unwrap();
        }
        db.store
            .save(&globex, &device(device_row(&theirs, "globex", "GLOB-0001")))
            .await
            .unwrap();

        let own = db.store.list_lapsed(&db.tenant, at(600)).await.unwrap();
        let other = db.store.list_lapsed(&globex, at(600)).await.unwrap();

        assert_eq!(own.len(), 1);
        assert_eq!(own[0].user_code().as_str(), "ABCD-1234");
        assert_eq!(other.len(), 1);
        assert_eq!(other[0].user_code().as_str(), "GLOB-0001");
        db.assert_no_expiry(&tenant()).await;
    }

    /// A moved tenant's expiry read excludes its stale platform requests.
    /// Expiring the current shared and dedicated requests drains each
    /// tenant's pending expiry batch separately.
    #[tokio::test]
    async fn device_expiry_ignores_stale_requests_after_a_tenant_moves() {
        let db = fixture().await;
        for number in 0..501 {
            let row = DeviceAuthRow {
                expires_at: at(200),
                ..db.pending(&format!("stale-{number}"), &format!("OLDX-{number:04}"))
            };
            db.store.save(&db.tenant, &device(row)).await.unwrap();
        }
        let shared = tenant();
        let shared_tv = db.client(&shared, "shared").await;
        db.store
            .save(
                &shared,
                &device(device_row(&shared_tv, "shared", "SHRD-0001")),
            )
            .await
            .unwrap();
        let own = TestDb::fresh().await;
        db.db.databases.register(*db.tenant, own.as_dedicated());
        let dedicated_tv = db.client(&db.tenant, "dedicated").await;
        db.store
            .save(
                &db.tenant,
                &device(device_row(&dedicated_tv, "dedicated", "APRT-0001")),
            )
            .await
            .unwrap();

        for (owner, code) in [(&shared, "SHRD-0001"), (&db.tenant, "APRT-0001")] {
            db.drain_one(owner, code).await;
        }
    }

    /// Shared and dedicated tenants each have more requests than fit in one
    /// batch. Persisted expiry drains both backlogs without mixing their rows.
    #[tokio::test]
    async fn device_expiry_batches_bound_shared_and_dedicated_reads() {
        let db = fixture().await;
        let own = TestDb::fresh().await;
        let apart = tenant();
        db.db.databases.register(*apart, own.as_dedicated());
        let apart_tv = a_client(
            &db.db,
            &apart,
            oauth_client_row("apart", &[GrantType::DeviceCode]),
        )
        .await;
        for (owner, client) in [(&db.tenant, &db.tv), (&apart, &apart_tv)] {
            for number in 0..501 {
                let request = device(device_row(
                    client,
                    &format!("device-{number}"),
                    &format!("CODE-{number:04}"),
                ));
                db.store.save(owner, &request).await.unwrap();
            }
            for expected in [500, 1, 0] {
                let found = db.store.list_lapsed(owner, at(600)).await.unwrap();
                assert_eq!(found.len(), expected);
                for mut request in found {
                    request.expire().unwrap();
                    db.store.save(owner, &request).await.unwrap();
                }
            }
        }
    }

    /// Saving expiry from a stale read conflicts after Ann approves the
    /// request, preserving her approval and allowing redemption.
    #[tokio::test]
    async fn an_expiry_save_preserves_an_answer_made_after_the_read() {
        let db = fixture().await;
        db.store
            .save(&db.tenant, &device(db.pending("device-1", "ABCD-1234")))
            .await
            .unwrap();
        let mut found = db.store.list_lapsed(&db.tenant, at(600)).await.unwrap();
        db.store
            .save(&db.tenant, &device(db.approved("device-1", "ABCD-1234")))
            .await
            .unwrap();
        let mut expired = found.pop().unwrap();
        expired.expire().unwrap();

        let saved = db.store.save(&db.tenant, &expired).await;

        assert!(matches!(saved, Err(DomainError::Conflict(_))));
        assert_eq!(
            db.stored("device-1").await.state(),
            DeviceAuthState::Approved { by: db.ann }
        );
        assert!(
            db.store
                .redeem(&db.tenant, &hash("device-1"), at(599))
                .await
                .unwrap()
        );
    }

    /// An invalid sealed user code makes both the direct lookup and expiry
    /// read return infrastructure errors.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_request_is_refused() {
        let db = fixture().await;
        db.store
            .save(&db.tenant, &device(db.pending("device-1", "ABCD-1234")))
            .await
            .unwrap();
        db.db
            .tamper("UPDATE oauth_device_authorizations SET user_code_sealed = 'enc_97'")
            .await;

        let read = db
            .store
            .find_by_device_code_hash(&db.tenant, &hash("device-1"))
            .await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
        assert!(matches!(
            db.store.list_lapsed(&db.tenant, at(600)).await,
            Err(DomainError::Infrastructure(_))
        ));
    }
}
