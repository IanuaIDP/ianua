//! Impersonation grants, kept in the platform database under row-level
//! security.
//!
//! A grant names an operator, a tenant and a user of it. Operators work
//! across tenants, so the store reads and writes as platform work; the
//! tenant each grant names is still its row's tenant, and a tenant's grants
//! go with the tenant. The user may live in a database of its own, so it is
//! named by id alone. A grant leaves service by revocation, never by being
//! removed.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::operator::ImpersonationGrantStore;
use ianua_domain::domains::operator::impersonation::ImpersonationGrant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ImpersonationGrantId, OperatorId, TenantId, UserId};

use self::record::{GrantColumns, GrantRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres impersonation grant store.
pub struct PgImpersonationGrantStore {
    databases: Arc<Databases>,
}

impl PgImpersonationGrantStore {
    /// A store keeping impersonation grants in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl ImpersonationGrantStore for PgImpersonationGrantStore {
    async fn find_by_id(
        &self,
        id: &ImpersonationGrantId,
    ) -> Result<Option<ImpersonationGrant>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_as!(
                GrantRecord,
                "queries/impersonation_grants/by_ids.sql",
                ids.as_slice()
            )
            .fetch_all(connection)
            .await
        })
        .await?;
        records
            .into_iter()
            .next()
            .map(GrantRecord::into_grant)
            .transpose()
    }

    async fn find_active(
        &self,
        operator_id: &OperatorId,
        tenant_id: &TenantId,
        user_id: &UserId,
    ) -> Result<Option<ImpersonationGrant>, DomainError> {
        let now = clock::now();
        let record = scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_as!(
                GrantRecord,
                "queries/impersonation_grants/active.sql",
                operator_id.as_uuid(),
                tenant_id.as_uuid(),
                user_id.as_uuid(),
                now
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        record.map(GrantRecord::into_grant).transpose()
    }

    async fn save(&self, grant: &ImpersonationGrant) -> Result<(), DomainError> {
        let columns = GrantColumns::of(grant);
        let written = scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file!(
                "queries/impersonation_grants/save.sql",
                columns.id,
                columns.operator_id,
                columns.tenant_id,
                columns.user_id,
                columns.reason,
                columns.expires_at,
                columns.revoked_at,
                columns.created_at,
            )
            .execute(connection)
            .await
            .map(|done| done.rows_affected())
        })
        .await?;
        match written {
            0 => Err(DomainError::conflict(message!(
                "infra-this-impersonation-grant-is-another-operator",
                "this impersonation grant is another operator's, or was revoked already"
            ))),
            _ => Ok(()),
        }
    }

    async fn revoke_all_for_operator(&self, operator_id: &OperatorId) -> Result<u64, DomainError> {
        let now = clock::now();
        let revoked = scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_scalar!(
                "queries/impersonation_grants/revoke_all.sql",
                operator_id.as_uuid(),
                now
            )
            .fetch_one(connection)
            .await
        })
        .await?;
        u64::try_from(revoked).map_err(DomainError::infra)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::operator::OperatorStore;
    use ianua_app::ports::organization::OrganizationStore;
    use ianua_app::ports::tenant::TenantStore;
    use ianua_domain::domains::operator::impersonation::ImpersonationGrantRow;
    use ianua_domain::domains::organization::lifecycle::Organization;
    use ianua_domain::domains::tenant::lifecycle::Tenant;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::Revocation;

    use super::*;
    use crate::postgres::operator::PgOperatorStore;
    use crate::postgres::organization::PgOrganizationStore;
    use crate::postgres::tenant::PgTenantStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::operator::{active_operator, grant_row};
    use crate::test_support::rows::organization::organization_row;
    use crate::test_support::rows::tenant::tenant_row;

    struct Fixture {
        db: TestDb,
        store: PgImpersonationGrantStore,
        olga: OperatorId,
        acme: TenantId,
    }

    /// A fresh database holding the operator Olga and the tenant Acme, and
    /// the store on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let olga = an_operator(&db, "olga@ianua.dev").await;
        let acme = a_tenant(&db, "acme").await;
        Fixture {
            store: PgImpersonationGrantStore::new(Arc::clone(&db.databases)),
            olga,
            acme,
            db,
        }
    }

    /// Saves an operator at `email` through their store.
    async fn an_operator(db: &TestDb, email: &str) -> OperatorId {
        let operator = active_operator(email);
        PgOperatorStore::new(Arc::clone(&db.databases))
            .save(&operator)
            .await
            .unwrap();
        *operator.id()
    }

    /// Saves a tenant under `slug`, with an organization of its own,
    /// through their stores.
    async fn a_tenant(db: &TestDb, slug: &str) -> TenantId {
        let organization =
            Organization::reconstitute(organization_row(&format!("{slug}-org"), slug)).unwrap();
        PgOrganizationStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&organization)
            .await
            .unwrap();
        let tenant = Tenant::reconstitute(tenant_row(*organization.id(), slug)).unwrap();
        PgTenantStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&tenant)
            .await
            .unwrap();
        *tenant.id()
    }

    fn grant(row: ImpersonationGrantRow) -> ImpersonationGrant {
        ImpersonationGrant::reconstitute(row).unwrap()
    }

    impl Fixture {
        fn granted(&self, user: UserId) -> ImpersonationGrant {
            grant(grant_row(self.olga, self.acme, user))
        }

        async fn active(&self, user: &UserId) -> Option<ImpersonationGrant> {
            self.store
                .find_active(&self.olga, &self.acme, user)
                .await
                .unwrap()
        }
    }

    /// Olga's grant to act as Ann is found by its id as it was saved.
    #[tokio::test]
    async fn a_saved_grant_is_found_by_its_id() {
        let fx = fixture().await;
        let ann = UserId::new();
        let saved = fx.granted(ann);

        fx.store.save(&saved).await.unwrap();

        let found = fx.store.find_by_id(saved.id()).await.unwrap().unwrap();
        assert_eq!(found.operator_id(), &fx.olga);
        assert_eq!(found.tenant_id(), &fx.acme);
        assert_eq!(found.user_id(), &ann);
        assert_eq!(found.reason(), saved.reason());
        assert_eq!(found.expires_at(), saved.expires_at());
        assert_eq!(found.created_at(), saved.created_at());
        assert!(!found.is_revoked());
    }

    /// An id no grant has finds nothing, rather than failing.
    #[tokio::test]
    async fn an_unknown_grant_is_not_found() {
        let fx = fixture().await;

        let found = fx
            .store
            .find_by_id(&ImpersonationGrantId::new())
            .await
            .unwrap();

        assert!(found.is_none());
    }

    /// The grant in force for Olga acting as Ann is found; one for another
    /// user, a revoked one and one run out are not.
    #[tokio::test]
    async fn only_a_grant_in_force_is_active() {
        let fx = fixture().await;
        let [ann, bob, cid, dee] = [(); 4].map(|()| UserId::new());
        let mut ran_out = grant_row(fx.olga, fx.acme, dee);
        ran_out.created_at -= time::Duration::hours(2);
        ran_out.expires_at -= time::Duration::hours(2);
        let mut revoked = grant_row(fx.olga, fx.acme, cid);
        revoked.revocation = Revocation::Revoked {
            at: revoked.created_at,
        };
        for saved in [&fx.granted(ann), &grant(revoked), &grant(ran_out)] {
            fx.store.save(saved).await.unwrap();
        }

        assert_eq!(fx.active(&ann).await.unwrap().user_id(), &ann);
        assert!(fx.active(&bob).await.is_none());
        assert!(fx.active(&cid).await.is_none());
        assert!(fx.active(&dee).await.is_none());
    }

    /// Olga's grant for Acme is absent when looked up in Globex.
    #[tokio::test]
    async fn a_grant_is_active_only_in_its_tenant() {
        let fx = fixture().await;
        let globex = a_tenant(&fx.db, "globex").await;
        let ann = UserId::new();
        fx.store.save(&fx.granted(ann)).await.unwrap();

        let elsewhere = fx.store.find_active(&fx.olga, &globex, &ann).await.unwrap();

        assert!(elsewhere.is_none());
    }

    /// Olga leaves: every grant she holds still unrevoked is revoked and
    /// counted, in every tenant, and Pete's grant stays in force.
    #[tokio::test]
    async fn revoking_an_operators_grants_revokes_only_theirs() {
        let fx = fixture().await;
        let globex = a_tenant(&fx.db, "globex").await;
        let pete = an_operator(&fx.db, "pete@ianua.dev").await;
        let ann = UserId::new();
        let theirs = grant(grant_row(pete, fx.acme, ann));
        for saved in [
            &fx.granted(ann),
            &grant(grant_row(fx.olga, globex, ann)),
            &theirs,
        ] {
            fx.store.save(saved).await.unwrap();
        }

        let revoked = fx.store.revoke_all_for_operator(&fx.olga).await.unwrap();
        let again = fx.store.revoke_all_for_operator(&fx.olga).await.unwrap();

        assert_eq!(revoked, 2);
        assert_eq!(again, 0);
        assert!(fx.active(&ann).await.is_none());
        assert!(
            fx.store
                .find_active(&pete, &fx.acme, &ann)
                .await
                .unwrap()
                .is_some()
        );
    }

    /// Olga revokes her grant: saving it again keeps the revocation.
    #[tokio::test]
    async fn saving_again_keeps_the_revocation() {
        let fx = fixture().await;
        let saved = fx.granted(UserId::new());
        fx.store.save(&saved).await.unwrap();
        let revoked = grant(ImpersonationGrantRow {
            id: *saved.id(),
            operator_id: fx.olga,
            tenant_id: fx.acme,
            user_id: *saved.user_id(),
            reason: saved.reason().clone(),
            expires_at: saved.expires_at(),
            revocation: Revocation::Revoked {
                at: saved.created_at(),
            },
            created_at: saved.created_at(),
        });

        fx.store.save(&revoked).await.unwrap();

        let found = fx.store.find_by_id(saved.id()).await.unwrap().unwrap();
        assert!(found.is_revoked());
    }

    /// Saving a stale copy of Olga's revoked grant returns a conflict;
    /// the grant stays revoked and cannot be found as active.
    #[tokio::test]
    async fn a_stale_save_does_not_undo_a_revocation() {
        let fx = fixture().await;
        let ann = UserId::new();
        let saved = fx.granted(ann);
        fx.store.save(&saved).await.unwrap();
        fx.store.revoke_all_for_operator(&fx.olga).await.unwrap();

        let stale = fx.store.save(&saved).await;

        assert!(matches!(stale, Err(DomainError::Conflict(_))));
        assert!(fx.active(&ann).await.is_none());
        let found = fx.store.find_by_id(saved.id()).await.unwrap().unwrap();
        assert!(found.is_revoked());
    }

    /// A grant whose stored reason is blank is rejected as corrupt storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_grant_is_refused() {
        let fx = fixture().await;
        let saved = fx.granted(UserId::new());
        fx.store.save(&saved).await.unwrap();
        fx.db
            .tamper("UPDATE impersonation_grants SET reason = ''")
            .await;

        let read = fx.store.find_by_id(saved.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
