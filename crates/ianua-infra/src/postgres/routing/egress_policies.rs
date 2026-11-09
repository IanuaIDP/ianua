//! A tenant's egress policies, under row-level security: where each of its
//! services may send traffic out.
//!
//! Every read goes through one checked query and one mapping into the
//! aggregate. A service has at most one policy in a tenant, which a unique
//! index keeps. The egress gateway finds every tenant's policy for a
//! service by the service's identity alone, through
//! [`PgCrossTenantEgressPolicies`], since it knows the tenant only from
//! the claim.

mod record;

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::future::try_join_all;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::routing::{
    ClaimedEgressPolicy, CrossTenantEgressPolicies, EgressPolicyStore,
};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::routing::egress::{EgressPolicy, ServiceIdentity};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{EgressPolicyId, TenantId};

use self::record::{ClaimRecord, EgressPolicyColumns, EgressPolicyRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a service to one policy.
const SERVICE_KEY: &str = "egress_policies_service_key";

/// The Postgres egress policy store.
pub struct PgEgressPolicyStore {
    databases: Arc<Databases>,
}

impl PgEgressPolicyStore {
    /// A store keeping egress policies in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgEgressPolicyStore {}

/// The policy `record` holds, if any, rebuilt through the domain's checks.
fn rebuilt(
    record: Option<EgressPolicyRecord>,
) -> Result<Option<EgressPolicy<ResolvedTenant>>, DomainError> {
    record.map(EgressPolicyRecord::into_policy).transpose()
}

/// Converts an already-owned service identity into a conflicting policy error.
fn ensure_service_available(written: Uniqueness) -> Result<(), DomainError> {
    match written {
        Uniqueness::Kept => Ok(()),
        Uniqueness::Taken => Err(DomainError::conflict(message!(
            "infra-the-service-already-has-an-egress",
            "the service already has an egress policy"
        ))),
    }
}

#[async_trait]
impl EgressPolicyStore for PgEgressPolicyStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        policy: &EgressPolicy<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = EgressPolicyColumns::of(policy)?;
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let attempt = sqlx::query_file!(
                    "queries/egress_policies/save.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.name,
                    columns.service,
                    columns.destinations,
                    columns.max_data_class,
                    columns.created_by_kind,
                    columns.created_by,
                    columns.created_at,
                    columns.updated_at,
                )
                .execute(connection)
                .await;
                unique_on(attempt, SERVICE_KEY)
            },
        )
        .await?;
        ensure_service_available(written)
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &EgressPolicyId,
    ) -> Result<Option<EgressPolicy<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    EgressPolicyRecord,
                    "queries/egress_policies/by_ids.sql",
                    tenant_id.as_uuid(),
                    &ids[..]
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        rebuilt(record)
    }

    async fn find_by_service(
        &self,
        tenant_id: &ScopedTenant,
        service: &ServiceIdentity,
    ) -> Result<Option<EgressPolicy<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    EgressPolicyRecord,
                    "queries/egress_policies/by_service.sql",
                    tenant_id.as_uuid(),
                    service.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        rebuilt(record)
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<EgressPolicy<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    EgressPolicyRecord,
                    "queries/egress_policies/of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records
            .into_iter()
            .map(EgressPolicyRecord::into_policy)
            .collect()
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &EgressPolicyId,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/egress_policies/delete.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }
}

/// The Postgres read of every tenant's egress policies for one service,
/// for the egress gateway under the data plane's role.
///
/// A tenant's policies are tenant rows, in the platform database or in the
/// tenant's own. So the platform database is read once, as platform work,
/// and each tenant living apart from its own database at once; a tenant
/// that lives apart is read from its own database alone.
pub struct PgCrossTenantEgressPolicies {
    databases: Arc<Databases>,
}

impl PgCrossTenantEgressPolicies {
    /// A read of the policies in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// The policies for `service` among the rows `scope` reaches.
    async fn claims_in(
        &self,
        scope: RowScope,
        service: &ServiceIdentity,
    ) -> Result<Vec<ClaimRecord>, DomainError> {
        scoped(&self.databases, scope, async |connection| {
            sqlx::query_file_as!(
                ClaimRecord,
                "queries/egress_policies/claiming.sql",
                service.as_str()
            )
            .fetch_all(connection)
            .await
        })
        .await
    }
}

#[async_trait]
impl CrossTenantEgressPolicies for PgCrossTenantEgressPolicies {
    async fn claiming(
        &self,
        service: &ServiceIdentity,
    ) -> Result<Vec<ClaimedEgressPolicy>, DomainError> {
        let apart = self.databases.with_own_database();
        let shared = self.claims_in(RowScope::Platform, service);
        let own = apart
            .iter()
            .map(|tenant| self.claims_in(RowScope::Tenant(*tenant), service));
        let (shared, own) = futures_util::try_join!(shared, try_join_all(own))?;
        let living_apart: HashSet<TenantId> = apart.into_iter().collect();
        shared
            .into_iter()
            .filter(|record| !living_apart.contains(&TenantId::from_uuid(record.tenant_id)))
            .chain(own.into_iter().flatten())
            .map(ClaimRecord::into_claim)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::routing::egress::EgressPolicyRow;
    use ianua_domain::types::{Label, TenantId};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::routing::egress_policy_row;

    struct Fixture {
        database: TestDb,
        store: PgEgressPolicyStore,
        tenant: ScopedTenant,
    }

    /// A fresh database, one tenant, and the store on it.
    async fn fixture() -> Fixture {
        let database = TestDb::fresh().await;
        let store = PgEgressPolicyStore::new(Arc::clone(&database.databases));
        Fixture {
            database,
            store,
            tenant: ScopedTenant::for_background(TenantId::new()),
        }
    }

    fn policy(row: EgressPolicyRow) -> EgressPolicy<ResolvedTenant> {
        EgressPolicy::reconstitute(row).unwrap()
    }

    fn for_service(name: &str, service: &str) -> EgressPolicy<ResolvedTenant> {
        policy(egress_policy_row(name, service))
    }

    /// A saved policy is found by its id and by its service, with its
    /// destinations and who made it.
    #[tokio::test]
    async fn a_saved_policy_is_found_by_its_id_and_its_service() {
        let db = fixture().await;
        let fetcher = for_service("fetcher", "spiffe://acme.example/fetcher");

        db.store.save(&db.tenant, &fetcher).await.unwrap();

        let by_id = db
            .store
            .find_by_id(&db.tenant, fetcher.id())
            .await
            .unwrap()
            .unwrap();
        let by_service = db
            .store
            .find_by_service(&db.tenant, fetcher.service())
            .await
            .unwrap()
            .unwrap();
        for found in [&by_id, &by_service] {
            assert_eq!(found.id(), fetcher.id());
            assert_eq!(found.destinations(), fetcher.destinations());
            assert_eq!(found.created_by(), fetcher.created_by());
            assert_eq!(found.max_data_class(), fetcher.max_data_class());
        }
    }

    /// A service with no policy finds none, and so reaches nothing.
    #[tokio::test]
    async fn a_service_without_a_policy_finds_none() {
        let db = fixture().await;
        let unknown = ServiceIdentity::new("spiffe://acme.example/unknown").unwrap();

        let found = db.store.find_by_service(&db.tenant, &unknown).await;
        let by_id = db
            .store
            .find_by_id(&db.tenant, &EgressPolicyId::new())
            .await;

        assert!(found.unwrap().is_none());
        assert!(by_id.unwrap().is_none());
    }

    /// Saving a second egress policy for the tenant's fetcher service
    /// returns a conflict.
    #[tokio::test]
    async fn a_second_policy_for_one_service_is_refused() {
        let db = fixture().await;
        db.store
            .save(
                &db.tenant,
                &for_service("one", "spiffe://acme.example/fetcher"),
            )
            .await
            .unwrap();

        let second = db
            .store
            .save(
                &db.tenant,
                &for_service("two", "spiffe://acme.example/fetcher"),
            )
            .await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
    }

    /// Another tenant cannot find Acme's egress policy by service, and its
    /// policy list is empty.
    #[tokio::test]
    async fn a_policy_is_invisible_to_another_tenant() {
        let db = fixture().await;
        let fetcher = for_service("fetcher", "spiffe://acme.example/fetcher");
        db.store.save(&db.tenant, &fetcher).await.unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        let found = db
            .store
            .find_by_service(&other, fetcher.service())
            .await
            .unwrap();
        let listed = db.store.list(&other).await.unwrap();

        assert!(found.is_none());
        assert!(listed.is_empty());
    }

    /// The tenant's policies list by name.
    #[tokio::test]
    async fn policies_are_listed_by_name() {
        let db = fixture().await;
        for (name, service) in [
            ("web", "spiffe://acme.example/web"),
            ("api", "spiffe://acme.example/api"),
        ] {
            db.store
                .save(&db.tenant, &for_service(name, service))
                .await
                .unwrap();
        }

        let listed = db.store.list(&db.tenant).await.unwrap();

        let names: Vec<&str> = listed.iter().map(|p| p.name().as_str()).collect();
        assert_eq!(names, ["api", "web"]);
    }

    /// Saving again keeps the new values, and a deleted policy is gone.
    #[tokio::test]
    async fn a_policy_is_changed_and_then_deleted() {
        let db = fixture().await;
        let fetcher = for_service("fetcher", "spiffe://acme.example/fetcher");
        db.store.save(&db.tenant, &fetcher).await.unwrap();
        let changed = policy(EgressPolicyRow {
            id: *fetcher.id(),
            name: Label::new("name", "renamed").unwrap(),
            max_data_class: DataClassLevel::Restricted,
            updated_at: at(5),
            ..egress_policy_row("fetcher", "spiffe://acme.example/fetcher")
        });

        db.store.save(&db.tenant, &changed).await.unwrap();
        let found = db
            .store
            .find_by_id(&db.tenant, fetcher.id())
            .await
            .unwrap()
            .unwrap();
        db.store.delete(&db.tenant, fetcher.id()).await.unwrap();
        let gone = db.store.find_by_id(&db.tenant, fetcher.id()).await.unwrap();

        assert_eq!(found.name().as_str(), "renamed");
        assert_eq!(found.max_data_class(), DataClassLevel::Restricted);
        assert!(gone.is_none());
    }

    /// The egress gateway, knowing only the fetcher's name, finds the
    /// policy each tenant wrote for it, each with its tenant, and none for
    /// another service.
    #[tokio::test]
    async fn every_tenants_policy_for_a_service_is_found_with_its_tenant() {
        let db = fixture().await;
        let other = ScopedTenant::for_background(TenantId::new());
        let ours = for_service("fetcher", "spiffe://acme.example/fetcher");
        let theirs = for_service("fetcher", "spiffe://acme.example/fetcher");
        db.store.save(&db.tenant, &ours).await.unwrap();
        db.store.save(&other, &theirs).await.unwrap();
        db.store
            .save(&db.tenant, &for_service("web", "spiffe://acme.example/web"))
            .await
            .unwrap();
        let claims = PgCrossTenantEgressPolicies::new(Arc::clone(&db.database.databases));

        let found = claims.claiming(ours.service()).await.unwrap();

        let mut tenants: Vec<TenantId> = found.iter().map(|claim| claim.tenant_id).collect();
        tenants.sort_by_key(|tenant| *tenant.as_uuid());
        let mut expected = vec![*db.tenant, *other];
        expected.sort_by_key(|tenant| *tenant.as_uuid());
        assert_eq!(tenants, expected);
        assert!(
            found
                .iter()
                .all(|claim| claim.policy.service() == ours.service())
        );
    }

    /// An egress policy with no stored destinations fails to load as
    /// corrupt storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_policy_is_refused() {
        let db = fixture().await;
        let fetcher = for_service("fetcher", "spiffe://acme.example/fetcher");
        db.store.save(&db.tenant, &fetcher).await.unwrap();
        db.database
            .tamper("UPDATE egress_policies SET destinations = '{\"v\": 1, \"value\": []}'")
            .await;

        let read = db.store.find_by_id(&db.tenant, fetcher.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
