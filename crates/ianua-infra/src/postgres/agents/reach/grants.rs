//! Who holds which relation on which named resource of a tenant, each
//! table row under row-level security: written by the grant store, read
//! by the resolver delegation consults before a principal hands a resource
//! on.
//!
//! The two are separate adapters over one table, so the read path a
//! decision depends on cannot widen itself. A relation is matched exactly:
//! nothing records that one relation implies another, so holding `owner`
//! does not answer a question about `reader`. A relation nobody recorded
//! is not held.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::agents::{RelationshipResolver, ResourceGrantStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::agents::authority::capability::{
    Relation, ResourceCapability, ResourceRef,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::PrincipalRef;

use self::record::{GrantRecord, PrincipalColumns, WantedColumns};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of resource grants.
pub struct PgResourceGrantStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgResourceGrantStore {}

impl PgResourceGrantStore {
    /// A store keeping resource grants in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

/// The Postgres resolver of the relations principals hold on named
/// resources.
pub struct PgRelationshipResolver {
    databases: Arc<Databases>,
}

impl TenantScoped for PgRelationshipResolver {}

impl PgRelationshipResolver {
    /// A resolver reading the resource grants in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// The ones of `wanted` that `subject` holds in `tenant`, read in one
    /// query.
    async fn held(
        &self,
        tenant: &ScopedTenant,
        subject: &PrincipalRef,
        wanted: &[ResourceCapability],
    ) -> Result<Vec<ResourceCapability>, DomainError> {
        let holder = PrincipalColumns::of(subject);
        let asked = WantedColumns::of(wanted);
        let records = scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| {
                sqlx::query_file_as!(
                    GrantRecord,
                    "queries/resource_grants/held.sql",
                    tenant.as_uuid(),
                    holder.kind,
                    holder.id,
                    &asked.relations,
                    &asked.object_refs
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records
            .into_iter()
            .map(GrantRecord::into_capability)
            .collect()
    }
}

#[async_trait]
impl RelationshipResolver for PgRelationshipResolver {
    async fn check(
        &self,
        tenant_id: &ScopedTenant,
        subject: &PrincipalRef,
        relation: &Relation,
        object: &ResourceRef,
    ) -> Result<bool, DomainError> {
        let wanted = [ResourceCapability::new(relation.clone(), object.clone())];
        let held = self.held(tenant_id, subject, &wanted).await?;
        Ok(!held.is_empty())
    }

    async fn held_subset(
        &self,
        tenant_id: &ScopedTenant,
        subject: &PrincipalRef,
        wanted: &[ResourceCapability],
    ) -> Result<Vec<ResourceCapability>, DomainError> {
        let held = self.held(tenant_id, subject, wanted).await?;
        Ok(wanted
            .iter()
            .filter(|capability| held.contains(capability))
            .cloned()
            .collect())
    }
}

#[async_trait]
impl ResourceGrantStore for PgResourceGrantStore {
    async fn grant(
        &self,
        tenant_id: &ScopedTenant,
        subject: &PrincipalRef,
        capability: &ResourceCapability,
        granted_by: &PrincipalRef,
    ) -> Result<(), DomainError> {
        let (holder, giver) = (
            PrincipalColumns::of(subject),
            PrincipalColumns::of(granted_by),
        );
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/resource_grants/grant.sql",
                    tenant_id.as_uuid(),
                    holder.kind,
                    holder.id,
                    capability.relation().as_str(),
                    capability.resource_ref().as_str(),
                    giver.kind,
                    giver.id
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn revoke(
        &self,
        tenant_id: &ScopedTenant,
        subject: &PrincipalRef,
        capability: &ResourceCapability,
    ) -> Result<(), DomainError> {
        let holder = PrincipalColumns::of(subject);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/resource_grants/revoke.sql",
                    tenant_id.as_uuid(),
                    holder.kind,
                    holder.id,
                    capability.relation().as_str(),
                    capability.resource_ref().as_str()
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::{AgentId, TenantId, UserId};

    use super::*;
    use crate::test_support::TestDb;

    fn holds(relation: &str, object: &str) -> ResourceCapability {
        ResourceCapability::new(
            Relation::new(relation).unwrap(),
            ResourceRef::new(object).unwrap(),
        )
    }

    /// A fresh database, the grant store and the resolver on it, and one
    /// tenant to keep grants in.
    async fn fixture() -> (
        TestDb,
        PgResourceGrantStore,
        PgRelationshipResolver,
        ScopedTenant,
    ) {
        let db = TestDb::fresh().await;
        let store = PgResourceGrantStore::new(Arc::clone(&db.databases));
        let resolver = PgRelationshipResolver::new(Arc::clone(&db.databases));
        (
            db,
            store,
            resolver,
            ScopedTenant::for_background(TenantId::new()),
        )
    }

    fn ann() -> PrincipalRef {
        PrincipalRef::User(UserId::new())
    }

    /// Ann is granted read access to a calendar twice: she holds exactly
    /// that, and no other relation or calendar.
    #[tokio::test]
    async fn a_granted_relation_is_held_exactly() {
        let (_db, store, resolver, tenant) = fixture().await;
        let (ann, admin) = (ann(), ann());
        let reading = holds("reader", "calendar:q1");
        store.grant(&tenant, &ann, &reading, &admin).await.unwrap();
        store.grant(&tenant, &ann, &reading, &admin).await.unwrap();

        let held = resolver
            .check(&tenant, &ann, reading.relation(), reading.resource_ref())
            .await
            .unwrap();
        let other_relation = resolver
            .check(
                &tenant,
                &ann,
                &Relation::new("owner").unwrap(),
                reading.resource_ref(),
            )
            .await
            .unwrap();
        let by_admin = resolver
            .check(&tenant, &admin, reading.relation(), reading.resource_ref())
            .await
            .unwrap();

        assert!(held);
        assert!(!other_relation);
        assert!(!by_admin);
    }

    /// Of several relations asked for at once, the held ones come back in
    /// the order asked; an agent holds its own grants apart from a person.
    #[tokio::test]
    async fn the_held_subset_keeps_the_order_asked() {
        let (_db, store, resolver, tenant) = fixture().await;
        let (ann, admin) = (ann(), ann());
        let agent = PrincipalRef::Agent(AgentId::new());
        let [q1, q2, q3] =
            ["calendar:q1", "calendar:q2", "calendar:q3"].map(|object| holds("reader", object));
        store.grant(&tenant, &ann, &q3, &admin).await.unwrap();
        store.grant(&tenant, &ann, &q1, &admin).await.unwrap();
        store.grant(&tenant, &agent, &q2, &ann).await.unwrap();

        let held = resolver
            .held_subset(&tenant, &ann, &[q1.clone(), q2.clone(), q3.clone()])
            .await
            .unwrap();
        let none = resolver.held_subset(&tenant, &ann, &[]).await.unwrap();

        assert_eq!(held, [q1, q3]);
        assert!(none.is_empty());
    }

    /// A revoked relation is no longer held, and revoking one never held
    /// changes nothing.
    #[tokio::test]
    async fn a_revoked_relation_is_no_longer_held() {
        let (_db, store, resolver, tenant) = fixture().await;
        let (ann, admin) = (ann(), ann());
        let reading = holds("reader", "calendar:q1");
        store.grant(&tenant, &ann, &reading, &admin).await.unwrap();

        store.revoke(&tenant, &ann, &reading).await.unwrap();
        store.revoke(&tenant, &ann, &reading).await.unwrap();

        let held = resolver
            .check(&tenant, &ann, reading.relation(), reading.resource_ref())
            .await
            .unwrap();
        assert!(!held);
    }

    /// Checking Ann's resource grant in another tenant returns false.
    #[tokio::test]
    async fn a_grant_is_held_only_in_its_tenant() {
        let (_db, store, resolver, tenant) = fixture().await;
        let (ann, admin) = (ann(), ann());
        let reading = holds("reader", "calendar:q1");
        store.grant(&tenant, &ann, &reading, &admin).await.unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        let elsewhere = resolver
            .check(&other, &ann, reading.relation(), reading.resource_ref())
            .await
            .unwrap();

        assert!(!elsewhere);
    }

    /// A grant of a tenant with a database of its own is kept there, and
    /// not in the platform database.
    #[tokio::test]
    async fn a_grant_of_a_tenant_with_its_own_database_is_kept_there() {
        let (db, store, resolver, _) = fixture().await;
        let own = TestDb::fresh().await;
        let apart = ScopedTenant::for_background(TenantId::new());
        db.databases.register(*apart, own.as_dedicated());
        let (ann, admin) = (ann(), ann());
        let reading = holds("reader", "calendar:q1");
        store.grant(&apart, &ann, &reading, &admin).await.unwrap();

        let in_its_own = resolver
            .check(&apart, &ann, reading.relation(), reading.resource_ref())
            .await
            .unwrap();
        db.databases.deregister(&apart);
        let in_the_platform = resolver
            .check(&apart, &ann, reading.relation(), reading.resource_ref())
            .await
            .unwrap();

        assert!(in_its_own);
        assert!(!in_the_platform);
    }
}
