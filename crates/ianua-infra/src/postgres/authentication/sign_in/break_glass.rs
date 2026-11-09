//! Break-glass grants and each tenant's break-glass policy, under the
//! tenant's row-level security.
//!
//! The grants are the rows the authorization context reads among a
//! tenant's access records, through the same mapping. A tenant that never
//! set a policy has no row, which reads as self-service switched off.

pub(crate) mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authentication::BreakGlassStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authorization::break_glass::{BreakGlassGrant, BreakGlassPolicy};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{BreakGlassGrantId, TenantId};
use sqlx::PgConnection;

use self::record::{BreakGlassColumns, BreakGlassRecord, PolicyColumns, PolicyRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of break-glass grants and policies.
pub struct PgBreakGlassStore {
    databases: Arc<Databases>,
}

impl PgBreakGlassStore {
    /// A store keeping grants and policies in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgBreakGlassStore {}

/// Refuses a record made in `held_in` from being kept in `tenant_id`.
fn ensure_kept_in(
    tenant_id: &ScopedTenant,
    held_in: &TenantId,
    what: &'static str,
) -> Result<(), DomainError> {
    if held_in != &**tenant_id {
        return Err(DomainError::invalid(what));
    }
    Ok(())
}

/// Writes `grant` in `tenant_id`, and says how many rows took it: none when
/// the stored grant is another user's or was revoked already.
async fn write_grant(
    connection: &mut PgConnection,
    tenant_id: &TenantId,
    grant: &BreakGlassColumns<'_>,
) -> Result<u64, sqlx::Error> {
    let written = sqlx::query_file!(
        "queries/break_glass_grants/save.sql",
        grant.id,
        tenant_id.as_uuid(),
        grant.user_id,
        grant.grantee_person,
        &grant.system_permissions,
        &grant.custom_permissions,
        grant.reason,
        grant.approver_kind,
        grant.approver_id,
        grant.approver_person,
        grant.expires_at,
        grant.revoked_at,
        grant.created_at,
    )
    .execute(connection)
    .await?;
    Ok(written.rows_affected())
}

#[async_trait]
impl BreakGlassStore for PgBreakGlassStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &BreakGlassGrantId,
    ) -> Result<Option<BreakGlassGrant>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    BreakGlassRecord,
                    "queries/break_glass_grants/by_id.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record
            .map(|grant| grant.into_grant(**tenant_id))
            .transpose()
    }

    async fn list(&self, tenant_id: &ScopedTenant) -> Result<Vec<BreakGlassGrant>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    BreakGlassRecord,
                    "queries/break_glass_grants/of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records
            .into_iter()
            .map(|grant| grant.into_grant(**tenant_id))
            .collect()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        grant: &BreakGlassGrant,
    ) -> Result<(), DomainError> {
        ensure_kept_in(
            tenant_id,
            grant.tenant_id(),
            "a break-glass grant is kept in the tenant it was given in",
        )?;
        let columns = BreakGlassColumns::of(grant);
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| write_grant(connection, tenant_id, &columns).await,
        )
        .await?;
        match written {
            0 => Err(DomainError::conflict(message!(
                "infra-this-break-glass-grant-is-another",
                "this break-glass grant is another user's, or was revoked already"
            ))),
            _ => Ok(()),
        }
    }

    async fn find_policy(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<BreakGlassPolicy>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    PolicyRecord,
                    "queries/break_glass_policies/of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record
            .map(|policy| policy.into_policy(**tenant_id))
            .transpose()
    }

    async fn save_policy(
        &self,
        tenant_id: &ScopedTenant,
        policy: &BreakGlassPolicy,
    ) -> Result<(), DomainError> {
        ensure_kept_in(
            tenant_id,
            policy.tenant_id(),
            "a break-glass policy is kept in the tenant it applies in",
        )?;
        let columns = PolicyColumns::of(policy);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/break_glass_policies/save.sql",
                    tenant_id.as_uuid(),
                    columns.self_service_system.as_deref(),
                    columns.self_service_custom.as_deref(),
                    columns.updated_at
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
    use ianua_app::ports::identity::UserStore;
    use ianua_domain::domains::authorization::break_glass::{
        BreakGlassGrantRow, BreakGlassPolicyRow, SelfService,
    };
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::{Revocation, UserId};

    use super::*;
    use crate::postgres::identity::PgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authentication::{grant_row, policy_row, viewing_users};
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::identity::user_row;

    /// A fresh database holding Ann in Acme, and the store on it.
    async fn fixture() -> (TestDb, PgBreakGlassStore, ScopedTenant, UserId) {
        let db = TestDb::fresh().await;
        let acme = tenant();
        let ann = User::reconstitute(user_row("ann@acme.example")).unwrap();
        PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&acme, &ann)
            .await
            .unwrap();
        let store = PgBreakGlassStore::new(Arc::clone(&db.databases));
        (db, store, acme, *ann.id())
    }

    fn grant(row: BreakGlassGrantRow) -> BreakGlassGrant {
        BreakGlassGrant::reconstitute(row).unwrap()
    }

    /// Ann's grants are found by id and listed oldest first, as they were
    /// saved.
    #[tokio::test]
    async fn saved_grants_are_found_and_listed() {
        let (_db, store, acme, ann) = fixture().await;
        let first = grant(grant_row(*acme, ann, 0));
        let second = grant(grant_row(*acme, ann, 60));
        store.save(&acme, &second).await.unwrap();
        store.save(&acme, &first).await.unwrap();

        let found = store.find_by_id(&acme, first.id()).await.unwrap().unwrap();
        let listed = store.list(&acme).await.unwrap();

        assert_eq!(found.user_id(), &ann);
        assert_eq!(found.access(), &viewing_users());
        assert_eq!(found.expires_at(), first.expires_at());
        let ids: Vec<&BreakGlassGrantId> = listed.iter().map(BreakGlassGrant::id).collect();
        assert_eq!(ids, [first.id(), second.id()]);
    }

    /// An id nobody was granted finds nothing.
    #[tokio::test]
    async fn an_unknown_grant_is_not_found() {
        let (_db, store, acme, _) = fixture().await;

        assert!(
            store
                .find_by_id(&acme, &BreakGlassGrantId::new())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Ann's grant is revoked: saving it again keeps when.
    #[tokio::test]
    async fn saving_again_keeps_the_revocation() {
        let (_db, store, acme, ann) = fixture().await;
        let given = grant(grant_row(*acme, ann, 0));
        store.save(&acme, &given).await.unwrap();
        let revoked = grant(BreakGlassGrantRow {
            id: *given.id(),
            revocation: Revocation::Revoked { at: at(30) },
            ..grant_row(*acme, ann, 0)
        });

        store.save(&acme, &revoked).await.unwrap();

        let found = store.find_by_id(&acme, given.id()).await.unwrap().unwrap();
        assert_eq!(found.revoked_at(), Some(at(30)));
    }

    /// Neither a stale grant nor a later revocation can overwrite Ann's
    /// revoked grant; both saves conflict and its original revocation time remains.
    #[tokio::test]
    async fn a_stale_save_does_not_undo_a_revocation() {
        let (_db, store, acme, ann) = fixture().await;
        let given = grant(grant_row(*acme, ann, 0));
        store.save(&acme, &given).await.unwrap();
        let revoked = grant(BreakGlassGrantRow {
            id: *given.id(),
            revocation: Revocation::Revoked { at: at(30) },
            ..grant_row(*acme, ann, 0)
        });
        store.save(&acme, &revoked).await.unwrap();
        let revoked_later = grant(BreakGlassGrantRow {
            id: *given.id(),
            revocation: Revocation::Revoked { at: at(40) },
            ..grant_row(*acme, ann, 0)
        });

        let stale = store.save(&acme, &given).await;
        let again = store.save(&acme, &revoked_later).await;

        assert!(matches!(stale, Err(DomainError::Conflict(_))));
        assert!(matches!(again, Err(DomainError::Conflict(_))));
        let found = store.find_by_id(&acme, given.id()).await.unwrap().unwrap();
        assert_eq!(found.revoked_at(), Some(at(30)));
    }

    /// Saving a Globex grant through Acme's scope fails validation and
    /// leaves Acme's grant list empty.
    #[tokio::test]
    async fn a_grant_of_another_tenant_is_refused() {
        let (_db, store, acme, ann) = fixture().await;
        let globex = tenant();

        let saved = store.save(&acme, &grant(grant_row(*globex, ann, 0))).await;

        assert!(matches!(saved, Err(DomainError::Validation(_))));
        assert!(store.list(&acme).await.unwrap().is_empty());
    }

    /// A tenant that never set a policy has none; one it set reads back,
    /// and switching self-service off is kept too.
    #[tokio::test]
    async fn a_policy_is_kept_per_tenant() {
        let (_db, store, acme, _) = fixture().await;
        assert!(store.find_policy(&acme).await.unwrap().is_none());

        store
            .save_policy(
                &acme,
                &BreakGlassPolicy::reconstitute(policy_row(*acme)).unwrap(),
            )
            .await
            .unwrap();
        let set = store.find_policy(&acme).await.unwrap().unwrap();
        store
            .save_policy(
                &acme,
                &BreakGlassPolicy::reconstitute(BreakGlassPolicyRow {
                    self_service: SelfService::Off,
                    updated_at: at(50),
                    ..policy_row(*acme)
                })
                .unwrap(),
            )
            .await
            .unwrap();
        let off = store.find_policy(&acme).await.unwrap().unwrap();

        assert_eq!(set.self_service(), &SelfService::UpTo(viewing_users()));
        assert_eq!(off.self_service(), &SelfService::Off);
        assert_eq!(off.updated_at(), at(50));
    }

    /// Globex cannot find or list Acme's break-glass grant or read its policy.
    #[tokio::test]
    async fn another_tenants_grants_and_policy_are_invisible() {
        let (_db, store, acme, ann) = fixture().await;
        let given = grant(grant_row(*acme, ann, 0));
        store.save(&acme, &given).await.unwrap();
        store
            .save_policy(
                &acme,
                &BreakGlassPolicy::reconstitute(policy_row(*acme)).unwrap(),
            )
            .await
            .unwrap();
        let globex = tenant();

        assert!(
            store
                .find_by_id(&globex, given.id())
                .await
                .unwrap()
                .is_none()
        );
        assert!(store.list(&globex).await.unwrap().is_empty());
        assert!(store.find_policy(&globex).await.unwrap().is_none());
    }

    /// Unknown permissions written into a grant and policy cause both
    /// reads to fail as corrupt storage.
    #[tokio::test]
    async fn an_unknown_permission_is_refused() {
        let (db, store, acme, ann) = fixture().await;
        let given = grant(grant_row(*acme, ann, 0));
        store.save(&acme, &given).await.unwrap();
        store
            .save_policy(
                &acme,
                &BreakGlassPolicy::reconstitute(policy_row(*acme)).unwrap(),
            )
            .await
            .unwrap();
        db.tamper(
            "UPDATE break_glass_grants SET system_permissions = ARRAY['idp:nothing:never']; \
             UPDATE break_glass_policies SET self_service_system = ARRAY['idp:nothing:never']",
        )
        .await;

        let read_grant = store.find_by_id(&acme, given.id()).await;
        let read_policy = store.find_policy(&acme).await;

        assert!(matches!(read_grant, Err(DomainError::Infrastructure(_))));
        assert!(matches!(read_policy, Err(DomainError::Infrastructure(_))));
    }
}
