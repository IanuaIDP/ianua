//! The devices people trust to skip their second factor, under the
//! tenant's row-level security. Only the hash of the secret a device
//! presents is kept. A revoked device takes nothing new, so a sign-in that
//! read it before the revocation never trusts it again.
//!
//! The gateway's role reads only a device's standing, whose it is and
//! whether it is still trusted, for a device posture check: its grant
//! leaves the secret's digest, name, address and client out.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authentication::TrustedDeviceStore;
use ianua_app::ports::proxy::DeviceStandings;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authentication::device_trust::{DeviceStanding, TrustedDevice};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{TrustedDeviceId, UserId};

use self::record::{DeviceColumns, DeviceRecord, StandingRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of trusted devices.
pub struct PgTrustedDeviceStore {
    databases: Arc<Databases>,
}

impl PgTrustedDeviceStore {
    /// A store keeping trusted devices in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgTrustedDeviceStore {}

/// The Postgres reader of trusted devices' standings, as the gateway's role
/// reads them.
pub struct PgDeviceStandings {
    databases: Arc<Databases>,
}

impl PgDeviceStandings {
    /// A reader of the standings kept in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgDeviceStandings {}

#[async_trait]
impl TrustedDeviceStore for PgTrustedDeviceStore {
    async fn list_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<TrustedDevice<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    DeviceRecord,
                    "queries/trusted_devices/of_user.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records.into_iter().map(DeviceRecord::into_device).collect()
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &TrustedDeviceId,
    ) -> Result<Option<TrustedDevice<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    DeviceRecord,
                    "queries/trusted_devices/by_id.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(DeviceRecord::into_device).transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        device: &TrustedDevice<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = DeviceColumns::of(device);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/trusted_devices/save.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.user_id,
                    columns.secret_hash,
                    columns.device_name,
                    columns.last_user_agent,
                    columns.last_ip,
                    columns.status,
                    columns.last_seen_at,
                    columns.created_at,
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &TrustedDeviceId,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/trusted_devices/delete.sql",
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

#[async_trait]
impl DeviceStandings for PgDeviceStandings {
    async fn standing_of(
        &self,
        tenant_id: &ScopedTenant,
        device: &TrustedDeviceId,
    ) -> Result<Option<DeviceStanding>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    StandingRecord,
                    "queries/trusted_devices/standing.sql",
                    tenant_id.as_uuid(),
                    device.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(StandingRecord::into_standing).transpose()
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::identity::UserStore;
    use ianua_domain::domains::authentication::device_status::DeviceStatus;
    use ianua_domain::domains::authentication::device_trust::TrustedDeviceRow;
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::PrincipalId;

    use super::*;
    use crate::postgres::identity::PgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authentication::device_row;
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::identity::user_row;

    /// A fresh database holding Ann and Bob in Acme, and the store on it.
    async fn fixture() -> (TestDb, PgTrustedDeviceStore, ScopedTenant, UserId, UserId) {
        let db = TestDb::fresh().await;
        let acme = tenant();
        let users = PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default());
        let mut ids = Vec::new();
        for email in ["ann@acme.example", "bob@acme.example"] {
            let user = User::reconstitute(user_row(email)).unwrap();
            users.save(&acme, &user).await.unwrap();
            ids.push(*user.id());
        }
        let store = PgTrustedDeviceStore::new(Arc::clone(&db.databases));
        (db, store, acme, ids[0], ids[1])
    }

    fn device(row: TrustedDeviceRow) -> TrustedDevice<ResolvedTenant> {
        TrustedDevice::reconstitute(row).unwrap()
    }

    /// Ann's two devices are listed in the order she trusted them, and one
    /// is found by its id; Bob's is not among hers.
    #[tokio::test]
    async fn saved_devices_are_listed_and_found_by_id() {
        let (_db, store, acme, ann, bob) = fixture().await;
        let laptop = device(device_row(ann));
        let phone = device(TrustedDeviceRow {
            created_at: at(10),
            last_seen_at: at(10),
            ..device_row(ann)
        });
        for held in [&laptop, &phone, &device(device_row(bob))] {
            store.save(&acme, held).await.unwrap();
        }

        let listed = store.list_by_user(&acme, &ann).await.unwrap();
        let found = store.find_by_id(&acme, phone.id()).await.unwrap().unwrap();

        let ids: Vec<&TrustedDeviceId> = listed.iter().map(TrustedDevice::id).collect();
        assert_eq!(ids, [laptop.id(), phone.id()]);
        assert_eq!(found.secret_hash(), phone.secret_hash());
        assert_eq!(found.device_name(), phone.device_name());
    }

    /// An id nobody trusted finds nothing.
    #[tokio::test]
    async fn an_unknown_device_is_not_found() {
        let (_db, store, acme, _, _) = fixture().await;

        assert!(
            store
                .find_by_id(&acme, &TrustedDeviceId::new())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Ann revokes her laptop: saving it again keeps the new status, and
    /// deleting it removes it.
    #[tokio::test]
    async fn a_device_is_revoked_and_deleted() {
        let (_db, store, acme, ann, _) = fixture().await;
        let laptop = device(device_row(ann));
        store.save(&acme, &laptop).await.unwrap();
        let revoked = device(TrustedDeviceRow {
            id: *laptop.id(),
            secret_hash: laptop.secret_hash().clone(),
            status: DeviceStatus::Revoked,
            ..device_row(ann)
        });

        store.save(&acme, &revoked).await.unwrap();
        let after_revoke = store.find_by_id(&acme, laptop.id()).await.unwrap().unwrap();
        store.delete(&acme, laptop.id()).await.unwrap();

        assert_eq!(after_revoke.status(), DeviceStatus::Revoked);
        assert!(
            store
                .find_by_id(&acme, laptop.id())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Saving a trusted-device copy read before revocation leaves Ann's
    /// laptop revoked.
    #[tokio::test]
    async fn a_save_never_trusts_a_revoked_device_again() {
        let (_db, store, acme, ann, _) = fixture().await;
        let stale = device(device_row(ann));
        store.save(&acme, &stale).await.unwrap();
        let revoked = device(TrustedDeviceRow {
            id: *stale.id(),
            secret_hash: stale.secret_hash().clone(),
            status: DeviceStatus::Revoked,
            ..device_row(ann)
        });
        store.save(&acme, &revoked).await.unwrap();

        store.save(&acme, &stale).await.unwrap();

        let found = store.find_by_id(&acme, stale.id()).await.unwrap().unwrap();
        assert_eq!(found.status(), DeviceStatus::Revoked);
    }

    /// Globex cannot find Ann's laptop, and a delete from Globex leaves it
    /// in Acme's device list.
    #[tokio::test]
    async fn another_tenants_devices_are_invisible() {
        let (_db, store, acme, ann, _) = fixture().await;
        let laptop = device(device_row(ann));
        store.save(&acme, &laptop).await.unwrap();
        let globex = tenant();

        let found = store.find_by_id(&globex, laptop.id()).await.unwrap();
        store.delete(&globex, laptop.id()).await.unwrap();

        assert!(found.is_none());
        assert_eq!(store.list_by_user(&acme, &ann).await.unwrap().len(), 1);
    }

    /// An invalid IP address written directly to a device row causes the
    /// device list to fail as corrupt storage.
    #[tokio::test]
    async fn a_device_with_a_broken_address_is_refused() {
        let (db, store, acme, ann, _) = fixture().await;
        store.save(&acme, &device(device_row(ann))).await.unwrap();
        db.tamper("UPDATE trusted_devices SET last_ip = 'not an address'")
            .await;

        let read = store.list_by_user(&acme, &ann).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// The gateway reads, as its own role, whose Ann's laptop is and that
    /// she still trusts it, and once she revokes it, that she does not.
    #[tokio::test]
    async fn the_gateway_reads_a_devices_standing() {
        let (db, store, acme, ann, bob) = fixture().await;
        let laptop = device(device_row(ann));
        store.save(&acme, &laptop).await.unwrap();
        let gateway = PgDeviceStandings::new(Arc::clone(&db.gateway));

        let trusted = gateway.standing_of(&acme, laptop.id()).await.unwrap();
        let revoked = device(TrustedDeviceRow {
            id: *laptop.id(),
            secret_hash: laptop.secret_hash().clone(),
            status: DeviceStatus::Revoked,
            ..device_row(ann)
        });
        store.save(&acme, &revoked).await.unwrap();
        let after = gateway.standing_of(&acme, laptop.id()).await.unwrap();

        let trusted = trusted.unwrap();
        assert!(trusted.is_trusted_by(PrincipalId::from(ann)));
        assert!(!trusted.is_trusted_by(PrincipalId::from(bob)));
        assert!(!after.unwrap().is_trusted_by(PrincipalId::from(ann)));
    }

    /// The gateway finds no standing for an unknown device or for Ann's
    /// device when queried from another tenant.
    #[tokio::test]
    async fn an_unknown_or_other_tenants_device_has_no_standing() {
        let (db, store, acme, ann, _) = fixture().await;
        let laptop = device(device_row(ann));
        store.save(&acme, &laptop).await.unwrap();
        let gateway = PgDeviceStandings::new(Arc::clone(&db.gateway));

        let unknown = gateway
            .standing_of(&acme, &TrustedDeviceId::new())
            .await
            .unwrap();
        let elsewhere = gateway.standing_of(&tenant(), laptop.id()).await.unwrap();

        assert!(unknown.is_none());
        assert!(elsewhere.is_none());
    }
}
