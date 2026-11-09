//! The devices members trust to skip their second factor, kept in the
//! platform database.
//!
//! A device belongs to the member who remembered it, so every read names
//! that member, and a device of anyone else reads as absent. Its owner never
//! changes once it is kept, and a revoked device takes nothing new, so a
//! sign-in that read it before the revocation never trusts it again.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::organization::OrgTrustedDeviceStore;
use ianua_domain::domains::authentication::device_trust::TrustedDevice;
use ianua_domain::isolation::organization::scope::ResolvedOrganization;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrgUserId, TrustedDeviceId};

use self::record::{DeviceColumns, DeviceRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of the devices members trust.
pub struct PgOrgTrustedDeviceStore {
    databases: Arc<Databases>,
}

impl PgOrgTrustedDeviceStore {
    /// A store keeping trusted devices in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl OrgTrustedDeviceStore for PgOrgTrustedDeviceStore {
    async fn list_by_user(
        &self,
        org_user_id: &OrgUserId,
    ) -> Result<Vec<TrustedDevice<ResolvedOrganization>>, DomainError> {
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                DeviceRecord,
                "queries/org_trusted_devices/of_member.sql",
                org_user_id.as_uuid()
            )
            .fetch_all(connection)
            .await
        })
        .await?;
        records.into_iter().map(DeviceRecord::into_device).collect()
    }

    async fn find_by_id(
        &self,
        org_user_id: &OrgUserId,
        id: &TrustedDeviceId,
    ) -> Result<Option<TrustedDevice<ResolvedOrganization>>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                DeviceRecord,
                "queries/org_trusted_devices/one_of_member.sql",
                org_user_id.as_uuid(),
                id.as_uuid()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        record.map(DeviceRecord::into_device).transpose()
    }

    async fn save(
        &self,
        org_user_id: &OrgUserId,
        device: &TrustedDevice<ResolvedOrganization>,
    ) -> Result<(), DomainError> {
        let columns = DeviceColumns::of(org_user_id, device)?;
        let written = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            let done = sqlx::query_file!(
                "queries/org_trusted_devices/save.sql",
                columns.id,
                columns.org_user_id,
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
            Ok(done.rows_affected())
        })
        .await?;
        match written {
            0 => Err(DomainError::conflict(message!(
                "infra-this-device-is-kept-for-another",
                "this device is kept for another member, or was revoked"
            ))),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::organization::{OrgUserStore, OrganizationStore};
    use ianua_domain::domains::authentication::device_status::DeviceStatus;
    use ianua_domain::domains::authentication::device_trust::TrustedDeviceRow;
    use ianua_domain::domains::organization::lifecycle::Organization;
    use ianua_domain::domains::organization::members::org_user::OrgUser;
    use ianua_domain::shared::config::DomainLimits;

    use super::*;
    use crate::postgres::organization::{PgOrgUserStore, PgOrganizationStore};
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::organization::{
        org_trusted_device_row, org_user_row, organization_row,
    };

    struct Fixture {
        database: TestDb,
        store: PgOrgTrustedDeviceStore,
        ann: OrgUserId,
        bob: OrgUserId,
    }

    /// A fresh database holding Acme with two members, Ann and Bob, and the
    /// store on it.
    async fn fixture() -> Fixture {
        let database = TestDb::fresh().await;
        let acme = Organization::reconstitute(organization_row("acme", "Acme")).unwrap();
        PgOrganizationStore::new(Arc::clone(&database.databases), DomainLimits::default())
            .save(&acme)
            .await
            .unwrap();
        let members = PgOrgUserStore::new(Arc::clone(&database.databases), DomainLimits::default());
        let mut ids = Vec::new();
        for email in ["ann@acme.example", "bob@acme.example"] {
            let member = OrgUser::reconstitute(org_user_row(*acme.id(), email)).unwrap();
            members.save(&member).await.unwrap();
            ids.push(*member.id());
        }
        let store = PgOrgTrustedDeviceStore::new(Arc::clone(&database.databases));
        Fixture {
            database,
            store,
            ann: ids.remove(0),
            bob: ids.remove(0),
        }
    }

    fn device(row: TrustedDeviceRow) -> TrustedDevice<ResolvedOrganization> {
        TrustedDevice::reconstitute(row).unwrap()
    }

    fn ids(devices: &[TrustedDevice<ResolvedOrganization>]) -> Vec<TrustedDeviceId> {
        devices.iter().map(|device| *device.id()).collect()
    }

    /// Ann trusts her laptop and her phone: both are listed for her in the
    /// order she trusted them, and each is found again as it was saved.
    #[tokio::test]
    async fn a_members_devices_are_listed_and_found_as_saved() {
        let db = fixture().await;
        let laptop = device(org_trusted_device_row(db.ann));
        let phone = device(TrustedDeviceRow {
            created_at: at(5),
            last_seen_at: at(5),
            ..org_trusted_device_row(db.ann)
        });

        db.store.save(&db.ann, &phone).await.unwrap();
        db.store.save(&db.ann, &laptop).await.unwrap();

        let listed = db.store.list_by_user(&db.ann).await.unwrap();
        assert_eq!(ids(&listed), [*laptop.id(), *phone.id()]);
        let found = db
            .store
            .find_by_id(&db.ann, laptop.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.subject_id(), laptop.subject_id());
        assert_eq!(found.secret_hash(), laptop.secret_hash());
        assert_eq!(found.device_name(), laptop.device_name());
        assert_eq!(found.last_ip(), laptop.last_ip());
        assert_eq!(found.last_user_agent(), laptop.last_user_agent());
        assert_eq!(found.status(), DeviceStatus::Trusted);
        assert_eq!(found.created_at(), laptop.created_at());
    }

    /// Ann's stored laptop is absent from Bob's device lookup and list.
    #[tokio::test]
    async fn another_members_device_reads_as_absent() {
        let db = fixture().await;
        let laptop = device(org_trusted_device_row(db.ann));
        db.store.save(&db.ann, &laptop).await.unwrap();

        let found = db.store.find_by_id(&db.bob, laptop.id()).await.unwrap();
        let listed = db.store.list_by_user(&db.bob).await.unwrap();

        assert!(found.is_none());
        assert!(listed.is_empty());
    }

    /// An id nobody has finds nothing, rather than failing.
    #[tokio::test]
    async fn an_unknown_device_is_not_found() {
        let db = fixture().await;

        let found = db
            .store
            .find_by_id(&db.ann, &TrustedDeviceId::new())
            .await
            .unwrap();

        assert!(found.is_none());
    }

    /// Ann revokes her laptop after using it again: saving it keeps both
    /// the revocation and when it was last seen.
    #[tokio::test]
    async fn saving_again_keeps_the_new_values() {
        let db = fixture().await;
        let laptop = device(org_trusted_device_row(db.ann));
        db.store.save(&db.ann, &laptop).await.unwrap();
        let revoked = device(TrustedDeviceRow {
            id: *laptop.id(),
            status: DeviceStatus::Revoked,
            last_seen_at: at(9),
            ..org_trusted_device_row(db.ann)
        });

        db.store.save(&db.ann, &revoked).await.unwrap();

        let found = db
            .store
            .find_by_id(&db.ann, laptop.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.status(), DeviceStatus::Revoked);
        assert_eq!(found.last_seen_at(), at(9));
    }

    /// Saving a stale trusted copy after revoking Ann's laptop returns a
    /// conflict and leaves the stored device revoked.
    #[tokio::test]
    async fn a_save_never_trusts_a_revoked_device_again() {
        let db = fixture().await;
        let stale = device(org_trusted_device_row(db.ann));
        db.store.save(&db.ann, &stale).await.unwrap();
        let revoked = device(TrustedDeviceRow {
            id: *stale.id(),
            status: DeviceStatus::Revoked,
            ..org_trusted_device_row(db.ann)
        });
        db.store.save(&db.ann, &revoked).await.unwrap();

        let saved = db.store.save(&db.ann, &stale).await;

        assert!(matches!(saved, Err(DomainError::Conflict(_))));
        let found = db
            .store
            .find_by_id(&db.ann, stale.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.status(), DeviceStatus::Revoked);
    }

    /// Saving Ann's device under Bob returns a validation error and leaves
    /// Bob's device list empty.
    #[tokio::test]
    async fn a_device_saved_for_another_member_is_refused() {
        let db = fixture().await;
        let laptop = device(org_trusted_device_row(db.ann));

        let saved = db.store.save(&db.bob, &laptop).await;

        assert!(matches!(saved, Err(DomainError::Validation(_))));
        assert!(db.store.list_by_user(&db.bob).await.unwrap().is_empty());
    }

    /// Saving Bob's device under Ann's existing device ID returns a
    /// conflict and leaves the device findable under Ann.
    #[tokio::test]
    async fn a_device_kept_for_one_member_never_moves_to_another() {
        let db = fixture().await;
        let laptop = device(org_trusted_device_row(db.ann));
        db.store.save(&db.ann, &laptop).await.unwrap();
        let taken = device(TrustedDeviceRow {
            id: *laptop.id(),
            ..org_trusted_device_row(db.bob)
        });

        let saved = db.store.save(&db.bob, &taken).await;

        assert!(matches!(saved, Err(DomainError::Conflict(_))));
        assert!(
            db.store
                .find_by_id(&db.ann, laptop.id())
                .await
                .unwrap()
                .is_some()
        );
    }

    /// Reading a device whose stored last IP is malformed returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_device_is_refused() {
        let db = fixture().await;
        let laptop = device(org_trusted_device_row(db.ann));
        db.store.save(&db.ann, &laptop).await.unwrap();
        db.database
            .tamper("UPDATE org_trusted_devices SET last_ip = 'not an address'")
            .await;

        let read = db.store.find_by_id(&db.ann, laptop.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
