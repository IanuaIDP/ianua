//! Organizations' connections to their own cloud accounts, kept in the
//! platform database, one per organization and cloud.
//!
//! A connection is what is read to reach a tenant's own database, so it is
//! never kept inside one. Its external id and its credential are sealed by
//! the platform's secret sealer before they are written and opened as they
//! are read; the database never holds either in clear. The credential is
//! sealed whole, as JSON in the column's versioned envelope, so a shape it
//! was written in is read back through the domain's own constructors. Each
//! is sealed for the organization, the field and the cloud it belongs to,
//! so one moved into another connection's row does not open there.
//!
//! The external id is written when the connection is begun and never
//! replaced, since the customer has placed it in a trust policy by then.

mod credential;
mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use futures_util::future::try_join_all;
use ianua_app::ports::authentication::{SealOwner, SealedField, SealedFor, SecretEncryptor};
use ianua_app::ports::cloud::CloudAccountStore;
use ianua_domain::domains::organization::cloud::account::CloudAccount;
use ianua_domain::domains::organization::cloud::credential::{CloudCredential, ExternalId};
use ianua_domain::domains::tenant::provisioning::infrastructure::CloudProvider;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrganizationId, SealedSecret};

use self::record::{
    CloudAccountColumns, CloudAccountRecord, credential_from, credential_json, external_id_from,
    external_id_json,
};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::stored::StoredWord as _;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of organizations' cloud connections.
pub struct PgCloudAccountStore {
    databases: Arc<Databases>,
    sealer: Arc<dyn SecretEncryptor>,
}

/// The parts of a connection kept sealed: its external id, and its
/// credential once it holds one.
struct Sealed {
    external_id: SealedSecret,
    credential: Option<SealedSecret>,
}

/// The connection a sealed part belongs to: an organization's connection
/// to one cloud, whose row is keyed by the two.
#[derive(Debug, Clone, Copy)]
struct Connection<'a> {
    organization: OrganizationId,
    provider: &'a str,
}

impl Connection<'_> {
    /// Where the connection keeps its part `field`.
    fn place(self, field: SealedField) -> SealedFor {
        SealedFor::new(
            SealOwner::Organization(self.organization),
            field,
            self.provider,
        )
    }
}

impl PgCloudAccountStore {
    /// A store keeping connections in `databases`, their external ids and
    /// credentials sealed and opened by `sealer`.
    #[must_use]
    pub fn new(databases: Arc<Databases>, sealer: Arc<dyn SecretEncryptor>) -> Self {
        Self { databases, sealer }
    }

    /// The external id and credential of `account`, each sealed for
    /// storage in the connection it belongs to.
    async fn sealed(
        &self,
        account: &CloudAccount,
        external_id: &ExternalId,
    ) -> Result<Sealed, DomainError> {
        let connection = Connection {
            organization: *account.organization_id(),
            provider: account.provider().word(),
        };
        let external_id = self
            .sealer
            .encrypt(
                &external_id_json(external_id)?,
                &connection.place(SealedField::CloudExternalId),
            )
            .await?;
        let credential = match account.credential() {
            None => None,
            Some(credential) => Some(self.sealed_credential(connection, credential).await?),
        };
        Ok(Sealed {
            external_id,
            credential,
        })
    }

    /// `credential`, sealed for storage in `connection`.
    async fn sealed_credential(
        &self,
        connection: Connection<'_>,
        credential: &CloudCredential,
    ) -> Result<SealedSecret, DomainError> {
        self.sealer
            .encrypt(
                &credential_json(credential)?,
                &connection.place(SealedField::CloudCredential),
            )
            .await
    }

    /// The external id `sealed` holds for `connection`, opened.
    async fn opened_external_id(
        &self,
        connection: Connection<'_>,
        sealed: &SealedSecret,
    ) -> Result<ExternalId, DomainError> {
        let place = connection.place(SealedField::CloudExternalId);
        let opened = self.sealer.decrypt(sealed, &place).await?;
        external_id_from(&opened)
    }

    /// The credential `sealed` holds for `connection`, opened.
    async fn opened_credential(
        &self,
        connection: Connection<'_>,
        sealed: &SealedSecret,
    ) -> Result<CloudCredential, DomainError> {
        let place = connection.place(SealedField::CloudCredential);
        let opened = self.sealer.decrypt(sealed, &place).await?;
        credential_from(&opened)
    }

    /// The connection `record` holds, its sealed parts opened.
    async fn opened(&self, record: CloudAccountRecord) -> Result<CloudAccount, DomainError> {
        let connection = Connection {
            organization: record.organization(),
            provider: &record.provider,
        };
        let external_id = self
            .opened_external_id(connection, &record.sealed_external_id()?)
            .await?;
        let credential = match record.sealed_credential()? {
            None => None,
            Some(sealed) => Some(self.opened_credential(connection, &sealed).await?),
        };
        record.into_account(external_id, credential)
    }
}

#[async_trait]
impl CloudAccountStore for PgCloudAccountStore {
    async fn find(
        &self,
        organization_id: &OrganizationId,
        provider: CloudProvider,
    ) -> Result<Option<CloudAccount>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                CloudAccountRecord,
                "queries/org_cloud_accounts/find.sql",
                organization_id.as_uuid(),
                provider.word()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        let Some(record) = record else {
            return Ok(None);
        };
        self.opened(record).await.map(Some)
    }

    async fn list_for_organization(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Vec<CloudAccount>, DomainError> {
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                CloudAccountRecord,
                "queries/org_cloud_accounts/of_organization.sql",
                organization_id.as_uuid()
            )
            .fetch_all(connection)
            .await
        })
        .await?;
        try_join_all(records.into_iter().map(|record| self.opened(record))).await
    }

    async fn save(
        &self,
        account: &CloudAccount,
        external_id: &ExternalId,
    ) -> Result<(), DomainError> {
        let sealed = self.sealed(account, external_id).await?;
        let columns = CloudAccountColumns::of(account);
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/org_cloud_accounts/save.sql",
                columns.organization_id,
                columns.provider,
                sealed.external_id.as_str(),
                columns.state,
                sealed.credential.as_ref().map(SealedSecret::as_str),
                columns.checked_at,
                columns.verified_identity,
                columns.failure_reason,
                columns.bound_identity,
                columns.created_at,
                columns.updated_at,
            )
            .execute(connection)
            .await
            .map(|_| ())
        })
        .await
    }

    async fn external_id(
        &self,
        organization_id: &OrganizationId,
        provider: CloudProvider,
    ) -> Result<Option<ExternalId>, DomainError> {
        let sealed = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_scalar!(
                "queries/org_cloud_accounts/external_id.sql",
                organization_id.as_uuid(),
                provider.word()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        let Some(sealed) = sealed else {
            return Ok(None);
        };
        let sealed = SealedSecret::new(sealed).map_err(DomainError::infra)?;
        let connection = Connection {
            organization: *organization_id,
            provider: provider.word(),
        };
        self.opened_external_id(connection, &sealed).await.map(Some)
    }

    async fn delete(
        &self,
        organization_id: &OrganizationId,
        provider: CloudProvider,
    ) -> Result<(), DomainError> {
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/org_cloud_accounts/delete.sql",
                organization_id.as_uuid(),
                provider.word()
            )
            .execute(connection)
            .await
            .map(|_| ())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::cloud::account::{
        CloudAccountRow, CloudBinding, CloudSetup, ConnectionState,
    };
    use ianua_domain::types::Text;

    use super::*;
    use crate::crypto::{AesGcmSecretEncryptor, SealingKey};
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::cloud::{
        aws_account_row, aws_role, cloud_identity, digital_ocean_account_row, digital_ocean_token,
        external_id, saved_organization, verified,
    };

    struct Fixture {
        db: TestDb,
        store: PgCloudAccountStore,
        organization: OrganizationId,
    }

    /// A fresh database holding Acme, and the store on it sealing with the
    /// platform's own sealer, so a part sealed for one connection is
    /// refused in another.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases, "acme").await;
        let sealer =
            AesGcmSecretEncryptor::new(SealingKey::new("k1", [7; 32]).unwrap(), Vec::new());
        Fixture {
            store: PgCloudAccountStore::new(Arc::clone(&db.databases), Arc::new(sealer)),
            organization,
            db,
        }
    }

    fn account(row: CloudAccountRow) -> CloudAccount {
        CloudAccount::reconstitute(row).unwrap()
    }

    impl Fixture {
        async fn saved(&self, row: CloudAccountRow) -> CloudAccount {
            let saved = account(row);
            self.store.save(&saved, &external_id()).await.unwrap();
            saved
        }

        async fn found(&self, provider: CloudProvider) -> CloudAccount {
            self.store
                .find(&self.organization, provider)
                .await
                .unwrap()
                .unwrap()
        }
    }

    /// Acme begins an AWS connection: it is found waiting for a credential,
    /// set up with the external id it was begun with, which reads back
    /// opened.
    #[tokio::test]
    async fn a_begun_connection_is_found_with_its_external_id() {
        let fx = fixture().await;
        fx.saved(aws_account_row(
            fx.organization,
            ConnectionState::AwaitingCredential,
        ))
        .await;

        let found = fx.found(CloudProvider::Aws).await;
        let kept = fx
            .store
            .external_id(&fx.organization, CloudProvider::Aws)
            .await
            .unwrap();

        assert_eq!(found.state(), &ConnectionState::AwaitingCredential);
        assert_eq!(
            found.setup(),
            &CloudSetup::Aws {
                external_id: external_id()
            }
        );
        assert_eq!(found.created_at(), at(0));
        assert!(kept == Some(external_id()));
    }

    /// A verified connection reads back with its credential opened, the
    /// account it opened, when it was proved, and the account it is tied
    /// to.
    #[tokio::test]
    async fn a_verified_connection_reads_back_whole() {
        let fx = fixture().await;
        let saved = fx
            .saved(aws_account_row(fx.organization, verified(aws_role())))
            .await;

        let found = fx.found(CloudProvider::Aws).await;

        assert_eq!(found.state(), saved.state());
        assert!(found.usable_credential() == Some(&aws_role()));
        assert_eq!(found.binding(), &CloudBinding::Bound(cloud_identity()));
        assert_eq!(found.updated_at(), at(10));
    }

    /// A connection the cloud refused keeps why, and a later save of its
    /// new credential replaces the refusal.
    #[tokio::test]
    async fn saving_again_keeps_the_new_standing() {
        let fx = fixture().await;
        let failed = ConnectionState::Failed {
            credential: digital_ocean_token(),
            at: at(10),
            reason: Text::new("reason", "the token was revoked").unwrap(),
        };
        fx.saved(digital_ocean_account_row(fx.organization, failed))
            .await;
        let refused = fx.found(CloudProvider::DigitalOcean).await;

        fx.saved(digital_ocean_account_row(
            fx.organization,
            ConnectionState::AwaitingVerification {
                credential: digital_ocean_token(),
            },
        ))
        .await;

        assert!(
            matches!(refused.state(), ConnectionState::Failed { reason, .. }
            if reason.as_str() == "the token was revoked")
        );
        assert!(matches!(
            fx.found(CloudProvider::DigitalOcean).await.state(),
            ConnectionState::AwaitingVerification { .. }
        ));
    }

    /// Saving an existing cloud connection with another external ID keeps
    /// the ID saved when the connection began.
    #[tokio::test]
    async fn the_external_id_is_never_replaced() {
        let fx = fixture().await;
        let begun = fx
            .saved(digital_ocean_account_row(
                fx.organization,
                ConnectionState::AwaitingCredential,
            ))
            .await;
        let other = ExternalId::new("zyxwvutsrqponmlkjihgfedcba543210").unwrap();

        fx.store.save(&begun, &other).await.unwrap();

        let kept = fx
            .store
            .external_id(&fx.organization, CloudProvider::DigitalOcean)
            .await
            .unwrap();
        assert!(kept == Some(external_id()));
    }

    /// Acme's connections to two clouds are listed, and another
    /// organization's are not.
    #[tokio::test]
    async fn an_organizations_connections_are_listed() {
        let fx = fixture().await;
        let globex = saved_organization(&fx.db.databases, "globex").await;
        fx.saved(aws_account_row(fx.organization, verified(aws_role())))
            .await;
        fx.saved(digital_ocean_account_row(
            fx.organization,
            ConnectionState::AwaitingCredential,
        ))
        .await;
        fx.saved(aws_account_row(globex, ConnectionState::AwaitingCredential))
            .await;

        let listed = fx
            .store
            .list_for_organization(&fx.organization)
            .await
            .unwrap();

        let mut clouds: Vec<&str> = listed
            .iter()
            .map(|account| account.provider().as_str())
            .collect();
        clouds.sort_unstable();
        assert_eq!(clouds, ["aws", "digitalocean"]);
    }

    /// A cloud never connected finds nothing, and a removed connection is
    /// gone with its external id.
    #[tokio::test]
    async fn an_unknown_or_removed_connection_is_not_found() {
        let fx = fixture().await;
        fx.saved(aws_account_row(fx.organization, verified(aws_role())))
            .await;

        let never = fx.store.find(&fx.organization, CloudProvider::Gcp).await;
        fx.store
            .delete(&fx.organization, CloudProvider::Aws)
            .await
            .unwrap();

        assert!(never.unwrap().is_none());
        assert!(
            fx.store
                .find(&fx.organization, CloudProvider::Aws)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            fx.store
                .external_id(&fx.organization, CloudProvider::Aws)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Sealing a cloud connection hides the token and external ID text in
    /// their respective sealed values.
    #[tokio::test]
    async fn no_secret_is_written_in_clear() {
        let fx = fixture().await;
        let connection = account(digital_ocean_account_row(
            fx.organization,
            verified(digital_ocean_token()),
        ));

        let sealed = fx.store.sealed(&connection, &external_id()).await.unwrap();

        let credential = sealed.credential.unwrap();
        assert!(!credential.as_str().contains("dop_v1_secret_token"));
        assert!(!sealed.external_id.as_str().contains(external_id().as_str()));
    }

    /// Saving a cloud connection for an unknown organization returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_connection_of_an_unknown_organization_is_refused() {
        let fx = fixture().await;
        let stray = account(aws_account_row(
            OrganizationId::new(),
            ConnectionState::AwaitingCredential,
        ));

        let saved = fx.store.save(&stray, &external_id()).await;

        assert!(matches!(saved, Err(DomainError::Infrastructure(_))));
    }

    /// A cloud connection whose stored credential cannot be decrypted
    /// fails to load with an infrastructure error.
    #[tokio::test]
    async fn a_credential_that_does_not_open_is_refused() {
        let fx = fixture().await;
        fx.saved(aws_account_row(fx.organization, verified(aws_role())))
            .await;
        fx.db
            .tamper("UPDATE org_cloud_accounts SET credential_sealed = 'v1.AAECAwQF'")
            .await;

        let read = fx.store.find(&fx.organization, CloudProvider::Aws).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// Copying Acme's sealed credential and external ID into Globex's row
    /// makes Globex's connection fail to load, while Acme's remains readable.
    #[tokio::test]
    async fn a_credential_moved_to_another_organization_is_refused() {
        let fx = fixture().await;
        let globex = saved_organization(&fx.db.databases, "globex").await;
        fx.saved(aws_account_row(fx.organization, verified(aws_role())))
            .await;
        fx.saved(aws_account_row(globex, verified(aws_role())))
            .await;
        fx.db
            .tamper(&format!(
                "UPDATE org_cloud_accounts SET credential_sealed = acme.credential_sealed, \
                 external_id_sealed = acme.external_id_sealed \
                 FROM org_cloud_accounts acme \
                 WHERE acme.organization_id = '{}' AND org_cloud_accounts.organization_id = '{}'",
                fx.organization.as_uuid(),
                globex.as_uuid()
            ))
            .await;

        let read = fx.store.find(&globex, CloudProvider::Aws).await;
        let own = fx.store.find(&fx.organization, CloudProvider::Aws).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
        assert!(own.unwrap().is_some());
    }

    /// Invalid stored verified and bound account identities make the cloud
    /// connection fail to load as corrupt storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_connection_is_refused() {
        let fx = fixture().await;
        fx.saved(aws_account_row(fx.organization, verified(aws_role())))
            .await;
        fx.db
            .tamper(
                "UPDATE org_cloud_accounts SET verified_identity = 'a b', bound_identity = 'a b'",
            )
            .await;

        let read = fx.store.find(&fx.organization, CloudProvider::Aws).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
