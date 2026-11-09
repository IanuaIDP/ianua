//! Refresh metadata: the sweep that reads again the metadata each SAML
//! connection's provider publishes at the address the connection follows,
//! and takes its endpoints and certificates.
//!
//! A provider rolls its signing key over by publishing the next
//! certificate beside the current one. Read on a schedule, the connection
//! takes it before the switch, so sign-ins keep working without an admin.
//! The metadata must still name the same provider; a certificate it brings
//! re-keys the connection, as an admin's import would.
//!
//! Each connection stands alone: one whose address does not answer, or
//! whose metadata is refused, is logged and tried on the next round.

use std::sync::Arc;

use ianua_domain::domains::federation::connection::{
    ConnectionConfig, FederatedIdpConnection, ImportedIdpMetadata,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, PublicHttpsUrl, Setting};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::listing::{Limit, PageRequest};
use crate::ports::federation::{
    ConnectionStore, MetadataFollower, MetadataFollowers, SamlMetadataReader,
};
use crate::ports::runtime::UnitOfWork;
use crate::services::kept_together::kept_together;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// How many following connections are read at a time.
const PAGE: u32 = 200;

/// The ports [`RefreshMetadataUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RefreshMetadataPorts {
    /// The connections that follow a metadata address, across tenants.
    pub followers: Arc<dyn MetadataFollowers>,
    /// Loads and saves connections.
    pub connection_store: Arc<dyn ConnectionStore>,
    /// Fetches and reads a provider's metadata.
    pub metadata_reader: Arc<dyn SamlMetadataReader>,
    /// Keeps each refreshed connection and its record together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Reads again the metadata of every SAML connection that follows an
/// address.
///
/// It runs as a sweep: no one calls it, so it takes no caller.
pub struct RefreshMetadataUseCase {
    ports: RefreshMetadataPorts,
}

impl RefreshMetadataUseCase {
    /// A sweep over `ports`.
    #[must_use]
    pub fn new(ports: RefreshMetadataPorts) -> Self {
        Self { ports }
    }

    /// Refreshes `follower`, logging why when it cannot be, and says
    /// whether it was refreshed.
    async fn refresh(&self, follower: MetadataFollower, auditor: &RequestAuditor) -> u32 {
        let tenant = ScopedTenant::for_background(follower.tenant_id);
        let auditor = auditor.with_tenant(follower.tenant_id);
        let unit = self.ports.unit_of_work.as_ref();
        let refreshed =
            kept_together(unit, self.refresh_connection(&tenant, &follower, &auditor)).await;
        match refreshed {
            Ok(()) => 1,
            Err(error) => {
                tracing::warn!(
                    connection_id = %follower.connection_id,
                    %error,
                    "SAML metadata not refreshed"
                );
                0
            }
        }
    }

    /// Reads `follower`'s metadata again, takes it, and saves and records
    /// the connection. One gone, or no longer following, is left alone.
    async fn refresh_connection(
        &self,
        tenant: &ScopedTenant,
        follower: &MetadataFollower,
        auditor: &RequestAuditor,
    ) -> Result<(), AppError> {
        let store = self.ports.connection_store.as_ref();
        let found = store
            .find_by_id(tenant, &follower.connection_id)
            .await
            .or_internal()?;
        let Some(mut connection) = found else {
            return Ok(());
        };
        let Some(address) = followed_address(&connection) else {
            return Ok(());
        };
        let metadata = self.published(address).await?;
        connection
            .refresh_metadata(metadata)
            .map_err(AppError::from_domain)?;
        store.save(tenant, &connection).await.or_internal()?;
        auditor
            .dispatch_by(&ActorRef::System, connection.take_events(tenant))
            .await
            .or_internal()
    }

    /// What the provider publishes at `address`, read and checked.
    async fn published(&self, address: PublicHttpsUrl) -> Result<ImportedIdpMetadata, AppError> {
        let reader = self.ports.metadata_reader.as_ref();
        let document = reader
            .fetch(&address)
            .await
            .map_err(AppError::from_domain)?;
        let facts = reader.read(&document).map_err(AppError::from_domain)?;
        let metadata = ImportedIdpMetadata::new(facts).map_err(AppError::from_domain)?;
        Ok(metadata.published_at(address))
    }
}

impl Command for RefreshMetadataUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<u32, AppError>;

    /// Reads again, for every SAML connection that follows a metadata
    /// address, what its provider publishes there, and takes it. A change
    /// records `federation.connection_updated` by the system. Returns how
    /// many connections were read again.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the following connections cannot be
    ///   listed. A connection that fails on its own is logged and left for
    ///   the next round.
    async fn execute(&self, (): &(), auditor: &RequestAuditor, (): ()) -> Result<u32, AppError> {
        let mut refreshed = 0u32;
        let mut next = Some(PageRequest::first(Limit::internal(PAGE)));
        while let Some(asked) = next.take() {
            let page = self
                .ports
                .followers
                .list_following(&asked)
                .await
                .or_internal()?;
            next = asked.following(&page);
            for follower in page.items {
                refreshed = refreshed.saturating_add(self.refresh(follower, auditor).await);
            }
        }
        Ok(refreshed)
    }
}

/// The address `connection` takes its metadata from, if it follows one.
fn followed_address(connection: &FederatedIdpConnection<ResolvedTenant>) -> Option<PublicHttpsUrl> {
    let ConnectionConfig::Saml(saml) = connection.config() else {
        return None;
    };
    match &saml.metadata_url {
        Setting::Set(address) => Some(address.clone()),
        Setting::Unset => None,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::federation::connection::{GroupMapping, SamlConfig};
    use ianua_domain::types::{CertificatePem, ConnectionId};

    use super::*;
    use crate::test_support::federation::{
        FakeConnectionStore, FakeSamlMetadataReader, TEST_IDP_CERTIFICATE, test_saml_connection,
        test_saml_settings,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const ADDRESS: &str = "https://idp.acme.com/metadata";
    const NEXT: &str = "-----BEGIN CERTIFICATE-----\nMIIDnext\n-----END CERTIFICATE-----";

    struct Setup {
        uc: RefreshMetadataUseCase,
        store: Arc<FakeConnectionStore>,
        reader: Arc<FakeSamlMetadataReader>,
        audit: Arc<FakeEventDispatcher>,
        id: ConnectionId,
    }

    /// Acme's Okta connection, following `metadata_url`, where Okta now
    /// publishes its next certificate too.
    fn setup(metadata_url: Setting<PublicHttpsUrl>) -> Setup {
        let id = ConnectionId::new();
        let saml = SamlConfig {
            metadata_url,
            ..test_saml_settings()
        };
        let conn = test_saml_connection(id, saml, GroupMapping::Off);
        let store = Arc::new(FakeConnectionStore::holding(&test_ctx().tenant(), [conn]));
        let reader = Arc::new(FakeSamlMetadataReader::listing(&[
            TEST_IDP_CERTIFICATE,
            NEXT,
        ]));
        let uc = RefreshMetadataUseCase::new(RefreshMetadataPorts {
            followers: store.clone(),
            connection_store: store.clone(),
            metadata_reader: reader.clone(),
            ..RefreshMetadataPorts::fakes()
        });
        Setup {
            uc,
            store,
            reader,
            audit: Arc::new(FakeEventDispatcher::new()),
            id,
        }
    }

    fn sweep(setup: &Setup) -> u32 {
        block_on(
            setup
                .uc
                .execute(&(), &test_auditor(setup.audit.clone()), ()),
        )
        .unwrap()
    }

    fn saml_now(setup: &Setup) -> SamlConfig {
        let conn = block_on(setup.store.find_by_id(&test_ctx().tenant(), &setup.id))
            .unwrap()
            .unwrap();
        let ConnectionConfig::Saml(saml) = conn.config().clone() else {
            panic!("a SAML connection");
        };
        *saml
    }

    /// Acme made its Okta connection from Okta's metadata address. Okta
    /// publishes its next certificate, and the sweep takes it, by the
    /// system, without an admin.
    #[test]
    fn a_following_connection_takes_the_published_certificate() {
        let address = PublicHttpsUrl::new(ADDRESS).unwrap();
        let setup = setup(Setting::Set(address));

        let refreshed = sweep(&setup);

        assert_eq!(refreshed, 1);
        assert_eq!(setup.reader.fetched(), [ADDRESS]);
        let next = CertificatePem::new(NEXT).unwrap();
        assert!(saml_now(&setup).certificates.accepts(&next));
        assert_eq!(
            setup.audit.records.lock().unwrap().as_slice(),
            ["federation.connection_updated"]
        );
    }

    /// A connection with no metadata address is excluded from the sweep's
    /// refreshed count, and no metadata is fetched.
    #[test]
    fn a_connection_following_no_address_is_left_alone() {
        let setup = setup(Setting::Unset);

        let refreshed = sweep(&setup);

        assert_eq!(refreshed, 0);
        assert!(setup.reader.fetched().is_empty());
    }
}
