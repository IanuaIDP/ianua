//! Fakes for federation connections and the links between local accounts
//! and who their owners are at a provider.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::federation::connection::{
    ConnectionConfig, ConnectionRow, FederatedIdpConnection,
};
use ianua_domain::domains::federation::connection_status::ConnectionStatus;
use ianua_domain::domains::federation::link::{FederatedLink, FederatedLinkRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    ConnectionId, FederatedSubject, GroupId, RoleId, Setting, TenantId, UserId,
};

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::federation::{
    ConnectionSortField, ConnectionStore, FederatedLinkStore, MetadataFollower,
    MetadataFollowerSortField, MetadataFollowers,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::listing::page;

/// In-memory connection store, each connection kept under its tenant.
#[derive(Default)]
pub struct FakeConnectionStore {
    connections: Mutex<Vec<(TenantId, FederatedIdpConnection<ResolvedTenant>)>>,
}

impl TenantScoped for FakeConnectionStore {}

impl FakeConnectionStore {
    /// A store holding no connection.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `connections` in `tenant`.
    #[must_use]
    pub fn holding(
        tenant: &ScopedTenant,
        connections: impl IntoIterator<Item = FederatedIdpConnection<ResolvedTenant>>,
    ) -> Self {
        let kept = connections
            .into_iter()
            .map(|connection| (**tenant, connection))
            .collect();
        Self {
            connections: Mutex::new(kept),
        }
    }

    /// How many connections are kept, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.connections.lock().unwrap().len()
    }

    fn matching(
        &self,
        tenant_id: &ScopedTenant,
        keeps: impl Fn(&FederatedIdpConnection<ResolvedTenant>) -> bool,
    ) -> Result<Vec<FederatedIdpConnection<ResolvedTenant>>, DomainError> {
        self.connections
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, connection)| tenant == &**tenant_id && keeps(connection))
            .map(|(_, connection)| copy_connection(connection))
            .collect()
    }
}

#[async_trait]
impl ConnectionStore for FakeConnectionStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ConnectionId,
    ) -> Result<Option<FederatedIdpConnection<ResolvedTenant>>, DomainError> {
        let found = self.matching(tenant_id, |connection| connection.id() == id)?;
        Ok(found.into_iter().next())
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        status: Option<ConnectionStatus>,
        sort: &SortOrder<ConnectionSortField>,
        request: &PageRequest,
    ) -> Result<Page<FederatedIdpConnection<ResolvedTenant>>, DomainError> {
        let found = self.matching(tenant_id, |connection| {
            status.is_none_or(|status| connection.status() == status)
        })?;
        page(found, sort, request)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        connection: &FederatedIdpConnection<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let copy = copy_connection(connection)?;
        let mut connections = self.connections.lock().unwrap();
        connections
            .retain(|(tenant, kept)| !(tenant == &**tenant_id && kept.id() == connection.id()));
        connections.push((**tenant_id, copy));
        Ok(())
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &ConnectionId) -> Result<(), DomainError> {
        self.connections
            .lock()
            .unwrap()
            .retain(|(tenant, connection)| !(tenant == &**tenant_id && connection.id() == id));
        Ok(())
    }

    async fn count_naming_role(
        &self,
        tenant_id: &ScopedTenant,
        role_id: &RoleId,
    ) -> Result<u64, DomainError> {
        Ok(self.counting(tenant_id, |connection| connection.names_role(role_id)))
    }

    async fn count_naming_group(
        &self,
        tenant_id: &ScopedTenant,
        group_id: &GroupId,
    ) -> Result<u64, DomainError> {
        Ok(self.counting(tenant_id, |connection| connection.names_group(group_id)))
    }
}

impl FakeConnectionStore {
    /// How many of `tenant_id`'s connections `naming` holds for.
    fn counting(
        &self,
        tenant_id: &ScopedTenant,
        naming: impl Fn(&FederatedIdpConnection<ResolvedTenant>) -> bool,
    ) -> u64 {
        let held = self.connections.lock().unwrap();
        let counted = held
            .iter()
            .filter(|(tenant, connection)| tenant == &**tenant_id && naming(connection))
            .count();
        u64::try_from(counted).expect("a test holds fewer connections than u64 counts")
    }
}

impl Fake for Arc<dyn ConnectionStore> {
    fn fake() -> Self {
        Arc::new(FakeConnectionStore::empty())
    }
}

#[async_trait]
impl MetadataFollowers for FakeConnectionStore {
    async fn list_following(
        &self,
        request: &PageRequest,
    ) -> Result<Page<MetadataFollower>, DomainError> {
        let following: Vec<MetadataFollower> = self
            .connections
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, connection)| follows_an_address(connection))
            .map(|(tenant_id, connection)| MetadataFollower {
                tenant_id: *tenant_id,
                connection_id: *connection.id(),
            })
            .collect();
        page(
            following,
            &SortOrder::<MetadataFollowerSortField>::default(),
            request,
        )
    }
}

impl Fake for Arc<dyn MetadataFollowers> {
    fn fake() -> Self {
        Arc::new(FakeConnectionStore::empty())
    }
}

/// Whether `connection` takes its SAML metadata from an address.
fn follows_an_address(connection: &FederatedIdpConnection<ResolvedTenant>) -> bool {
    matches!(
        connection.config(),
        ConnectionConfig::Saml(saml) if matches!(saml.metadata_url, Setting::Set(_))
    )
}

/// `connection` written out and read back, as storage would return it.
fn copy_connection(
    connection: &FederatedIdpConnection<ResolvedTenant>,
) -> Result<FederatedIdpConnection<ResolvedTenant>, DomainError> {
    FederatedIdpConnection::reconstitute(ConnectionRow {
        id: *connection.id(),
        provider_name: connection.provider_name().clone(),
        status: connection.status(),
        config: connection.config().clone(),
        jit_provisioning: connection.jit_provisioning(),
        jit_default_role_id: Setting::from_stored(connection.jit_default_role_id().copied()),
        email_trust: connection.email_trust(),
        assurance_trust: connection.assurance_trust(),
        domain_hint: Setting::from_stored(connection.domain_hint().cloned()),
        allowed_domains: connection.allowed_domains().to_vec(),
        attribute_mapping: connection.attribute_mapping().clone(),
        group_mapping: connection.group_mapping().clone(),
        created_at: connection.created_at(),
        keyed_at: connection.keyed_at(),
    })
}

/// In-memory link store that, like the table, holds one link per subject and
/// one per account on each connection of a tenant.
#[derive(Default)]
pub struct FakeFederatedLinkStore {
    links: Mutex<Vec<(TenantId, FederatedLink<ResolvedTenant>)>>,
}

impl TenantScoped for FakeFederatedLinkStore {}

impl FakeFederatedLinkStore {
    /// A store holding no link.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// How many links are kept, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.links.lock().unwrap().len()
    }

    fn find(
        &self,
        tenant_id: &ScopedTenant,
        connection_id: &ConnectionId,
        matches: impl Fn(&FederatedLink<ResolvedTenant>) -> bool,
    ) -> Result<Option<FederatedLink<ResolvedTenant>>, DomainError> {
        self.links
            .lock()
            .unwrap()
            .iter()
            .find(|(tenant, link)| {
                tenant == &**tenant_id && link.connection_id() == connection_id && matches(link)
            })
            .map(|(_, link)| copy_link(link))
            .transpose()
    }
}

#[async_trait]
impl FederatedLinkStore for FakeFederatedLinkStore {
    async fn find_by_subject(
        &self,
        tenant_id: &ScopedTenant,
        connection_id: &ConnectionId,
        subject: &FederatedSubject,
    ) -> Result<Option<FederatedLink<ResolvedTenant>>, DomainError> {
        self.find(tenant_id, connection_id, |link| link.subject() == subject)
    }

    async fn find_by_user(
        &self,
        tenant_id: &ScopedTenant,
        connection_id: &ConnectionId,
        user_id: &UserId,
    ) -> Result<Option<FederatedLink<ResolvedTenant>>, DomainError> {
        self.find(tenant_id, connection_id, |link| link.user_id() == user_id)
    }

    async fn list_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<FederatedLink<ResolvedTenant>>, DomainError> {
        let mut held: Vec<_> = self
            .links
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, link)| tenant == &**tenant_id && link.user_id() == user_id)
            .map(|(_, link)| copy_link(link))
            .collect::<Result<_, _>>()?;
        held.sort_by_key(FederatedLink::linked_at);
        Ok(held)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        link: &FederatedLink<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let copy = copy_link(link)?;
        let mut links = self.links.lock().unwrap();
        let taken = links.iter().any(|(tenant, kept)| {
            tenant == &**tenant_id
                && kept.connection_id() == link.connection_id()
                && (kept.subject() == link.subject() || kept.user_id() == link.user_id())
        });
        if taken {
            return Err(DomainError::conflict("already linked"));
        }
        links.push((**tenant_id, copy));
        Ok(())
    }

    async fn update(
        &self,
        tenant_id: &ScopedTenant,
        link: &FederatedLink<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let copy = copy_link(link)?;
        let mut links = self.links.lock().unwrap();
        let kept = links.iter_mut().find(|(tenant, kept)| {
            tenant == &**tenant_id
                && kept.connection_id() == link.connection_id()
                && kept.user_id() == link.user_id()
        });
        let Some((_, kept)) = kept else {
            return Err(DomainError::infra_msg("no such link is kept"));
        };
        *kept = copy;
        Ok(())
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        connection_id: &ConnectionId,
        user_id: &UserId,
    ) -> Result<(), DomainError> {
        self.links.lock().unwrap().retain(|(tenant, link)| {
            !(tenant == &**tenant_id
                && link.connection_id() == connection_id
                && link.user_id() == user_id)
        });
        Ok(())
    }
}

impl Fake for Arc<dyn FederatedLinkStore> {
    fn fake() -> Self {
        Arc::new(FakeFederatedLinkStore::empty())
    }
}

/// `link` written out and read back, as storage would return it.
fn copy_link(
    link: &FederatedLink<ResolvedTenant>,
) -> Result<FederatedLink<ResolvedTenant>, DomainError> {
    FederatedLink::reconstitute(FederatedLinkRow {
        connection_id: *link.connection_id(),
        subject: link.subject().clone(),
        user_id: *link.user_id(),
        linked_at: link.linked_at(),
        confirmed_at: link.confirmed_at(),
    })
}
