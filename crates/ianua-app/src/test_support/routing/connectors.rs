//! An in-memory store of private-network connectors, the fake that makes
//! their enrollment codes, and the connectors a test starts from.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::routing::connector::scope::ConnectorScope;
use ianua_domain::domains::routing::connector::{
    ConnectorEnrollment, CreateConnectorParams, PrivateConnector,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ConnectorId, DomainName, TenantId, TokenHash};

use crate::ports::TenantScoped;
use crate::ports::routing::{ConnectorCodeGenerator, ConnectorStore};
use crate::tenancy::ScopedTenant;
use crate::test_support::routing::held::remove_where;
use crate::test_support::routing::{routing_admin, routing_label};
use crate::test_support::{Fake, rivals};

/// The hash the connector fakes keep for the enrollment code `raw`.
#[must_use]
pub fn connector_code_hash(raw: &str) -> TokenHash {
    TokenHash::from_stored(format!("hash:{raw}"))
}

/// A scope naming the domains `domains` and no network.
///
/// # Panics
///
/// Panics if a domain is not valid or the list is empty.
#[must_use]
pub fn connector_scope(domains: &[&str]) -> ConnectorScope {
    let names = domains
        .iter()
        .map(|domain| DomainName::new(*domain).expect("the test domain is valid"))
        .collect();
    ConnectorScope::new(Vec::new(), names).expect("the test scope names something")
}

/// A connector named `name`, awaiting enrollment with the code `code`,
/// allowed to dial `domains`, as a routing admin creates it.
///
/// # Panics
///
/// Panics if the domain refuses the connector, which it never does here.
#[must_use]
pub fn awaiting_connector(
    name: &str,
    code: &str,
    domains: &[&str],
) -> PrivateConnector<ResolvedTenant> {
    PrivateConnector::create(
        CreateConnectorParams {
            name: routing_label(name),
            scope: connector_scope(domains),
            code_hash: connector_code_hash(code),
        },
        &routing_admin(),
    )
    .expect("a routing admin creates a connector")
}

/// In-memory connector store for tests, keeping each connector under the
/// tenant it was saved for. A second connector with a name already taken
/// is refused, as the unique index refuses it.
#[derive(Default)]
pub struct FakeConnectorStore {
    connectors: Mutex<Vec<(TenantId, PrivateConnector<ResolvedTenant>)>>,
}

impl TenantScoped for FakeConnectorStore {}

impl FakeConnectorStore {
    /// Creates an empty store.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `connector` in `tenant`.
    #[must_use]
    pub fn holding(tenant: TenantId, connector: &PrivateConnector<ResolvedTenant>) -> Self {
        Self {
            connectors: Mutex::new(vec![(tenant, connector.clone())]),
        }
    }

    /// The connector `id` as stored in `tenant`, if any.
    #[must_use]
    pub fn stored(
        &self,
        tenant: TenantId,
        id: &ConnectorId,
    ) -> Option<PrivateConnector<ResolvedTenant>> {
        self.connectors
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, connector)| *owner == tenant && connector.id() == id)
            .map(|(_, connector)| connector.clone())
    }

    /// Number of stored connectors, across every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.connectors.lock().unwrap().len()
    }

    /// The first connector of `tenant` that is `wanted`.
    fn first(
        &self,
        tenant: &ScopedTenant,
        wanted: impl Fn(&PrivateConnector<ResolvedTenant>) -> bool,
    ) -> Option<PrivateConnector<ResolvedTenant>> {
        self.connectors
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, connector)| owner == &**tenant && wanted(connector))
            .map(|(_, connector)| connector.clone())
    }
}

/// Whether `entry` is the connector `id` of `tenant`.
fn is(
    entry: &(TenantId, PrivateConnector<ResolvedTenant>),
    tenant: &ScopedTenant,
    id: &ConnectorId,
) -> bool {
    entry.0 == **tenant && entry.1.id() == id
}

/// Whether `connector` still awaits enrollment with the code hashed to
/// `code_hash`.
fn awaits_code(connector: &PrivateConnector<ResolvedTenant>, code_hash: &TokenHash) -> bool {
    matches!(
        connector.enrollment(),
        ConnectorEnrollment::Awaiting { code_hash: held, .. } if held == code_hash
    )
}

#[async_trait]
impl ConnectorStore for FakeConnectorStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ConnectorId,
    ) -> Result<Option<PrivateConnector<ResolvedTenant>>, DomainError> {
        Ok(self.first(tenant_id, |connector| connector.id() == id))
    }

    async fn find_awaiting_by_code(
        &self,
        tenant_id: &ScopedTenant,
        code_hash: &TokenHash,
    ) -> Result<Option<PrivateConnector<ResolvedTenant>>, DomainError> {
        Ok(self.first(tenant_id, |connector| awaits_code(connector, code_hash)))
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<PrivateConnector<ResolvedTenant>>, DomainError> {
        let mut all: Vec<_> = self
            .connectors
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, _)| owner == &**tenant_id)
            .map(|(_, connector)| connector.clone())
            .collect();
        all.sort_by(|a, b| a.name().as_str().cmp(b.name().as_str()));
        Ok(all)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        connector: &PrivateConnector<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut connectors = self.connectors.lock().unwrap();
        let by_name = |kept: &PrivateConnector<ResolvedTenant>| (kept.name().clone(), *kept.id());
        if connectors
            .iter()
            .any(|entry| rivals(entry, tenant_id, connector, by_name))
        {
            return Err(DomainError::conflict(
                "another connector of the tenant has the name",
            ));
        }
        connectors.retain(|entry| !is(entry, tenant_id, connector.id()));
        connectors.push((**tenant_id, connector.clone()));
        Ok(())
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &ConnectorId) -> Result<(), DomainError> {
        remove_where(&self.connectors, |entry| is(entry, tenant_id, id));
        Ok(())
    }
}

/// Code generator that counts the codes it makes: `enroll-code-1`,
/// `enroll-code-2`, each hashed with [`connector_code_hash`].
#[derive(Default)]
pub struct FakeConnectorCodeGenerator {
    made: Mutex<u32>,
}

#[async_trait]
impl ConnectorCodeGenerator for FakeConnectorCodeGenerator {
    async fn generate(&self) -> Result<(Secret, TokenHash), DomainError> {
        let mut made = self.made.lock().unwrap();
        *made = made.saturating_add(1);
        let raw = format!("enroll-code-{made}");
        let hash = connector_code_hash(&raw);
        Ok((Secret::new(raw), hash))
    }

    fn hash_presented(&self, presented: &Secret) -> TokenHash {
        connector_code_hash(presented.expose())
    }
}

impl Fake for Arc<dyn ConnectorStore> {
    fn fake() -> Self {
        Arc::new(FakeConnectorStore::empty())
    }
}

impl Fake for Arc<dyn ConnectorCodeGenerator> {
    fn fake() -> Self {
        Arc::new(FakeConnectorCodeGenerator::default())
    }
}
