//! An enrolled connector as the gateway reads its row: read back into the
//! parts a link is judged by.

use ianua_domain::domains::routing::connector::tunnel::{ConnectorTunnel, ConnectorTunnelRow};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ConnectorId, PublicKeyPin};
use serde_json::Value;
use uuid::Uuid;

use crate::postgres::routing::connectors::record::{CONNECTOR, SCOPE};

/// An enrolled connector as the gateway reads it. The store's checked
/// query fills it.
pub(super) struct TunnelRecord {
    pub(super) id: Uuid,
    pub(super) scope: Value,
    pub(super) public_key: String,
    pub(super) status: String,
}

impl TunnelRecord {
    /// The tunnel the record holds, each part through its checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules or a word is unknown.
    pub(super) fn into_tunnel(self) -> Result<ConnectorTunnel, DomainError> {
        ConnectorTunnel::reconstitute(ConnectorTunnelRow {
            id: ConnectorId::from_uuid(self.id),
            scope: SCOPE.open(self.scope)?,
            key: CONNECTOR.value("public_key", PublicKeyPin::parse(&self.public_key))?,
            status: CONNECTOR.choice(&self.status)?,
        })
    }
}
