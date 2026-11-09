//! What the gateway holds of a connector to let its link in and to send
//! connections down it: the key it enrolled with, what it may be asked to
//! dial, and whether it may carry traffic. Nothing about its enrollment
//! code is part of it, so the gateway's database role never reads one.

use crate::domains::routing::connector::ConnectorStatus;
use crate::domains::routing::connector::scope::ConnectorScope;
use crate::shared::errors::DomainError;
use crate::types::{ConnectorId, PublicKeyPin};

/// A [`ConnectorTunnel`] as storage holds it, read back through
/// [`ConnectorTunnel::reconstitute`].
pub struct ConnectorTunnelRow {
    /// The connector's id.
    pub id: ConnectorId,
    /// What it may be asked to dial.
    pub scope: ConnectorScope,
    /// The pin of the key it enrolled with.
    pub key: PublicKeyPin,
    /// Whether it may carry traffic.
    pub status: ConnectorStatus,
}

/// An enrolled connector, as the gateway sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorTunnel {
    id: ConnectorId,
    scope: ConnectorScope,
    key: PublicKeyPin,
    status: ConnectorStatus,
}

impl ConnectorTunnel {
    /// Rebuilds an enrolled connector from storage. Every part of it was
    /// checked when it was read, and no rule holds between them.
    ///
    /// # Errors
    ///
    /// None today; the signature matches every other row read back.
    pub fn reconstitute(row: ConnectorTunnelRow) -> Result<Self, DomainError> {
        Ok(Self {
            id: row.id,
            scope: row.scope,
            key: row.key,
            status: row.status,
        })
    }

    /// The connector's id.
    #[must_use]
    pub fn id(&self) -> &ConnectorId {
        &self.id
    }

    /// What it may be asked to dial.
    #[must_use]
    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    /// Whether a link held with a certificate carrying `key` is this
    /// connector's, and it may carry traffic. The gateway asks when the
    /// link opens and again whenever the tenant's connectors are read.
    #[must_use]
    pub fn admits(&self, key: &PublicKeyPin) -> bool {
        self.status == ConnectorStatus::Active && self.key == *key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DomainName;

    fn tunnel(status: ConnectorStatus) -> ConnectorTunnel {
        ConnectorTunnel::reconstitute(ConnectorTunnelRow {
            id: ConnectorId::new(),
            scope: ConnectorScope::new(
                Vec::new(),
                vec![DomainName::new("wiki.corp.internal").unwrap()],
            )
            .unwrap(),
            key: PublicKeyPin::from_digest([1; 32]),
            status,
        })
        .unwrap()
    }

    /// Acme's connector enrolled with its key. Its link is let in.
    #[test]
    fn an_active_connector_admits_its_own_key() {
        assert!(tunnel(ConnectorStatus::Active).admits(&PublicKeyPin::from_digest([1; 32])));
    }

    /// An active connector refuses a key other than its enrolled key.
    #[test]
    fn another_key_is_refused() {
        assert!(!tunnel(ConnectorStatus::Active).admits(&PublicKeyPin::from_digest([2; 32])));
    }

    /// A revoked connector refuses its own enrolled key.
    #[test]
    fn a_revoked_connector_admits_nothing() {
        assert!(!tunnel(ConnectorStatus::Revoked).admits(&PublicKeyPin::from_digest([1; 32])));
    }
}
