//! Who the gateway found on a stream connection, and the record each
//! connection leaves.
//!
//! A stream has no method, path or status, so its record has a shape of its
//! own: the route and its port, the client, the name its handshake asked
//! for, who was named on it, the decision and why, the backend it was
//! spliced to and how many bytes moved each way. Never a byte of what
//! moved, a token or a certificate: the record has no place for one. The
//! records are kept as long as the tenant's retention says, and removed
//! after.

use std::net::IpAddr;
use std::num::NonZeroU32;

use async_trait::async_trait;
use ianua_domain::domains::routing::stream::ListenPort;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ConsumerId, DomainName, StreamRouteId, TenantId, UserId};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Who the gateway found on a stream connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamConnectionCaller {
    /// No one: no certificate, no tunnel token.
    Nobody,
    /// A certificate from the tenant's CAs that belongs to no consumer.
    UnnamedCertificate,
    /// A consumer, by its certificate or its tunnel token.
    Consumer(ConsumerId),
    /// A person signed in to the tenant, through the tunnel.
    Person(UserId),
}

/// Whether a stream connection was let through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamDecision {
    /// It was admitted, and spliced or tried.
    Allowed,
    /// It was closed before a byte of it was forwarded.
    Denied,
}

/// What one stream connection came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamRecord {
    /// The tenant whose route owns the port.
    pub tenant_id: TenantId,
    /// The routing rule that admitted or refused this connection.
    pub stream_route_id: StreamRouteId,
    /// The port it arrived on.
    pub listen_port: ListenPort,
    /// The client's address.
    pub client: IpAddr,
    /// The name its TLS handshake asked for, when there was one.
    pub server_name: Option<DomainName>,
    /// Who was named on it; `None` when its credential named no one.
    pub caller: Option<StreamConnectionCaller>,
    /// Whether it was let through.
    pub decision: StreamDecision,
    /// Why it was refused, or how it ended: a short, stable word.
    pub reason: &'static str,
    /// The backend it was spliced to, as `host:port`, once one was picked.
    pub backend: Option<String>,
    /// Bytes from the client to the backend.
    pub bytes_to_backend: u64,
    /// Bytes from the backend to the client.
    pub bytes_to_client: u64,
    /// How long it lasted, in milliseconds.
    pub duration_ms: u32,
    /// When it ended.
    pub occurred_at: OffsetDateTime,
}

/// Dyn-safe port writing many stream records at once, for the gateway,
/// which queues them and writes them in batches like its request records.
#[async_trait]
pub trait StreamRecordWriter: Send + Sync {
    /// Writes `records`, of any tenants, each in the database its tenant
    /// lives in.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when they cannot be written.
    async fn write(&self, records: &[StreamRecord]) -> Result<(), DomainError>;
}

/// Dyn-safe port removing a tenant's stream records once its retention has
/// passed them.
#[async_trait]
pub trait StreamRecordRetention: Send + Sync + TenantScoped {
    /// Removes at most `most` of the tenant's stream records that ended
    /// before `before`, oldest first, and returns how many went. Each call
    /// is its own short statement, so a tenant with millions of old records
    /// never holds a lock for long.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when they cannot be removed;
    /// nothing is removed then.
    async fn forget_before(
        &self,
        tenant_id: &ScopedTenant,
        before: OffsetDateTime,
        most: NonZeroU32,
    ) -> Result<u64, DomainError>;
}
