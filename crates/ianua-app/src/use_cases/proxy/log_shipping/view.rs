//! What a caller is shown of a log shipping target: everything but its
//! credential.

use ianua_domain::domains::proxy::log_shipping::{
    LogDestination, LogFormat, LogShippingTarget, LogTargetStatus, ShippedRecords,
    ShippingCredential,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{Label, LogShippingTargetId};
use time::OffsetDateTime;

/// Whether a target holds a credential. The credential itself is never
/// shown, sealed or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialState {
    /// The destination is shipped to without one.
    NotSet,
    /// Delivery uses a stored authentication credential.
    Set,
}

/// A log shipping target as a caller sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogTargetView {
    /// The target's id.
    pub id: LogShippingTargetId,
    /// The label shown when choosing or inspecting this destination.
    pub name: Label,
    /// Where records go.
    pub destination: LogDestination,
    /// Whether it signs in with a credential.
    pub credential: CredentialState,
    /// Which records are sent.
    pub records: ShippedRecords,
    /// The shape each record is written in.
    pub format: LogFormat,
    /// Whether it is being shipped to.
    pub status: LogTargetStatus,
    /// When it was created.
    pub created_at: OffsetDateTime,
    /// When it last changed.
    pub updated_at: OffsetDateTime,
}

impl From<&LogShippingTarget<ResolvedTenant>> for LogTargetView {
    fn from(target: &LogShippingTarget<ResolvedTenant>) -> Self {
        Self {
            id: *target.id(),
            name: target.name().clone(),
            destination: target.destination().clone(),
            credential: match target.credential() {
                ShippingCredential::None => CredentialState::NotSet,
                ShippingCredential::Sealed(_) => CredentialState::Set,
            },
            records: target.records(),
            format: target.format(),
            status: target.status(),
            created_at: target.created_at(),
            updated_at: target.updated_at(),
        }
    }
}
