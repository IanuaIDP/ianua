//! What a connection's group mapping gave one person, as its rows hold it:
//! read back into the record, and written out from it.

use ianua_domain::domains::federation::connection::{MappedHoldings, MappedHoldingsRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ConnectionId, GroupId, RoleId, UserId};
use uuid::Uuid;

/// The holdings as they are read. The store's checked query fills it.
pub(super) struct HoldingsRecord {
    pub(super) connection_id: Uuid,
    pub(super) user_id: Uuid,
    pub(super) role_ids: Vec<Uuid>,
    pub(super) group_ids: Vec<Uuid>,
}

impl HoldingsRecord {
    /// The holdings the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a role or a group is
    /// named twice.
    pub(super) fn into_holdings(self) -> Result<MappedHoldings<ResolvedTenant>, DomainError> {
        MappedHoldings::reconstitute(MappedHoldingsRow {
            connection_id: ConnectionId::from_uuid(self.connection_id),
            user_id: UserId::from_uuid(self.user_id),
            roles: self.role_ids.into_iter().map(RoleId::from_uuid).collect(),
            groups: self.group_ids.into_iter().map(GroupId::from_uuid).collect(),
        })
    }
}

/// The holdings' columns, as they are written.
pub(super) struct HoldingsColumns<'a> {
    pub(super) connection_id: &'a Uuid,
    pub(super) user_id: &'a Uuid,
    pub(super) role_ids: Vec<Uuid>,
    pub(super) group_ids: Vec<Uuid>,
}

impl<'a> HoldingsColumns<'a> {
    /// The columns `holdings` is written to.
    pub(super) fn of(holdings: &'a MappedHoldings<ResolvedTenant>) -> Self {
        Self {
            connection_id: holdings.connection_id().as_uuid(),
            user_id: holdings.user_id().as_uuid(),
            role_ids: holdings
                .roles()
                .iter()
                .map(|role| *role.as_uuid())
                .collect(),
            group_ids: holdings
                .groups()
                .iter()
                .map(|group| *group.as_uuid())
                .collect(),
        }
    }
}
