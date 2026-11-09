//! A tenant's SCIM endpoint as its row holds it: read back into the
//! aggregate, and written out from it. Each yes-or-no setting is a
//! boolean column, as the domain's two cases are stored.

use ianua_domain::domains::federation::scim::{ScimEndpoint, ScimEndpointRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Enablement, RoleId, Setting, TokenHash};
use time::OffsetDateTime;
use uuid::Uuid;

/// An endpoint as it is read. The store's checked queries fill it.
pub(super) struct EndpointRecord {
    pub(super) bearer_token_hash: String,
    pub(super) enabled: bool,
    pub(super) default_role_id: Option<Uuid>,
    pub(super) auto_activate: bool,
    pub(super) deactivate_on_remove: bool,
    pub(super) last_sync_at: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
}

impl EndpointRecord {
    /// The endpoint the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it synced before it was
    /// set up.
    pub(super) fn into_endpoint(self) -> Result<ScimEndpoint<ResolvedTenant>, DomainError> {
        ScimEndpoint::reconstitute(ScimEndpointRow {
            bearer_token_hash: TokenHash::from_stored(self.bearer_token_hash),
            enabled: Enablement::from(self.enabled),
            default_role_id: Setting::from_stored(self.default_role_id.map(RoleId::from_uuid)),
            auto_activate: self.auto_activate.into(),
            deactivate_on_remove: self.deactivate_on_remove.into(),
            last_sync_at: self.last_sync_at,
            created_at: self.created_at,
        })
    }
}

/// An endpoint's columns, as they are written.
pub(super) struct EndpointColumns<'a> {
    pub(super) bearer_token_hash: &'a str,
    pub(super) enabled: bool,
    pub(super) default_role_id: Option<Uuid>,
    pub(super) auto_activate: bool,
    pub(super) deactivate_on_remove: bool,
    pub(super) last_sync_at: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
}

impl<'a> EndpointColumns<'a> {
    /// The columns `endpoint` is written to.
    pub(super) fn of(endpoint: &'a ScimEndpoint<ResolvedTenant>) -> Self {
        Self {
            bearer_token_hash: endpoint.bearer_token_hash().as_str(),
            enabled: endpoint.enabled(),
            default_role_id: endpoint.default_role_id().map(|role| *role.as_uuid()),
            auto_activate: endpoint.auto_activate().into(),
            deactivate_on_remove: endpoint.deactivate_on_remove().into(),
            last_sync_at: endpoint.last_sync_at(),
            created_at: endpoint.created_at(),
        }
    }
}
