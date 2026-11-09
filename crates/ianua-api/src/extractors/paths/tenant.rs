//! What a tenant request's path names: the organization by slug, a clone
//! of a tenant's setup, and one of a tenant's audit streams.

use ianua_domain::types::{AuditStreamId, TenantCloneId, TenantSlug};
use serde::Deserialize;
use uuid::Uuid;

/// `/api/v1/organizations/{org_slug}/...`.
#[derive(Deserialize)]
pub(crate) struct OrgSlugPath {
    org_slug: TenantSlug,
}

impl OrgSlugPath {
    /// The organization's slug, which a tenant's sign-in link names.
    #[must_use]
    pub(crate) fn organization(&self) -> &TenantSlug {
        &self.org_slug
    }
}

/// `.../tenant-clones/{clone_id}`.
#[derive(Deserialize)]
pub(crate) struct ClonePath {
    clone_id: Uuid,
}

impl ClonePath {
    /// The clone named.
    #[must_use]
    pub(crate) fn clone_id(&self) -> TenantCloneId {
        TenantCloneId::from_uuid(self.clone_id)
    }
}

/// `.../audit-streams/{stream_id}/...`.
#[derive(Deserialize)]
pub(crate) struct AuditStreamPath {
    stream_id: Uuid,
}

impl AuditStreamPath {
    /// The stream named.
    #[must_use]
    pub(crate) fn stream(&self) -> AuditStreamId {
        AuditStreamId::from_uuid(self.stream_id)
    }
}
