//! Organization API key bodies: a key as listed, minting one, and the
//! catalog of permissions a key's scopes may name.

use std::collections::BTreeMap;

use ianua_app::listing::{PageRequest, SortOrder};
use ianua_app::ports::organization::OrgApiKeySortField;
use ianua_app::use_cases::organization::api_keys::{CreateOrgRequest, CreatedOrg, ListOrgRequest};
use ianua_domain::domains::organization::access::api_key::OrgApiKey;
use ianua_domain::domains::organization::members::permission::OrgPermission;
use ianua_domain::types::{Expiry, Label, Scope};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;

/// An organization API key, without the key itself.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OrgApiKeyResponse {
    /// Key ID.
    pub id: Uuid,
    /// Human-readable name.
    pub name: String,
    /// Scannable prefix.
    pub key_prefix: String,
    /// The member who made it.
    pub created_by: Uuid,
    /// When it expires, or `null` for never.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<time::OffsetDateTime>,
    /// When it was last used.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_used_at: Option<time::OffsetDateTime>,
    /// Whether it was revoked.
    pub revoked: bool,
    /// When it was made.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    /// What the key may do, as `org:<domain>:<action>` scopes.
    pub scopes: Vec<String>,
}

impl From<OrgApiKey> for OrgApiKeyResponse {
    fn from(k: OrgApiKey) -> Self {
        Self {
            id: *k.id().as_uuid(),
            name: k.name().as_str().to_owned(),
            key_prefix: k.key_prefix().as_str().to_owned(),
            created_by: *k.created_by().as_uuid(),
            expires_at: k.expires_at().instant(),
            last_used_at: k.last_used_at(),
            revoked: k.is_revoked(),
            created_at: k.created_at(),
            scopes: k
                .scopes()
                .iter()
                .map(|scope| scope.as_str().to_owned())
                .collect(),
        }
    }
}

/// The page of keys asked for, in `sort` order.
#[must_use]
pub(crate) fn key_listing(
    sort: SortOrder<OrgApiKeySortField>,
    pagination: PageRequest,
) -> ListOrgRequest {
    ListOrgRequest {
        sort,
        page: pagination,
    }
}

/// A key to mint.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateOrgApiKeyBody {
    /// Human-readable name.
    pub name: String,
    /// What the key may do, as `org:<domain>:<action>` scopes. At least
    /// one, each naming a permission the org plane checks:
    /// `GET .../permissions` lists them. A key reaches only what it names,
    /// never more than the member minting it holds.
    #[schema(value_type = Vec<String>)]
    pub scopes: Vec<Scope>,
    /// When it stops working (ISO 8601); omit for never.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<time::OffsetDateTime>,
}

impl TryFrom<CreateOrgApiKeyBody> for CreateOrgRequest {
    type Error = ApiError;

    fn try_from(body: CreateOrgApiKeyBody) -> Result<Self, Self::Error> {
        Ok(Self {
            name: Label::new("api_key_name", body.name).map_err(ApiError::validation)?,
            scopes: body.scopes,
            expires_at: body.expires_at.map_or(Expiry::Never, Expiry::At),
        })
    }
}

/// A key just minted, with the raw key shown this once.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CreatedOrgApiKeyResponse {
    /// Key ID.
    pub id: Uuid,
    /// The raw key: shown once, never again.
    pub raw_key: String,
    /// The scannable prefix.
    pub key_prefix: String,
}

impl From<CreatedOrg> for CreatedOrgApiKeyResponse {
    fn from(created: CreatedOrg) -> Self {
        Self {
            id: *created.id.as_uuid(),
            raw_key: created.raw_key.expose().to_owned(),
            key_prefix: created.key_prefix.as_str().to_owned(),
        }
    }
}

/// The org plane's permissions in one domain.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PermissionGroupResponse {
    /// The domain, such as `members`.
    pub label: String,
    /// The actions in this domain that may be named in an organization key's scopes.
    pub permissions: Vec<PermissionEntryResponse>,
}

/// One permission a key's scopes may name.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PermissionEntryResponse {
    /// The permission as stored.
    #[schema(value_type = Object)]
    pub value: serde_json::Value,
    /// Its scope spelling, `org:<domain>:<action>`, to send verbatim.
    pub label: String,
}

impl PermissionGroupResponse {
    /// Every permission the org plane checks, grouped by domain: a fixed
    /// catalog.
    #[must_use]
    pub(crate) fn org_catalog() -> Vec<Self> {
        let mut groups: BTreeMap<String, Vec<PermissionEntryResponse>> = BTreeMap::new();
        for permission in OrgPermission::ALL_VARIANTS {
            groups
                .entry(permission.domain().to_owned())
                .or_default()
                .push(PermissionEntryResponse {
                    value: serde_json::to_value(permission).unwrap_or(serde_json::Value::Null),
                    label: permission.to_string(),
                });
        }
        groups
            .into_iter()
            .map(|(label, permissions)| Self { label, permissions })
            .collect()
    }
}
