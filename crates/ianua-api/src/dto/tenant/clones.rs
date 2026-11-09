//! Clone bodies: what to copy from one tenant into another of its
//! organization, and how far the copy has come.

use ianua_app::use_cases::tenant::clones::StartRequest;
use ianua_domain::domains::tenant::clone::{ClonePart, CloneState, TenantClone};
use ianua_domain::message;
use ianua_domain::types::{TenantCloneId, TenantId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::ApiError;

/// What to copy, from which tenant into which. Users, sessions, signing
/// keys and secrets are never copied.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct StartCloneBody {
    /// The tenant copied from.
    pub source_tenant_id: Uuid,
    /// The tenant filled, of the same organization.
    pub target_tenant_id: Uuid,
    /// The parts of the source's setup to copy, each once: `settings`,
    /// `branding`, `roles_and_policies`, `routes`, `oauth_applications`.
    pub parts: Vec<String>,
}

impl TryFrom<StartCloneBody> for StartRequest {
    type Error = ApiError;

    fn try_from(body: StartCloneBody) -> Result<Self, Self::Error> {
        let parts = body
            .parts
            .iter()
            .map(String::as_str)
            .map(clone_part)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            source: TenantId::from_uuid(body.source_tenant_id),
            target: TenantId::from_uuid(body.target_tenant_id),
            parts,
        })
    }
}

/// The part `name` names, refused when it names none.
fn clone_part(name: &str) -> Result<ClonePart, ApiError> {
    ClonePart::parse(name).ok_or_else(|| {
        ApiError::validation(message!(
            "api-a-part-is-settings-branding-roles",
            "a part is settings, branding, roles_and_policies, routes or oauth_applications"
        ))
    })
}

/// A copy just started, to follow by its id.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CloneStartedResponse {
    /// The clone's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: TenantCloneId,
}

/// A copy of one tenant's setup into another, and how far it has come.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct TenantCloneResponse {
    /// The clone's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: TenantCloneId,
    /// The tenant copied from.
    #[schema(value_type = String, format = Uuid)]
    pub source_tenant_id: TenantId,
    /// The tenant filled.
    #[schema(value_type = String, format = Uuid)]
    pub target_tenant_id: TenantId,
    /// The parts it copies.
    pub parts: Vec<&'static str>,
    /// The parts copied so far.
    pub copied: Vec<&'static str>,
    /// `copying`, `completed` or `failed`.
    pub state: &'static str,
    /// Why it stopped, when it failed: `source_gone`, `target_gone` or
    /// `copy_failed`.
    pub failure: Option<&'static str>,
    /// When it started.
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    /// When it completed or failed, once it has.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub ended_at: Option<OffsetDateTime>,
}

impl From<&TenantClone> for TenantCloneResponse {
    fn from(clone: &TenantClone) -> Self {
        let (state, failure, ended_at) = match clone.state() {
            CloneState::Copying => ("copying", None, None),
            CloneState::Completed { at } => ("completed", None, Some(at)),
            CloneState::Failed { at, reason } => ("failed", Some(reason.as_str()), Some(at)),
        };
        Self {
            id: *clone.id(),
            source_tenant_id: *clone.source(),
            target_tenant_id: *clone.target(),
            parts: names(clone.parts()),
            copied: names(clone.copied()),
            state,
            failure,
            started_at: clone.started_at(),
            ended_at,
        }
    }
}

/// The stable names of `parts`.
fn names(parts: &[ClonePart]) -> Vec<&'static str> {
    parts.iter().map(|part| part.as_str()).collect()
}
