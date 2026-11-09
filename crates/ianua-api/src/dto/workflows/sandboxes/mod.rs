//! Sandboxes on the wire: a sandbox, the body that makes one, the runtimes
//! offered, and, by topic, its versions, its trials, its code written by
//! the tenant's model or pushed to a repository, and the image registries
//! a tenant allows.

mod agent;
mod code;
mod registries;
mod trials;
mod versions;

use ianua_app::listing::{PageRequest, SortOrder};
use ianua_app::ports::workflows::{OfferedRuntime, SandboxSortField};
use ianua_app::use_cases::workflows::sandboxes::{
    CreateSandboxRequest, GetSandboxRequest, ListRequest, SandboxDetail,
};
use ianua_domain::domains::workflows::sandbox::runtime::Language;
use ianua_domain::domains::workflows::sandbox::{Sandbox, SandboxKind};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{Label, SandboxId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

pub(crate) use self::agent::HeldAgentBody;
pub(crate) use self::code::{FixBody, PushVersionBody, WriteCodeBody, WrittenCodeResponse};
pub(crate) use self::registries::{AllowRegistryBody, RegistryResponse};
pub(crate) use self::trials::{StartTrialBody, TrialResponse, trial_reading};
pub(crate) use self::versions::{
    BuildResponse, FindingsResponse, ImportBody, ImportedFromResponse, PackageBody,
    SandboxVersionResponse, SaveVersionBody, VersionSaving,
};
use crate::dto::workflows::data::person_label;
use crate::error::ApiError;
use crate::response::PageResponse;

/// Request body for making a sandbox.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateSandboxBody {
    /// Its name for people.
    pub name: String,
    /// What its versions run: `code`, the default, or `image` for the
    /// company's own container image. It never changes.
    #[serde(default)]
    pub kind: Option<String>,
    /// The language its code is written in: `python` or `javascript`. It
    /// never changes. Given for `code`, left out for `image`.
    #[serde(default)]
    pub language: Option<String>,
}

impl TryFrom<CreateSandboxBody> for CreateSandboxRequest {
    type Error = ApiError;

    fn try_from(body: CreateSandboxBody) -> Result<Self, ApiError> {
        Ok(Self {
            name: Label::new("name", body.name).map_err(ApiError::validation)?,
            kind: sandbox_kind(body.kind.as_deref(), body.language.as_deref())?,
        })
    }
}

/// The kind `kind` names with `language`: code in a language, or the
/// company's image with none.
fn sandbox_kind(kind: Option<&str>, language: Option<&str>) -> Result<SandboxKind, ApiError> {
    match (kind, language) {
        (None | Some("code"), Some(language)) => Language::parse(language)
            .map(SandboxKind::Code)
            .map_err(ApiError::validation),
        (Some("image"), None) => Ok(SandboxKind::OwnImage),
        _ => Err(ApiError::validation(DomainError::invalid(message!(
            "workflows-a-sandbox-is-code-in-a-language-or-an-image",
            "a sandbox is code with its language, or kind image with no language"
        )))),
    }
}

/// A code project's language, lifecycle and latest saved revision.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SandboxResponse {
    /// Unique identifier.
    pub id: Uuid,
    /// Its name for people.
    pub name: String,
    /// What its versions run: `code`, or `image` for the company's own
    /// container image.
    pub kind: String,
    /// `python` or `javascript`; absent for an `image` sandbox.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    /// `active`, or `archived` once nothing new is saved or picked.
    pub status: String,
    /// The number of its latest version, or 0 before the first.
    pub latest_version: u32,
    /// The person who made it, as `<kind>:<uuid>`.
    pub created_by: String,
    /// When it was made.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<Sandbox<ResolvedTenant>> for SandboxResponse {
    fn from(sandbox: Sandbox<ResolvedTenant>) -> Self {
        Self {
            id: *sandbox.id().as_uuid(),
            name: sandbox.name().as_str().to_owned(),
            kind: sandbox.kind().as_str().to_owned(),
            language: sandbox
                .kind()
                .language()
                .map(|language| language.as_str().to_owned()),
            status: sandbox.status().as_str().to_owned(),
            latest_version: sandbox.latest_version(),
            created_by: person_label(sandbox.created_by()),
            created_at: sandbox.created_at(),
            updated_at: sandbox.updated_at(),
        }
    }
}

/// One runtime a new version may pick now.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RuntimeResponse {
    /// The runtime, such as `python-3.13`.
    pub runtime: String,
    /// The language it runs: `python` or `javascript`.
    pub language: String,
    /// The image a version saved now keeps, named by its content.
    pub image: String,
}

impl From<OfferedRuntime> for RuntimeResponse {
    fn from(offered: OfferedRuntime) -> Self {
        Self {
            runtime: offered.runtime.as_str().to_owned(),
            language: offered.runtime.language().as_str().to_owned(),
            image: offered.image.as_str().to_owned(),
        }
    }
}

/// A sandbox with one page of its versions, newest first.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SandboxDetailResponse {
    /// The code project whose revision history accompanies it.
    pub sandbox: SandboxResponse,
    /// Its versions, newest first.
    pub versions: PageResponse<SandboxVersionResponse>,
}

impl From<SandboxDetail> for SandboxDetailResponse {
    fn from(detail: SandboxDetail) -> Self {
        Self {
            sandbox: SandboxResponse::from(detail.sandbox),
            versions: PageResponse::from_page(detail.versions, SandboxVersionResponse::from),
        }
    }
}

/// The listing asked for: the tenant's sandboxes in `sort` order, the page
/// `pagination` names.
#[must_use]
pub(crate) fn sandbox_listing(
    sort: SortOrder<SandboxSortField>,
    pagination: PageRequest,
) -> ListRequest {
    ListRequest {
        sort,
        page: pagination,
    }
}

/// The read asked for: sandbox `sandbox_id` and the page of its versions
/// `pagination` names.
#[must_use]
pub(crate) fn sandbox_reading(sandbox_id: SandboxId, pagination: PageRequest) -> GetSandboxRequest {
    GetSandboxRequest {
        sandbox_id,
        page: pagination,
    }
}
