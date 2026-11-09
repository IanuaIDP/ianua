//! Sandbox handlers: making a sandbox, saving its versions with code
//! written or imported from a repository or the company's own image,
//! reading them with how far each version's package bundle or image scan
//! got, trying a version on sample input and reading the trial, pushing a
//! version to a repository, having the tenant's model write code,
//! archiving one, and the image registries a tenant allows.

use axum::extract::{Path, State};
use ianua_app::ports::workflows::SandboxSortField;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::workflows::WorkflowState;

use crate::dto::workflows::sandboxes::{
    AllowRegistryBody, CreateSandboxBody, PushVersionBody, RegistryResponse, RuntimeResponse,
    SandboxDetailResponse, SandboxResponse, SandboxVersionResponse, SaveVersionBody,
    StartTrialBody, TrialResponse, VersionSaving, WriteCodeBody, WrittenCodeResponse,
    sandbox_listing, sandbox_reading, trial_reading,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::paths::workflows::{
    RegistryPath, SandboxPath, SandboxTrialPath, SandboxVersionPath,
};
use crate::extractors::sort::SortQuery;
use crate::response::{Accepted, Created, NoContent, PageResponse};

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/sandboxes",
    tag = "Workflows",
    params(SortQuery<SandboxSortField>, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<SandboxResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// List sandboxes
///
/// Returns the tenant's sandboxes, archived ones among them, sortable and
/// paginated. Requires the right to view workflows.
pub(crate) async fn list_sandboxes(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    SortQuery(sort): SortQuery<SandboxSortField>,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<SandboxResponse>>, ApiError> {
    let page = workflows
        .list_sandboxes
        .execute(&tenant.caller, sandbox_listing(sort, pagination))
        .await?;
    Ok(Json(PageResponse::from_page(page, SandboxResponse::from)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/sandboxes",
    tag = "Workflows",
    request_body = CreateSandboxBody,
    responses(
        (status = 201, description = "Made", body = SandboxResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the installation runs no company images for an image sandbox", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Make a sandbox
///
/// Makes a named sandbox for code in `python` or `javascript`, or with
/// `kind` `image` for the company's own container image, with no version
/// yet. Its kind and language never change. An image sandbox is made only
/// where the operator turned companies' images on. Records
/// `workflows.sandbox_created`. Requires the right to create workflows.
pub(crate) async fn create_sandbox(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Json(body): Json<CreateSandboxBody>,
) -> Result<Created<SandboxResponse>, ApiError> {
    let sandbox = workflows
        .create_sandbox
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(SandboxResponse::from(sandbox)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/sandboxes/runtimes",
    tag = "Workflows",
    responses(
        (status = 200, description = "Success", body = Vec<RuntimeResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// List sandbox runtimes
///
/// Returns the runtimes a new version may pick now, each with the exact
/// image a version saved now keeps. A runtime the operator retired is left
/// out; versions saved under it still run. Requires the right to view
/// workflows.
pub(crate) async fn list_runtimes(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
) -> Result<Json<Vec<RuntimeResponse>>, ApiError> {
    let offered = workflows
        .list_sandbox_runtimes
        .execute(&tenant.caller, ())
        .await?;
    Ok(Json(
        offered.into_iter().map(RuntimeResponse::from).collect(),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/sandboxes/{sandbox_id}",
    tag = "Workflows",
    params(PaginationParams),
    responses(
        (status = 200, description = "Success", body = SandboxDetailResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such sandbox", body = ErrorBody)
    )
)]
/// Get a sandbox
///
/// Returns the sandbox and one page of its versions, newest first, each
/// with its code, packages, limits and how far building its package
/// bundle got. Requires the right to view workflows.
pub(crate) async fn get_sandbox(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<SandboxPath>,
    Paging(pagination): Paging,
) -> Result<Json<SandboxDetailResponse>, ApiError> {
    let detail = workflows
        .get_sandbox
        .execute(&tenant.caller, sandbox_reading(path.sandbox(), pagination))
        .await?;
    Ok(Json(SandboxDetailResponse::from(detail)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/sandboxes/{sandbox_id}/versions",
    tag = "Workflows",
    request_body = SaveVersionBody,
    responses(
        (status = 201, description = "Saved; its package bundle is being built, or its image scanned", body = SandboxVersionResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the installation runs no company images", body = ErrorBody),
        (status = 404, description = "No such sandbox, or the account, repository or file to import from is not there for the caller", body = ErrorBody),
        (status = 409, description = "The sandbox is archived, keeps 50 versions already, or another version was saved meanwhile", body = ErrorBody),
        (status = 422, description = "Validation error: a runtime not offered or of another language, code, limits, both or neither of code and import, a package that is no exact version of a name its registry takes, or an image from a registry not on the tenant's list, one its registry refuses or one over 2 GiB", body = ErrorBody),
        (status = 502, description = "The service keeping the file to import, or the image's registry, refused or could not be reached", body = ErrorBody)
    )
)]
/// Save a sandbox version
///
/// Saves `code`, `packages` and the limits as the sandbox's next version,
/// under the `runtime` picked and the exact image it is offered in now,
/// and has its packages fetched, checked against the fingerprints their
/// registry published and against the runtime, and kept as one bundle.
/// With `import` instead of `code`, the code is read from a file of a
/// GitHub or GitLab repository through an account the caller owns or may
/// manage, and the version keeps the exact commit its `ref` pointed to.
/// For an `image` sandbox, `image` alone names the company's image instead:
/// its registry must be on the tenant's list, and the version keeps the
/// digest the tag points to now, asked of the registry with its login; the
/// image is then scanned for known vulnerabilities, and one critical
/// finding fails the version. The version answers with `build.status`
/// `building`; read the sandbox for `ready` or `failed`. A sandbox keeps at
/// most 50 versions. Records `workflows.sandbox_version_saved`. Requires
/// the right to change workflows.
pub(crate) async fn save_version(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<SandboxPath>,
    Json(body): Json<SaveVersionBody>,
) -> Result<Created<SandboxVersionResponse>, ApiError> {
    let version = match body.saving(path.sandbox())? {
        VersionSaving::Code(request) => {
            workflows
                .save_sandbox_version
                .execute(&tenant.caller, &tenant.auditor, *request)
                .await?
        }
        VersionSaving::Image(request) => {
            workflows
                .save_image_version
                .execute(&tenant.caller, &tenant.auditor, request)
                .await?
        }
    };
    Ok(Created(SandboxVersionResponse::from(version)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/sandboxes/{sandbox_id}/versions/{version_id}/trials",
    tag = "Workflows",
    request_body = StartTrialBody,
    responses(
        (status = 202, description = "Started; a worker runs it", body = TrialResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the plan's trials running at once are reached", body = ErrorBody),
        (status = 404, description = "No such sandbox or version", body = ErrorBody),
        (status = 409, description = "The sandbox is archived, or the version's bundle is not built", body = ErrorBody),
        (status = 422, description = "Validation error: input that is no data a workflow holds", body = ErrorBody)
    )
)]
/// Try a sandbox version
///
/// Runs the built version on `input`, as a code step hands its code its
/// mapped fields, in a sandbox of its own on a worker. It answers at once
/// with `status` `running`; read the trial for `succeeded` with the
/// output, or `failed` with why. A version that names allowed hosts
/// reaches them as its runs do. Records `workflows.sandbox_trial_started`.
/// Requires the right to change workflows.
pub(crate) async fn start_trial(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<SandboxVersionPath>,
    Json(body): Json<StartTrialBody>,
) -> Result<Accepted<TrialResponse>, ApiError> {
    let trial = workflows
        .start_sandbox_trial
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.request(path.sandbox(), path.version())?,
        )
        .await?;
    Ok(Accepted(TrialResponse::from(trial)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/sandboxes/{sandbox_id}/versions/{version_id}/pushes",
    tag = "Workflows",
    request_body = PushVersionBody,
    responses(
        (status = 200, description = "Pushed", body = SandboxVersionResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such sandbox, version or account of the caller's, or the repository or branch is not there for it", body = ErrorBody),
        (status = 422, description = "Validation error, or the account's integration keeps no code", body = ErrorBody),
        (status = 502, description = "The service refused or could not be reached", body = ErrorBody)
    )
)]
/// Push a sandbox version
///
/// Sends a copy of the version to `folder` on `branch` of `repository`,
/// through a GitHub or GitLab account the caller owns or may manage: its
/// code as `main.py` or `main.js`, and its pinned packages as
/// `requirements.txt` or `package.json`. The branch must exist. The
/// version saved here stays the one that runs. Records
/// `workflows.sandbox_version_pushed` with the commit it became. Requires
/// the right to change workflows.
pub(crate) async fn push_version(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<SandboxVersionPath>,
    Json(body): Json<PushVersionBody>,
) -> Result<Json<SandboxVersionResponse>, ApiError> {
    let version = workflows
        .push_sandbox_version
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.request(path.sandbox(), path.version())?,
        )
        .await?;
    Ok(Json(SandboxVersionResponse::from(version)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/sandboxes/{sandbox_id}/suggestions",
    tag = "Workflows",
    request_body = WriteCodeBody,
    responses(
        (status = 200, description = "Written", body = WrittenCodeResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such sandbox or provider", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 502, description = "The model gave no code to use", body = ErrorBody)
    )
)]
/// Write sandbox code from words
///
/// Gives the person's `words` to the tenant's model provider, with the
/// names of the step's `inputs` (never their values) and the `packages`
/// the code may use, and answers code in the sandbox's language with what
/// it does. With `fix`, the model fixes code that failed when tried.
/// Nothing is saved, run or recorded: save the code as a version and try
/// it. Requires the right to change workflows.
pub(crate) async fn write_code(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<SandboxPath>,
    Json(body): Json<WriteCodeBody>,
) -> Result<Json<WrittenCodeResponse>, ApiError> {
    let written = workflows
        .write_sandbox_code
        .execute(&tenant.caller, body.request(path.sandbox())?)
        .await?;
    Ok(Json(WrittenCodeResponse::from(written)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/sandboxes/{sandbox_id}/trials/{trial_id}",
    tag = "Workflows",
    responses(
        (status = 200, description = "Success", body = TrialResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such trial of this sandbox, or it was cleared", body = ErrorBody)
    )
)]
/// Get a sandbox trial
///
/// Returns the trial with its input, and once it ran, what the code gave
/// back or why it failed. A trial is kept for a day after it ended.
/// Requires the right to view workflows.
pub(crate) async fn get_trial(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<SandboxTrialPath>,
) -> Result<Json<TrialResponse>, ApiError> {
    let trial = workflows
        .get_sandbox_trial
        .execute(&tenant.caller, trial_reading(path.sandbox(), path.trial()))
        .await?;
    Ok(Json(TrialResponse::from(trial)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/sandboxes/{sandbox_id}/archive",
    tag = "Workflows",
    responses(
        (status = 200, description = "Archived", body = SandboxResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such sandbox", body = ErrorBody),
        (status = 409, description = "It is archived already", body = ErrorBody)
    )
)]
/// Archive a sandbox
///
/// Nothing new is saved or picked of it again. Records
/// `workflows.sandbox_archived`. Requires the right to delete workflows.
pub(crate) async fn archive_sandbox(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<SandboxPath>,
) -> Result<Json<SandboxResponse>, ApiError> {
    let sandbox = workflows
        .archive_sandbox
        .execute(&tenant.caller, &tenant.auditor, path.sandbox())
        .await?;
    Ok(Json(SandboxResponse::from(sandbox)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/sandboxes/registries",
    tag = "Workflows",
    responses(
        (status = 200, description = "Success", body = Vec<RegistryResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// List image registries
///
/// Returns the registries image sandboxes may take the company's own
/// images from, by host, each with how its images are pulled; a password
/// is never shown. Requires the right to view workflows.
pub(crate) async fn list_registries(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
) -> Result<Json<Vec<RegistryResponse>>, ApiError> {
    let registries = workflows
        .list_image_registries
        .execute(&tenant.caller, ())
        .await?;
    Ok(Json(
        registries.into_iter().map(RegistryResponse::from).collect(),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/sandboxes/registries",
    tag = "Workflows",
    request_body = AllowRegistryBody,
    responses(
        (status = 201, description = "Allowed", body = RegistryResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the installation runs no company images", body = ErrorBody),
        (status = 409, description = "The host is allowed already", body = ErrorBody),
        (status = 422, description = "Validation error: a host that is no DNS name, or a user without a password", body = ErrorBody)
    )
)]
/// Allow an image registry
///
/// Puts `host` on the tenant's list, so image sandboxes may take the
/// company's own images from it, pulled as `username` with `password`, or
/// with no login when both are left out. The password is sealed before it
/// is kept. Records `workflows.image_registry_allowed`. Requires the right
/// to connect integration accounts.
pub(crate) async fn allow_registry(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Json(body): Json<AllowRegistryBody>,
) -> Result<Created<RegistryResponse>, ApiError> {
    let registry = workflows
        .allow_image_registry
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(RegistryResponse::from(registry)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/sandboxes/registries/{registry_id}",
    tag = "Workflows",
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such registry", body = ErrorBody)
    )
)]
/// Remove an image registry
///
/// Takes the registry off the tenant's list. Versions whose image it keeps
/// stay as they are but no longer run: their next run fails as not run
/// until the registry is allowed again. Records
/// `workflows.image_registry_removed`. Requires the right to connect
/// integration accounts.
pub(crate) async fn remove_registry(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<RegistryPath>,
) -> Result<NoContent, ApiError> {
    workflows
        .remove_image_registry
        .execute(&tenant.caller, &tenant.auditor, path.registry())
        .await?;
    Ok(NoContent)
}
