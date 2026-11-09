//! Model provider handlers: the LLM backends a tenant's runs reason with.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::agents::AgentState;

use crate::dto::agents::model_providers::{
    ChangeModelProviderClearanceBody, ChangeModelProviderModelBody, ConnectModelProviderBody,
    ConnectModelProviderResponse, ModelProviderResponse, OfferEmbeddingsBody,
    RotateModelProviderKeyBody, TestModelProviderResponse, UpdateModelProviderStatusBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::agents::ModelProviderPath;
use crate::response::{Created, NoContent};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/model-providers",
    tag = "Agents",
    request_body = ConnectModelProviderBody,
    responses(
        (status = 201, description = "Connected", body = ConnectModelProviderResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Plan limit reached", body = ErrorBody)
    )
)]
/// Connect a model provider
///
/// Registers where this tenant's agent reasoning comes from: a self-hosted
/// OpenAI-compatible endpoint (DeepSeek, Kimi or vLLM in your own
/// Kubernetes), OpenAI, or Anthropic, the most sensitive data runs may
/// send it (`clearance`), and what it charges (`pricing`), which runs'
/// spend is counted at. Paste an `api_key` to bring your own OpenAI or
/// Anthropic key, or leave it out for a keyless self-hosted endpoint. The
/// key is encrypted at rest and never returned. The person connecting it
/// may use it from then on. Records `agents.model_provider_connected`.
/// Requires `Agents(Manage)`.
pub(crate) async fn connect_model_provider(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Json(body): Json<ConnectModelProviderBody>,
) -> Result<Created<ConnectModelProviderResponse>, ApiError> {
    let id = agents
        .model_providers
        .connect
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(ConnectModelProviderResponse::from(id)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/model-providers",
    tag = "Agents",
    responses(
        (status = 200, description = "Success", body = Vec<ModelProviderResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// List model providers
///
/// Returns this tenant's model backends: kind, endpoint, model, clearance,
/// and whether a key is stored (never the key itself). Requires
/// `Agents(View)`.
pub(crate) async fn list_model_providers(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
) -> Result<Json<Vec<ModelProviderResponse>>, ApiError> {
    let providers = agents
        .model_providers
        .list
        .execute(&tenant.caller, ())
        .await?;
    Ok(Json(
        providers
            .into_iter()
            .map(ModelProviderResponse::from)
            .collect(),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/model-providers/{id}/test",
    tag = "Agents",
    responses(
        (status = 200, description = "Probe result", body = TestModelProviderResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 502, description = "The provider did not answer", body = ErrorBody)
    )
)]
/// Test a model provider
///
/// Sends a trivial completion to confirm the endpoint is reachable and
/// answering: the check to run before wiring agents to a freshly
/// self-hosted model. Returns the start of the model's reply, and keeps the
/// outcome as the provider's last test. Records
/// `agents.model_provider_tested`. Requires `Agents(Update)`.
pub(crate) async fn test_model_provider(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<ModelProviderPath>,
) -> Result<Json<TestModelProviderResponse>, ApiError> {
    let answer = agents
        .model_providers
        .test
        .execute(&tenant.caller, &tenant.auditor, path.provider())
        .await?;
    Ok(Json(TestModelProviderResponse::from(answer)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/model-providers/{id}",
    tag = "Agents",
    request_body = UpdateModelProviderStatusBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Enable or disable a model provider
///
/// Sets a provider's status. A disabled provider is kept but can no longer
/// be chosen for new runs. Records `agents.model_provider_status_changed`.
/// Requires `Agents(Update)`.
pub(crate) async fn update_model_provider_status(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<ModelProviderPath>,
    Json(body): Json<UpdateModelProviderStatusBody>,
) -> Result<NoContent, ApiError> {
    agents
        .model_providers
        .update_status
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.provider())?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/model-providers/{id}",
    tag = "Agents",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Still active", body = ErrorBody)
    )
)]
/// Delete a model provider
///
/// Removes a model provider for good. It must be disabled first. Records
/// `agents.model_provider_deleted`. Requires `Agents(Delete)`.
pub(crate) async fn delete_model_provider(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<ModelProviderPath>,
) -> Result<NoContent, ApiError> {
    agents
        .model_providers
        .delete
        .execute(&tenant.caller, &tenant.auditor, path.provider())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/model-providers/{id}/rotate-key",
    tag = "Agents",
    request_body = RotateModelProviderKeyBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "The provider holds that key already", body = ErrorBody),
        (status = 422, description = "The provider always takes a key", body = ErrorBody)
    )
)]
/// Rotate a model provider's API key
///
/// Replaces the key sent to the provider, for one that leaked or one the
/// backend retires. The new key is encrypted at rest and never returned;
/// the old one is no longer sent. Leave `api_key` out to remove the key of
/// a keyless self-hosted endpoint; OpenAI and Anthropic always take one
/// (`422`). Records `agents.model_provider_key_rotated`, without the key.
/// Requires `Agents(Manage)`.
pub(crate) async fn rotate_model_provider_key(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<ModelProviderPath>,
    Json(body): Json<RotateModelProviderKeyBody>,
) -> Result<NoContent, ApiError> {
    agents
        .model_providers
        .rotate_key
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.provider()),
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/model-providers/{id}/model",
    tag = "Agents",
    request_body = ChangeModelProviderModelBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "The provider asks for that model at that price already", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Change a model provider's model and price
///
/// Points the provider at another `model`, at the `pricing` it charges, so
/// runs started from then on reason with it and their spend is counted at
/// its price. Leave `pricing` out when the price is unknown: a run held to
/// a spend limit then stops after its first model call. Records
/// `agents.model_provider_model_changed`, naming both models. Requires
/// `Agents(Manage)`.
pub(crate) async fn change_model_provider_model(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<ModelProviderPath>,
    Json(body): Json<ChangeModelProviderModelBody>,
) -> Result<NoContent, ApiError> {
    agents
        .model_providers
        .change_model
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.provider())?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/model-providers/{id}/clearance",
    tag = "Agents",
    request_body = ChangeModelProviderClearanceBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Change a model provider's clearance
///
/// Sets the most sensitive data runs may send the provider (`Public`,
/// `Internal`, `Confidential` or `Restricted`); runs send it nothing above
/// it. Records `agents.model_provider_clearance_changed`, naming both
/// levels; clearing it for what it already has records nothing. Requires
/// `Agents(Manage)`.
pub(crate) async fn change_model_provider_clearance(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<ModelProviderPath>,
    Json(body): Json<ChangeModelProviderClearanceBody>,
) -> Result<NoContent, ApiError> {
    agents
        .model_providers
        .change_clearance
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.provider()),
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/model-providers/{id}/embeddings",
    tag = "Agents",
    request_body = OfferEmbeddingsBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "The provider offers that embedding model already", body = ErrorBody),
        (status = 422, description = "Validation error, or an Anthropic provider, whose API has no embeddings endpoint", body = ErrorBody)
    )
)]
/// Set a model provider's embedding model
///
/// Has the provider offer an `embedding_model` beside its chat model, such
/// as `text-embedding-3-small`, served at the same endpoint with the same
/// key, so the tenant's memories may be filled through it; `null` offers
/// none. A memory filled with another model stops taking texts. Records
/// `agents.model_provider_embeddings_changed`. Requires `Agents(Manage)`.
pub(crate) async fn offer_model_provider_embeddings(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<ModelProviderPath>,
    Json(body): Json<OfferEmbeddingsBody>,
) -> Result<NoContent, ApiError> {
    agents
        .model_providers
        .offer_embeddings
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.provider())?,
        )
        .await?;
    Ok(NoContent)
}
