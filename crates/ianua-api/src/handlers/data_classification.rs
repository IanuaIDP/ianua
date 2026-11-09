//! Data classification handlers: a tenant's field-level sensitivity rules,
//! which the proxy's redaction stage reads.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::data_classification::AddClassificationRuleRequest;
use ianua_assembly::data_classification::DataClassificationState;

use crate::dto::data_classification::{
    AddRuleBody, ChangeRuleBody, ClassificationResponse, ClassificationRuleResponse,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::data_classification::ClassificationRulePath;
use crate::response::{Created, NoContent};

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/classification",
    tag = "Classification",
    responses(
        (status = 200, description = "Success", body = ClassificationResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// Tenant data-classification rule set
///
/// Maps dot-notation fields to `Public`, `Internal`, `Confidential` or
/// `Restricted` sensitivity, in ascending order, and `Remove`, `Mask` or
/// `Hash` redaction. The proxy applies these at or above its configured threshold.
/// Before the first rule, returns empty `rules` and `null` `id`, not `404`.
/// Requires `Classification(View)` and changes nothing.
pub(crate) async fn get_classification(
    State(classification): State<DataClassificationState>,
    tenant: TenantCaller,
) -> Result<Json<ClassificationResponse>, ApiError> {
    let rule_set = classification.get.execute(&tenant.caller, ()).await?;
    Ok(Json(ClassificationResponse::from(rule_set)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/classification/rules",
    tag = "Classification",
    request_body = AddRuleBody,
    responses(
        (status = 201, description = "Created", body = ClassificationRuleResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 409, description = "The field path is already classified", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Add a classification rule
///
/// Creates the set on its first rule. Each path has one rule until removed;
/// duplicates return `409`, so use `PUT` to change level or redaction in place.
/// Paths have at most 256 ASCII characters and 10 dot-separated segments,
/// each `[a-zA-Z_][a-zA-Z0-9_]*`, without empty segments or edge dots.
/// Levels are `Public`, `Internal`, `Confidential`, `Restricted`; redactions
/// are `Remove`, `Mask`, `Hash`. Unsupported `Encrypt` and invalid fields
/// return `422`. Returns `201` with the rule's edit/delete `id`.
/// Requires `Classification(Update)`; records `proxy.classification_rule_added`.
pub(crate) async fn add_rule(
    State(classification): State<DataClassificationState>,
    tenant: TenantCaller,
    Json(body): Json<AddRuleBody>,
) -> Result<Created<ClassificationRuleResponse>, ApiError> {
    let request = AddClassificationRuleRequest::try_from(&body)?;
    let id = classification
        .add_rule
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(Created(ClassificationRuleResponse::added(id, body)))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/classification/rules/{id}",
    tag = "Classification",
    request_body = ChangeRuleBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such rule", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Change a classification rule
///
/// Sets a rule's sensitivity `level` and `redaction` strategy in place. The
/// rule keeps its `id` and its `field_path`, and the field is never sent
/// unredacted between the old rule and the new, as removing and adding
/// again would allow.
///
/// Returns `404` if no rule has this `id`. **Field validation** (`422`):
/// `level` is one of `Public`, `Internal`, `Confidential`, `Restricted`;
/// `redaction` is `Remove`, `Mask` or `Hash`. `Encrypt` parses but is
/// refused, because nothing behind it encrypts yet. Records
/// `proxy.classification_rule_changed` with the level and redaction before
/// and after. Requires `Classification(Update)`, as adding a rule does.
pub(crate) async fn change_rule(
    State(classification): State<DataClassificationState>,
    tenant: TenantCaller,
    Path(path): Path<ClassificationRulePath>,
    Json(body): Json<ChangeRuleBody>,
) -> Result<NoContent, ApiError> {
    classification
        .change_rule
        .execute(&tenant.caller, &tenant.auditor, body.change_of(path.rule()))
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/classification/rules/{id}",
    tag = "Classification",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such rule", body = ErrorBody)
    )
)]
/// Remove a classification rule
///
/// Deletes a single rule from this tenant's classification set by `id`.
///
/// **State.** The rule goes `present -> absent`; the rule set itself stays,
/// and the field it classified reaches callers unredacted. Returns `404` if
/// no rule has this `id`. To change a rule rather than drop it, `PUT` it.
/// Records `proxy.classification_rule_removed`. Requires
/// `Classification(Update)`.
pub(crate) async fn remove_rule(
    State(classification): State<DataClassificationState>,
    tenant: TenantCaller,
    Path(path): Path<ClassificationRulePath>,
) -> Result<NoContent, ApiError> {
    classification
        .remove_rule
        .execute(&tenant.caller, &tenant.auditor, path.rule())
        .await?;
    Ok(NoContent)
}
