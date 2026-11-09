//! Gateway configuration bodies: the document as it travels over HTTP.
//!
//! The wire form is deliberately plainer than the domain: names as strings,
//! no ids anywhere. It is meant to be written by hand and reviewed in a pull
//! request, so every value in it is one a person would type.

pub mod edge;
pub mod openapi;

use ianua_app::use_cases::gateway::diff::{
    ChangeKind, ConfigDiff, ImportMode, ResourceChange, ResourceKind,
};
use ianua_app::use_cases::gateway::document::{
    AcceptedSignInDeclaration, GatewayConfig, PipelineDeclaration, RouteDeclaration,
    ServiceDeclaration, StageDeclaration, StageSwitch,
};
use ianua_app::use_cases::gateway::{ApplyPlan, ImportConfigRequest};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::proxy::pipeline_status::PipelineStatus;
use ianua_domain::domains::proxy::stages::stage::{StageKind, StageRemoval};
use ianua_domain::domains::routing::backend::health_check::HealthCheckPolicy;
use ianua_domain::domains::routing::backend::upstream::Upstream;
use ianua_domain::domains::routing::matching::parameter::{ParameterRule, RouteReach};
use ianua_domain::domains::routing::matching::request_match::RouteConditions;
use ianua_domain::domains::routing::policy::RoutePolicy;
use ianua_domain::domains::routing::route_status::RouteStatus;
use ianua_domain::domains::routing::sign_in::accepted::SignInDelivery;
use ianua_domain::domains::routing::sign_in::app::AppSignIn;
use ianua_domain::types::{
    ActionClass, CertificatePem, DeclaredAction, HttpMethod, Label, Setting, UrlPath,
};
use serde::{Deserialize, Serialize};

use crate::dto::gateway::edge::{
    ConsumerConfigBody, EgressPolicyConfigBody, StreamRouteConfigBody,
};
use crate::dto::routing::routes::{PathRewriteBody, host_names, route_hosts};
use crate::dto::routing::sign_in::{AppSignInSettings, SignInDeliveryBody};
use crate::error::ApiError;

/// The priority a declared route gets when the document names none.
const DEFAULT_PRIORITY: u16 = 100;

/// A tenant's gateway configuration.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct GatewayConfigBody {
    /// The backends routes forward to.
    #[serde(default)]
    pub services: Vec<ServiceConfigBody>,
    /// The pipelines routes run.
    #[serde(default)]
    pub pipelines: Vec<PipelineConfigBody>,
    /// The routes, naming a service and a pipeline.
    #[serde(default)]
    pub routes: Vec<RouteConfigBody>,
    /// The ports listened on below HTTP.
    #[serde(default)]
    pub stream_routes: Vec<StreamRouteConfigBody>,
    /// Where services agents can reach may send traffic.
    #[serde(default)]
    pub egress_policies: Vec<EgressPolicyConfigBody>,
    /// The non-human callers let in.
    #[serde(default)]
    pub consumers: Vec<ConsumerConfigBody>,
}

/// A backend, as declared.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct ServiceConfigBody {
    /// Unique within the tenant; how the document addresses it.
    pub name: String,
    /// Where requests go.
    #[schema(value_type = Object)]
    pub upstream: Upstream,
    /// The client certificate it presents to its upstream, as PEM. Only the
    /// certificate is written down: its key is never in a document, so a
    /// service declared with one must already hold its key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_certificate: Option<String>,
    /// The private-network connector, by name, its upstream is reached
    /// through. Left out, it is reached directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connector: Option<String>,
    /// How its backends are probed. Omitted means probing is off.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub health_check: Option<HealthCheckPolicy>,
    /// Sign-in on the hosts it is served on. Omitted means none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_sign_in: Option<AppSignInSettings>,
    /// The service, by name, whose app sign-in this one accepts instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepts_app_sign_in_of: Option<String>,
    /// How that sign-in reaches this service. Defaults to `same_host`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_in_delivery: Option<SignInDeliveryBody>,
    /// Whether it accepts traffic.
    #[serde(default = "active")]
    #[schema(schema_with = crate::dto::schemas::route_status)]
    pub status: RouteStatus,
}

/// A pipeline, as declared.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct PipelineConfigBody {
    /// Unique within the tenant.
    pub name: String,
    /// Its stages, in the order given. Identity and Policy are added if
    /// omitted: a pipeline that skips them is not a pipeline this gateway
    /// will run.
    #[serde(default)]
    pub stages: Vec<StageConfigBody>,
    /// Whether it is live. Defaults to `Draft`: a pipeline arriving in a
    /// document has not been reviewed against this gateway's traffic yet.
    #[serde(default = "draft")]
    #[schema(schema_with = crate::dto::schemas::pipeline_status)]
    pub status: PipelineStatus,
}

/// One stage of a declared pipeline. No id: the document is portable.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct StageConfigBody {
    /// What the stage does, with its configuration.
    #[schema(value_type = Object)]
    pub kind: StageKind,
    /// Evaluation order. Lower runs first.
    pub position: u16,
    /// Whether it runs.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Whether the tenant may remove it.
    #[serde(default)]
    pub mandatory: bool,
}

/// A route, as declared.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct RouteConfigBody {
    /// Unique within the tenant.
    pub name: String,
    /// The path it claims.
    pub path_pattern: String,
    /// The methods it answers. Empty means all of them.
    #[serde(default)]
    #[schema(schema_with = crate::dto::schemas::http_method_list)]
    pub methods: Vec<HttpMethod>,
    /// The service it forwards to, by name.
    pub service: String,
    /// The pipeline it runs, by name.
    pub pipeline: String,
    /// Who may reach it.
    #[schema(value_type = Object)]
    pub policy: RoutePolicy,
    /// What path the upstream sees.
    #[serde(default)]
    pub path_rewrite: PathRewriteBody,
    /// Higher wins where two routes claim one path.
    #[serde(default = "default_priority")]
    pub priority: u16,
    /// Which of the tenant's domains it answers on. Empty means all of them.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Header and cookie conditions a request must all meet for the route
    /// to match it. Empty means none.
    #[serde(default)]
    #[schema(value_type = Vec<Object>)]
    pub conditions: RouteConditions,
    /// The most sensitive data it serves or accepts. Defaults to
    /// `Internal`.
    #[serde(default = "internal")]
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub data_class: DataClassLevel,
    /// What kind of action it takes, such as `Financial`. Left out, each
    /// request is judged by its method and path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(schema_with = crate::dto::schemas::action_class)]
    pub action_class: Option<ActionClass>,
    /// `fixed` (the default) or `open_ended`, for a service that fetches
    /// whatever it is given.
    #[serde(default)]
    #[schema(schema_with = crate::dto::schemas::route_reach)]
    pub reach: RouteReach,
    /// The parameters that carry a URL or host name, and the hosts each may
    /// name.
    #[serde(default)]
    #[schema(value_type = Vec<Object>)]
    pub parameter_rules: Vec<ParameterRule>,
    /// Whether it serves.
    #[serde(default = "active")]
    #[schema(schema_with = crate::dto::schemas::route_status)]
    pub status: RouteStatus,
}

/// A declared route serves unless it says otherwise.
fn active() -> RouteStatus {
    RouteStatus::Active
}

/// A declared pipeline starts as a draft unless it says otherwise.
fn draft() -> PipelineStatus {
    PipelineStatus::Draft
}

/// A declared route serves internal data unless it says otherwise.
fn internal() -> DataClassLevel {
    DataClassLevel::Internal
}

/// A declared stage runs unless it says otherwise.
fn yes() -> bool {
    true
}

/// The priority of a declared route that gives none.
fn default_priority() -> u16 {
    DEFAULT_PRIORITY
}

impl TryFrom<GatewayConfigBody> for GatewayConfig {
    type Error = ApiError;

    fn try_from(body: GatewayConfigBody) -> Result<Self, Self::Error> {
        Ok(Self {
            services: declared(body.services)?,
            pipelines: declared(body.pipelines)?,
            routes: declared(body.routes)?,
            stream_routes: declared(body.stream_routes)?,
            egress_policies: declared(body.egress_policies)?,
            consumers: declared(body.consumers)?,
        })
    }
}

/// Every declaration `bodies` describe, refusing the first that does not
/// read.
fn declared<B, D>(bodies: Vec<B>) -> Result<Vec<D>, ApiError>
where
    D: TryFrom<B, Error = ApiError>,
{
    bodies.into_iter().map(D::try_from).collect()
}

/// Every body describing `declarations`.
fn described<D, B: From<D>>(declarations: Vec<D>) -> Vec<B> {
    declarations.into_iter().map(B::from).collect()
}

impl TryFrom<ServiceConfigBody> for ServiceDeclaration {
    type Error = ApiError;

    fn try_from(body: ServiceConfigBody) -> Result<Self, Self::Error> {
        let app_sign_in = body.app_sign_in.map(AppSignIn::try_from).transpose()?;
        let client_certificate = body
            .client_certificate
            .map(CertificatePem::new)
            .transpose()
            .map_err(ApiError::validation)?;
        Ok(Self {
            name: label(body.name)?,
            upstream: body.upstream,
            client_certificate: Setting::from_stored(client_certificate),
            connector: Setting::from_stored(body.connector.map(label).transpose()?),
            health_check: body.health_check.unwrap_or(HealthCheckPolicy::Disabled),
            app_sign_in: Setting::from_stored(app_sign_in),
            accepts_app_sign_in: accepted_declaration(
                body.accepts_app_sign_in_of,
                body.sign_in_delivery,
            )?,
            status: body.status,
        })
    }
}

impl TryFrom<PipelineConfigBody> for PipelineDeclaration {
    type Error = ApiError;

    fn try_from(body: PipelineConfigBody) -> Result<Self, Self::Error> {
        Ok(Self {
            name: label(body.name)?,
            stages: body
                .stages
                .into_iter()
                .map(StageDeclaration::from)
                .collect(),
            status: body.status,
        })
    }
}

impl From<StageConfigBody> for StageDeclaration {
    fn from(body: StageConfigBody) -> Self {
        Self {
            kind: body.kind,
            position: body.position,
            switch: stage_switch(body.enabled),
            removal: stage_removal(body.mandatory),
        }
    }
}

/// Whether a declared stage runs.
fn stage_switch(enabled: bool) -> StageSwitch {
    if enabled {
        return StageSwitch::On;
    }
    StageSwitch::Off
}

/// Whether a declared stage may be removed.
fn stage_removal(mandatory: bool) -> StageRemoval {
    if mandatory {
        return StageRemoval::Locked;
    }
    StageRemoval::Allowed
}

impl TryFrom<RouteConfigBody> for RouteDeclaration {
    type Error = ApiError;

    fn try_from(body: RouteConfigBody) -> Result<Self, Self::Error> {
        Ok(Self {
            name: label(body.name)?,
            path_pattern: UrlPath::new(body.path_pattern).map_err(ApiError::validation)?,
            methods: body.methods,
            service: label(body.service)?,
            pipeline: label(body.pipeline)?,
            policy: body.policy,
            path_rewrite: body.path_rewrite.try_into()?,
            priority: body.priority,
            hosts: route_hosts(&body.hosts)?,
            conditions: body.conditions,
            data_class: body.data_class,
            action_class: DeclaredAction::from_stored(body.action_class),
            reach: body.reach,
            parameter_rules: body.parameter_rules,
            status: body.status,
        })
    }
}

/// The sign-in a declared service accepts, from the owner's name and the
/// delivery, which defaults to the owner's hosts.
fn accepted_declaration(
    owner: Option<String>,
    delivery: Option<SignInDeliveryBody>,
) -> Result<Setting<AcceptedSignInDeclaration>, ApiError> {
    let Some(owner) = owner else {
        return Ok(Setting::Unset);
    };
    let delivery = delivery
        .map(SignInDelivery::try_from)
        .transpose()?
        .unwrap_or(SignInDelivery::SameHost);
    Ok(Setting::Set(AcceptedSignInDeclaration {
        owner: label(owner)?,
        delivery,
    }))
}

/// Reads a name, which is how the document addresses everything in it.
fn label(value: String) -> Result<Label, ApiError> {
    Label::new("name", value).map_err(ApiError::validation)
}

impl From<GatewayConfig> for GatewayConfigBody {
    fn from(config: GatewayConfig) -> Self {
        Self {
            services: described(config.services),
            pipelines: described(config.pipelines),
            routes: described(config.routes),
            stream_routes: described(config.stream_routes),
            egress_policies: described(config.egress_policies),
            consumers: described(config.consumers),
        }
    }
}

impl From<ServiceDeclaration> for ServiceConfigBody {
    fn from(declaration: ServiceDeclaration) -> Self {
        let ServiceDeclaration {
            name,
            upstream,
            client_certificate,
            connector,
            health_check,
            app_sign_in,
            accepts_app_sign_in,
            status,
        } = declaration;
        let accepted = accepts_app_sign_in.value();
        Self {
            name: name.as_str().to_owned(),
            upstream,
            client_certificate: client_certificate
                .value()
                .map(|certificate| certificate.as_str().to_owned()),
            connector: connector.value().map(|name| name.as_str().to_owned()),
            health_check: Some(health_check),
            app_sign_in: app_sign_in.value().map(AppSignInSettings::from),
            accepts_app_sign_in_of: accepted.map(|accepted| accepted.owner.as_str().to_owned()),
            sign_in_delivery: accepted.map(|accepted| SignInDeliveryBody::from(&accepted.delivery)),
            status,
        }
    }
}

impl From<PipelineDeclaration> for PipelineConfigBody {
    fn from(declaration: PipelineDeclaration) -> Self {
        Self {
            name: declaration.name.as_str().to_owned(),
            stages: declaration.stages.into_iter().map(Into::into).collect(),
            status: declaration.status,
        }
    }
}

impl From<StageDeclaration> for StageConfigBody {
    fn from(declaration: StageDeclaration) -> Self {
        Self {
            kind: declaration.kind,
            position: declaration.position,
            enabled: declaration.switch == StageSwitch::On,
            mandatory: declaration.removal == StageRemoval::Locked,
        }
    }
}

impl From<RouteDeclaration> for RouteConfigBody {
    fn from(declaration: RouteDeclaration) -> Self {
        Self {
            name: declaration.name.as_str().to_owned(),
            path_pattern: declaration.path_pattern.as_str().to_owned(),
            methods: declaration.methods,
            service: declaration.service.as_str().to_owned(),
            pipeline: declaration.pipeline.as_str().to_owned(),
            policy: declaration.policy,
            path_rewrite: PathRewriteBody::from(&declaration.path_rewrite),
            priority: declaration.priority,
            hosts: host_names(&declaration.hosts),
            conditions: declaration.conditions,
            data_class: declaration.data_class,
            action_class: declaration.action_class.stored(),
            reach: declaration.reach,
            parameter_rules: declaration.parameter_rules,
            status: declaration.status,
        }
    }
}

/// A document and what to do with it.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ImportConfigBody {
    /// The desired configuration.
    pub config: GatewayConfigBody,
    /// Whether resources the document omits are removed. Defaults to
    /// `merge`, which removes nothing.
    #[serde(default)]
    pub mode: ImportModeBody,
    /// Whether to apply the change or only report it. Defaults to
    /// `dry_run`: an import that writes has to be asked for.
    #[serde(default)]
    pub plan: ApplyPlanBody,
}

impl TryFrom<ImportConfigBody> for ImportConfigRequest {
    type Error = ApiError;

    fn try_from(body: ImportConfigBody) -> Result<Self, Self::Error> {
        Ok(Self {
            config: GatewayConfig::try_from(body.config)?,
            mode: body.mode.into(),
            plan: body.plan.into(),
        })
    }
}

/// Whether an apply may remove what the document does not mention.
#[derive(Deserialize, Default, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ImportModeBody {
    /// Create and update only.
    #[default]
    Merge,
    /// Make the gateway match the document exactly.
    Replace,
}

/// Whether the caller wants the change or only the plan.
#[derive(Deserialize, Default, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ApplyPlanBody {
    /// Report the plan and change nothing.
    #[default]
    DryRun,
    /// Carry the plan out.
    Apply,
}

impl From<ImportModeBody> for ImportMode {
    fn from(body: ImportModeBody) -> Self {
        match body {
            ImportModeBody::Merge => Self::Merge,
            ImportModeBody::Replace => Self::Replace,
        }
    }
}

impl From<ApplyPlanBody> for ApplyPlan {
    fn from(body: ApplyPlanBody) -> Self {
        match body {
            ApplyPlanBody::DryRun => Self::DryRun,
            ApplyPlanBody::Apply => Self::Apply,
        }
    }
}

/// What an import did, or would do.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ConfigDiffResponse {
    /// Whether anything would change.
    pub empty: bool,
    /// How many resources are not `unchanged`.
    pub change_count: usize,
    /// Every resource, in apply order.
    pub changes: Vec<ResourceChangeResponse>,
}

/// One line of the plan.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ResourceChangeResponse {
    /// What kind of thing it is: `service`, `pipeline`, `route`,
    /// `consumer`, `stream_route` or `egress_policy`.
    pub resource: String,
    /// The resource label matching the planned edit to the submitted configuration.
    pub name: String,
    /// What happens to it: `create`, `update`, `delete` or `unchanged`.
    pub change: String,
}

impl From<ConfigDiff> for ConfigDiffResponse {
    fn from(diff: ConfigDiff) -> Self {
        Self {
            empty: diff.is_empty(),
            change_count: diff.effective_count(),
            changes: diff
                .changes
                .iter()
                .map(ResourceChangeResponse::from)
                .collect(),
        }
    }
}

impl From<&ResourceChange> for ResourceChangeResponse {
    fn from(change: &ResourceChange) -> Self {
        let resource = match change.resource {
            ResourceKind::Service => "service",
            ResourceKind::Pipeline => "pipeline",
            ResourceKind::Route => "route",
            ResourceKind::Consumer => "consumer",
            ResourceKind::StreamRoute => "stream_route",
            ResourceKind::EgressPolicy => "egress_policy",
        };
        let kind = match change.kind {
            ChangeKind::Create => "create",
            ChangeKind::Update => "update",
            ChangeKind::Delete => "delete",
            ChangeKind::Unchanged => "unchanged",
        };
        Self {
            resource: resource.to_owned(),
            name: change.name.as_str().to_owned(),
            change: kind.to_owned(),
        }
    }
}
