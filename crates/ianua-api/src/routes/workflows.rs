//! Workflow endpoints: integration accounts, their connections by signing
//! in and the catalog's operations and events, definitions and their
//! drafts, webhook secrets and the webhook itself, services' events,
//! executions and their approvals, agent flows, raised operation risks,
//! and sandboxes.

use std::time::Duration;

use axum::Router;
use utoipa::OpenApi;

use crate::dto::workflows::accounts::channels::{
    ChannelResponse, ChannelSetupBody, ChannelStatusBody, ChannelTokenResponse, SetChannelKeyBody,
};
use crate::dto::workflows::accounts::connections::{
    BeginConnectionBody, ConnectionBegunResponse, FinishConnectionBody,
};
use crate::dto::workflows::accounts::{
    AccountResponse, ChangeAccountBody, ConnectAccountBody, SharingBody,
};
use crate::dto::workflows::builder::{
    DraftAfterBody, DraftBody, EarlierDataResponse, ProposalResponse, ProposedEdgeResponse,
    ProposedInputResponse, ProposedKindResponse, ProposedStepResponse, ProposedTriggerResponse,
    ReadableValueResponse, StepDataResponse,
};
use crate::dto::workflows::catalog::apps::AppResponse;
use crate::dto::workflows::catalog::data::DataResponse;
use crate::dto::workflows::catalog::risk_overrides::{ChangeRiskBody, RaiseRiskBody, RiskResponse};
use crate::dto::workflows::catalog::{
    ChoiceResponse, ChoicesResponse, EventResponse, InputFormResponse, IntegrationResponse,
    ListChoicesBody, OfferedChoiceResponse, OperationInputResponse, OperationOutputResponse,
    OperationResponse, PickerResponse, PreviewPartResponse, PreviewResponse,
};
use crate::dto::workflows::definitions::{
    CreateWorkflowBody, EditDraftBody, NeedsAccountResponse, PublishWorkflowBody, StepPositionBody,
    WorkflowResponse,
};
use crate::dto::workflows::evaluations::{
    CaseBody, CaseResponse, CaseResultResponse, CheckBody, DifferenceResponse, EvaluationResponse,
    EvaluationSetResponse, SaveEvaluationSetBody,
};
use crate::dto::workflows::executions::{
    ApprovalDataResponse, ApproveStepBody, ExecutionDecidedResponse, ExecutionResponse,
    LoopProgressResponse, PassResponse, StartExecutionBody, StartTestBody, StepFailureResponse,
    StepStateResponse, WebhookStartResponse,
};
use crate::dto::workflows::flows::{CreateFlowBody, FlowNodeBody, FlowNodeResponse, FlowResponse};
use crate::dto::workflows::graph::{
    ClauseBody, CoveringBody, EdgeBody, GraphBody, JoinBody, MappedFieldBody, MatchingBody,
    NodeBody, SourceBody, StepBody, TestBody, TriggerBody,
};
use crate::dto::workflows::loop_approvals::{
    ApprovalItemResponse, ApproveItemsBody, ItemsPageResponse,
};
use crate::dto::workflows::memories::{
    CreateMemoryBody, DeleteMemoryBody, MemoryEntryPageResponse, MemoryEntryResponse,
    MemoryResponse,
};
use crate::dto::workflows::sandboxes::{
    AllowRegistryBody, BuildResponse, CreateSandboxBody, FindingsResponse, FixBody, HeldAgentBody,
    ImportBody, ImportedFromResponse, PackageBody, PushVersionBody, RegistryResponse,
    RuntimeResponse, SandboxDetailResponse, SandboxResponse, SandboxVersionResponse,
    SaveVersionBody, StartTrialBody, TrialResponse, WriteCodeBody, WrittenCodeResponse,
};
use crate::dto::workflows::triggers::TriggerSecretResponse;
use crate::handlers::workflows::{
    accounts, catalog, channels, connections, definitions, evaluations, events, executions, flows,
    live, memories, risk_overrides, sandboxes, triggers,
};
use crate::method::{delete, get, patch, post, shared};
use crate::middleware::ip_rate_limit::{ip_rate_limit, per_address};
use crate::state::ApiState;

/// The tenant part of every workflow path.
const TENANT: &str = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}";

/// A workflow's webhook, called by whatever was handed its secret, and the
/// browser a service sends back after a sign-in, both with no session:
/// limited per client address.
pub(crate) fn public_routes(state: &ApiState) -> Router<ApiState> {
    let limiter = per_address(
        state,
        state.http.rate.api_default_per_minute,
        Duration::from_secs(60),
    );
    Router::new()
        .route(
            &format!("{TENANT}/workflows/triggers/{{trigger_id}}"),
            post(executions::call_webhook),
        )
        .route(
            "/api/v1/integrations/callback",
            get(connections::answer_connection),
        )
        .layer(axum::middleware::from_fn_with_state(limiter, ip_rate_limit))
        .merge(service_routes(state))
}

/// What integrations' services send registered workflows, with no session:
/// a service sends every tenant's events from a few addresses, so these
/// get the window a payment provider's burst of notices gets.
fn service_routes(state: &ApiState) -> Router<ApiState> {
    let window = state.http.rate.sso;
    let limiter = per_address(state, window.max, window.window);
    Router::new()
        .route(
            "/api/v1/integrations/events/{subscription_id}",
            post(events::receive_event).head(shared(events::address_served)),
        )
        .route(
            "/api/v1/integrations/events/channels/{channel_id}",
            post(events::receive_channel_event),
        )
        .route(
            "/api/v1/integrations/{integration}/events",
            post(events::receive_app_event),
        )
        .layer(axum::middleware::from_fn_with_state(limiter, ip_rate_limit))
}

/// The workflow endpoints for a person of the tenant.
pub(crate) fn routes() -> Router<ApiState> {
    let base = format!("{TENANT}/workflows");
    let workflow = format!("{base}/{{workflow_id}}");
    account_routes(&base)
        .merge(catalog_routes(&base))
        .merge(definition_routes(&base, &workflow))
        .merge(version_routes(&workflow))
        .merge(execution_routes(&base, &workflow))
        .merge(flow_routes())
        .merge(risk_routes(&base))
        .merge(sandbox_routes())
        .merge(memory_routes())
        .merge(evaluation_routes(&workflow))
}

/// A workflow's sample cases and its evaluations against them.
fn evaluation_routes(workflow: &str) -> Router<ApiState> {
    let evaluations = format!("{workflow}/evaluations");
    Router::new()
        .route(
            &format!("{workflow}/evaluation-set"),
            get(evaluations::get_evaluation_set).put(shared(evaluations::save_evaluation_set)),
        )
        .route(
            &evaluations,
            get(evaluations::list_evaluations).post(shared(evaluations::start_evaluation)),
        )
        .route(
            &format!("{evaluations}/{{evaluation_id}}"),
            get(evaluations::get_evaluation),
        )
}

/// Integration accounts and their browser-based connection steps.
fn account_routes(base: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{base}/accounts"),
            get(accounts::list_accounts).post(shared(accounts::connect_account)),
        )
        .route(
            &format!("{base}/accounts/{{account_id}}"),
            patch(accounts::change_account),
        )
        .route(
            &format!("{base}/accounts/connections"),
            post(connections::begin_connection),
        )
        .route(
            &format!("{base}/accounts/connections/{{connection_id}}/finish"),
            post(connections::finish_connection),
        )
        .merge(account_channel_routes(base))
}

/// An account's one address for a service's events.
fn account_channel_routes(base: &str) -> Router<ApiState> {
    let channel = format!("{base}/accounts/{{account_id}}/event-channel");
    Router::new()
        .route(&channel, get(channels::show_channel))
        .route(&format!("{channel}/key"), post(channels::set_channel_key))
        .route(
            &format!("{channel}/token"),
            post(channels::show_channel_token),
        )
        .route(
            &format!("{channel}/confirm"),
            post(channels::confirm_channel),
        )
}

/// Available integrations, operations, choices, events, apps, and data.
fn catalog_routes(base: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{base}/integrations"),
            get(catalog::list_integrations),
        )
        .route(&format!("{base}/operations"), get(catalog::list_operations))
        .route(
            &format!("{base}/operations/{{integration}}/{{operation}}/inputs/{{input}}/choices"),
            post(catalog::list_choices),
        )
        .route(&format!("{base}/events"), get(catalog::list_events))
        .route(&format!("{base}/apps"), get(catalog::list_apps))
        .route(&format!("{base}/data"), get(catalog::list_data))
}

/// Workflow definitions, drafting assistance, tests, and live updates.
fn definition_routes(base: &str, workflow: &str) -> Router<ApiState> {
    Router::new()
        .route(
            base,
            get(definitions::list_workflows).post(shared(definitions::create_workflow)),
        )
        .route(
            &format!("{base}/suggestions"),
            post(definitions::suggest_steps),
        )
        .route(workflow, get(definitions::get_workflow))
        .route(
            &format!("{workflow}/step-data"),
            get(definitions::step_data),
        )
        .route(&format!("{workflow}/tests"), post(executions::start_test))
        .route(
            &format!("{TENANT}/ws/workflows/executions/{{execution_id}}"),
            get(live::run_ws),
        )
        .route(
            &format!("{TENANT}/ws/workflows/{{workflow_id}}/draft"),
            get(live::draft_ws),
        )
}

/// Version publishing, archival, and webhook secrets for a workflow.
fn version_routes(workflow: &str) -> Router<ApiState> {
    let version = format!("{workflow}/versions/{{version}}");
    Router::new()
        .route(&version, get(definitions::get_workflow_version))
        .route(
            &format!("{workflow}/draft"),
            patch(definitions::edit_draft).post(shared(definitions::next_draft)),
        )
        .route(
            &format!("{workflow}/publish"),
            post(definitions::publish_workflow),
        )
        .route(
            &format!("{version}/archive"),
            post(definitions::archive_workflow),
        )
        .route(
            &format!("{workflow}/trigger-secret"),
            post(triggers::issue_trigger_secret).delete(shared(triggers::revoke_trigger_secret)),
        )
        .route(
            &format!("{workflow}/trigger-secret/rotate"),
            post(triggers::rotate_trigger_secret),
        )
}

/// Starting and reading executions, with their control and approval endpoints.
fn execution_routes(base: &str, workflow: &str) -> Router<ApiState> {
    let execution = format!("{base}/executions/{{execution_id}}");
    Router::new()
        .route(
            &format!("{workflow}/executions"),
            get(executions::list_executions).post(shared(executions::start_execution)),
        )
        .route(
            &format!("{base}/executions"),
            get(executions::list_all_executions),
        )
        .route(&execution, get(executions::get_execution))
        .route(&format!("{execution}/passes"), get(executions::list_passes))
        .merge(execution_control_routes(&execution))
}

/// Cancellation, retries, and decisions on execution approvals.
fn execution_control_routes(execution: &str) -> Router<ApiState> {
    let approval = format!("{execution}/approvals/{{step}}");
    Router::new()
        .route(
            &format!("{execution}/cancel"),
            post(executions::cancel_execution),
        )
        .route(
            &format!("{execution}/rerun"),
            post(executions::rerun_execution),
        )
        .route(
            &format!("{execution}/retry"),
            post(executions::retry_execution),
        )
        .route(&approval, get(executions::show_approval))
        .route(
            &format!("{approval}/approve"),
            post(executions::approve_step),
        )
        .route(&format!("{approval}/deny"), post(executions::deny_step))
        .route(
            &format!("{approval}/items"),
            get(executions::list_approval_items),
        )
        .route(
            &format!("{approval}/items/approve"),
            post(executions::approve_items),
        )
}

/// Agent flow creation, cancellation, and removal.
fn flow_routes() -> Router<ApiState> {
    let flow_base = format!("{TENANT}/flows");
    Router::new()
        .route(
            &flow_base,
            get(flows::list_flows).post(shared(flows::create_flow)),
        )
        .route(
            &format!("{flow_base}/{{flow_id}}"),
            get(flows::get_flow).delete(shared(flows::delete_flow)),
        )
        .route(
            &format!("{flow_base}/{{flow_id}}/cancel"),
            post(flows::cancel_flow),
        )
}

/// Tenant overrides of operation risk levels.
fn risk_routes(base: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{base}/risks"),
            get(risk_overrides::list_risks).post(shared(risk_overrides::raise_risk)),
        )
        .route(
            &format!("{base}/risks/{{risk_id}}"),
            patch(risk_overrides::change_risk).delete(shared(risk_overrides::remove_risk)),
        )
}

/// Sandbox definitions and available runtimes, with version operations.
fn sandbox_routes() -> Router<ApiState> {
    let sandbox_base = format!("{TENANT}/sandboxes");
    let sandbox = format!("{sandbox_base}/{{sandbox_id}}");
    Router::new()
        .route(
            &sandbox_base,
            get(sandboxes::list_sandboxes).post(shared(sandboxes::create_sandbox)),
        )
        .route(
            &format!("{sandbox_base}/runtimes"),
            get(sandboxes::list_runtimes),
        )
        .route(
            &format!("{sandbox_base}/registries"),
            get(sandboxes::list_registries).post(shared(sandboxes::allow_registry)),
        )
        .route(
            &format!("{sandbox_base}/registries/{{registry_id}}"),
            delete(sandboxes::remove_registry),
        )
        .route(&sandbox, get(sandboxes::get_sandbox))
        .merge(sandbox_version_routes(&sandbox))
}

/// Sandbox code, saved versions, trials, publication, and archival.
fn sandbox_version_routes(sandbox: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{sandbox}/versions"),
            post(sandboxes::save_version),
        )
        .route(
            &format!("{sandbox}/versions/{{version_id}}/trials"),
            post(sandboxes::start_trial),
        )
        .route(
            &format!("{sandbox}/versions/{{version_id}}/pushes"),
            post(sandboxes::push_version),
        )
        .route(
            &format!("{sandbox}/suggestions"),
            post(sandboxes::write_code),
        )
        .route(
            &format!("{sandbox}/trials/{{trial_id}}"),
            get(sandboxes::get_trial),
        )
        .route(
            &format!("{sandbox}/archive"),
            post(sandboxes::archive_sandbox),
        )
}

/// Tenant memories and their stored entries, including deletion and restoration.
fn memory_routes() -> Router<ApiState> {
    let memory_base = format!("{TENANT}/memories");
    let memory = format!("{memory_base}/{{memory_id}}");
    Router::new()
        .route(
            &memory_base,
            get(memories::list_memories).post(shared(memories::create_memory)),
        )
        .route(&format!("{memory}/delete"), post(memories::delete_memory))
        .route(&format!("{memory}/restore"), post(memories::restore_memory))
        .route(
            &format!("{memory}/entries"),
            get(memories::list_memory_entries),
        )
}

/// The workflow part of the OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    paths(
        accounts::list_accounts,
        accounts::connect_account,
        accounts::change_account,
        channels::show_channel,
        channels::set_channel_key,
        channels::show_channel_token,
        channels::confirm_channel,
        events::receive_channel_event,
        connections::begin_connection,
        connections::answer_connection,
        connections::finish_connection,
        catalog::list_integrations,
        catalog::list_operations,
        catalog::list_events,
        catalog::list_apps,
        catalog::list_data,
        catalog::list_choices,
        definitions::list_workflows,
        definitions::create_workflow,
        definitions::get_workflow,
        definitions::get_workflow_version,
        definitions::edit_draft,
        definitions::next_draft,
        definitions::publish_workflow,
        definitions::archive_workflow,
        definitions::step_data,
        definitions::suggest_steps,
        triggers::issue_trigger_secret,
        triggers::rotate_trigger_secret,
        triggers::revoke_trigger_secret,
        executions::call_webhook,
        events::receive_event,
        events::address_served,
        events::receive_app_event,
        executions::start_execution,
        executions::start_test,
        evaluations::get_evaluation_set,
        evaluations::save_evaluation_set,
        evaluations::start_evaluation,
        evaluations::list_evaluations,
        evaluations::get_evaluation,
        executions::list_executions,
        executions::list_all_executions,
        executions::get_execution,
        executions::list_passes,
        executions::cancel_execution,
        executions::rerun_execution,
        executions::retry_execution,
        executions::show_approval,
        executions::approve_step,
        executions::deny_step,
        executions::list_approval_items,
        executions::approve_items,
        live::run_ws,
        live::draft_ws,
        flows::create_flow,
        flows::list_flows,
        flows::get_flow,
        flows::cancel_flow,
        flows::delete_flow,
        risk_overrides::list_risks,
        risk_overrides::raise_risk,
        risk_overrides::change_risk,
        risk_overrides::remove_risk,
        sandboxes::list_sandboxes,
        sandboxes::create_sandbox,
        sandboxes::list_runtimes,
        sandboxes::get_sandbox,
        sandboxes::save_version,
        sandboxes::start_trial,
        sandboxes::push_version,
        sandboxes::write_code,
        sandboxes::get_trial,
        sandboxes::archive_sandbox,
        sandboxes::list_registries,
        sandboxes::allow_registry,
        sandboxes::remove_registry,
        memories::list_memories,
        memories::create_memory,
        memories::delete_memory,
        memories::restore_memory,
        memories::list_memory_entries,
    ),
    components(schemas(
        AccountResponse,
        ConnectAccountBody,
        ChangeAccountBody,
        SharingBody,
        ChannelResponse,
        ChannelSetupBody,
        ChannelStatusBody,
        ChannelTokenResponse,
        SetChannelKeyBody,
        IntegrationResponse,
        OperationResponse,
        OperationInputResponse,
        OperationOutputResponse,
        InputFormResponse,
        ChoiceResponse,
        PickerResponse,
        PreviewResponse,
        PreviewPartResponse,
        ListChoicesBody,
        ChoicesResponse,
        OfferedChoiceResponse,
        EventResponse,
        AppResponse,
        DataResponse,
        BeginConnectionBody,
        ConnectionBegunResponse,
        FinishConnectionBody,
        WorkflowResponse,
        NeedsAccountResponse,
        CreateWorkflowBody,
        EditDraftBody,
        PublishWorkflowBody,
        StepPositionBody,
        StepDataResponse,
        EarlierDataResponse,
        ReadableValueResponse,
        DraftBody,
        DraftAfterBody,
        ProposalResponse,
        ProposedTriggerResponse,
        ProposedStepResponse,
        ProposedKindResponse,
        ProposedInputResponse,
        ProposedEdgeResponse,
        GraphBody,
        NodeBody,
        JoinBody,
        StepBody,
        MatchingBody,
        CoveringBody,
        MappedFieldBody,
        SourceBody,
        ClauseBody,
        TestBody,
        EdgeBody,
        TriggerBody,
        TriggerSecretResponse,
        WebhookStartResponse,
        ExecutionResponse,
        PassResponse,
        StepStateResponse,
        LoopProgressResponse,
        StepFailureResponse,
        ExecutionDecidedResponse,
        StartExecutionBody,
        StartTestBody,
        SaveEvaluationSetBody,
        CaseBody,
        CheckBody,
        EvaluationSetResponse,
        CaseResponse,
        EvaluationResponse,
        CaseResultResponse,
        DifferenceResponse,
        ApprovalDataResponse,
        ApproveStepBody,
        ItemsPageResponse,
        ApprovalItemResponse,
        ApproveItemsBody,
        CreateFlowBody,
        FlowNodeBody,
        FlowResponse,
        FlowNodeResponse,
        RiskResponse,
        RaiseRiskBody,
        ChangeRiskBody,
        SandboxResponse,
        CreateMemoryBody,
        DeleteMemoryBody,
        MemoryResponse,
        MemoryEntryResponse,
        MemoryEntryPageResponse,
        SandboxVersionResponse,
        SandboxDetailResponse,
        BuildResponse,
        FindingsResponse,
        RegistryResponse,
        AllowRegistryBody,
        RuntimeResponse,
        PackageBody,
        CreateSandboxBody,
        SaveVersionBody,
        HeldAgentBody,
        ImportBody,
        ImportedFromResponse,
        StartTrialBody,
        TrialResponse,
        WriteCodeBody,
        FixBody,
        WrittenCodeResponse,
        PushVersionBody,
    ))
)]
pub(crate) struct Document;
