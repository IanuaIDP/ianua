//! The automation product: the integrations and operations a builder may
//! use, connecting an account with its credential or by signing in at its
//! service, drafting and publishing a workflow, archiving a version, its
//! webhook's secret and a service's deliveries, starting, listing,
//! reading and retrying executions, the passes of their loops, deciding
//! the approvals they wait for, one approval for every item of a loop,
//! the builder's reads: what each step may read, a picker's options, and
//! tests of a draft, and evaluations of a draft against sample cases.

use serde_json::Value;

use super::{Request, TenantPath, Text};
use crate::net::Call;
use crate::wire::Page;
use crate::wire::workflows::{
    Account, App, Approval, Approve, ApproveItems, Choices, ConnectionBegun, DataRoute, Evaluation,
    EvaluationSet, Execution, ExecutionDecided, ExecutionSummary, FinishConnection, Integration,
    ItemsPage, ListChoices, NewAccount, NewConnection, NewEvaluationSet, NewWorkflow, Operation,
    PassRun, Publication, StartExecution, StepData, TriggerSecret, WebhookStarted, Workflow,
};

/// The header a webhook call carries its secret in.
const SECRET_HEADER: &str = "Ianua-Trigger-Secret";

/// Where every service sends the browser back after signing in.
const CALLBACK: &str = "/api/v1/integrations/callback";

/// `GET …/workflows/integrations`: every integration installed.
#[must_use]
pub fn integrations(tenant: &TenantPath) -> Request<Vec<Integration>> {
    Request::of(Call::get(tenant.at("/workflows/integrations")))
}

/// `GET …/workflows/apps`: every route open to workflows.
#[must_use]
pub fn apps(tenant: &TenantPath) -> Request<Vec<App>> {
    Request::of(Call::get(tenant.at("/workflows/apps")))
}

/// `GET …/workflows/data`: every stream route open to workflows.
#[must_use]
pub fn data(tenant: &TenantPath) -> Request<Vec<DataRoute>> {
    Request::of(Call::get(tenant.at("/workflows/data")))
}

/// `GET …/workflows/operations`: every operation offered, with its guide.
#[must_use]
pub fn operations(tenant: &TenantPath) -> Request<Vec<Operation>> {
    Request::of(Call::get(tenant.at("/workflows/operations")))
}

/// `POST …/workflows/accounts`: connects an integration's account.
#[must_use]
pub fn connect_account(tenant: &TenantPath, account: &NewAccount) -> Request<Account> {
    Request::of(Call::post(tenant.at("/workflows/accounts")).json(account))
}

/// `POST …/workflows/accounts/connections`: begins connecting an account
/// by signing in at its service.
#[must_use]
pub fn begin_connection(
    tenant: &TenantPath,
    connection: &NewConnection,
) -> Request<ConnectionBegun> {
    Request::of(Call::post(tenant.at("/workflows/accounts/connections")).json(connection))
}

/// `GET /api/v1/integrations/callback`: the browser back from the service
/// with its `code` for the sign-in `state`, sent on to the dashboard.
#[must_use]
pub fn answer_connection(state: &str, code: &str) -> Request<Text> {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("state", state)
        .append_pair("code", code)
        .finish();
    Request::text(Call::get(format!("{CALLBACK}?{query}")))
}

/// `POST …/accounts/connections/{id}/finish`: the connection finished with
/// the one-time code the browser brought back.
#[must_use]
pub fn finish_connection(
    tenant: &TenantPath,
    connection_id: &str,
    finish: &FinishConnection,
) -> Request<Account> {
    let path = tenant.at(&format!(
        "/workflows/accounts/connections/{connection_id}/finish"
    ));
    Request::of(Call::post(path).json(finish))
}

/// `POST` of `delivery` to its registration's address, as the service
/// delivers an event.
#[must_use]
pub fn deliver_event(delivery: &ServiceDelivery<'_>) -> Request<Text> {
    let call = delivery.headers.iter().fold(
        Call::post(delivery.path).raw(delivery.content_type, delivery.body),
        |call, (name, value)| call.header(name, value),
    );
    Request::text(call)
}

/// `HEAD` of a registration's address, as Trello checks it before it
/// takes a webhook.
#[must_use]
pub fn check_event_address(path: &str) -> Request<Text> {
    Request::text(Call::head(path))
}

/// One event a service delivers.
pub struct ServiceDelivery<'a> {
    /// The registration's address, its path and query.
    pub path: &'a str,
    /// The body's type, such as `application/json`.
    pub content_type: &'a str,
    /// The headers the service sends.
    pub headers: &'a [(&'a str, &'a str)],
    /// The body, as the service sends it.
    pub body: &'a str,
}

/// `POST …/workflows`: a new workflow, as a draft.
#[must_use]
pub fn create_draft(tenant: &TenantPath, workflow: &NewWorkflow) -> Request<Workflow> {
    Request::of(Call::post(tenant.at("/workflows")).json(workflow))
}

/// `POST …/workflows/{id}/publish`: puts the reviewed draft in service.
#[must_use]
pub fn publish(
    tenant: &TenantPath,
    workflow_id: &str,
    publication: &Publication,
) -> Request<Workflow> {
    let path = tenant.at(&format!("/workflows/{workflow_id}/publish"));
    Request::of(Call::post(path).json(publication))
}

/// `POST …/workflows/{id}/versions/{version}/archive`: takes a version
/// out of service for good.
#[must_use]
pub fn archive_version(tenant: &TenantPath, workflow_id: &str, version: u32) -> Request<Workflow> {
    let path = tenant.at(&format!(
        "/workflows/{workflow_id}/versions/{version}/archive"
    ));
    Request::of(Call::post(path))
}

/// `POST …/workflows/{id}/trigger-secret`: issues the webhook's secret.
#[must_use]
pub fn issue_trigger_secret(tenant: &TenantPath, workflow_id: &str) -> Request<TriggerSecret> {
    Request::of(Call::post(
        tenant.at(&format!("/workflows/{workflow_id}/trigger-secret")),
    ))
}

/// `POST …/workflows/{id}/trigger-secret/rotate`: a new secret, the old
/// one dead.
#[must_use]
pub fn rotate_trigger_secret(tenant: &TenantPath, workflow_id: &str) -> Request<TriggerSecret> {
    Request::of(Call::post(
        tenant.at(&format!("/workflows/{workflow_id}/trigger-secret/rotate")),
    ))
}

/// `POST …/workflows/triggers/{trigger}`: an outside caller fires the
/// webhook with `payload`, the secret in its header and nowhere else.
#[must_use]
pub fn call_webhook(
    tenant: &TenantPath,
    secret: &TriggerSecret,
    payload: &Value,
) -> Request<WebhookStarted> {
    let path = tenant.at(&format!("/workflows/triggers/{}", secret.trigger_id));
    Request::of(
        Call::post(path)
            .header(SECRET_HEADER, &secret.secret)
            .json(payload),
    )
}

/// `POST …/workflows/{id}/executions`: starts the published version by
/// hand.
#[must_use]
pub fn start(
    tenant: &TenantPath,
    workflow_id: &str,
    start: &StartExecution,
) -> Request<ExecutionDecided> {
    let path = tenant.at(&format!("/workflows/{workflow_id}/executions"));
    Request::of(Call::post(path).json(start))
}

/// `GET …/workflows/{id}/executions`: the first page of the workflow's
/// executions.
#[must_use]
pub fn executions(tenant: &TenantPath, workflow_id: &str) -> Request<Page<ExecutionSummary>> {
    Request::of(Call::get(
        tenant.at(&format!("/workflows/{workflow_id}/executions")),
    ))
}

/// `GET …/workflows/{id}/executions?kind=tests`: the first page of the
/// workflow's tests.
#[must_use]
pub fn tests(tenant: &TenantPath, workflow_id: &str) -> Request<Page<ExecutionSummary>> {
    Request::of(Call::get(
        tenant.at(&format!("/workflows/{workflow_id}/executions?kind=tests")),
    ))
}

/// `POST …/workflows/{id}/tests`: tests the workflow's latest version on
/// example data.
#[must_use]
pub fn start_test(
    tenant: &TenantPath,
    workflow_id: &str,
    start: &StartExecution,
) -> Request<ExecutionDecided> {
    let path = tenant.at(&format!("/workflows/{workflow_id}/tests"));
    Request::of(Call::post(path).json(start))
}

/// `GET …/workflows/{id}/step-data`: what each step of the latest version
/// may read.
#[must_use]
pub fn step_data(tenant: &TenantPath, workflow_id: &str) -> Request<Vec<StepData>> {
    Request::of(Call::get(
        tenant.at(&format!("/workflows/{workflow_id}/step-data")),
    ))
}

/// The input of an operation whose picker is filled.
pub struct PickedInput<'a> {
    /// The integration, such as `github`.
    pub integration: &'a str,
    /// The operation, such as `create-issue`.
    pub operation: &'a str,
    /// The input, such as `labels`.
    pub input: &'a str,
}

/// `POST …/workflows/operations/{integration}/{operation}/inputs/{input}/choices`:
/// the options a step form's picker offers now.
#[must_use]
pub fn choices(
    tenant: &TenantPath,
    picked: &PickedInput<'_>,
    asked: &ListChoices,
) -> Request<Choices> {
    let path = tenant.at(&format!(
        "/workflows/operations/{}/{}/inputs/{}/choices",
        picked.integration, picked.operation, picked.input
    ));
    Request::of(Call::post(path).json(asked))
}

/// `GET …/workflows/executions/{id}`.
#[must_use]
pub fn execution(tenant: &TenantPath, execution_id: &str) -> Request<Execution> {
    Request::of(Call::get(
        tenant.at(&format!("/workflows/executions/{execution_id}")),
    ))
}

/// `GET …/workflows/executions/{id}/passes`: the first page of the passes
/// the execution's loops started, newest first.
#[must_use]
pub fn passes(tenant: &TenantPath, execution_id: &str) -> Request<Page<PassRun>> {
    Request::of(Call::get(
        tenant.at(&format!("/workflows/executions/{execution_id}/passes")),
    ))
}

/// `POST …/workflows/executions/{id}/retry`: a failed execution run again
/// from its failed step, as a new execution.
#[must_use]
pub fn retry(tenant: &TenantPath, execution_id: &str) -> Request<ExecutionDecided> {
    Request::of(Call::post(
        tenant.at(&format!("/workflows/executions/{execution_id}/retry")),
    ))
}

/// `GET …/workflows/executions/{id}/approvals/{step}`: what the step
/// lets through, to decide on.
#[must_use]
pub fn approval(tenant: &TenantPath, execution_id: &str, step: &str) -> Request<Approval> {
    Request::of(Call::get(approval_path(tenant, execution_id, step)))
}

/// `POST …/approvals/{step}/approve`: approves exactly what was shown.
#[must_use]
pub fn approve(
    tenant: &TenantPath,
    execution_id: &str,
    step: &str,
    approve: &Approve,
) -> Request<ExecutionDecided> {
    let path = format!("{}/approve", approval_path(tenant, execution_id, step));
    Request::of(Call::post(path).json(approve))
}

/// `POST …/approvals/{step}/deny`: denies the step, ending the execution.
#[must_use]
pub fn deny(tenant: &TenantPath, execution_id: &str, step: &str) -> Request<ExecutionDecided> {
    let path = format!("{}/deny", approval_path(tenant, execution_id, step));
    Request::of(Call::post(path))
}

/// One page of the items a loop asks one approval for.
pub struct ItemsAsked<'a> {
    /// The run whose loop asks.
    pub execution_id: &'a str,
    /// The loop step's key.
    pub step: &'a str,
    /// The cursor of the page, or none for the first.
    pub after: Option<&'a str>,
    /// The most items the page holds.
    pub limit: u32,
}

/// `GET …/approvals/{step}/items`: one page of the items a loop's single
/// approval covers, kept as opened by the reader.
#[must_use]
pub fn approval_items(tenant: &TenantPath, asked: &ItemsAsked<'_>) -> Request<ItemsPage> {
    let base = approval_path(tenant, asked.execution_id, asked.step);
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("limit", &asked.limit.to_string());
    if let Some(cursor) = asked.after {
        query.append_pair("after", cursor);
    }
    Request::of(Call::get(format!("{base}/items?{}", query.finish())))
}

/// `POST …/approvals/{step}/items/approve`: approves every item of a loop
/// the approver was shown.
#[must_use]
pub fn approve_items(
    tenant: &TenantPath,
    execution_id: &str,
    step: &str,
    approve: &ApproveItems,
) -> Request<ExecutionDecided> {
    let path = format!(
        "{}/items/approve",
        approval_path(tenant, execution_id, step)
    );
    Request::of(Call::post(path).json(approve))
}

/// `PUT …/workflows/{id}/evaluation-set`: replaces the workflow's sample
/// cases and its publishing gate.
#[must_use]
pub fn save_evaluation_set(
    tenant: &TenantPath,
    workflow_id: &str,
    set: &NewEvaluationSet,
) -> Request<EvaluationSet> {
    let path = tenant.at(&format!("/workflows/{workflow_id}/evaluation-set"));
    Request::of(Call::put(path).json(set))
}

/// `POST …/workflows/{id}/evaluations`: tries the latest version against
/// every saved case.
#[must_use]
pub fn start_evaluation(tenant: &TenantPath, workflow_id: &str) -> Request<Evaluation> {
    Request::of(Call::post(
        tenant.at(&format!("/workflows/{workflow_id}/evaluations")),
    ))
}

/// `GET …/workflows/{id}/evaluations/{evaluation_id}`: what each case
/// came to so far.
#[must_use]
pub fn evaluation(
    tenant: &TenantPath,
    workflow_id: &str,
    evaluation_id: &str,
) -> Request<Evaluation> {
    Request::of(Call::get(tenant.at(&format!(
        "/workflows/{workflow_id}/evaluations/{evaluation_id}"
    ))))
}

/// Where the approval of `step` in `execution_id` is decided.
fn approval_path(tenant: &TenantPath, execution_id: &str, step: &str) -> String {
    tenant.at(&format!(
        "/workflows/executions/{execution_id}/approvals/{step}"
    ))
}
