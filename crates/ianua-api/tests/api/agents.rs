//! The agent endpoints: what people and agents are answered, and in what
//! shape.

use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use ianua_api::test_support::{ORG, TENANT, TENANT_USER, adapters, relay_router, router};
use ianua_app::ports::agents::{
    APPROVAL_RELAY_PATH, APPROVAL_WIRE_VERSION, AgentStore as _, ApprovalWireAction,
    ApprovalWireQuestion, ApprovalWireRequest, DelegationStore as _, RunStore as _,
};
use ianua_app::ports::authentication::{RequestSeal as _, SEAL_HEADER};
use ianua_app::test_support::acting::{FakeTenantAuthorities, Refusal};
use ianua_app::test_support::agents::{
    FakeAgentSightingStore, FakeAgentStore, FakeDelegationRequestStore, FakeDelegationStore,
    FakeRunStore, agent_owned_by, asked_request, caller_person, callers_agent, connected_provider,
    delegation_from, delegation_row, order_tool, paused_run, providers_holding, run_started_by,
    sighted_client, someone,
};
use ianua_app::test_support::audit::{FakeChainVerdictStore, FakeEvidenceStore};
use ianua_app::test_support::authentication::TagSeal;
use ianua_app::test_support::identity::FakeUserStore;
use ianua_app::test_support::{FakeEventDispatcher, test_ctx};
use ianua_assembly::deps::Adapters;
use ianua_domain::domains::agents::authority::capability::CapabilitySet;
use ianua_domain::domains::agents::authority::delegation::Delegation;
use ianua_domain::domains::audit::walk::ChainStanding;
use ianua_domain::shared::clock;
use ianua_domain::types::{
    AgentId, AgentRunId, DeclaredAction, DelegationId, HttpMethod, Human, HumanAccount, Nonce,
    PersonKey, UserId,
};
use serde_json::{Value, json};

/// The path under the test tenant.
fn tenant_path(rest: &str) -> String {
    format!("/api/v1/organizations/{ORG}/tenants/{TENANT}{rest}")
}

/// A server over the given adapters.
fn server(adapters: Adapters) -> TestServer {
    TestServer::new(router(adapters)).unwrap()
}

/// A server whose test tenant holds one active agent, `id`.
fn with_agent(id: AgentId) -> TestServer {
    server(Adapters {
        agent_store: Arc::new(FakeAgentStore::with_active(id)),
        ..adapters()
    })
}

/// Ann creates an agent that will bootstrap from an attestation later. It
/// is created, and it brought no key, so it has no credential yet.
#[tokio::test]
async fn a_tenant_user_creates_an_agent() {
    let server = server(adapters());

    let response = server
        .post(&tenant_path("/agents"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"name": "nightly-report", "description": "Writes the nightly report"}))
        .await;

    response.assert_status(StatusCode::CREATED);
    let created: Value = response.json();
    assert!(created["id"].is_string());
    assert_eq!(created["credential"], Value::Null);
}

/// Ann opens an agent, in the shape the dashboard reads: its status by
/// name, its owner as a kind and an id, and no attestation policy.
#[tokio::test]
async fn an_agent_reads_in_the_shape_the_dashboard_reads() {
    let id = AgentId::new();
    let server = with_agent(id);

    let response = server
        .get(&tenant_path(&format!("/agents/{}", id.as_uuid())))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let agent: Value = response.json();
    assert_eq!(agent["id"], json!(id.as_uuid()));
    assert_eq!(agent["name"], "fake-agent");
    assert_eq!(agent["status"], "Active");
    assert_eq!(agent["owner"]["kind"], "user");
    assert!(agent["owner"]["id"].is_string());
    assert_eq!(agent["attestation_policy"], Value::Null);
}

/// The agent list is a page.
#[tokio::test]
async fn agents_are_listed_in_a_page() {
    let server = with_agent(AgentId::new());

    let response = server
        .get(&tenant_path("/agents"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let page: Value = response.json();
    assert_eq!(page["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(page["items"][0]["name"], "fake-agent");
}

/// A name the domain refuses is a validation error, and nothing is made.
#[tokio::test]
async fn an_empty_agent_name_is_refused() {
    let server = server(adapters());

    let response = server
        .post(&tenant_path("/agents"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"name": ""}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Creating an agent with a name already used in the tenant returns 409.
#[tokio::test]
async fn an_agent_name_already_taken_is_a_conflict() {
    let store = FakeAgentStore::with_active(AgentId::new());
    store.keeps_names_unique();
    let server = server(Adapters {
        agent_store: Arc::new(store),
        ..adapters()
    });

    let response = server
        .post(&tenant_path("/agents"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"name": "fake-agent"}))
        .await;

    response.assert_status(StatusCode::CONFLICT);
}

/// Renaming an agent to another agent's name returns 409.
#[tokio::test]
async fn a_rename_onto_a_taken_agent_name_is_a_conflict() {
    let ledger = AgentId::new();
    let store = FakeAgentStore::with_active(ledger);
    let other = AgentId::new();
    store.add_active(other);
    store.keeps_names_unique();
    let server = server(Adapters {
        agent_store: Arc::new(store),
        ..adapters()
    });
    let rename = |id: AgentId| {
        server
            .patch(&tenant_path(&format!("/agents/{}", id.as_uuid())))
            .authorization_bearer(TENANT_USER)
            .json(&json!({"name": "ledger"}))
    };
    rename(ledger).await.assert_status(StatusCode::NO_CONTENT);

    let response = rename(other).await;

    response.assert_status(StatusCode::CONFLICT);
}

/// An attestation method ianua does not know is refused before any policy
/// is set.
#[tokio::test]
async fn an_unknown_attestation_method_is_refused() {
    let server = server(adapters());

    let response = server
        .post(&tenant_path("/agents"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "name": "ledger-bot",
            "trusted_methods": ["telepathy"],
            "re_attest_every": 3600,
            "allowed_origins": ["aws:123456789012"]
        }))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Listing agents without tenant authority returns 403.
#[tokio::test]
async fn a_caller_the_app_refuses_is_forbidden() {
    let server = server(Adapters {
        tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::Forbidden)),
        ..adapters()
    });

    let response = server
        .get(&tenant_path("/agents"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// A request with no credential at all is not a caller.
#[tokio::test]
async fn an_anonymous_request_is_unauthenticated() {
    let server = server(adapters());

    let response = server.get(&tenant_path("/agents")).await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

/// A tenant with nothing registered answers empty lists for its tools,
/// model providers, task templates and channels.
#[tokio::test]
async fn the_catalogue_lists_answer_empty() {
    let server = server(adapters());

    for path in ["/tools", "/model-providers", "/agents/task-templates"] {
        let response = server
            .get(&tenant_path(path))
            .authorization_bearer(TENANT_USER)
            .await;
        response.assert_status_ok();
        assert_eq!(response.json::<Value>(), json!([]), "{path}");
    }
    let channels = server
        .get(&tenant_path("/messaging/channels"))
        .authorization_bearer(TENANT_USER)
        .await;
    channels.assert_status_ok();
    assert_eq!(
        channels.json::<Value>()["items"].as_array().map(Vec::len),
        Some(0)
    );
}

/// A channel names topics or one resource, never both.
#[tokio::test]
async fn a_channel_naming_both_topics_and_a_resource_is_refused() {
    let server = server(adapters());

    let response = server
        .post(&tenant_path("/messaging/channels"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "sender_agent_id": AgentId::new().as_uuid(),
            "receiver_agent_id": AgentId::new().as_uuid(),
            "topics": "agents.x.tasks",
            "resource": "doc:42",
            "max_class": "Internal",
            "lifetime_seconds": 3600
        }))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// An assertion naming an unknown agent receives 403.
#[tokio::test]
async fn an_assertion_for_an_unknown_agent_is_refused() {
    let server = server(adapters());

    let response = server
        .post(&tenant_path(&format!(
            "/agents/{}/token",
            AgentId::new().as_uuid()
        )))
        .json(&json!({"assertion": "not-a-signed-assertion", "ttl_seconds": 300}))
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// The relay takes an agent's task token as its credential; with none, the
/// request is not an agent.
#[tokio::test]
async fn the_relay_without_a_task_token_is_unauthenticated() {
    let server = server(adapters());

    let response = server
        .post(&tenant_path("/agents/messages/agents.x.tasks"))
        .json(&json!({"hello": "world"}))
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

/// Ann reads her agent's evidence after last night's sweep found record 7
/// rewritten. The records come with the sweep's verdict, in the shape the
/// audit chain endpoint answers: broken, and where.
#[tokio::test]
async fn evidence_carries_the_sweeps_verdict_on_the_chain() {
    let agent = AgentId::new();
    let verdicts =
        FakeChainVerdictStore::holding(test_ctx().tenant_id(), ChainStanding::BrokenAt(7));
    let server = server(Adapters {
        agent_store: Arc::new(callers_agent(agent)),
        evidence_store: Arc::new(FakeEvidenceStore(agent)),
        audit_chain_verdict_store: Arc::new(verdicts),
        ..adapters()
    });

    let response = server
        .get(&tenant_path(&format!(
            "/agents/{}/evidence",
            agent.as_uuid()
        )))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let page: Value = response.json();
    assert_eq!(page["records"].as_array().map(Vec::len), Some(3));
    assert_eq!(page["chain"]["status"], "broken");
    assert_eq!(page["chain"]["broken_at_seq"], 7);
    assert!(page["chain"]["verified_at"].is_string());
}

/// The review desk takes a reviewer that names itself and signs an
/// assertion; without them, the request is not a reviewer.
#[tokio::test]
async fn the_review_desk_without_a_reviewer_is_unauthenticated() {
    let server = server(adapters());

    let response = server
        .get(&tenant_path(&format!(
            "/agents/review-desk/{}/evidence",
            AgentId::new().as_uuid()
        )))
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

/// A guessed relay token receives 401 for both known and unknown tenants.
#[tokio::test]
async fn the_relay_of_an_unknown_tenant_answers_like_a_bad_token() {
    let server = server(adapters());
    let body = json!({"payload": {"x": 1}});

    let unknown = server
        .post(&format!(
            "/api/v1/organizations/{ORG}/tenants/nobody/agents/messages/agents.x.tasks"
        ))
        .authorization_bearer("guess")
        .json(&body)
        .await;
    let known = server
        .post(&tenant_path("/agents/messages/agents.x.tasks"))
        .authorization_bearer("guess")
        .json(&body)
        .await;

    unknown.assert_status(StatusCode::UNAUTHORIZED);
    assert_eq!(unknown.status_code(), known.status_code());
}

/// A server whose test tenant holds Owen's agent and the request it made
/// of the test caller, answering with the agent's id and the request's.
fn with_request_of_the_caller() -> (TestServer, AgentId, String) {
    let agent = AgentId::new();
    let agents = FakeAgentStore::empty();
    agents.add_owned_by(agent, someone("owen@example.test"));
    let stored = agents.find_by_id_direct(&agent).unwrap();
    let request = asked_request(&stored, caller_person(), CapabilitySet::empty());
    let request_id = request.id().as_uuid().to_string();
    let server = server(Adapters {
        agent_store: Arc::new(agents),
        delegation_request_store: Arc::new(FakeDelegationRequestStore::holding([request])),
        ..adapters()
    });
    (server, agent, request_id)
}

/// The tenant-wide approval inbox, and the caller's own lists of
/// delegations, delegation requests and agent offers, answer empty lists
/// for a tenant with nothing in them.
#[tokio::test]
async fn the_tenant_and_personal_agent_lists_answer_empty() {
    let server = server(adapters());

    for path in [
        "/agents/approvals",
        "/agents/sightings",
        "/me/delegations",
        "/me/delegation-requests",
        "/me/agent-offers",
    ] {
        let response = server
            .get(&tenant_path(path))
            .authorization_bearer(TENANT_USER)
            .await;
        response.assert_status_ok();
        assert_eq!(response.json::<Value>(), json!([]), "{path}");
    }
}

/// An agent with completed history and a held call, served through real routes.
struct RunPages {
    server: TestServer,
    agent: AgentId,
    completed: AgentRunId,
    pending: AgentRunId,
}

/// Stores two completed traces and one held call for the test caller's agent.
async fn run_pages() -> RunPages {
    let owner = caller_person();
    let agent = agent_owned_by(AgentId::new(), owner.clone());
    let delegation = delegation_from(&owner, *agent.id());
    let runs = Arc::new(FakeRunStore::empty());
    let mut completed = run_started_by(&owner, &agent, &delegation);
    completed.complete("finished one").unwrap();
    runs.save(&test_ctx().tenant(), &completed).await.unwrap();
    let mut other = run_started_by(&owner, &agent, &delegation);
    other.complete("finished two").unwrap();
    runs.save(&test_ctx().tenant(), &other).await.unwrap();
    let pending = paused_run(&owner, &agent, &delegation, &order_tool("delete_order"));
    runs.save(&test_ctx().tenant(), &pending).await.unwrap();
    RunPages {
        server: server(Adapters {
            agent_store: Arc::new(callers_agent(*agent.id())),
            run_store: runs,
            ..adapters()
        }),
        agent: *agent.id(),
        completed: *completed.id(),
        pending: *pending.id(),
    }
}

/// Reads a run page through authentication and the HTTP handler.
async fn run_page(server: &TestServer, path: &str) -> Value {
    let response = server
        .get(&tenant_path(path))
        .authorization_bearer(TENANT_USER)
        .await;
    response.assert_status_ok();
    response.json()
}

/// Both run lists expose cursor pages without traces; following their cursors
/// visits all three runs once and preserves the held call's approval fields.
#[tokio::test]
async fn run_lists_page_summaries_and_keep_pending_call_fields() {
    let fixture = run_pages().await;
    for path in [
        "/agents/runs".to_owned(),
        format!("/agents/{}/runs", fixture.agent),
    ] {
        let first = run_page(&fixture.server, &format!("{path}?limit=1")).await;
        let cursor = first["next_cursor"].as_str().unwrap();
        let second = run_page(&fixture.server, &format!("{path}?limit=1&after={cursor}")).await;
        let cursor = second["next_cursor"].as_str().unwrap();
        let third = run_page(&fixture.server, &format!("{path}?limit=1&after={cursor}")).await;
        let mut ids = Vec::new();
        for page in [&first, &second, &third] {
            assert_eq!(page["limit"], 1);
            assert_eq!(page["items"].as_array().unwrap().len(), 1);
            let run = &page["items"][0];
            assert!(run.get("steps").is_none());
            assert!(run.get("answer").is_none());
            assert!(run["usage"]["input_tokens"].is_number());
            ids.push(run["id"].as_str().unwrap());
        }
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 3);
        assert!(third["next_cursor"].is_null());
        let awaiting = run_page(&fixture.server, &format!("{path}?status=awaiting_approval")).await;
        assert_pending_call(&awaiting, fixture.pending);
    }
}

/// Checks that the approval page retains the held call's identity and arguments.
fn assert_pending_call(awaiting: &Value, pending: AgentRunId) {
    let held = &awaiting["items"][0];
    assert_eq!(awaiting["limit"], 20);
    assert_eq!(held["id"], json!(pending.as_uuid()));
    assert_eq!(held["pending_tool"], "delete_order");
    assert_eq!(held["pending_arguments"], "{\"id\":1}");
    assert_eq!(held["pending_at_step"], 1);
}

/// Reading a completed run separately still returns its complete trace and answer.
#[tokio::test]
async fn a_run_detail_keeps_its_full_trace_after_summary_paging() {
    let fixture = run_pages().await;
    let path = format!("/agents/{}/runs/{}", fixture.agent, fixture.completed);

    let detail = run_page(&fixture.server, &path).await;

    assert_eq!(detail["answer"], "finished one");
    assert_eq!(detail["steps"].as_array().unwrap().len(), 1);
    assert_eq!(detail["steps"][0]["outcome"], "answered");
    assert_eq!(detail["steps"][0]["detail"], "finished one");
}

/// Both run lists return 422 for invalid page sizes and cursors; their
/// default empty pages remain available with a limit of twenty.
#[tokio::test]
async fn run_lists_refuse_invalid_page_parameters() {
    let agent = AgentId::new();
    let server = with_agent(agent);
    for path in ["/agents/runs".to_owned(), format!("/agents/{agent}/runs")] {
        for query in ["limit=0", "limit=101", "after=not-a-cursor"] {
            let response = server
                .get(&tenant_path(&format!("{path}?{query}")))
                .authorization_bearer(TENANT_USER)
                .await;
            response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
        }
        let empty = run_page(&server, &path).await;
        assert_eq!(
            empty,
            json!({"items": [], "next_cursor": null, "limit": 20})
        );
    }
}

/// A run status ianua does not know is refused on the tenant-wide list.
#[tokio::test]
async fn an_unknown_run_status_is_refused_on_the_tenant_list() {
    let server = server(adapters());

    let response = server
        .get(&tenant_path("/agents/runs?status=sleeping"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Ann pauses a run the agent does not have. It is not found.
#[tokio::test]
async fn pausing_a_run_that_does_not_exist_is_not_found() {
    let id = AgentId::new();
    let server = with_agent(id);

    let response = server
        .post(&tenant_path(&format!(
            "/agents/{}/runs/{}/pause",
            id.as_uuid(),
            uuid::Uuid::now_v7()
        )))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// A blank reply to a held call is refused before any run is read.
#[tokio::test]
async fn a_blank_reply_to_a_held_call_is_refused() {
    let id = AgentId::new();
    let server = with_agent(id);

    let response = server
        .post(&tenant_path(&format!(
            "/agents/{}/runs/{}/reply",
            id.as_uuid(),
            uuid::Uuid::now_v7()
        )))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"reply": "   "}))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Ann connects a provider with its price, and the list shows the price
/// runs' spend is counted at.
#[tokio::test]
async fn a_provider_connected_with_a_price_lists_it() {
    let server = server(adapters());

    let connected = server
        .post(&tenant_path("/model-providers"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "name": "prod-deepseek",
            "kind": "self_hosted",
            "endpoint": "https://deepseek.models.example/v1",
            "model": "deepseek-chat",
            "pricing": {"input_micros_per_million": 270_000, "output_micros_per_million": 1_100_000}
        }))
        .await;
    connected.assert_status(StatusCode::CREATED);
    let listed = server
        .get(&tenant_path("/model-providers"))
        .authorization_bearer(TENANT_USER)
        .await;

    listed.assert_status_ok();
    let providers: Value = listed.json();
    assert_eq!(
        providers[0]["pricing"],
        json!({"input_micros_per_million": 270_000, "output_micros_per_million": 1_100_000})
    );
}

/// Ann rotates the key of a provider the tenant does not have. It is not
/// found.
#[tokio::test]
async fn rotating_the_key_of_an_unknown_provider_is_not_found() {
    let server = server(adapters());

    let response = server
        .post(&tenant_path(&format!(
            "/model-providers/{}/rotate-key",
            uuid::Uuid::now_v7()
        )))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"api_key": "sk-new"}))
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

/// Ann clears `prod-deepseek` for confidential data. The change reaches the
/// audit trail as `agents.model_provider_clearance_changed`, so a review
/// sees when runs began sending it more.
#[tokio::test]
async fn changing_a_provider_clearance_is_recorded() {
    let provider = connected_provider("prod-deepseek");
    let id = *provider.id();
    let sink = Arc::new(FakeEventDispatcher::new());
    let server = server(Adapters {
        model_provider_store: Arc::new(providers_holding([provider])),
        event_dispatcher: sink.clone(),
        ..adapters()
    });

    let response = server
        .put(&tenant_path(&format!(
            "/model-providers/{}/clearance",
            id.as_uuid()
        )))
        .authorization_bearer(TENANT_USER)
        .json(&json!({"clearance": "Confidential"}))
        .await;

    response.assert_status(StatusCode::NO_CONTENT);
    assert!(
        sink.records
            .lock()
            .unwrap()
            .iter()
            .any(|kind| kind == "agents.model_provider_clearance_changed")
    );
}

/// Ann creates an agent trusted through one repository's GitHub Actions
/// workflow, and reads the trust back in the policy.
#[tokio::test]
async fn an_agent_trusting_a_workload_token_reads_it_back() {
    let server = server(adapters());
    let trust = json!({
        "method": "github_actions",
        "issuer": "https://token.actions.githubusercontent.com",
        "subject": "repo:corp/reports:ref:refs/heads/main"
    });

    let created = server
        .post(&tenant_path("/agents"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "name": "reports-bot",
            "trusted_methods": ["github_actions"],
            "re_attest_every": 3600,
            "workload_trusts": [trust]
        }))
        .await;
    created.assert_status(StatusCode::CREATED);
    let id = created.json::<Value>()["id"].as_str().unwrap().to_owned();
    let read = server
        .get(&tenant_path(&format!("/agents/{id}")))
        .authorization_bearer(TENANT_USER)
        .await;

    read.assert_status_ok();
    let agent: Value = read.json();
    assert_eq!(agent["trusted_methods"], json!(["github_actions"]));
    assert_eq!(
        agent["attestation_policy"]["workload_trusts"],
        json!([trust])
    );
}

/// A GitHub workload trust naming a foreign issuer returns 422.
#[tokio::test]
async fn a_workload_trust_with_a_foreign_issuer_is_refused() {
    let server = server(adapters());

    let response = server
        .post(&tenant_path("/agents"))
        .authorization_bearer(TENANT_USER)
        .json(&json!({
            "name": "reports-bot",
            "trusted_methods": ["github_actions"],
            "re_attest_every": 3600,
            "workload_trusts": [{
                "method": "github_actions",
                "issuer": "https://mallory.example",
                "subject": "repo:corp/reports:ref:refs/heads/main"
            }]
        }))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// Requesting a delegation without an agent assertion returns 401.
#[tokio::test]
async fn asking_for_a_delegation_without_an_assertion_is_unauthenticated() {
    let id = AgentId::new();
    let server = with_agent(id);

    let response = server
        .post(&tenant_path(&format!(
            "/agents/{}/delegation-requests",
            id.as_uuid()
        )))
        .json(&json!({
            "asked_of": {"kind": "user", "id": uuid::Uuid::now_v7()},
            "granted": {},
            "ttl_seconds": 3600,
            "reason": "I need to read the monthly reports"
        }))
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

/// Ann sees the request Owen's agent made of her, pending, with the
/// agent's reason.
#[tokio::test]
async fn the_requests_asked_of_me_are_listed() {
    let (server, agent, request_id) = with_request_of_the_caller();

    let response = server
        .get(&tenant_path("/me/delegation-requests"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    let requests: Value = response.json();
    assert_eq!(requests[0]["id"], request_id);
    assert_eq!(requests[0]["agent_id"], json!(agent.as_uuid()));
    assert_eq!(requests[0]["status"], "pending");
    assert_eq!(requests[0]["reason"], "I need to read the monthly reports");
}

/// Ann refuses the request Owen's agent made of her. It answers refused.
#[tokio::test]
async fn the_person_asked_refuses_a_delegation_request() {
    let (server, agent, request_id) = with_request_of_the_caller();

    let response = server
        .post(&tenant_path(&format!(
            "/agents/{}/delegation-requests/{request_id}/deny",
            agent.as_uuid()
        )))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status_ok();
    assert_eq!(response.json::<Value>()["status"], "denied");
}

/// A sighted OAuth client is listed unreviewed, in the shape the dashboard
/// reads, and Ann dismisses it.
#[tokio::test]
async fn a_sighting_is_listed_and_dismissed() {
    let sighting = sighted_client("client-7f3a", "report-scraper");
    let id = sighting.id().as_uuid().to_string();
    let server = server(Adapters {
        agent_sighting_store: Arc::new(FakeAgentSightingStore::holding([sighting])),
        ..adapters()
    });

    let listed = server
        .get(&tenant_path("/agents/sightings"))
        .authorization_bearer(TENANT_USER)
        .await;
    let dismissed = server
        .post(&tenant_path(&format!("/agents/sightings/{id}/dismiss")))
        .authorization_bearer(TENANT_USER)
        .await;

    listed.assert_status_ok();
    let sightings: Value = listed.json();
    assert_eq!(sightings[0]["id"], id);
    assert_eq!(sightings[0]["source"], "oauth_client");
    assert_eq!(sightings[0]["calls_itself"], "report-scraper");
    assert_eq!(sightings[0]["status"], "unreviewed");
    dismissed.assert_status_ok();
    assert_eq!(dismissed.json::<Value>()["status"], "dismissed");
}

/// A sightings filter ianua does not know is refused.
#[tokio::test]
async fn an_unknown_sightings_filter_is_refused() {
    let server = server(adapters());

    let response = server
        .get(&tenant_path("/agents/sightings?shown=hidden"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

/// The tenant-wide run list returns 403 when agent authority is denied.
#[tokio::test]
async fn the_tenant_run_list_follows_the_app_refusal() {
    let server = server(Adapters {
        tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::Forbidden)),
        ..adapters()
    });

    let response = server
        .get(&tenant_path("/agents/runs"))
        .authorization_bearer(TENANT_USER)
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

/// Bob's agent, and Ann's delegation to it that requires approval, held in
/// the test tenant: what the gateway's questions are answered over.
struct Gated {
    adapters: Adapters,
    agent: AgentId,
    delegation: DelegationId,
    sink: Arc<FakeEventDispatcher>,
}

/// Ann's delegation to Bob's agent, kept in the stores the API answers
/// over, and a sink for what it records.
async fn gated() -> Gated {
    let ann_account = UserId::new();
    let ann = Human::new(
        HumanAccount::User(ann_account),
        PersonKey::new("ann@corp.test").unwrap(),
    );
    let agent = agent_owned_by(AgentId::new(), someone("bob@corp.test"));
    let delegation =
        Delegation::reconstitute(delegation_row(*agent.id(), ann.principal())).unwrap();
    let tenant = test_ctx().tenant();
    let (agents, delegations) = (
        Arc::new(FakeAgentStore::empty()),
        Arc::new(FakeDelegationStore::empty()),
    );
    agents.save(&tenant, &agent).await.unwrap();
    delegations.save(&tenant, &delegation).await.unwrap();
    let sink = Arc::new(FakeEventDispatcher::new());
    Gated {
        adapters: Adapters {
            agent_store: agents,
            delegation_store: delegations,
            user_store: Arc::new(FakeUserStore::with_user(ann_account, "ann@corp.test")),
            event_dispatcher: sink.clone(),
            ..adapters()
        },
        agent: *agent.id(),
        delegation: *delegation.id(),
        sink,
    }
}

impl Gated {
    /// The gateway's question about the agent's payment, as it sends it.
    fn asking(&self, question: fn(ApprovalWireAction) -> ApprovalWireQuestion) -> Vec<u8> {
        let request = ApprovalWireRequest {
            v: APPROVAL_WIRE_VERSION,
            tenant_id: test_ctx().tenant_id(),
            ts: clock::now().unix_timestamp(),
            nonce: Nonce::new("a-nonce-used-only-once").unwrap(),
            question: question(ApprovalWireAction {
                agent_id: self.agent,
                delegation_id: self.delegation,
                method: HttpMethod::Post,
                target: "/payments".to_owned(),
                declared: DeclaredAction::Undeclared,
            }),
        };
        serde_json::to_vec(&request).unwrap()
    }
}

/// `body` posted to the internal listener's approvals endpoint, sealed
/// with `seal` when there is one.
async fn relayed(server: &TestServer, body: Vec<u8>, seal: Option<String>) -> Value {
    let request = server
        .post(APPROVAL_RELAY_PATH)
        .content_type("application/json")
        .bytes(body.into());
    let request = match seal {
        Some(seal) => request.add_header(SEAL_HEADER, seal),
        None => request,
    };
    let response = request.await;
    response.assert_status_ok();
    response.json()
}

/// The gateway asks the API to hold Bob's agent's payment for a person.
/// The API opens the request, answers with it, and records
/// `agents.approval_requested`.
#[tokio::test]
async fn the_gateway_holds_an_action_through_the_internal_listener() {
    let gated = gated().await;
    let body = gated.asking(ApprovalWireQuestion::Hold);
    let seal = TagSeal.seal(&body);
    let server = TestServer::new(relay_router(gated.adapters.clone())).unwrap();

    let answer = relayed(&server, body, Some(seal)).await;

    assert_eq!(answer["result"], "awaiting_decision");
    assert_eq!(answer["opened"], "now");
    assert!(answer["approval_id"].is_string());
    assert!(
        gated
            .sink
            .records
            .lock()
            .unwrap()
            .iter()
            .any(|record| record == "agents.approval_requested")
    );
}

/// The answer seal verifies against the exact response bytes and the
/// question's nonce.
#[tokio::test]
async fn the_answer_is_sealed_for_the_question() {
    let gated = gated().await;
    let body = gated.asking(ApprovalWireQuestion::Hold);
    let seal = TagSeal.seal(&body);
    let server = TestServer::new(relay_router(gated.adapters.clone())).unwrap();

    let response = server
        .post(APPROVAL_RELAY_PATH)
        .content_type("application/json")
        .add_header(SEAL_HEADER, seal)
        .bytes(body.into())
        .await;

    response.assert_status_ok();
    let answer_seal = response.header(SEAL_HEADER);
    let nonce = Nonce::new("a-nonce-used-only-once").unwrap();
    assert!(TagSeal.verifies_answer(&nonce, response.as_bytes(), answer_seal.to_str().unwrap()));
}

/// An unopened relay question receives a response without an answer seal.
#[tokio::test]
async fn an_unopened_question_is_answered_unsealed() {
    let gated = gated().await;
    let body = gated.asking(ApprovalWireQuestion::Spend);
    let server = TestServer::new(relay_router(gated.adapters.clone())).unwrap();

    let response = server
        .post(APPROVAL_RELAY_PATH)
        .content_type("application/json")
        .bytes(body.into())
        .await;

    response.assert_status_ok();
    assert!(response.maybe_header(SEAL_HEADER).is_none());
}

/// An unsealed approval-spend question receives only the refused result.
#[tokio::test]
async fn an_unsealed_question_is_refused() {
    let gated = gated().await;
    let body = gated.asking(ApprovalWireQuestion::Spend);
    let server = TestServer::new(relay_router(gated.adapters.clone())).unwrap();

    let answer = relayed(&server, body, None).await;

    assert_eq!(answer, json!({"result": "refused"}));
}

/// Replaying a sealed hold question returns the refused result.
#[tokio::test]
async fn a_repeated_question_is_refused() {
    let gated = gated().await;
    let body = gated.asking(ApprovalWireQuestion::Hold);
    let seal = TagSeal.seal(&body);
    let server = TestServer::new(relay_router(gated.adapters.clone())).unwrap();

    relayed(&server, body.clone(), Some(seal.clone())).await;
    let repeated = relayed(&server, body, Some(seal)).await;

    assert_eq!(repeated, json!({"result": "refused"}));
}

/// Spending under an unknown delegation returns only the refused result.
#[tokio::test]
async fn a_failed_spend_is_answered_as_a_refusal() {
    let gated = gated().await;
    let body = Gated {
        delegation: DelegationId::new(),
        ..gated
    }
    .asking(ApprovalWireQuestion::Spend);
    let seal = TagSeal.seal(&body);
    let server = TestServer::new(relay_router(adapters())).unwrap();

    let answer = relayed(&server, body, Some(seal)).await;

    assert_eq!(answer, json!({"result": "refused"}));
}

/// The public listener returns 404 for the internal approval relay path.
#[tokio::test]
async fn the_public_listener_does_not_serve_the_approvals_channel() {
    let gated = gated().await;
    let body = gated.asking(ApprovalWireQuestion::Spend);
    let seal = TagSeal.seal(&body);
    let server = server(gated.adapters);

    let response = server
        .post(APPROVAL_RELAY_PATH)
        .content_type("application/json")
        .add_header(SEAL_HEADER, seal)
        .bytes(body.into())
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}
