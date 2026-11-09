//! The workflow use cases the API serves: integration accounts, their
//! connections by signing in, and the operations and events the catalog
//! offers, workflow definitions and their drafts, webhook secrets, webhook
//! and service event starts, executions, their restarts and approvals,
//! agent flows, the tenant's raised operation risks, and its sandboxes.

use std::sync::Arc;

use ianua_app::ports::workflows::ChangeGuard;
use ianua_app::services::authentication::approver_presence::{
    ApproverPresence, ApproverPresencePorts,
};
use ianua_app::services::registrations::RegistrationPorts;
use ianua_app::use_cases::agents::runs::StopPorts;
use ianua_app::use_cases::workflows::accounts::{channels, connections};
use ianua_app::use_cases::workflows::catalog::risk_overrides;
use ianua_app::use_cases::workflows::{
    accounts, catalog, definitions, executions, flows, sandboxes, triggers,
};
use ianua_domain::types::HttpsUrl;

use crate::deps::{Adapters, Settings};
use crate::evaluations::{self, EvaluationUseCases};
use crate::memories::{self, MemoryUseCases};

/// The workflow use cases.
#[derive(Clone)]
pub struct WorkflowState {
    pub list_accounts: Arc<accounts::ListUseCase>,
    pub connect_account: Arc<accounts::ConnectUseCase>,
    pub change_account: Arc<accounts::ChangeUseCase>,
    pub show_channel: Arc<channels::ShowUseCase>,
    pub set_channel_key: Arc<channels::SetKeyUseCase>,
    pub show_channel_token: Arc<channels::ShowTokenUseCase>,
    pub confirm_channel: Arc<channels::ConfirmUseCase>,
    pub begin_connection: Arc<connections::BeginUseCase>,
    pub answer_connection: Arc<connections::AnswerUseCase>,
    pub finish_connection: Arc<connections::FinishUseCase>,
    pub list_integrations: Arc<catalog::ListIntegrationsUseCase>,
    pub list_operations: Arc<catalog::ListOperationsUseCase>,
    pub list_events: Arc<catalog::ListEventsUseCase>,
    pub list_apps: Arc<catalog::ListAppsUseCase>,
    pub list_data: Arc<catalog::ListDataUseCase>,
    pub list_choices: Arc<catalog::ListChoicesUseCase>,
    pub list_workflows: Arc<definitions::ListWorkflowsUseCase>,
    pub create_workflow: Arc<definitions::CreateWorkflowUseCase>,
    pub get_workflow: Arc<definitions::GetWorkflowUseCase>,
    pub edit_draft: Arc<definitions::EditDraftUseCase>,
    pub next_draft: Arc<definitions::NextDraftUseCase>,
    pub publish_workflow: Arc<definitions::PublishWorkflowUseCase>,
    pub archive_workflow: Arc<definitions::ArchiveWorkflowUseCase>,
    pub step_data: Arc<definitions::StepDataUseCase>,
    pub draft_steps: Arc<definitions::DraftUseCase>,
    pub issue_trigger_secret: Arc<triggers::IssueSecretUseCase>,
    pub rotate_trigger_secret: Arc<triggers::RotateSecretUseCase>,
    pub revoke_trigger_secret: Arc<triggers::RevokeSecretUseCase>,
    pub start_on_webhook: Arc<executions::StartOnWebhookUseCase>,
    pub start_on_service_event: Arc<executions::StartOnServiceEventUseCase>,
    pub start_by_hand: Arc<executions::StartByHandUseCase>,
    pub start_test: Arc<executions::StartTestUseCase>,
    pub list_executions: Arc<executions::ListUseCase>,
    pub list_all_executions: Arc<executions::ListAllUseCase>,
    pub list_passes: Arc<executions::ListPassesUseCase>,
    pub get_execution: Arc<executions::GetUseCase>,
    pub cancel_execution: Arc<executions::CancelUseCase>,
    pub rerun_execution: Arc<executions::RerunUseCase>,
    pub retry_execution: Arc<executions::RetryUseCase>,
    pub show_approval: Arc<executions::ShowApprovalUseCase>,
    pub approve_step: Arc<executions::ApproveStepUseCase>,
    pub deny_step: Arc<executions::DenyStepUseCase>,
    pub show_items: Arc<executions::ShowItemsUseCase>,
    pub approve_items: Arc<executions::ApproveItemsUseCase>,
    pub create_flow: Arc<flows::CreateUseCase>,
    pub list_flows: Arc<flows::ListUseCase>,
    pub get_flow: Arc<flows::GetUseCase>,
    pub cancel_flow: Arc<flows::CancelUseCase>,
    pub delete_flow: Arc<flows::DeleteUseCase>,
    pub list_risks: Arc<risk_overrides::ListRisksUseCase>,
    pub raise_risk: Arc<risk_overrides::RaiseRiskUseCase>,
    pub change_risk: Arc<risk_overrides::ChangeRiskUseCase>,
    pub remove_risk: Arc<risk_overrides::RemoveRiskUseCase>,
    pub list_sandboxes: Arc<sandboxes::ListUseCase>,
    pub create_sandbox: Arc<sandboxes::CreateSandboxUseCase>,
    pub get_sandbox: Arc<sandboxes::GetSandboxUseCase>,
    pub save_sandbox_version: Arc<sandboxes::SaveVersionUseCase>,
    pub push_sandbox_version: Arc<sandboxes::code::PushVersionUseCase>,
    pub write_sandbox_code: Arc<sandboxes::code::WriteUseCase>,
    pub archive_sandbox: Arc<sandboxes::ArchiveSandboxUseCase>,
    pub list_sandbox_runtimes: Arc<sandboxes::ListRuntimesUseCase>,
    pub start_sandbox_trial: Arc<sandboxes::trying::StartTrialUseCase>,
    pub get_sandbox_trial: Arc<sandboxes::trying::GetTrialUseCase>,
    pub save_image_version: Arc<sandboxes::images::SaveUseCase>,
    pub list_image_registries: Arc<sandboxes::images::registries::ListUseCase>,
    pub allow_image_registry: Arc<sandboxes::images::registries::AllowUseCase>,
    pub remove_image_registry: Arc<sandboxes::images::registries::RemoveUseCase>,
    pub memories: MemoryUseCases,
    pub evaluations: EvaluationUseCases,
    /// The deployment's public base URL: the dashboard a service's sign-in
    /// lands on, and the address services sign their deliveries for.
    pub app_base_url: HttpsUrl,
}

/// Builds the workflow use cases over `a`, with the lockout `s` sets for
/// an approver's second factor and its public base URL.
pub fn build(a: &Adapters, s: &Settings) -> WorkflowState {
    let parts = WorkflowParts {
        designs: designs(a),
        runs: runs(a, s),
        flows: agent_flows(a),
        risks: risks(a),
        sandboxes: sandboxes(a, s),
        connecting: connecting(a),
    };
    parts.state(a, s)
}

/// The workflow areas built before exposing the API's flat state.
struct WorkflowParts {
    designs: Designs,
    runs: Runs,
    flows: AgentFlows,
    risks: Risks,
    sandboxes: Sandboxes,
    connecting: Connecting,
}

impl WorkflowParts {
    /// Transfers each prepared use case to its existing public field and wires the remaining ports.
    /// This exhaustive initializer keeps the public field mapping and construction order together.
    #[allow(clippy::too_many_lines)]
    fn state(self, a: &Adapters, s: &Settings) -> WorkflowState {
        let Self {
            designs,
            runs,
            flows,
            risks,
            sandboxes,
            connecting,
        } = self;
        WorkflowState {
            list_accounts: Arc::new(accounts::ListUseCase::new(accounts::ListPorts {
                accounts: a.integration_account_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            })),
            connect_account: Arc::new(accounts::ConnectUseCase::new(accounts::ConnectPorts {
                accounts: a.integration_account_store.clone(),
                catalog: a.integration_catalog.clone(),
                verifier: a.account_verifier.clone(),
                encryptor: a.secret_encryptor.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            })),
            change_account: Arc::new(accounts::ChangeUseCase::new(accounts::ChangePorts {
                accounts: a.integration_account_store.clone(),
                encryptor: a.secret_encryptor.clone(),
                verifier: a.account_verifier.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            })),
            show_channel: Arc::new(channels::ShowUseCase::new(channels::ShowPorts {
                accounts: a.integration_account_store.clone(),
                channels: a.account_channel_store.clone(),
                channel_setup: a.service_channel_setup.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            })),
            set_channel_key: Arc::new(channels::SetKeyUseCase::new(channels::SetKeyPorts {
                accounts: a.integration_account_store.clone(),
                channels: a.account_channel_store.clone(),
                channel_setup: a.service_channel_setup.clone(),
                encryptor: a.secret_encryptor.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            })),
            show_channel_token: Arc::new(channels::ShowTokenUseCase::new(
                channels::ShowTokenPorts {
                    accounts: a.integration_account_store.clone(),
                    channels: a.account_channel_store.clone(),
                    encryptor: a.secret_encryptor.clone(),
                    tenant_authorities: a.tenant_authorities.clone(),
                },
            )),
            confirm_channel: Arc::new(channels::ConfirmUseCase::new(channels::ConfirmPorts {
                accounts: a.integration_account_store.clone(),
                channels: a.account_channel_store.clone(),
                channel_setup: a.service_channel_setup.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            })),
            begin_connection: connecting.begin,
            answer_connection: connecting.answer,
            finish_connection: connecting.finish,
            list_integrations: Arc::new(catalog::ListIntegrationsUseCase::new(
                catalog::ListIntegrationsPorts {
                    catalog: a.integration_catalog.clone(),
                    sign_in: a.service_sign_in.clone(),
                    tenant_authorities: a.tenant_authorities.clone(),
                },
            )),
            list_operations: Arc::new(catalog::ListOperationsUseCase::new(
                catalog::ListOperationsPorts {
                    catalog: a.integration_catalog.clone(),
                    risks: a.operation_risk_override_store.clone(),
                    tenant_authorities: a.tenant_authorities.clone(),
                },
            )),
            list_events: Arc::new(catalog::ListEventsUseCase::new(catalog::ListEventsPorts {
                catalog: a.integration_catalog.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            })),
            list_apps: Arc::new(catalog::ListAppsUseCase::new(catalog::ListAppsPorts {
                route_store: a.route_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            })),
            list_data: Arc::new(catalog::ListDataUseCase::new(catalog::ListDataPorts {
                stream_route_store: a.stream_route_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            })),
            list_choices: Arc::new(catalog::ListChoicesUseCase::new(
                catalog::ListChoicesPorts {
                    catalog: a.integration_catalog.clone(),
                    accounts: a.integration_account_store.clone(),
                    action_runner: a.action_runner.clone(),
                    grants: a.account_grants(),
                    unit_of_work: a.unit_of_work.clone(),
                    tenant_authorities: a.tenant_authorities.clone(),
                },
            )),
            list_workflows: designs.list,
            create_workflow: designs.create,
            get_workflow: designs.get,
            edit_draft: designs.edit_draft,
            next_draft: designs.next_draft,
            publish_workflow: designs.publish,
            archive_workflow: designs.archive,
            step_data: designs.step_data,
            draft_steps: designs.draft,
            issue_trigger_secret: Arc::new(triggers::IssueSecretUseCase::new(
                triggers::IssueSecretPorts {
                    workflows: a.workflow_store.clone(),
                    trigger_secrets: a.workflow_trigger_secret_store.clone(),
                    secret_generator: a.workflow_trigger_secret_generator.clone(),
                    tenant_authorities: a.tenant_authorities.clone(),
                },
            )),
            rotate_trigger_secret: Arc::new(triggers::RotateSecretUseCase::new(
                triggers::RotateSecretPorts {
                    workflows: a.workflow_store.clone(),
                    trigger_secrets: a.workflow_trigger_secret_store.clone(),
                    secret_generator: a.workflow_trigger_secret_generator.clone(),
                    tenant_authorities: a.tenant_authorities.clone(),
                },
            )),
            revoke_trigger_secret: Arc::new(triggers::RevokeSecretUseCase::new(
                triggers::RevokeSecretPorts {
                    workflows: a.workflow_store.clone(),
                    trigger_secrets: a.workflow_trigger_secret_store.clone(),
                    tenant_authorities: a.tenant_authorities.clone(),
                },
            )),
            start_on_webhook: runs.start_on_webhook,
            start_on_service_event: runs.start_on_service_event,
            start_by_hand: runs.start_by_hand,
            start_test: runs.start_test,
            list_executions: runs.list,
            list_all_executions: runs.list_all,
            list_passes: runs.list_passes,
            get_execution: runs.get,
            cancel_execution: runs.cancel,
            rerun_execution: runs.rerun,
            retry_execution: runs.retry,
            show_approval: runs.show_approval,
            approve_step: runs.approve_step,
            deny_step: runs.deny_step,
            show_items: runs.show_items,
            approve_items: runs.approve_items,
            create_flow: flows.create,
            list_flows: flows.list,
            get_flow: flows.get,
            cancel_flow: flows.cancel,
            delete_flow: flows.delete,
            list_risks: risks.list,
            raise_risk: risks.raise,
            change_risk: risks.change,
            remove_risk: risks.remove,
            list_sandboxes: sandboxes.list,
            create_sandbox: sandboxes.create,
            get_sandbox: sandboxes.get,
            save_sandbox_version: sandboxes.save_version,
            push_sandbox_version: sandboxes.push_version,
            write_sandbox_code: sandboxes.write_code,
            archive_sandbox: sandboxes.archive,
            list_sandbox_runtimes: sandboxes.runtimes,
            start_sandbox_trial: sandboxes.start_trial,
            get_sandbox_trial: sandboxes.get_trial,
            save_image_version: sandboxes.images.save_version,
            list_image_registries: sandboxes.images.list_registries,
            allow_image_registry: sandboxes.images.allow_registry,
            remove_image_registry: sandboxes.images.remove_registry,
            memories: memories::build(a),
            evaluations: evaluations::build(a),
            app_base_url: s.app_base_url.clone(),
        }
    }
}

/// The use cases connecting an account by signing in at its service.
struct Connecting {
    begin: Arc<connections::BeginUseCase>,
    answer: Arc<connections::AnswerUseCase>,
    finish: Arc<connections::FinishUseCase>,
}

/// Builds the connection use cases over `a`.
fn connecting(a: &Adapters) -> Connecting {
    let pending = || a.pending_connection_store.clone();
    let secrets = || a.connection_secrets.clone();
    let encryptor = || a.secret_encryptor.clone();
    Connecting {
        begin: Arc::new(connections::BeginUseCase::new(connections::BeginPorts {
            connections: pending(),
            sign_in: a.service_sign_in.clone(),
            secrets: secrets(),
            encryptor: encryptor(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        answer: Arc::new(connections::AnswerUseCase::new(connections::AnswerPorts {
            states: a.connection_states.clone(),
            connections: pending(),
            sign_in: a.service_sign_in.clone(),
            secrets: secrets(),
            encryptor: encryptor(),
        })),
        finish: Arc::new(connections::FinishUseCase::new(connections::FinishPorts {
            connections: pending(),
            accounts: a.integration_account_store.clone(),
            verifier: a.account_verifier.clone(),
            secrets: secrets(),
            encryptor: encryptor(),
            unit_of_work: a.unit_of_work.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
    }
}

/// The use cases on workflow definitions and their versions.
struct Designs {
    list: Arc<definitions::ListWorkflowsUseCase>,
    create: Arc<definitions::CreateWorkflowUseCase>,
    get: Arc<definitions::GetWorkflowUseCase>,
    edit_draft: Arc<definitions::EditDraftUseCase>,
    next_draft: Arc<definitions::NextDraftUseCase>,
    publish: Arc<definitions::PublishWorkflowUseCase>,
    archive: Arc<definitions::ArchiveWorkflowUseCase>,
    step_data: Arc<definitions::StepDataUseCase>,
    draft: Arc<definitions::DraftUseCase>,
}

/// Builds the definition use cases over `a`.
/// This exhaustive initializer keeps draft, publication and archive ports in one visible mapping.
#[allow(clippy::too_many_lines)]
fn designs(a: &Adapters) -> Designs {
    let workflows = || a.workflow_store.clone();
    let authorities = || a.tenant_authorities.clone();
    Designs {
        list: Arc::new(definitions::ListWorkflowsUseCase::new(
            definitions::ListWorkflowsPorts {
                workflows: workflows(),
                tenant_authorities: authorities(),
            },
        )),
        create: Arc::new(definitions::CreateWorkflowUseCase::new(
            definitions::CreateWorkflowPorts {
                workflows: workflows(),
                limit_enforcer: a.limit_enforcer.clone(),
                tenant_authorities: authorities(),
            },
        )),
        get: Arc::new(definitions::GetWorkflowUseCase::new(
            definitions::GetWorkflowPorts {
                workflows: workflows(),
                tenant_authorities: authorities(),
            },
        )),
        edit_draft: Arc::new(definitions::EditDraftUseCase::new(
            definitions::EditDraftPorts {
                workflows: workflows(),
                tenant_authorities: authorities(),
            },
        )),
        next_draft: Arc::new(definitions::NextDraftUseCase::new(
            definitions::NextDraftPorts {
                workflows: workflows(),
                tenant_authorities: authorities(),
            },
        )),
        publish: Arc::new(definitions::PublishWorkflowUseCase::new(
            definitions::PublishWorkflowPorts {
                workflows: workflows(),
                catalog: a.integration_catalog.clone(),
                risks: a.operation_risk_override_store.clone(),
                sandboxes: a.sandbox_store.clone(),
                sandbox_versions: a.sandbox_version_store.clone(),
                evaluation_sets: a.evaluation_set_store.clone(),
                evaluations: a.evaluation_store.clone(),
                registrations: registrations(a),
                unit_of_work: a.unit_of_work.clone(),
                tenant_authorities: authorities(),
            },
        )),
        archive: Arc::new(definitions::ArchiveWorkflowUseCase::new(
            definitions::ArchiveWorkflowPorts {
                workflows: workflows(),
                registrations: registrations(a),
                unit_of_work: a.unit_of_work.clone(),
                tenant_authorities: authorities(),
            },
        )),
        step_data: Arc::new(definitions::StepDataUseCase::new(
            definitions::StepDataPorts {
                workflows: workflows(),
                catalog: a.integration_catalog.clone(),
                tenant_authorities: authorities(),
            },
        )),
        draft: Arc::new(definitions::DraftUseCase::new(definitions::DraftPorts {
            workflows: workflows(),
            catalog: a.integration_catalog.clone(),
            providers: a.model_provider_store.clone(),
            encryptor: a.secret_encryptor.clone(),
            model_client: a.model_client.clone(),
            tenant_authorities: authorities(),
        })),
    }
}

/// The use cases on executions: starting, reading, stopping, starting
/// again and deciding their approvals.
struct Runs {
    start_on_webhook: Arc<executions::StartOnWebhookUseCase>,
    start_on_service_event: Arc<executions::StartOnServiceEventUseCase>,
    start_by_hand: Arc<executions::StartByHandUseCase>,
    start_test: Arc<executions::StartTestUseCase>,
    list: Arc<executions::ListUseCase>,
    list_all: Arc<executions::ListAllUseCase>,
    list_passes: Arc<executions::ListPassesUseCase>,
    get: Arc<executions::GetUseCase>,
    cancel: Arc<executions::CancelUseCase>,
    rerun: Arc<executions::RerunUseCase>,
    retry: Arc<executions::RetryUseCase>,
    show_approval: Arc<executions::ShowApprovalUseCase>,
    approve_step: Arc<executions::ApproveStepUseCase>,
    deny_step: Arc<executions::DenyStepUseCase>,
    show_items: Arc<executions::ShowItemsUseCase>,
    approve_items: Arc<executions::ApproveItemsUseCase>,
}

/// Builds the execution use cases over `a`, with the lockout `s` sets for
/// an approver's second factor.
/// The exhaustive initializer keeps each execution entry point's authority and wakeup ports together.
#[allow(clippy::too_many_lines)]
fn runs(a: &Adapters, s: &Settings) -> Runs {
    let executions = || a.workflow_execution_store.clone();
    let authorities = || a.tenant_authorities.clone();
    Runs {
        start_on_webhook: Arc::new(executions::StartOnWebhookUseCase::new(
            executions::StartOnWebhookPorts {
                trigger_secrets: a.workflow_trigger_secret_store.clone(),
                secret_hasher: a.workflow_trigger_secret_generator.clone(),
                starts: trigger_starts(a),
            },
        )),
        start_on_service_event: Arc::new(executions::StartOnServiceEventUseCase::new(
            executions::StartOnServiceEventPorts {
                directory: a.subscription_directory.clone(),
                subscriptions: a.service_subscription_store.clone(),
                reader: a.service_event_reader.clone(),
                encryptor: a.secret_encryptor.clone(),
                ledger: a.delivery_ledger.clone(),
                starts: trigger_starts(a),
                channel_directory: a.channel_directory.clone(),
                channels: a.account_channel_store.clone(),
                registrations: registrations(a),
            },
        )),
        start_by_hand: Arc::new(executions::StartByHandUseCase::new(
            executions::StartByHandPorts {
                workflows: a.workflow_store.clone(),
                executions: executions(),
                wakeups: wakeups(a),
                run_stops: run_stops(a),
                tenant_authorities: authorities(),
            },
        )),
        start_test: Arc::new(executions::StartTestUseCase::new(
            executions::StartTestPorts {
                workflows: a.workflow_store.clone(),
                executions: executions(),
                sandboxes: a.sandbox_store.clone(),
                sandbox_versions: a.sandbox_version_store.clone(),
                wakeups: wakeups(a),
                run_stops: run_stops(a),
                tenant_authorities: authorities(),
            },
        )),
        list: Arc::new(executions::ListUseCase::new(executions::ListPorts {
            executions: executions(),
            tenant_authorities: authorities(),
        })),
        list_all: Arc::new(executions::ListAllUseCase::new(executions::ListAllPorts {
            executions: executions(),
            tenant_authorities: authorities(),
        })),
        list_passes: Arc::new(executions::ListPassesUseCase::new(
            executions::ListPassesPorts {
                executions: executions(),
                tenant_authorities: authorities(),
            },
        )),
        get: Arc::new(executions::GetUseCase::new(executions::GetPorts {
            executions: executions(),
            tenant_authorities: authorities(),
        })),
        cancel: Arc::new(executions::CancelUseCase::new(executions::CancelPorts {
            executions: executions(),
            wakeups: wakeups(a),
            run_stops: run_stops(a),
            tenant_authorities: authorities(),
        })),
        rerun: Arc::new(executions::RerunUseCase::new(restarts(a))),
        retry: Arc::new(executions::RetryUseCase::new(restarts(a))),
        show_approval: Arc::new(executions::ShowApprovalUseCase::new(
            executions::ShowApprovalPorts {
                executions: executions(),
                tenant_authorities: authorities(),
            },
        )),
        approve_step: Arc::new(executions::ApproveStepUseCase::new(
            executions::ApproveStepPorts {
                executions: executions(),
                wakeups: wakeups(a),
                run_stops: run_stops(a),
                presence: Arc::new(presence(a, s)),
                tenant_authorities: authorities(),
            },
        )),
        deny_step: Arc::new(executions::DenyStepUseCase::new(
            executions::DenyStepPorts {
                executions: executions(),
                wakeups: wakeups(a),
                run_stops: run_stops(a),
                tenant_authorities: authorities(),
            },
        )),
        show_items: Arc::new(executions::ShowItemsUseCase::new(
            executions::ShowItemsPorts {
                executions: executions(),
                pages: a.approval_pages.clone(),
                tenant_authorities: authorities(),
            },
        )),
        approve_items: Arc::new(executions::ApproveItemsUseCase::new(
            executions::ApproveItemsPorts {
                executions: executions(),
                pages: a.approval_pages.clone(),
                wakeups: wakeups(a),
                run_stops: run_stops(a),
                presence: Arc::new(presence(a, s)),
                tenant_authorities: authorities(),
            },
        )),
    }
}

/// The use cases on agent flows.
struct AgentFlows {
    create: Arc<flows::CreateUseCase>,
    list: Arc<flows::ListUseCase>,
    get: Arc<flows::GetUseCase>,
    cancel: Arc<flows::CancelUseCase>,
    delete: Arc<flows::DeleteUseCase>,
}

/// Builds the agent flow use cases over `a`.
fn agent_flows(a: &Adapters) -> AgentFlows {
    let workflows = || a.workflow_store.clone();
    let executions = || a.workflow_execution_store.clone();
    let authorities = || a.tenant_authorities.clone();
    AgentFlows {
        create: create_flow(a),
        list: Arc::new(flows::ListUseCase::new(flows::ListPorts {
            workflows: workflows(),
            executions: executions(),
            tenant_authorities: authorities(),
        })),
        get: Arc::new(flows::GetUseCase::new(flows::GetPorts {
            workflows: workflows(),
            executions: executions(),
            tenant_authorities: authorities(),
        })),
        cancel: Arc::new(flows::CancelUseCase::new(flows::CancelPorts {
            workflows: workflows(),
            executions: executions(),
            wakeups: wakeups(a),
            run_stops: run_stops(a),
            tenant_authorities: authorities(),
        })),
        delete: Arc::new(flows::DeleteUseCase::new(flows::DeletePorts {
            workflows: workflows(),
            executions: executions(),
            tenant_authorities: authorities(),
        })),
    }
}

/// Creates agent flows with plan enforcement and the same execution wakeup and cancellation ports.
fn create_flow(a: &Adapters) -> Arc<flows::CreateUseCase> {
    Arc::new(flows::CreateUseCase::new(flows::CreatePorts {
        workflows: a.workflow_store.clone(),
        executions: a.workflow_execution_store.clone(),
        wakeups: wakeups(a),
        run_stops: run_stops(a),
        limit_enforcer: a.limit_enforcer.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    }))
}

/// The use cases on the tenant's raised operation risks.
struct Risks {
    list: Arc<risk_overrides::ListRisksUseCase>,
    raise: Arc<risk_overrides::RaiseRiskUseCase>,
    change: Arc<risk_overrides::ChangeRiskUseCase>,
    remove: Arc<risk_overrides::RemoveRiskUseCase>,
}

/// Builds the risk use cases over `a`.
fn risks(a: &Adapters) -> Risks {
    let store = || a.operation_risk_override_store.clone();
    let authorities = || a.tenant_authorities.clone();
    Risks {
        list: Arc::new(risk_overrides::ListRisksUseCase::new(
            risk_overrides::ListRisksPorts {
                risks: store(),
                tenant_authorities: authorities(),
            },
        )),
        raise: Arc::new(risk_overrides::RaiseRiskUseCase::new(
            risk_overrides::RaiseRiskPorts {
                risks: store(),
                tenant_authorities: authorities(),
            },
        )),
        change: Arc::new(risk_overrides::ChangeRiskUseCase::new(
            risk_overrides::ChangeRiskPorts {
                risks: store(),
                tenant_authorities: authorities(),
            },
        )),
        remove: Arc::new(risk_overrides::RemoveRiskUseCase::new(
            risk_overrides::RemoveRiskPorts {
                risks: store(),
                tenant_authorities: authorities(),
            },
        )),
    }
}

/// The use cases on the tenant's sandboxes.
struct Sandboxes {
    list: Arc<sandboxes::ListUseCase>,
    create: Arc<sandboxes::CreateSandboxUseCase>,
    get: Arc<sandboxes::GetSandboxUseCase>,
    save_version: Arc<sandboxes::SaveVersionUseCase>,
    push_version: Arc<sandboxes::code::PushVersionUseCase>,
    write_code: Arc<sandboxes::code::WriteUseCase>,
    archive: Arc<sandboxes::ArchiveSandboxUseCase>,
    runtimes: Arc<sandboxes::ListRuntimesUseCase>,
    start_trial: Arc<sandboxes::trying::StartTrialUseCase>,
    get_trial: Arc<sandboxes::trying::GetTrialUseCase>,
    images: OwnImageUseCases,
}

/// The use cases on companies' own images and the registries they come
/// from.
struct OwnImageUseCases {
    save_version: Arc<sandboxes::images::SaveUseCase>,
    list_registries: Arc<sandboxes::images::registries::ListUseCase>,
    allow_registry: Arc<sandboxes::images::registries::AllowUseCase>,
    remove_registry: Arc<sandboxes::images::registries::RemoveUseCase>,
}

/// The logins companies' images are pulled with, for the registries the
/// tenant allowed, while `s` lets tenants run their own images.
#[must_use]
pub fn image_pulls(a: &Adapters, s: &Settings) -> sandboxes::images::ImagePulls {
    sandboxes::images::ImagePulls::new(
        a.image_registry_store.clone(),
        a.secret_encryptor.clone(),
        s.own_images,
    )
}

/// Saving a version of a company's image over `a`, its scan queued as a
/// `sandbox.build` job.
fn save_image_version(a: &Adapters, s: &Settings) -> Arc<sandboxes::images::SaveUseCase> {
    Arc::new(sandboxes::images::SaveUseCase::new(
        sandboxes::images::SavePorts {
            sandboxes: a.sandbox_store.clone(),
            versions: a.sandbox_version_store.clone(),
            builds: sandboxes::SandboxBuilds::new(a.job_queue.clone()),
            pulls: image_pulls(a, s),
            resolver: a.image_resolver.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
            unit_of_work: a.unit_of_work.clone(),
        },
    ))
}

/// Builds the use cases on companies' own images over `a`, their versions'
/// scans queued as `sandbox.build` jobs.
fn own_images(a: &Adapters, s: &Settings) -> OwnImageUseCases {
    let registries = || a.image_registry_store.clone();
    let authorities = || a.tenant_authorities.clone();
    OwnImageUseCases {
        save_version: save_image_version(a, s),
        list_registries: Arc::new(sandboxes::images::registries::ListUseCase::new(
            sandboxes::images::registries::ListPorts {
                registries: registries(),
                tenant_authorities: authorities(),
            },
        )),
        allow_registry: Arc::new(sandboxes::images::registries::AllowUseCase::new(
            sandboxes::images::registries::AllowPorts {
                registries: registries(),
                encryptor: a.secret_encryptor.clone(),
                pulls: image_pulls(a, s),
                tenant_authorities: authorities(),
            },
        )),
        remove_registry: Arc::new(sandboxes::images::registries::RemoveUseCase::new(
            sandboxes::images::registries::RemovePorts {
                registries: registries(),
                tenant_authorities: authorities(),
                unit_of_work: a.unit_of_work.clone(),
            },
        )),
    }
}

/// Builds the sandbox use cases over `a`, their builds queued as
/// `sandbox.build` jobs and their trials as `sandbox.try` jobs.
/// The exhaustive initializer keeps sandbox versions, repositories and trial ports aligned by operation.
#[allow(clippy::too_many_lines)]
fn sandboxes(a: &Adapters, s: &Settings) -> Sandboxes {
    let store = || a.sandbox_store.clone();
    let authorities = || a.tenant_authorities.clone();
    Sandboxes {
        list: Arc::new(sandboxes::ListUseCase::new(sandboxes::ListPorts {
            sandboxes: store(),
            tenant_authorities: authorities(),
        })),
        create: Arc::new(sandboxes::CreateSandboxUseCase::new(
            sandboxes::CreateSandboxPorts {
                sandboxes: store(),
                limit_enforcer: a.limit_enforcer.clone(),
                pulls: image_pulls(a, s),
                tenant_authorities: authorities(),
            },
        )),
        get: Arc::new(sandboxes::GetSandboxUseCase::new(
            sandboxes::GetSandboxPorts {
                sandboxes: store(),
                versions: a.sandbox_version_store.clone(),
                tenant_authorities: authorities(),
            },
        )),
        save_version: Arc::new(sandboxes::SaveVersionUseCase::new(
            sandboxes::SaveVersionPorts {
                sandboxes: store(),
                versions: a.sandbox_version_store.clone(),
                builds: sandboxes::SandboxBuilds::new(a.job_queue.clone()),
                runtimes: a.sandbox_runtimes.clone(),
                accounts: a.integration_account_store.clone(),
                repositories: a.code_repositories.clone(),
                grants: a.account_grants(),
                tenant_authorities: authorities(),
                unit_of_work: a.unit_of_work.clone(),
            },
        )),
        push_version: Arc::new(sandboxes::code::PushVersionUseCase::new(
            sandboxes::code::PushVersionPorts {
                sandboxes: store(),
                versions: a.sandbox_version_store.clone(),
                accounts: a.integration_account_store.clone(),
                repositories: a.code_repositories.clone(),
                grants: a.account_grants(),
                unit_of_work: a.unit_of_work.clone(),
                tenant_authorities: authorities(),
            },
        )),
        write_code: Arc::new(sandboxes::code::WriteUseCase::new(
            sandboxes::code::WritePorts {
                sandboxes: store(),
                providers: a.model_provider_store.clone(),
                encryptor: a.secret_encryptor.clone(),
                model_client: a.model_client.clone(),
                tenant_authorities: authorities(),
            },
        )),
        archive: Arc::new(sandboxes::ArchiveSandboxUseCase::new(
            sandboxes::ArchiveSandboxPorts {
                sandboxes: store(),
                tenant_authorities: authorities(),
            },
        )),
        runtimes: Arc::new(sandboxes::ListRuntimesUseCase::new(
            sandboxes::ListRuntimesPorts {
                runtimes: a.sandbox_runtimes.clone(),
                tenant_authorities: authorities(),
            },
        )),
        start_trial: Arc::new(sandboxes::trying::StartTrialUseCase::new(
            sandboxes::trying::StartTrialPorts {
                sandboxes: store(),
                versions: a.sandbox_version_store.clone(),
                trials: a.sandbox_trial_store.clone(),
                runs: sandboxes::trying::SandboxTrials::new(a.job_queue.clone()),
                limit_enforcer: a.limit_enforcer.clone(),
                tenant_authorities: authorities(),
                unit_of_work: a.unit_of_work.clone(),
            },
        )),
        get_trial: Arc::new(sandboxes::trying::GetTrialUseCase::new(
            sandboxes::trying::GetTrialPorts {
                trials: a.sandbox_trial_store.clone(),
                tenant_authorities: authorities(),
            },
        )),
        images: own_images(a, s),
    }
}

/// Where executions ask to be driven again: `workflow.drive` jobs on the
/// job queue, written in the request's unit of work.
fn wakeups(a: &Adapters) -> executions::Wakeups {
    executions::Wakeups::new(a.job_queue.clone())
}

/// What a failed execution's restart needs.
fn restarts(a: &Adapters) -> executions::RestartPorts {
    executions::RestartPorts {
        workflows: a.workflow_store.clone(),
        executions: a.workflow_execution_store.clone(),
        wakeups: wakeups(a),
        run_stops: run_stops(a),
        tenant_authorities: a.tenant_authorities.clone(),
    }
}

/// What a start for a workflow's publisher needs: the stores, the agent
/// runs an execution gives up, and the publisher's account as it stands.
fn trigger_starts(a: &Adapters) -> executions::TriggerStartPorts {
    executions::TriggerStartPorts {
        workflows: a.workflow_store.clone(),
        executions: a.workflow_execution_store.clone(),
        wakeups: wakeups(a),
        run_stops: run_stops(a),
        accounts_now: a.accounts_now(),
        accounts: a.integration_account_store.clone(),
        unit_of_work: a.unit_of_work.clone(),
    }
}

/// What registering a workflow at its trigger's service, and removing it,
/// needs.
fn registrations(a: &Adapters) -> RegistrationPorts {
    RegistrationPorts {
        accounts: a.integration_account_store.clone(),
        accounts_now: a.accounts_now(),
        subscriptions: a.service_subscription_store.clone(),
        channels: a.account_channel_store.clone(),
        registrar: a.service_registrar.clone(),
        channel_setup: a.service_channel_setup.clone(),
        grants: a.account_grants(),
        encryptor: a.secret_encryptor.clone(),
        tokens: a.secure_token_generator.clone(),
        unit_of_work: a.unit_of_work.clone(),
    }
}

/// What stops the agent runs an execution gives up.
fn run_stops(a: &Adapters) -> StopPorts {
    StopPorts {
        run_cancellation: a.run_cancellation.clone(),
        run_store: a.run_store.clone(),
        approval_store: a.approval_store.clone(),
        audit_label_resolver: a.audit_label_resolver.clone(),
    }
}

/// The fresh second factor an approver of a high-risk step answers.
fn presence(a: &Adapters, s: &Settings) -> ApproverPresence {
    ApproverPresence::new(
        s.tunables.mfa_lockout,
        ApproverPresencePorts {
            tenant_mfa: a.mfa_enrollment_store.clone(),
            org_mfa: a.org_mfa_enrollment_store.clone(),
            encryptor: a.secret_encryptor.clone(),
            verifier: a.mfa_verifier.clone(),
            sent_codes: a.sent_code_store.clone(),
            sent_code_generator: a.sent_code_generator.clone(),
        },
    )
}

/// The company's "before" rules, deciding the changes they guard by
/// starting each published rule and waiting for its verdict.
#[must_use]
pub(crate) fn change_guard(a: &Adapters) -> Arc<dyn ChangeGuard> {
    Arc::new(executions::DecideBeforeUseCase::new(
        trigger_starts(a),
        a.pause.clone(),
    ))
}
