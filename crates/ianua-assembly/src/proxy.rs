//! The proxy use cases the API serves: a tenant's request pipelines and
//! their stages, canary tokens and WASM stage modules, the request records
//! the gateway kept, and the places those records are shipped to.

use std::sync::Arc;

use ianua_app::use_cases::proxy::log_shipping::{
    ChangeLogTargetPorts, ChangeLogTargetUseCase, CreateLogTargetPorts, CreateLogTargetUseCase,
    DeleteLogTargetPorts, DeleteLogTargetUseCase, GetLogTargetPorts, GetLogTargetUseCase,
    ListLogTargetsPorts, ListLogTargetsUseCase, PauseLogTargetPorts, PauseLogTargetUseCase,
    ResumeLogTargetPorts, ResumeLogTargetUseCase,
};
use ianua_app::use_cases::proxy::{
    SearchRequestRecordsPorts, SearchRequestRecordsUseCase, pipelines, stages,
};

use crate::deps::Adapters;

/// The proxy use cases.
#[derive(Clone)]
pub struct ProxyState {
    /// Makes a new pipeline, in draft.
    pub configure_pipeline: Arc<pipelines::ConfigureUseCase>,
    pub list_pipelines: Arc<pipelines::ListUseCase>,
    pub get_pipeline: Arc<pipelines::GetUseCase>,
    pub rename_pipeline: Arc<pipelines::RenameUseCase>,
    pub delete_pipeline: Arc<pipelines::DeleteUseCase>,
    /// Puts a pipeline in force on its routes.
    pub activate_pipeline: Arc<pipelines::ActivateUseCase>,
    pub disable_pipeline: Arc<pipelines::DisableUseCase>,
    pub stages: StageUseCases,
    pub search_requests: Arc<SearchRequestRecordsUseCase>,
    pub log_targets: LogTargetUseCases,
}

/// What a pipeline runs: its stages, and the tokens and modules they are
/// configured with.
#[derive(Clone)]
pub struct StageUseCases {
    pub add: Arc<stages::AddUseCase>,
    pub reconfigure: Arc<stages::ReconfigureUseCase>,
    pub remove: Arc<stages::RemoveUseCase>,
    pub enable: Arc<stages::EnableUseCase>,
    pub disable: Arc<stages::DisableUseCase>,
    pub reorder: Arc<stages::ReorderUseCase>,
    pub generate_canary_token: Arc<stages::GenerateCanaryTokenUseCase>,
    pub upload_wasm_module: Arc<stages::UploadWasmModuleUseCase>,
}

/// The places a tenant ships its request records to.
#[derive(Clone)]
pub struct LogTargetUseCases {
    pub create: Arc<CreateLogTargetUseCase>,
    pub list: Arc<ListLogTargetsUseCase>,
    pub get: Arc<GetLogTargetUseCase>,
    pub change: Arc<ChangeLogTargetUseCase>,
    pub pause: Arc<PauseLogTargetUseCase>,
    pub resume: Arc<ResumeLogTargetUseCase>,
    pub delete: Arc<DeleteLogTargetUseCase>,
}

/// Builds the proxy use cases over `a`.
pub fn build(a: &Adapters) -> ProxyState {
    ProxyState {
        configure_pipeline: Arc::new(configure_pipeline(a)),
        list_pipelines: Arc::new(pipelines::ListUseCase::new(pipelines::ListPorts {
            pipeline_store: a.pipeline_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        get_pipeline: Arc::new(pipelines::GetUseCase::new(pipelines::GetPorts {
            pipeline_store: a.pipeline_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        rename_pipeline: Arc::new(pipelines::RenameUseCase::new(pipelines::RenamePorts {
            pipeline_store: a.pipeline_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        delete_pipeline: Arc::new(pipelines::DeleteUseCase::new(pipelines::DeletePorts {
            pipeline_store: a.pipeline_store.clone(),
            route_store: a.route_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        activate_pipeline: Arc::new(activate_pipeline(a)),
        disable_pipeline: Arc::new(pipelines::DisableUseCase::new(pipelines::DisablePorts {
            pipeline_store: a.pipeline_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        stages: stage_use_cases(a),
        search_requests: Arc::new(search_requests(a)),
        log_targets: log_target_use_cases(a),
    }
}

/// Creates draft pipelines under the tenant's pipeline authority.
fn configure_pipeline(a: &Adapters) -> pipelines::ConfigureUseCase {
    pipelines::ConfigureUseCase::new(pipelines::ConfigurePorts {
        pipeline_store: a.pipeline_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Activates pipelines after checking the routes that use them.
fn activate_pipeline(a: &Adapters) -> pipelines::ActivateUseCase {
    pipelines::ActivateUseCase::new(pipelines::ActivatePorts {
        pipeline_store: a.pipeline_store.clone(),
        route_store: a.route_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Searches gateway observations under tenant authority.
fn search_requests(a: &Adapters) -> SearchRequestRecordsUseCase {
    SearchRequestRecordsUseCase::new(SearchRequestRecordsPorts {
        request_log: a.proxy_request_log.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// The stage use cases over `a`.
fn stage_use_cases(a: &Adapters) -> StageUseCases {
    StageUseCases {
        add: Arc::new(stages::AddUseCase::new(stages::AddPorts {
            pipeline_store: a.pipeline_store.clone(),
            classification_store: a.classification_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        reconfigure: Arc::new(stages::ReconfigureUseCase::new(stages::ReconfigurePorts {
            pipeline_store: a.pipeline_store.clone(),
            classification_store: a.classification_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        remove: Arc::new(stages::RemoveUseCase::new(stages::RemovePorts {
            pipeline_store: a.pipeline_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        enable: Arc::new(stages::EnableUseCase::new(stages::EnablePorts {
            pipeline_store: a.pipeline_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        disable: Arc::new(stages::DisableUseCase::new(stages::DisablePorts {
            pipeline_store: a.pipeline_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        reorder: Arc::new(stages::ReorderUseCase::new(stages::ReorderPorts {
            pipeline_store: a.pipeline_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        generate_canary_token: Arc::new(generate_canary_token(a)),
        upload_wasm_module: Arc::new(upload_wasm_module(a)),
    }
}

/// Issues unpredictable canary values to authorized pipeline managers.
fn generate_canary_token(a: &Adapters) -> stages::GenerateCanaryTokenUseCase {
    stages::GenerateCanaryTokenUseCase::new(stages::GenerateCanaryTokenPorts {
        token_generator: a.secure_token_generator.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Stores custom stage modules after checking pipeline authority.
fn upload_wasm_module(a: &Adapters) -> stages::UploadWasmModuleUseCase {
    stages::UploadWasmModuleUseCase::new(stages::UploadWasmModulePorts {
        wasm_module_store: a.wasm_module_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// The log shipping target use cases over `a`.
fn log_target_use_cases(a: &Adapters) -> LogTargetUseCases {
    LogTargetUseCases {
        create: Arc::new(create_log_target(a)),
        list: Arc::new(ListLogTargetsUseCase::new(ListLogTargetsPorts {
            log_shipping_store: a.log_shipping_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        get: Arc::new(GetLogTargetUseCase::new(GetLogTargetPorts {
            log_shipping_store: a.log_shipping_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        change: Arc::new(ChangeLogTargetUseCase::new(ChangeLogTargetPorts {
            log_shipping_store: a.log_shipping_store.clone(),
            encryptor: a.secret_encryptor.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        pause: Arc::new(PauseLogTargetUseCase::new(PauseLogTargetPorts {
            log_shipping_store: a.log_shipping_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        resume: Arc::new(ResumeLogTargetUseCase::new(ResumeLogTargetPorts {
            log_shipping_store: a.log_shipping_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        delete: Arc::new(DeleteLogTargetUseCase::new(DeleteLogTargetPorts {
            log_shipping_store: a.log_shipping_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
    }
}

/// Creates a log destination with sealed credentials and tenant plan limits.
fn create_log_target(a: &Adapters) -> CreateLogTargetUseCase {
    CreateLogTargetUseCase::new(CreateLogTargetPorts {
        log_shipping_store: a.log_shipping_store.clone(),
        encryptor: a.secret_encryptor.clone(),
        limit_enforcer: a.limit_enforcer.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}
