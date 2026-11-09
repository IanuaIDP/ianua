//! The use cases of the tenants' memories: making, listing, deleting after
//! the typed name, bringing back, and reading their texts for a copy.

use std::sync::Arc;

use ianua_app::use_cases::workflows::memories;

use crate::deps::Adapters;

/// The use cases of the tenants' memories.
#[derive(Clone)]
pub struct MemoryUseCases {
    pub create: Arc<memories::CreateUseCase>,
    pub list: Arc<memories::ListUseCase>,
    pub delete: Arc<memories::DeleteUseCase>,
    pub restore: Arc<memories::RestoreUseCase>,
    pub export: Arc<memories::ExportUseCase>,
}

/// Builds the memory use cases over `a`.
pub fn build(a: &Adapters) -> MemoryUseCases {
    MemoryUseCases {
        create: Arc::new(memories::CreateUseCase::new(memories::CreatePorts {
            memories: a.memory_store.clone(),
            embedder: a.embedder.clone(),
            providers: a.model_provider_store.clone(),
            encryptor: a.secret_encryptor.clone(),
            limit_enforcer: a.limit_enforcer.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        list: Arc::new(memories::ListUseCase::new(memories::ListPorts {
            memories: a.memory_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        delete: Arc::new(memories::DeleteUseCase::new(memories::DeletePorts {
            memories: a.memory_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
            unit_of_work: a.unit_of_work.clone(),
        })),
        restore: Arc::new(memories::RestoreUseCase::new(memories::RestorePorts {
            memories: a.memory_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
            unit_of_work: a.unit_of_work.clone(),
        })),
        export: Arc::new(memories::ExportUseCase::new(memories::ExportPorts {
            memories: a.memory_store.clone(),
            entries: a.memory_entries.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
    }
}
