//! The use cases of workflows' evaluations: saving and reading a
//! workflow's sample cases, starting an evaluation and reading it back.

use std::sync::Arc;

use ianua_app::use_cases::workflows::evaluations;

use crate::deps::Adapters;

/// The use cases of workflows' evaluations.
#[derive(Clone)]
pub struct EvaluationUseCases {
    pub save_set: Arc<evaluations::SaveSetUseCase>,
    pub get_set: Arc<evaluations::GetSetUseCase>,
    pub start: Arc<evaluations::StartUseCase>,
    pub list: Arc<evaluations::ListUseCase>,
    pub get: Arc<evaluations::GetUseCase>,
}

/// Builds the evaluation use cases over `a`.
pub fn build(a: &Adapters) -> EvaluationUseCases {
    EvaluationUseCases {
        save_set: Arc::new(evaluations::SaveSetUseCase::new(
            evaluations::SaveSetPorts {
                workflows: a.workflow_store.clone(),
                evaluation_sets: a.evaluation_set_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        get_set: Arc::new(evaluations::GetSetUseCase::new(evaluations::GetSetPorts {
            evaluation_sets: a.evaluation_set_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        start: Arc::new(evaluations::StartUseCase::new(evaluations::StartPorts {
            workflows: a.workflow_store.clone(),
            evaluation_sets: a.evaluation_set_store.clone(),
            evaluations: a.evaluation_store.clone(),
            looks: evaluations::Evaluations::new(a.job_queue.clone()),
            limit_enforcer: a.limit_enforcer.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
            unit_of_work: a.unit_of_work.clone(),
        })),
        list: Arc::new(evaluations::ListUseCase::new(evaluations::ListPorts {
            evaluations: a.evaluation_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        get: Arc::new(evaluations::GetUseCase::new(evaluations::GetPorts {
            evaluations: a.evaluation_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
    }
}
