//! The data classification use cases the API serves: a tenant's
//! field-level sensitivity rules.

use std::sync::Arc;

use ianua_app::use_cases::data_classification::{
    AddClassificationRulePorts, AddClassificationRuleUseCase, ChangeClassificationRulePorts,
    ChangeClassificationRuleUseCase, GetClassificationPorts, GetClassificationUseCase,
    RemoveClassificationRulePorts, RemoveClassificationRuleUseCase,
};

use crate::deps::Adapters;

/// The data classification use cases.
#[derive(Clone)]
pub struct DataClassificationState {
    pub get: Arc<GetClassificationUseCase>,
    pub add_rule: Arc<AddClassificationRuleUseCase>,
    pub change_rule: Arc<ChangeClassificationRuleUseCase>,
    pub remove_rule: Arc<RemoveClassificationRuleUseCase>,
}

/// Builds the data classification use cases over `a`.
pub fn build(a: &Adapters) -> DataClassificationState {
    DataClassificationState {
        get: Arc::new(GetClassificationUseCase::new(GetClassificationPorts {
            store: a.classification_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        add_rule: Arc::new(AddClassificationRuleUseCase::new(
            AddClassificationRulePorts {
                store: a.classification_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        change_rule: Arc::new(ChangeClassificationRuleUseCase::new(
            ChangeClassificationRulePorts {
                store: a.classification_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        remove_rule: Arc::new(RemoveClassificationRuleUseCase::new(
            RemoveClassificationRulePorts {
                store: a.classification_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
    }
}
