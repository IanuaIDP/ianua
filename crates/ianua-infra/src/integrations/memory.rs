//! The built-in memory integration: keeping a text in one of the tenant's
//! memories, and finding the memory's texts most like one.
//!
//! It declares its two operations and explains them to a workflow's
//! builder, so the catalog lists them beside every other step. The
//! platform runs them itself, through the memory's own embedding model and
//! the vector store, with the rules the memory keeps checked at each call;
//! nothing is ever called through this integration.

use async_trait::async_trait;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::data::FieldName;
use ianua_domain::domains::workflows::execution::ActionCall;
use ianua_domain::domains::workflows::integration::account_check::AccountCheck;
use ianua_domain::domains::workflows::integration::form::FormGroup;
use ianua_domain::domains::workflows::integration::guide::OperationGuide;
use ianua_domain::domains::workflows::integration::profile::IntegrationProfile;
use ianua_domain::domains::workflows::integration::{
    AccountNeed, InputNeed, InputSpec, IntegrationKey, MEMORY_INPUT, OperationKey, OperationSpec,
    OperationSpecParams,
};
use ianua_domain::domains::workflows::memory::{
    COUNT_INPUT, FIND_SIMILAR, MEMORY_INTEGRATION, REMEMBER, TEXT_INPUT,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::answer::failed;
use ianua_integration::describe::{BuiltInText, GuideText, InputText, built_in_profile, guide};
use ianua_integration::form::{Ask, FormText, Suggested};
use ianua_integration::{Called, Integration};

/// How the integration presents itself.
const PROFILE: BuiltInText<'static> = BuiltInText {
    title: "Memory",
    description: "Keeps texts in one of the company's memories and finds the ones most alike, such as the three past tickets closest to a new one.",
    icon: "memory",
    brand: "6d28d9",
};

/// What keeping a text gives back.
const REMEMBER_OUTPUTS: &[(&str, &str)] = &[("entry_id", "The id the text is kept under.")];

/// What a search gives back.
const FIND_OUTPUTS: &[(&str, &str)] = &[
    (
        "found",
        "The texts found, most alike first, each with its text, its similarity from -1 to 1, when it was kept as kept_at, and its entry_id.",
    ),
    ("found_count", "How many texts were found."),
];

/// The memory integration, installed under `memory`.
pub struct MemorySteps {
    profile: IntegrationProfile,
    operations: Vec<OperationSpec>,
    guides: Vec<OperationGuide>,
}

impl MemorySteps {
    /// The integration, its operations taking data up to `ceiling`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when an operation or a guide breaks a rule
    /// of the workflow domain, which a change here would cause.
    pub fn new(ceiling: DataClassLevel) -> Result<Self, DomainError> {
        let key = IntegrationKey::new(MEMORY_INTEGRATION)?;
        Ok(Self {
            profile: built_in_profile(&key, &PROFILE)?,
            operations: vec![
                operation(&key, REMEMBER, ActionClass::Write, ceiling)?,
                operation(&key, FIND_SIMILAR, ActionClass::Read, ceiling)?,
            ],
            guides: vec![remember_guide()?, find_guide()?],
        })
    }
}

#[async_trait]
impl Integration for MemorySteps {
    fn profile(&self) -> &IntegrationProfile {
        &self.profile
    }

    fn operations(&self) -> &[OperationSpec] {
        &self.operations
    }

    fn guides(&self) -> &[OperationGuide] {
        &self.guides
    }

    /// A memory keeps no account.
    async fn check_account(&self, _credential: &Secret) -> AccountCheck {
        AccountCheck::NotCheckable
    }

    async fn call(&self, _call: &ActionCall, _credential: Option<&Secret>) -> Called {
        failed("a memory step is run by the platform itself").into()
    }
}

/// The operation `name`, of `effect`, on the memory a step names.
fn operation(
    key: &IntegrationKey,
    name: &str,
    effect: ActionClass,
    ceiling: DataClassLevel,
) -> Result<OperationSpec, DomainError> {
    let mut inputs = vec![
        InputSpec::new(FieldName::new(MEMORY_INPUT)?, InputNeed::Required),
        InputSpec::new(FieldName::new(TEXT_INPUT)?, InputNeed::Required),
    ];
    if name == FIND_SIMILAR {
        inputs.push(InputSpec::new(
            FieldName::new(COUNT_INPUT)?,
            InputNeed::Optional,
        ));
    }
    OperationSpec::new(OperationSpecParams {
        integration: key.clone(),
        operation: OperationKey::new(name)?,
        inputs,
        effect: DeclaredAction::Declared(effect),
        account: AccountNeed::TenantMemory,
        ceiling,
    })
}

/// How the memory input is asked for.
fn memory_input() -> InputText<'static> {
    InputText {
        name: MEMORY_INPUT,
        meaning: "One of the company's memories.",
        suggested: Suggested::Text,
        form: FormText {
            label: Some("Memory"),
            ask: Ask::MemoryPicker,
            ..FormText::plain()
        },
    }
}

/// How keeping a text is explained.
fn remember_guide() -> Result<OperationGuide, DomainError> {
    guide(&GuideText {
        operation: REMEMBER,
        title: "Remember a text",
        description: "Keeps a text in a memory, such as a support ticket, so later steps can find it by what it means. It is kept until a person deletes the memory.",
        inputs: &[
            memory_input(),
            InputText {
                name: TEXT_INPUT,
                meaning: "The text to keep, up to 8,000 characters.",
                suggested: Suggested::Text,
                form: FormText {
                    label: Some("Text"),
                    ask: Ask::LongText,
                    ..FormText::plain()
                },
            },
        ],
        outputs: REMEMBER_OUTPUTS,
        preview: None,
    })
}

/// How a search is explained.
fn find_guide() -> Result<OperationGuide, DomainError> {
    guide(&GuideText {
        operation: FIND_SIMILAR,
        title: "Find similar texts",
        description: "Finds the texts of a memory most alike in meaning to a text, such as the past tickets closest to a new one.",
        inputs: &[
            memory_input(),
            InputText {
                name: TEXT_INPUT,
                meaning: "The text to compare with.",
                suggested: Suggested::Text,
                form: FormText {
                    label: Some("Text"),
                    ask: Ask::LongText,
                    ..FormText::plain()
                },
            },
            InputText {
                name: COUNT_INPUT,
                meaning: "How many texts to find, from 1 to 20; 3 when left out.",
                suggested: Suggested::Text,
                form: FormText {
                    group: FormGroup::MoreOptions,
                    ..FormText::plain()
                },
            },
        ],
        outputs: FIND_OUTPUTS,
        preview: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The memory integration offers keeping a text, which writes, and
    /// finding similar ones, which reads, each on a memory the step names
    /// and each explained by a guide.
    #[test]
    fn it_offers_remembering_and_finding() {
        let steps = MemorySteps::new(DataClassLevel::Confidential).unwrap();

        let named: Vec<_> = steps
            .operations()
            .iter()
            .map(|spec| (spec.operation().as_str(), spec.account()))
            .collect();

        assert_eq!(
            named,
            [
                (REMEMBER, AccountNeed::TenantMemory),
                (FIND_SIMILAR, AccountNeed::TenantMemory)
            ]
        );
        assert_eq!(steps.guides().len(), 2);
    }
}
