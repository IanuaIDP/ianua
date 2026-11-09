//! What a workflow knows of the integrations its steps use.
//!
//! It knows their names, the operations they offer and the inputs those
//! operations take. It never knows what an integration is or how it works.
//!
//! The integrations themselves live outside the domain. A spreadsheet, a
//! chat service, a phone line and a script runner are examples. Each
//! describes its operations as [`OperationSpec`]s. The application reads
//! them from a catalog to check a workflow before it runs. An adapter does
//! the work, through a port. Adding an integration means a new adapter and
//! new specs, never a change here.
//!
//! For the people building workflows, an integration also presents itself
//! with a [`profile`] and explains each operation with a [`guide`], whose
//! inputs are asked for with the building blocks of [`form`]; and
//! before an account is kept, the integration is asked whether its
//! credential works ([`account_check`]). An integration whose service
//! sends events describes the ones a workflow may start on ([`events`]).
//! A tenant may count an operation as riskier than its integration
//! declares ([`risk_override`]).

pub mod account_check;
pub mod company;
pub mod events;
pub mod form;
pub mod guide;
pub mod profile;
pub mod risk_override;

use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::workflows::data::FieldName;
use crate::domains::workflows::design::node::Mapping;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;
use crate::shared::validation::{Charset, TextValue, Validator, text_value};
use crate::types::{DeclaredAction, IntegrationAccountId};

/// The most inputs one operation may declare.
pub(crate) const MAX_OPERATION_INPUTS: usize = 64;

/// The input an operation acting as the run's person names what it reaches
/// with, by id: a route for a Protected apps step, a stream route for a
/// Protected data step. Its pass is made for that one alone.
pub const ROUTE_INPUT: &str = "route";

/// The input a memory operation names the tenant's memory it keeps texts
/// in or searches with, by id.
pub const MEMORY_INPUT: &str = "memory";

text_value! {
    /// The name an integration is registered under, such as `google-sheets`.
    pub struct IntegrationKey;
}

impl TextValue for IntegrationKey {
    const FIELD: &'static str = "integration";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .length(1..=64)
            .charset(Charset::LOWERCASE | Charset::DIGIT | Charset::HYPHEN)
    }
}

text_value! {
    /// The name of one operation an integration offers, such as `append-row`.
    pub struct OperationKey;
}

impl TextValue for OperationKey {
    const FIELD: &'static str = "operation";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .length(1..=64)
            .charset(Charset::LOWERCASE | Charset::DIGIT | Charset::HYPHEN)
    }
}

/// Whether an operation must be given an input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputNeed {
    /// It does not run without it.
    Required,
    /// It runs without it.
    Optional,
}

/// One input an operation declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputSpec {
    name: FieldName,
    need: InputNeed,
}

impl InputSpec {
    /// An input called `name`.
    #[must_use]
    pub fn new(name: FieldName, need: InputNeed) -> Self {
        Self { name, need }
    }

    /// The argument key required or accepted by the catalogue operation.
    #[must_use]
    pub fn name(&self) -> &FieldName {
        &self.name
    }

    /// Whether it must be given.
    #[must_use]
    pub fn need(&self) -> InputNeed {
        self.need
    }
}

/// Whether an operation acts through an account the tenant connected, such
/// as a spreadsheet account, or needs none, such as a sandboxed script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountNeed {
    /// It acts through one of the tenant's accounts for its integration.
    Account,
    /// It needs no account.
    NoAccount,
    /// It acts as the person the run acts for, through a pass made for the
    /// one call, as a Protected apps step calls a route behind the gateway.
    /// It names no account.
    RunPerson,
    /// It acts as the person the run acts for on a stream route opened to
    /// workflows, as a Protected data step reaches a database behind the
    /// gateway: through a connection the platform opens for the one call,
    /// signing in with the login the route keeps. It names no account.
    RunPersonData,
    /// It keeps texts in or searches one of the tenant's memories, named by
    /// its required `memory` input, through the memory's own embedding
    /// model. It names no account.
    TenantMemory,
    /// It acts on the tenant's own platform, run by the platform itself as
    /// the person the run acts for, with what they hold at that moment: the
    /// same action they could take from the dashboard. It names no account.
    Company,
}

/// The values an integration describes one of its operations with.
pub struct OperationSpecParams {
    /// The integration offering it.
    pub integration: IntegrationKey,
    /// The action key within this integration's catalogue namespace.
    pub operation: OperationKey,
    /// The inputs it takes.
    pub inputs: Vec<InputSpec>,
    /// What kind of action it is, such as reading, writing, sending or
    /// paying. An operation that cannot say, such as a script, is
    /// undeclared. It counts as the riskiest kind there is.
    pub effect: DeclaredAction,
    /// Whether it acts through an account.
    pub account: AccountNeed,
    /// The most sensitive data it may be handed. Data above it never
    /// reaches the integration. The step fails instead.
    pub ceiling: DataClassLevel,
}

/// How an integration describes one operation it offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationSpec {
    integration: IntegrationKey,
    operation: OperationKey,
    inputs: Vec<InputSpec>,
    effect: DeclaredAction,
    account: AccountNeed,
    ceiling: DataClassLevel,
}

impl OperationSpec {
    /// This operation as a tenant treats it, at least as risky as `effect`.
    ///
    /// `effect` only ever raises the class its integration declared. A
    /// tenant can mark an operation riskier, never safer.
    #[must_use]
    pub(super) fn at_least(&self, effect: DeclaredAction) -> Self {
        Self {
            effect: self.effect.stricter(effect),
            ..self.clone()
        }
    }

    /// An operation's description.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when it declares more than
    ///   `MAX_OPERATION_INPUTS` inputs.
    /// - [`DomainError::Validation`] when it declares one input twice.
    /// - [`DomainError::Validation`] when it acts as the run's person and
    ///   does not require a [`ROUTE_INPUT`].
    pub fn new(params: OperationSpecParams) -> Result<Self, DomainError> {
        validate_count(
            "operation_inputs",
            params.inputs.len(),
            0..=MAX_OPERATION_INPUTS,
        )?;
        if let Some(twice) = first_repeat(params.inputs.iter().map(InputSpec::name)) {
            return Err(DomainError::invalid(message!(
                "workflows-the-input-is-declared-twice",
                format!("the input {twice} is declared twice")
            )));
        }
        ensure_route_named(params.account, &params.inputs)?;
        ensure_memory_named(params.account, &params.inputs)?;
        Ok(Self {
            integration: params.integration,
            operation: params.operation,
            inputs: params.inputs,
            effect: params.effect,
            account: params.account,
            ceiling: params.ceiling,
        })
    }

    /// The most sensitive data it may be handed.
    #[must_use]
    pub fn ceiling(&self) -> DataClassLevel {
        self.ceiling
    }

    /// The integration offering it.
    #[must_use]
    pub fn integration(&self) -> &IntegrationKey {
        &self.integration
    }

    /// The action key used to resolve this specification within its integration.
    #[must_use]
    pub fn operation(&self) -> &OperationKey {
        &self.operation
    }

    /// The inputs it takes.
    #[must_use]
    pub fn inputs(&self) -> &[InputSpec] {
        &self.inputs
    }

    /// What kind of action it is.
    #[must_use]
    pub fn effect(&self) -> DeclaredAction {
        self.effect
    }

    /// Whether it acts through an account.
    #[must_use]
    pub fn account(&self) -> AccountNeed {
        self.account
    }
}

/// The account an action step acts through, or that it needs none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ActionAccount {
    /// Through this account of the tenant's.
    Account(IntegrationAccountId),
    /// Through none.
    NoAccount,
}

/// One use of an integration's operation: which one, through which account,
/// and how its inputs are built from the step's input.
///
/// It is built against the operation's [`OperationSpec`]. So a step never
/// maps an input the operation does not take, never leaves out one it
/// requires, and agrees with it about needing an account.
///
/// The spec's effect and data ceiling are kept with the step. So the kind
/// of action and what it may be handed stay as published, even if the
/// integration changes.
///
/// A stored step is read back as it was written. Whether it still fits its
/// operation is asked again at publish and before every call, against the
/// spec the integration declares then.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ActionStep {
    integration: IntegrationKey,
    operation: OperationKey,
    account: ActionAccount,
    inputs: Mapping,
    effect: DeclaredAction,
    ceiling: DataClassLevel,
}

impl ActionStep {
    /// A use of `spec`'s operation.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `inputs` maps a field the
    ///   operation does not take.
    /// - [`DomainError::Validation`] when `inputs` leaves out a field the
    ///   operation requires.
    /// - [`DomainError::Validation`] when `account` disagrees with whether
    ///   the operation acts through one.
    pub fn new(
        spec: &OperationSpec,
        account: ActionAccount,
        inputs: Mapping,
    ) -> Result<Self, DomainError> {
        let step = Self {
            integration: spec.integration.clone(),
            operation: spec.operation.clone(),
            account,
            inputs,
            effect: spec.effect,
            ceiling: spec.ceiling,
        };
        step.ensure_fits(spec)?;
        Ok(step)
    }

    /// Checks a step against the current operation catalogue when publishing.
    ///
    /// # Errors
    /// [`DomainError::Validation`] at the first mismatch: operation identity, action kind,
    /// a lower ceiling, changed account authority, extra mapped inputs or missing required inputs.
    pub fn ensure_fits(&self, spec: &OperationSpec) -> Result<(), DomainError> {
        self.ensure_same_operation(spec)?;
        self.ensure_effect_and_ceiling_fit(spec)?;
        self.ensure_account_fits(spec)?;
        self.ensure_inputs_fit(spec)
    }

    fn ensure_same_operation(&self, spec: &OperationSpec) -> Result<(), DomainError> {
        if self.integration != spec.integration || self.operation != spec.operation {
            return Err(DomainError::invalid(message!(
                "workflows-the-step-uses-not",
                format!(
                    "the step uses {}.{}, not {}.{}",
                    self.integration, self.operation, spec.integration, spec.operation
                )
            )));
        }
        Ok(())
    }

    fn ensure_effect_and_ceiling_fit(&self, spec: &OperationSpec) -> Result<(), DomainError> {
        if self.effect != spec.effect {
            return Err(DomainError::invalid(message!(
                "workflows-is-now-a-action-not-a",
                format!(
                    "{}.{} is now a {} action, not a {} one",
                    spec.integration,
                    spec.operation,
                    spec.effect.as_str(),
                    self.effect.as_str()
                )
            )));
        }
        if spec.ceiling < self.ceiling {
            return Err(DomainError::invalid(message!(
                "workflows-now-takes-data-up-to-not",
                format!(
                    "{}.{} now takes data up to {}, not {}",
                    spec.integration,
                    spec.operation,
                    spec.ceiling.as_str(),
                    self.ceiling.as_str()
                )
            )));
        }
        Ok(())
    }

    fn ensure_account_fits(&self, spec: &OperationSpec) -> Result<(), DomainError> {
        match (spec.account, self.account) {
            (AccountNeed::Account, ActionAccount::Account(_))
            | (
                AccountNeed::NoAccount
                | AccountNeed::RunPerson
                | AccountNeed::RunPersonData
                | AccountNeed::TenantMemory
                | AccountNeed::Company,
                ActionAccount::NoAccount,
            ) => Ok(()),
            (AccountNeed::Account, ActionAccount::NoAccount) => Err(names_no_account(spec)),
            (
                AccountNeed::NoAccount
                | AccountNeed::RunPerson
                | AccountNeed::RunPersonData
                | AccountNeed::TenantMemory
                | AccountNeed::Company,
                ActionAccount::Account(_),
            ) => Err(names_an_account(spec)),
        }
    }

    fn ensure_inputs_fit(&self, spec: &OperationSpec) -> Result<(), DomainError> {
        let mapped = || self.inputs.fields().iter().map(|(name, _)| name);
        if let Some(unknown) =
            mapped().find(|name| !spec.inputs.iter().any(|input| &input.name == *name))
        {
            return Err(DomainError::invalid(message!(
                "workflows-takes-no-input",
                format!(
                    "{}.{} takes no input {unknown}",
                    spec.integration, spec.operation
                )
            )));
        }
        let missing = spec
            .inputs
            .iter()
            .filter(|input| input.need == InputNeed::Required)
            .find(|input| !mapped().any(|name| name == &input.name));
        let Some(missing) = missing else {
            return Ok(());
        };
        Err(DomainError::invalid(message!(
            "workflows-requires-the-input",
            format!(
                "{}.{} requires the input {}",
                spec.integration, spec.operation, missing.name
            )
        )))
    }

    /// The integration it uses.
    #[must_use]
    pub fn integration(&self) -> &IntegrationKey {
        &self.integration
    }

    /// The operation it calls.
    #[must_use]
    pub fn operation(&self) -> &OperationKey {
        &self.operation
    }

    /// The account it acts through.
    #[must_use]
    pub fn account(&self) -> ActionAccount {
        self.account
    }

    /// How its inputs are built.
    #[must_use]
    pub fn inputs(&self) -> &Mapping {
        &self.inputs
    }

    /// What kind of action it is.
    #[must_use]
    pub fn effect(&self) -> DeclaredAction {
        self.effect
    }

    /// The most sensitive data it may be handed.
    #[must_use]
    pub fn ceiling(&self) -> DataClassLevel {
        self.ceiling
    }
}

/// Refuses an operation acting as the run's person that does not require
/// the route it reaches: a pass names one route, never whichever the step
/// happens to call.
fn ensure_route_named(account: AccountNeed, inputs: &[InputSpec]) -> Result<(), DomainError> {
    if !matches!(account, AccountNeed::RunPerson | AccountNeed::RunPersonData) {
        return Ok(());
    }
    let named = inputs
        .iter()
        .any(|input| input.name().as_str() == ROUTE_INPUT && input.need() == InputNeed::Required);
    if named {
        return Ok(());
    }
    Err(DomainError::invalid(message!(
        "workflows-an-operation-acting-as-the-run-s-person-names-its-route",
        "an operation acting as the run's person must require the route it reaches"
    )))
}

/// Refuses a memory operation that does not require the memory it
/// reaches: a step reaches the one memory it names, checked before the
/// call.
fn ensure_memory_named(account: AccountNeed, inputs: &[InputSpec]) -> Result<(), DomainError> {
    if account != AccountNeed::TenantMemory {
        return Ok(());
    }
    let named = inputs
        .iter()
        .any(|input| input.name().as_str() == MEMORY_INPUT && input.need() == InputNeed::Required);
    if named {
        return Ok(());
    }
    Err(DomainError::invalid(message!(
        "workflows-a-memory-operation-names-its-memory",
        "a memory operation must require the memory it reaches"
    )))
}

/// The refusal of a step naming no account for `spec`, which acts through
/// one.
fn names_no_account(spec: &OperationSpec) -> DomainError {
    DomainError::invalid(message!(
        "workflows-acts-through-an-account-and-the",
        format!(
            "{}.{} acts through an account, and the step names none",
            spec.integration, spec.operation
        )
    ))
}

/// The refusal of a step naming an account for `spec`, which needs none.
fn names_an_account(spec: &OperationSpec) -> DomainError {
    DomainError::invalid(message!(
        "workflows-needs-no-account-and-the-step",
        format!(
            "{}.{} needs no account, and the step names one",
            spec.integration, spec.operation
        )
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::workflows::data::{DataPath, FlowData};
    use crate::domains::workflows::design::node::Source;
    use crate::types::ActionClass;

    fn field(name: &str) -> FieldName {
        FieldName::new(name).unwrap()
    }

    fn append_row() -> OperationSpec {
        OperationSpec::new(OperationSpecParams {
            integration: IntegrationKey::new("google-sheets").unwrap(),
            operation: OperationKey::new("append-row").unwrap(),
            inputs: vec![
                InputSpec::new(field("sheet"), InputNeed::Required),
                InputSpec::new(field("values"), InputNeed::Required),
                InputSpec::new(field("note"), InputNeed::Optional),
            ],
            effect: DeclaredAction::Declared(ActionClass::Write),
            account: AccountNeed::Account,
            ceiling: DataClassLevel::Confidential,
        })
        .unwrap()
    }

    fn mapping(names: &[&str]) -> Mapping {
        Mapping::new(
            names
                .iter()
                .map(|name| (field(name), Source::Literal(FlowData::text("x").unwrap())))
                .collect(),
        )
        .unwrap()
    }

    fn account() -> ActionAccount {
        ActionAccount::Account(IntegrationAccountId::new())
    }

    /// A step for "append row" maps the required `sheet` and `values` and
    /// skips the optional `note`. It is accepted, keeps the write class and
    /// still fits the spec.
    #[test]
    fn a_step_mapping_every_required_input_fits() {
        let step =
            ActionStep::new(&append_row(), account(), mapping(&["sheet", "values"])).unwrap();

        assert_eq!(step.effect(), DeclaredAction::Declared(ActionClass::Write));
        assert!(step.ensure_fits(&append_row()).is_ok());
    }

    /// A step that maps only `sheet` is refused, since `values` is
    /// required. A step that also maps `colour`, which the operation does
    /// not take, is refused too.
    #[test]
    fn a_step_leaving_out_a_required_input_or_mapping_an_unknown_one_is_refused() {
        assert!(ActionStep::new(&append_row(), account(), mapping(&["sheet"])).is_err());
        assert!(
            ActionStep::new(
                &append_row(),
                account(),
                mapping(&["sheet", "values", "colour"])
            )
            .is_err()
        );
    }

    /// "Append row" acts through an account. A step that names no account
    /// is refused.
    #[test]
    fn a_step_must_agree_with_the_operation_about_an_account() {
        let inputs = mapping(&["sheet", "values"]);

        assert!(ActionStep::new(&append_row(), ActionAccount::NoAccount, inputs).is_err());
    }

    /// A step created for a write operation fails validation against a
    /// specification that changes the same operation to financial.
    #[test]
    fn a_step_no_longer_fits_an_operation_whose_effect_changed() {
        let step =
            ActionStep::new(&append_row(), account(), mapping(&["sheet", "values"])).unwrap();
        let now_financial = OperationSpec::new(OperationSpecParams {
            integration: IntegrationKey::new("google-sheets").unwrap(),
            operation: OperationKey::new("append-row").unwrap(),
            inputs: append_row().inputs().to_vec(),
            effect: DeclaredAction::Declared(ActionClass::Financial),
            account: AccountNeed::Account,
            ceiling: DataClassLevel::Confidential,
        })
        .unwrap();

        assert!(step.ensure_fits(&now_financial).is_err());
    }

    /// Slack's "send message" declares `text` twice, once required and once
    /// optional. The spec is refused.
    #[test]
    fn a_spec_declaring_an_input_twice_is_refused() {
        let twice = OperationSpec::new(OperationSpecParams {
            integration: IntegrationKey::new("slack").unwrap(),
            operation: OperationKey::new("send-message").unwrap(),
            inputs: vec![
                InputSpec::new(field("text"), InputNeed::Required),
                InputSpec::new(field("text"), InputNeed::Optional),
            ],
            effect: DeclaredAction::Declared(ActionClass::Communicate),
            account: AccountNeed::Account,
            ceiling: DataClassLevel::Internal,
        });

        assert!(twice.is_err());
    }

    /// A Protected apps call acting as the run's person names the route it
    /// reaches; one that left the route to the path it calls is refused.
    #[test]
    fn a_spec_acting_as_the_run_s_person_requires_its_route() {
        let spec = |inputs: Vec<InputSpec>| {
            OperationSpec::new(OperationSpecParams {
                integration: IntegrationKey::new("apps").unwrap(),
                operation: OperationKey::new("get").unwrap(),
                inputs,
                effect: DeclaredAction::Declared(ActionClass::Read),
                account: AccountNeed::RunPerson,
                ceiling: DataClassLevel::Internal,
            })
        };

        let named = spec(vec![
            InputSpec::new(field(ROUTE_INPUT), InputNeed::Required),
            InputSpec::new(field("path"), InputNeed::Required),
        ]);
        let optional = spec(vec![InputSpec::new(
            field(ROUTE_INPUT),
            InputNeed::Optional,
        )]);
        let unnamed = spec(vec![InputSpec::new(field("path"), InputNeed::Required)]);

        assert!(named.is_ok());
        assert!(optional.is_err());
        assert!(unnamed.is_err());
    }

    /// A Protected data query acting as the run's person names the stream
    /// route it reaches; one that left it out is refused.
    #[test]
    fn a_data_spec_acting_as_the_run_s_person_requires_its_route() {
        let spec = |inputs: Vec<InputSpec>| {
            OperationSpec::new(OperationSpecParams {
                integration: IntegrationKey::new("postgres").unwrap(),
                operation: OperationKey::new("query").unwrap(),
                inputs,
                effect: DeclaredAction::Declared(ActionClass::Read),
                account: AccountNeed::RunPersonData,
                ceiling: DataClassLevel::Internal,
            })
        };

        let named = spec(vec![
            InputSpec::new(field(ROUTE_INPUT), InputNeed::Required),
            InputSpec::new(field("statement"), InputNeed::Required),
        ]);
        let unnamed = spec(vec![InputSpec::new(
            field("statement"),
            InputNeed::Required,
        )]);

        assert!(named.is_ok());
        assert!(unnamed.is_err());
    }

    /// A memory search names the memory it reaches; one that left it out,
    /// or only offers it, is refused.
    #[test]
    fn a_memory_spec_requires_its_memory() {
        let spec = |memory: InputNeed| {
            OperationSpec::new(OperationSpecParams {
                integration: IntegrationKey::new("memory").unwrap(),
                operation: OperationKey::new("find-similar").unwrap(),
                inputs: vec![
                    InputSpec::new(field(MEMORY_INPUT), memory),
                    InputSpec::new(field("text"), InputNeed::Required),
                ],
                effect: DeclaredAction::Declared(ActionClass::Read),
                account: AccountNeed::TenantMemory,
                ceiling: DataClassLevel::Internal,
            })
        };

        assert!(spec(InputNeed::Required).is_ok());
        assert!(spec(InputNeed::Optional).is_err());
    }

    /// A step fills `sheet` and `values` from paths into the trigger's data
    /// instead of fixed values. They count as mapped and the step is
    /// accepted.
    #[test]
    fn a_path_input_counts_as_mapped() {
        let inputs = Mapping::new(vec![
            (
                field("sheet"),
                Source::Input(DataPath::parse("trigger.sheet").unwrap()),
            ),
            (
                field("values"),
                Source::Input(DataPath::parse("trigger.row").unwrap()),
            ),
        ])
        .unwrap();

        assert!(ActionStep::new(&append_row(), account(), inputs).is_ok());
    }
}
