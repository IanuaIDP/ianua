//! List choices: the options a picker in a step's form offers, filled live
//! by its integration's read operation through the builder's account, such
//! as Acme's GitHub repositories or the labels of one of them.
//!
//! Opening a form never acts. The picker's operation must be one its
//! integration declares as a read, checked again here before every call,
//! so a picker cannot be pointed at an operation that writes. Only the
//! account's owner, or someone who may connect accounts, fills a picker
//! through it; anyone else types the value. A credential the service
//! renewed on the way is kept, as after any call.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::account::IntegrationAccount;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::data::{DataPath, FieldName, FlowData, FlowValue};
use ianua_domain::domains::workflows::execution::ActionCall;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::domains::workflows::integration::form::Picker;
use ianua_domain::domains::workflows::integration::{ActionAccount, IntegrationKey, OperationKey};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::chain::EventOrigin;
use ianua_domain::types::{
    ActionCallId, ActionClass, DeclaredAction, IntegrationAccountId, UntrustedText,
};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authentication::SealedAt;
use crate::ports::runtime::UnitOfWork;
use crate::ports::workflows::{
    ActionRun, ActionRunner, CallCredential, IntegrationAccountStore, IntegrationCatalog, Renewal,
};
use crate::services::account_grants::{AccountGrants, GrantHolder};
use crate::services::renewals::Renewing;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::workflows::accounts::connect::integration_credential_place;
use crate::use_cases::workflows::lookup::owned_account;

/// The most options one picker offers. A longer list is cut, and the
/// builder types the value instead.
pub const MAX_CHOICES: usize = 200;

/// Which picker to fill, through which account, and the values of the
/// inputs it depends on.
pub struct ListChoicesRequest {
    /// The integration of the step.
    pub integration: IntegrationKey,
    /// The step's operation.
    pub operation: OperationKey,
    /// The input whose picker is filled.
    pub input: FieldName,
    /// The account the read goes through.
    pub account: IntegrationAccountId,
    /// The value of the input the picker depends on, when it depends on
    /// one, such as the chosen repository.
    pub depends_on: Option<FlowData>,
}

/// One option a picker offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    /// What the input is set to when it is picked.
    pub value: String,
    /// How it is shown.
    pub label: String,
}

/// The options a picker offers, or why it offers none.
#[derive(Debug, Clone, PartialEq)]
pub enum Choices {
    /// These options, at most [`MAX_CHOICES`].
    Listed(Vec<Choice>),
    /// The service did not answer with a list: the builder types the value.
    /// This is what it said.
    Unavailable(UntrustedText),
}

/// The ports [`ListChoicesUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListChoicesPorts {
    /// The operations and forms the integrations declare.
    pub catalog: Arc<dyn IntegrationCatalog>,
    /// The tenant's integration accounts.
    pub accounts: Arc<dyn IntegrationAccountStore>,
    /// Makes the read through the account.
    pub action_runner: Arc<dyn ActionRunner>,
    /// Keeps the account's short-lived token good just before the read.
    pub grants: Arc<AccountGrants>,
    /// Keeps a renewed credential with its record together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Fills a step form's pickers.
pub struct ListChoicesUseCase {
    ports: ListChoicesPorts,
}

impl ListChoicesUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ListChoicesPorts) -> Self {
        Self { ports }
    }

    /// The picker the form of `request`'s input is drawn with.
    async fn picker_of(&self, request: &ListChoicesRequest) -> Result<Picker, AppError> {
        let guides = self
            .ports
            .catalog
            .guides(&request.integration)
            .await
            .or_internal()?;
        guides
            .iter()
            .find(|guide| guide.operation() == &request.operation)
            .and_then(|guide| guide.input(&request.input))
            .and_then(|note| note.form().block().picker().cloned())
            .or_not_found(message!("workflows-picker", "picker"))
    }

    /// Refuses `picker` unless its integration declares its operation as a
    /// read now.
    async fn ensure_reads(
        &self,
        integration: &IntegrationKey,
        picker: &Picker,
    ) -> Result<(), AppError> {
        let offered = self
            .ports
            .catalog
            .offered(integration)
            .await
            .or_internal()?;
        let reads = offered.iter().any(|spec| {
            spec.operation() == picker.filled_by()
                && spec.effect() == DeclaredAction::Declared(ActionClass::Read)
        });
        if reads {
            return Ok(());
        }
        Err(AppError::Forbidden(message!(
            "workflows-a-picker-is-filled-only-by-a-read",
            "a picker is filled only by an operation that reads"
        )))
    }

    /// `call` made through `account`'s credential, sealed where the account
    /// keeps it.
    async fn called(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        call: &ActionCall,
        account: &IntegrationAccount<ResolvedTenant>,
    ) -> ActionRun {
        let read = SealedAt {
            secret: account.credential().clone(),
            place: integration_credential_place(tenant, account.id()),
        };
        let holder = GrantHolder {
            id: account.id(),
            integration: account.integration(),
            credential: &read,
        };
        let credential = match self.ports.grants.current(tenant, auditor, holder).await {
            Ok(credential) => credential,
            Err(outcome) => {
                return ActionRun {
                    outcome,
                    renewal: Renewal::Unchanged,
                };
            }
        };
        self.ports
            .action_runner
            .run(tenant, call, CallCredential::Account(&credential))
            .await
    }
}

impl Command for ListChoicesUseCase {
    type Caller = CallerContext;
    type Input = ListChoicesRequest;
    type Output = Result<Choices, AppError>;

    /// The options the picker `request` names offers now, read through its
    /// account for the person `ctx` names.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not edit workflows, or
    ///   the picker's operation does not read.
    /// - `AppError::NotFound` when the input has no picker, or the account
    ///   is not the caller's to use.
    /// - `AppError::Internal` when a store, the catalog or the audit trail
    ///   fails.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: ListChoicesRequest,
    ) -> Result<Choices, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        control
            .ensure_may(WorkflowAction::Update)
            .map_err(AppError::from_domain)?;
        let picker = self.picker_of(&request).await?;
        self.ensure_reads(&request.integration, &picker).await?;
        let account = owned_account(
            self.ports.accounts.as_ref(),
            &ctx.tenant(),
            &request.account,
            &control,
        )
        .await?;
        let call = read_call(&request, &picker)?;
        let ran = self.called(&ctx.tenant(), auditor, &call, &account).await;
        Renewing {
            accounts: self.ports.accounts.as_ref(),
            unit_of_work: self.ports.unit_of_work.as_ref(),
        }
        .keep(ctx, auditor, &request.account, ran.renewal)
        .await?;
        Ok(choices_from(&picker, ran.outcome))
    }
}

/// The read `picker` makes, given the value it depends on.
fn read_call(request: &ListChoicesRequest, picker: &Picker) -> Result<ActionCall, AppError> {
    let arguments = match (picker.depends_on(), &request.depends_on) {
        (Some(field), Some(value)) => FlowData::map(vec![(field.clone(), value.clone())]),
        (Some(_) | None, _) => FlowData::map(Vec::new()),
    }
    .map_err(AppError::from_domain)?;
    Ok(ActionCall {
        call_id: ActionCallId::new(),
        integration: request.integration.clone(),
        operation: picker.filled_by().clone(),
        account: ActionAccount::Account(request.account),
        arguments,
        effect: DeclaredAction::Declared(ActionClass::Read),
        exposure: DataClassLevel::Internal,
        origin: EventOrigin::Outside,
    })
}

/// The options `picker` reads from what its operation gave back.
fn choices_from(picker: &Picker, outcome: ActionOutcome) -> Choices {
    let output = match outcome {
        ActionOutcome::Succeeded { output, .. } => output,
        ActionOutcome::Failed(why) | ActionOutcome::TurnedAway(why) => {
            return Choices::Unavailable(why);
        }
        ActionOutcome::NotYet { .. } => {
            return Choices::Unavailable(UntrustedText::record("the operation gave no list yet"));
        }
    };
    let Some(FlowValue::List(items)) = output.at(picker.items_at()).map(FlowData::value) else {
        return Choices::Unavailable(UntrustedText::record(
            "the service did not answer with a list",
        ));
    };
    let listed = items
        .iter()
        .filter_map(|item| {
            let value = text_at(item, picker.value_at())?;
            let label = text_at(item, picker.label_at()).unwrap_or_else(|| value.clone());
            Some(Choice { value, label })
        })
        .take(MAX_CHOICES)
        .collect();
    Choices::Listed(listed)
}

/// The text at `path` in `item`, a number written out, or `None`.
fn text_at(item: &FlowData, path: &DataPath) -> Option<String> {
    match item.at(path)?.value() {
        FlowValue::Text(text) => Some(text.to_owned()),
        FlowValue::Number(number) => Some(number.to_string()),
        FlowValue::Null | FlowValue::Bool(_) | FlowValue::List(_) | FlowValue::Map(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::integration::form::PickerParams;

    use super::*;

    fn field(name: &str) -> FieldName {
        FieldName::new(name).unwrap()
    }

    fn repositories() -> Picker {
        Picker::new(PickerParams {
            filled_by: OperationKey::new("list-repositories").unwrap(),
            items_at: DataPath::parse("json").unwrap(),
            value_at: DataPath::parse("full_name").unwrap(),
            label_at: DataPath::parse("full_name").unwrap(),
            depends_on: None,
        })
    }

    fn repo(name: &str) -> FlowData {
        FlowData::map(vec![(field("full_name"), FlowData::text(name).unwrap())]).unwrap()
    }

    /// GitHub answers with two repositories. The picker offers both, by
    /// their full names.
    #[test]
    fn a_listed_answer_becomes_the_options() {
        let output = FlowData::map(vec![(
            field("json"),
            FlowData::list(vec![repo("acme/web"), repo("acme/api")]).unwrap(),
        )])
        .unwrap();

        let choices = choices_from(
            &repositories(),
            ActionOutcome::Succeeded {
                output,
                exposure: DataClassLevel::Internal,
            },
        );

        let Choices::Listed(listed) = choices else {
            panic!("the answer was a list");
        };
        let values: Vec<&str> = listed.iter().map(|choice| choice.value.as_str()).collect();
        assert_eq!(values, ["acme/web", "acme/api"]);
    }

    /// A refused action makes the picker's choices unavailable.
    #[test]
    fn a_failed_read_offers_nothing() {
        let choices = choices_from(
            &repositories(),
            ActionOutcome::TurnedAway(UntrustedText::record("rate limited")),
        );

        assert!(matches!(choices, Choices::Unavailable(_)));
    }
}
