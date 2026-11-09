//! The calls one repository read or push makes through its account, one
//! after another: each an operation of the account's installed integration,
//! made by the action runner, and a credential the service renews on one
//! call handed on to the next.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ianua_app::ports::workflows::{
    ActionRunner as _, CallCredential, Renewal, RepositoryAccount, RepositoryRefusal,
};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::data::{DataPath, FieldName, FlowData, FlowValue};
use ianua_domain::domains::workflows::execution::ActionCall;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::domains::workflows::integration::{ActionAccount, IntegrationKey, OperationKey};
use ianua_domain::shared::events::chain::EventOrigin;
use ianua_domain::types::{ActionCallId, ActionClass, DeclaredAction, UntrustedText};
use ianua_integration::answer::refused_status;

use crate::integrations::runner::InstalledActionRunner;

/// One operation's call: its key, what kind of action it is, and its
/// inputs by name.
pub(super) struct Step {
    /// The operation, such as `get-file`.
    pub(super) operation: &'static str,
    /// Whether it reads or writes.
    pub(super) class: ActionClass,
    /// Named arguments converted into workflow data for the action runner.
    pub(super) inputs: Vec<Input>,
}

/// One input of a step: its name and its text.
pub(super) struct Input {
    /// Its name, such as `path`.
    pub(super) name: &'static str,
    /// Its text.
    pub(super) value: String,
}

impl Input {
    /// The input `name` holding `value`.
    pub(super) fn new(name: &'static str, value: impl Into<String>) -> Self {
        Self {
            name,
            value: value.into(),
        }
    }
}

/// Calls made through one account of one integration.
pub(super) struct Calls<'a> {
    runner: &'a InstalledActionRunner,
    tenant: &'a ScopedTenant,
    integration: &'a IntegrationKey,
    account: RepositoryAccount,
    renewal: Renewal,
}

impl<'a> Calls<'a> {
    /// Calls through `account` of `integration`, for `tenant`.
    pub(super) fn new(
        runner: &'a InstalledActionRunner,
        tenant: &'a ScopedTenant,
        integration: &'a IntegrationKey,
        account: &RepositoryAccount,
    ) -> Self {
        Self {
            runner,
            tenant,
            integration,
            account: account.clone(),
            renewal: Renewal::Unchanged,
        }
    }

    /// What `step` answered with as JSON, or why it was refused.
    ///
    /// # Errors
    ///
    /// - [`RepositoryRefusal::NotFound`] when the service answered 404.
    /// - [`RepositoryRefusal::Refused`] for any other refusal.
    /// - [`RepositoryRefusal::Unreachable`] when it turned the call away.
    pub(super) async fn answer(&mut self, step: Step) -> Result<FlowData, RepositoryRefusal> {
        let call = self.call_of(step)?;
        let run = self
            .runner
            .run(
                self.tenant,
                &call,
                CallCredential::Account(&self.account.credential),
            )
            .await;
        if let Renewal::Renewed(renewed) = run.renewal {
            self.account.credential.secret = renewed.clone();
            self.renewal = Renewal::Renewed(renewed);
        }
        match run.outcome {
            ActionOutcome::Succeeded { output, .. } => {
                Ok(at(&output, "json").cloned().unwrap_or_else(FlowData::null))
            }
            ActionOutcome::Failed(reason) => Err(refusal_of(reason)),
            ActionOutcome::TurnedAway(reason) => Err(RepositoryRefusal::Unreachable(reason)),
            ActionOutcome::NotYet { .. } => Err(RepositoryRefusal::Unreachable(
                UntrustedText::record("the service gave no answer yet"),
            )),
        }
    }

    /// The credential the service last renewed on the way, if any.
    pub(super) fn renewal(self) -> Renewal {
        self.renewal
    }

    /// The action call `step` makes.
    fn call_of(&self, step: Step) -> Result<ActionCall, RepositoryRefusal> {
        let entries = step
            .inputs
            .into_iter()
            .map(|input| {
                let name = FieldName::new(input.name).map_err(|_| unbuilt())?;
                let value = FlowData::text(input.value).map_err(|_| unbuilt())?;
                Ok((name, value))
            })
            .collect::<Result<Vec<_>, RepositoryRefusal>>()?;
        Ok(ActionCall {
            call_id: ActionCallId::new(),
            integration: self.integration.clone(),
            operation: OperationKey::new(step.operation).map_err(|_| unbuilt())?,
            account: ActionAccount::Account(self.account.id),
            arguments: FlowData::map(entries).map_err(|_| unbuilt())?,
            effect: DeclaredAction::Declared(step.class),
            exposure: DataClassLevel::Internal,
            origin: EventOrigin::Outside,
        })
    }
}

/// The text at `path` of `answer`, such as `sha` or `commit.sha`.
pub(super) fn text_at<'v>(answer: &'v FlowData, path: &str) -> Option<&'v str> {
    match at(answer, path)?.value() {
        FlowValue::Text(text) => Some(text),
        FlowValue::Null
        | FlowValue::Bool(_)
        | FlowValue::Number(_)
        | FlowValue::List(_)
        | FlowValue::Map(_) => None,
    }
}

/// A refusal for an answer that is not what the service promised.
pub(super) fn unexpected(what: &str) -> RepositoryRefusal {
    RepositoryRefusal::Refused(UntrustedText::record(what))
}

/// A file's contents as a service gives them, base64 that may be broken
/// over lines, as text.
///
/// # Errors
///
/// [`RepositoryRefusal::Refused`] when it is not base64, or not text.
pub(super) fn decoded(encoded: &str) -> Result<String, RepositoryRefusal> {
    let joined: String = encoded.split_whitespace().collect();
    let bytes = STANDARD
        .decode(joined)
        .map_err(|_| unexpected("the file is not readable base64"))?;
    String::from_utf8(bytes).map_err(|_| unexpected("the file is not text"))
}

/// The value at the dotted `path` of `data`.
fn at<'v>(data: &'v FlowData, path: &str) -> Option<&'v FlowData> {
    data.at(&DataPath::parse(path).ok()?)
}

/// A call this adapter could not build: an input larger than workflow
/// data may be, since its fixed names are always valid.
fn unbuilt() -> RepositoryRefusal {
    unexpected("the repository call could not be built")
}

/// The refusal a failed call's `reason` says.
fn refusal_of(reason: UntrustedText) -> RepositoryRefusal {
    match refused_status(&reason) {
        Some(404) => RepositoryRefusal::NotFound,
        _ => RepositoryRefusal::Refused(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GitHub breaks a file's base64 every 60 characters. The lines are
    /// joined before it is read, so the text comes back whole.
    #[test]
    fn a_file_broken_over_lines_reads_whole() {
        let encoded = "ZGVmIG1haW4oaW5wdXQpOgogICAg\ncmV0dXJuIGlucHV0Cg==\n";

        let text = decoded(encoded).unwrap();

        assert_eq!(text, "def main(input):\n    return input\n");
    }

    /// Base64 containing invalid UTF-8 is refused as a repository text file.
    #[test]
    fn a_file_that_is_not_text_is_refused() {
        let encoded = STANDARD.encode([0xff, 0xfe, 0x00]);

        let read = decoded(&encoded);

        assert!(matches!(read, Err(RepositoryRefusal::Refused(_))));
    }

    /// A 404 is a file or branch that is not there; any other refusal is
    /// the service's.
    #[test]
    fn only_a_404_reads_as_not_found() {
        let missing = refusal_of(UntrustedText::record("the address answered 404"));
        let refused = refusal_of(UntrustedText::record("the address answered 403"));

        assert!(matches!(missing, RepositoryRefusal::NotFound));
        assert!(matches!(refused, RepositoryRefusal::Refused(_)));
    }
}
