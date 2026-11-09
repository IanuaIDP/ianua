//! How a step the platform runs itself answers: its output as workflow
//! data, and why it failed or was turned away.

use ianua_domain::domains::workflows::data::{FieldName, FlowData};
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::UntrustedText;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Named values as workflow data.
pub(in crate::use_cases::workflows::executions) fn data(
    fields: Vec<(&str, Result<FlowData, DomainError>)>,
) -> Result<FlowData, ActionOutcome> {
    let unfit = || failed("the answer does not fit workflow data");
    let entries = fields
        .into_iter()
        .map(|(name, value)| {
            Ok((
                FieldName::new(name).map_err(|_| unfit())?,
                value.map_err(|_| unfit())?,
            ))
        })
        .collect::<Result<Vec<_>, ActionOutcome>>()?;
    FlowData::map(entries).map_err(|_| unfit())
}

/// `at` as RFC 3339 text, such as `2026-11-05T09:30:00Z`.
pub(in crate::use_cases::workflows::executions) fn moment_text(
    at: OffsetDateTime,
) -> Result<FlowData, DomainError> {
    at.format(&Rfc3339)
        .map_err(|_| DomainError::infra_msg("a time that cannot be written"))
        .and_then(FlowData::text)
}

/// A failure trying again would not change.
pub(in crate::use_cases::workflows::executions) fn failed(reason: &str) -> ActionOutcome {
    ActionOutcome::Failed(UntrustedText::record(reason))
}
