//! The events an integration's service can start a workflow on, such as
//! GitHub's "an issue was opened", and how each is explained to the people
//! building workflows.
//!
//! An integration describes each event it offers as a [`ServiceEventSpec`]:
//! its key and the filters it takes, such as the repository it watches.
//! A workflow's [`ServiceTrigger`](crate::domains::workflows::triggers::ServiceTrigger)
//! is built against the spec, so it never names a filter the event does not
//! take or leaves out one it requires. A [`ServiceEventGuide`] only
//! explains, as an operation's guide does.

use crate::domains::workflows::data::FieldName;
use crate::domains::workflows::integration::guide::{InputNote, OutputNote};
use crate::domains::workflows::integration::{InputSpec, IntegrationKey};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;
use crate::shared::validation::{Charset, TextValue, Validator, text_value};
use crate::types::{Label, Text};

/// The most filters one event may take.
pub(crate) const MAX_EVENT_FILTERS: usize = 16;

text_value! {
    /// The name of one event an integration's service sends, such as
    /// `issue-opened`.
    pub struct ServiceEventKey;
}

impl TextValue for ServiceEventKey {
    const FIELD: &'static str = "event";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .length(1..=64)
            .charset(Charset::LOWERCASE | Charset::DIGIT | Charset::HYPHEN)
    }
}

/// How an integration describes one event its service sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceEventSpec {
    integration: IntegrationKey,
    event: ServiceEventKey,
    filters: Vec<InputSpec>,
}

impl ServiceEventSpec {
    /// The event `event` of `integration`, taking `filters`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when it takes more than
    ///   `MAX_EVENT_FILTERS` filters, or one filter twice.
    pub fn new(
        integration: IntegrationKey,
        event: ServiceEventKey,
        filters: Vec<InputSpec>,
    ) -> Result<Self, DomainError> {
        validate_count("event_filters", filters.len(), 0..=MAX_EVENT_FILTERS)?;
        if let Some(twice) = first_repeat(filters.iter().map(InputSpec::name)) {
            return Err(DomainError::invalid(message!(
                "workflows-the-event-filter-is-declared-twice",
                format!("the filter {twice} is declared twice")
            )));
        }
        Ok(Self {
            integration,
            event,
            filters,
        })
    }

    /// The integration whose service sends it.
    #[must_use]
    pub fn integration(&self) -> &IntegrationKey {
        &self.integration
    }

    /// The service occurrence whose schema and filters this specification describes.
    #[must_use]
    pub fn event(&self) -> &ServiceEventKey {
        &self.event
    }

    /// The filters it takes.
    #[must_use]
    pub fn filters(&self) -> &[InputSpec] {
        &self.filters
    }
}

/// The values an event is explained with.
pub struct ServiceEventGuideParams {
    /// The event explained.
    pub event: ServiceEventKey,
    /// Its name for people, such as "An issue is opened".
    pub title: Label,
    /// When it happens, in a sentence or two.
    pub description: Text,
    /// What each filter means, one note per filter the event takes.
    pub filters: Vec<InputNote>,
    /// The values it gives the workflow it starts.
    pub outputs: Vec<OutputNote>,
}

/// How an event is explained.
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceEventGuide {
    event: ServiceEventKey,
    title: Label,
    description: Text,
    filters: Vec<InputNote>,
    outputs: Vec<OutputNote>,
}

impl ServiceEventGuide {
    /// The guide `params` describe.
    #[must_use]
    pub fn new(params: ServiceEventGuideParams) -> Self {
        Self {
            event: params.event,
            title: params.title,
            description: params.description,
            filters: params.filters,
            outputs: params.outputs,
        }
    }

    /// Refuses this guide unless it explains `spec`: the same event, and
    /// exactly the filters it takes.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when it explains another event, or
    ///   other filters than the event takes.
    pub fn ensure_explains(&self, spec: &ServiceEventSpec) -> Result<(), DomainError> {
        if &self.event != spec.event() {
            return Err(DomainError::invalid(message!(
                "workflows-the-guide-explains-another-event",
                format!(
                    "the guide explains the event {}, not {}",
                    self.event,
                    spec.event()
                )
            )));
        }
        let mut explained: Vec<&FieldName> = self.filters.iter().map(InputNote::name).collect();
        let mut declared: Vec<&FieldName> = spec.filters().iter().map(InputSpec::name).collect();
        explained.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        declared.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        if explained != declared {
            return Err(DomainError::invalid(message!(
                "workflows-the-guide-explains-other-filters",
                format!(
                    "the guide for {} does not explain exactly the filters it takes",
                    spec.event()
                )
            )));
        }
        Ok(())
    }

    /// The event it explains.
    #[must_use]
    pub fn event(&self) -> &ServiceEventKey {
        &self.event
    }

    /// Its name for people.
    #[must_use]
    pub fn title(&self) -> &Label {
        &self.title
    }

    /// When it happens.
    #[must_use]
    pub fn description(&self) -> &Text {
        &self.description
    }

    /// What each filter means.
    #[must_use]
    pub fn filters(&self) -> &[InputNote] {
        &self.filters
    }

    /// The values it gives the workflow.
    #[must_use]
    pub fn outputs(&self) -> &[OutputNote] {
        &self.outputs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::workflows::data::DataPath;
    use crate::domains::workflows::integration::InputNeed;
    use crate::domains::workflows::integration::form::InputForm;

    fn field(name: &str) -> FieldName {
        FieldName::new(name).unwrap()
    }

    fn text(value: &str) -> Text {
        Text::new("description", value).unwrap()
    }

    /// GitHub's "an issue is opened", watching one repository.
    fn issue_opened() -> ServiceEventSpec {
        ServiceEventSpec::new(
            IntegrationKey::new("github").unwrap(),
            ServiceEventKey::new("issue-opened").unwrap(),
            vec![InputSpec::new(field("repository"), InputNeed::Required)],
        )
        .unwrap()
    }

    fn guide(event: &str, filters: &[&str]) -> ServiceEventGuide {
        ServiceEventGuide::new(ServiceEventGuideParams {
            event: ServiceEventKey::new(event).unwrap(),
            title: Label::new("title", "An issue is opened").unwrap(),
            description: text("Someone opens an issue in the repository."),
            filters: filters
                .iter()
                .map(|name| {
                    InputNote::new(
                        field(name),
                        text("a filter"),
                        InputForm::plain(Label::new("label", *name).unwrap()),
                    )
                })
                .collect(),
            outputs: vec![OutputNote::new(
                DataPath::parse("issue.number").unwrap(),
                text("The issue's number."),
            )],
        })
    }

    /// A guide explaining the event's one filter explains it.
    #[test]
    fn a_guide_explaining_every_filter_fits() {
        assert!(
            guide("issue-opened", &["repository"])
                .ensure_explains(&issue_opened())
                .is_ok()
        );
    }

    /// An event guide rejects a missing repository filter, an extra filter
    /// and a different event name.
    #[test]
    fn a_guide_that_does_not_match_its_event_is_refused() {
        for wrong in [
            guide("issue-opened", &[]),
            guide("issue-opened", &["repository", "label"]),
            guide("push", &["repository"]),
        ] {
            assert!(wrong.ensure_explains(&issue_opened()).is_err());
        }
    }

    /// An event specification cannot declare the same filter as both required
    /// and optional.
    #[test]
    fn an_event_taking_a_filter_twice_is_refused() {
        let twice = ServiceEventSpec::new(
            IntegrationKey::new("github").unwrap(),
            ServiceEventKey::new("issue-opened").unwrap(),
            vec![
                InputSpec::new(field("repository"), InputNeed::Required),
                InputSpec::new(field("repository"), InputNeed::Optional),
            ],
        );

        assert!(matches!(twice, Err(DomainError::Validation(_))));
    }
}
