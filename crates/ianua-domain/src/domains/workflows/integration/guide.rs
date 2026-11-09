//! How an operation is explained to the people building workflows: what
//! it does, what each input means, and what it gives back for the steps
//! after it.
//!
//! A guide only explains. Whether a step fits its operation is still
//! decided by the operation's [`OperationSpec`] alone, so a guide can be
//! reworded without a published workflow ever changing meaning. A guide
//! must still describe exactly the inputs its operation declares, so the
//! builder is never told about an input that does not exist or left to
//! guess one that does.

use crate::domains::workflows::data::{DataPath, FieldName};
use crate::domains::workflows::integration::form::{Block, FormGroup, InputForm, Picker, Preview};
use crate::domains::workflows::integration::{
    AccountNeed, InputNeed, InputSpec, MEMORY_INPUT, OperationKey, OperationSpec, ROUTE_INPUT,
};
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{ActionClass, DeclaredAction, Label, Text};

/// What one input of an operation means, and how a builder is asked for it.
#[derive(Debug, Clone, PartialEq)]
pub struct InputNote {
    name: FieldName,
    description: Text,
    form: InputForm,
}

impl InputNote {
    /// The input `name`, meaning `description`, asked for with `form`.
    #[must_use]
    pub fn new(name: FieldName, description: Text, form: InputForm) -> Self {
        Self {
            name,
            description,
            form,
        }
    }

    /// The input it explains.
    #[must_use]
    pub fn name(&self) -> &FieldName {
        &self.name
    }

    /// What the input means.
    #[must_use]
    pub fn description(&self) -> &Text {
        &self.description
    }

    /// How a builder is asked for it.
    #[must_use]
    pub fn form(&self) -> &InputForm {
        &self.form
    }
}

/// One value an operation gives back, at a path in the step's output,
/// such as `json.number` for the number of an issue GitHub opened.
#[derive(Debug, Clone, PartialEq)]
pub struct OutputNote {
    path: DataPath,
    description: Text,
}

impl OutputNote {
    /// The value at `path` in the output, meaning `description`.
    #[must_use]
    pub fn new(path: DataPath, description: Text) -> Self {
        Self { path, description }
    }

    /// Where it is in the step's output.
    #[must_use]
    pub fn path(&self) -> &DataPath {
        &self.path
    }

    /// What the value is.
    #[must_use]
    pub fn description(&self) -> &Text {
        &self.description
    }
}

/// The values an operation is explained with.
pub struct OperationGuideParams {
    /// The operation explained.
    pub operation: OperationKey,
    /// Its name for people, such as "Open an issue".
    pub title: Label,
    /// What it does, in a sentence or two.
    pub description: Text,
    /// What each input means, one note per input the operation declares.
    pub inputs: Vec<InputNote>,
    /// The values it gives back that the steps after it may use.
    pub outputs: Vec<OutputNote>,
    /// How its inputs are previewed, so the step looks like the product it
    /// acts in, if it has a preview.
    pub preview: Option<Preview>,
}

/// How an operation is explained.
#[derive(Debug, Clone, PartialEq)]
pub struct OperationGuide {
    operation: OperationKey,
    title: Label,
    description: Text,
    inputs: Vec<InputNote>,
    outputs: Vec<OutputNote>,
    preview: Option<Preview>,
}

impl OperationGuide {
    /// The guide `params` describe.
    #[must_use]
    pub fn new(params: OperationGuideParams) -> Self {
        Self {
            operation: params.operation,
            title: params.title,
            description: params.description,
            inputs: params.inputs,
            outputs: params.outputs,
            preview: params.preview,
        }
    }

    /// Checks that the guide describes exactly `spec` and presents a usable input form.
    ///
    /// # Errors
    /// [`DomainError::Validation`] for another operation; missing, extra or repeated inputs;
    /// hidden required inputs; unknown, self-referencing or cyclic picker dependencies;
    /// preview references to unknown inputs; or route pickers that do not match the
    /// operation's route kind and authority as the run's person.
    pub fn ensure_explains(&self, spec: &OperationSpec) -> Result<(), DomainError> {
        self.ensure_explains_inputs(spec)?;
        self.ensure_required_shown(spec)?;
        self.ensure_dependencies_resolve()?;
        self.ensure_route_pickers_fit(spec)?;
        self.ensure_preview_fits()
    }

    /// Refuses a list of the tenant's apps on anything but a Protected
    /// apps step's route, a list of its stream routes on anything but a
    /// Protected data step's, and a list of its memories on anything but a
    /// memory step's memory: the value picked is the id the step reaches.
    fn ensure_route_pickers_fit(&self, spec: &OperationSpec) -> Result<(), DomainError> {
        let misplaced = self.inputs.iter().find(|note| {
            listed_reach(note.form().block()).is_some_and(|(input, wanted)| {
                note.name().as_str() != input || spec.account() != wanted
            })
        });
        let Some(misplaced) = misplaced else {
            return Ok(());
        };
        let input = misplaced.name();
        let operation = &self.operation;
        Err(DomainError::invalid(message!(
            "workflows-a-list-asks-for-what-its-step-reaches",
            format!(
                "the list for {input} in {operation} may only ask for what a step of that kind reaches, on the input naming it"
            )
        )))
    }

    /// Refuses this guide unless every picker in it is filled by a read
    /// operation among `offered`, the operations of its own integration.
    /// Opening a form never acts: a picker filled by an operation that
    /// writes, sends or deletes would do so each time a builder looked.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when a picker is filled by an
    ///   operation not among `offered`, or by one that does more than read.
    pub fn ensure_pickers_read(&self, offered: &[OperationSpec]) -> Result<(), DomainError> {
        self.inputs
            .iter()
            .filter_map(|note| note.form().block().picker().map(|picker| (note, picker)))
            .try_for_each(|(note, picker)| {
                let reads = offered.iter().any(|spec| {
                    spec.operation() == picker.filled_by()
                        && spec.effect() == DeclaredAction::Declared(ActionClass::Read)
                });
                if reads {
                    return Ok(());
                }
                let input = note.name();
                let operation = &self.operation;
                let reader = picker.filled_by();
                Err(DomainError::invalid(message!(
                    "workflows-a-list-is-filled-by-no-read",
                    format!(
                        "the list for {input} in {operation} is filled by {reader}, which is not a read operation of the same integration"
                    )
                )))
            })
    }

    fn ensure_required_shown(&self, spec: &OperationSpec) -> Result<(), DomainError> {
        let hidden = spec.inputs().iter().find(|input| {
            input.need() == InputNeed::Required
                && self
                    .input(input.name())
                    .is_some_and(|note| note.form().group() == FormGroup::MoreOptions)
        });
        let Some(hidden) = hidden else {
            return Ok(());
        };
        let input = hidden.name();
        let operation = &self.operation;
        Err(DomainError::invalid(message!(
            "workflows-a-required-input-is-hidden",
            format!("{input} is required by {operation} but hidden under more options")
        )))
    }

    fn ensure_dependencies_resolve(&self) -> Result<(), DomainError> {
        self.inputs.iter().try_for_each(|note| {
            let mut seen: Vec<&FieldName> = vec![note.name()];
            let mut at = note;
            while let Some(on) = at.form().block().picker().and_then(Picker::depends_on) {
                if seen.contains(&on) {
                    return Err(self.circular_dependency(note.name()));
                }
                let Some(next) = self.input(on) else {
                    return Err(self.missing_dependency(note.name()));
                };
                seen.push(on);
                at = next;
            }
            Ok(())
        })
    }

    fn circular_dependency(&self, input: &FieldName) -> DomainError {
        let operation = &self.operation;
        DomainError::invalid(message!(
            "workflows-a-list-depends-on-itself",
            format!("the list for {input} in {operation} depends on itself through a circle")
        ))
    }

    fn missing_dependency(&self, input: &FieldName) -> DomainError {
        let operation = &self.operation;
        DomainError::invalid(message!(
            "workflows-a-list-depends-on-a-missing-input",
            format!(
                "the list for {input} in {operation} depends on an input the operation does not take"
            )
        ))
    }

    fn ensure_preview_fits(&self) -> Result<(), DomainError> {
        let Some(preview) = &self.preview else {
            return Ok(());
        };
        let Some((part, input)) = preview
            .parts()
            .iter()
            .find(|(_, input)| self.input(input).is_none())
        else {
            return Ok(());
        };
        let operation = &self.operation;
        let part = part.as_str();
        Err(DomainError::invalid(message!(
            "workflows-a-preview-shows-an-input-the",
            format!(
                "the preview of {operation} shows {input} as its {part}, which the operation does not take"
            )
        )))
    }

    /// Refuses this guide unless it explains exactly the inputs `spec`
    /// declares, each once.
    fn ensure_explains_inputs(&self, spec: &OperationSpec) -> Result<(), DomainError> {
        if &self.operation != spec.operation() {
            return Err(DomainError::invalid(message!(
                "workflows-the-guide-explains-another-operation",
                format!(
                    "the guide explains the operation {}, not {}",
                    self.operation,
                    spec.operation()
                )
            )));
        }
        let mut explained: Vec<&FieldName> = self.inputs.iter().map(InputNote::name).collect();
        let mut declared: Vec<&FieldName> = spec.inputs().iter().map(InputSpec::name).collect();
        explained.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        declared.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        if explained != declared {
            return Err(DomainError::invalid(message!(
                "workflows-the-guide-explains-other-inputs",
                format!(
                    "the guide for {} does not explain exactly the inputs it declares",
                    spec.operation()
                )
            )));
        }
        Ok(())
    }

    /// The operation it explains.
    #[must_use]
    pub fn operation(&self) -> &OperationKey {
        &self.operation
    }

    /// Its name for people.
    #[must_use]
    pub fn title(&self) -> &Label {
        &self.title
    }

    /// What it does.
    #[must_use]
    pub fn description(&self) -> &Text {
        &self.description
    }

    /// What each input means.
    #[must_use]
    pub fn inputs(&self) -> &[InputNote] {
        &self.inputs
    }

    /// The note on the input `name`, if it has one.
    #[must_use]
    pub fn input(&self, name: &FieldName) -> Option<&InputNote> {
        self.inputs.iter().find(|note| note.name() == name)
    }

    /// The values it gives back.
    #[must_use]
    pub fn outputs(&self) -> &[OutputNote] {
        &self.outputs
    }

    /// How its inputs are previewed, if it has a preview.
    #[must_use]
    pub fn preview(&self) -> Option<&Preview> {
        self.preview.as_ref()
    }
}

/// The input and the kind of step whose reach `block` lists, if it lists
/// one: apps for a step acting as the run's person, stream routes for one
/// reaching protected data, memories for a memory step.
fn listed_reach(block: &Block) -> Option<(&'static str, AccountNeed)> {
    match block {
        Block::AppPicker => Some((ROUTE_INPUT, AccountNeed::RunPerson)),
        Block::DataPicker => Some((ROUTE_INPUT, AccountNeed::RunPersonData)),
        Block::MemoryPicker => Some((MEMORY_INPUT, AccountNeed::TenantMemory)),
        Block::Text
        | Block::LongText
        | Block::Number
        | Block::Switch
        | Block::Choices(_)
        | Block::Picker(_)
        | Block::MultiPicker(_)
        | Block::DateTime
        | Block::KeyValues => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::data_classification::level::DataClassLevel;
    use crate::domains::workflows::integration::form::{
        Block, InputFormParams, InputStyle, PickerParams, PreviewKind, PreviewPart,
    };
    use crate::domains::workflows::integration::{
        AccountNeed, InputSpec, IntegrationKey, OperationSpecParams,
    };

    fn field(name: &str) -> FieldName {
        FieldName::new(name).unwrap()
    }

    fn text(value: &str) -> Text {
        Text::new("description", value).unwrap()
    }

    /// GitHub's "comment on an issue", taking a repository, an issue and a
    /// body.
    fn comment_spec() -> OperationSpec {
        OperationSpec::new(OperationSpecParams {
            integration: IntegrationKey::new("github").unwrap(),
            operation: OperationKey::new("comment-on-issue").unwrap(),
            inputs: ["repository", "issue", "body"]
                .into_iter()
                .map(|name| InputSpec::new(field(name), InputNeed::Required))
                .collect(),
            effect: DeclaredAction::Declared(ActionClass::Communicate),
            account: AccountNeed::Account,
            ceiling: DataClassLevel::Internal,
        })
        .unwrap()
    }

    fn plain(name: &str) -> InputForm {
        InputForm::plain(Label::new("label", name).unwrap())
    }

    fn guide(operation: &str, inputs: &[&str]) -> OperationGuide {
        guide_with(
            operation,
            inputs.iter().map(|name| (*name, plain(name))).collect(),
            None,
        )
    }

    fn guide_with(
        operation: &str,
        inputs: Vec<(&str, InputForm)>,
        preview: Option<Preview>,
    ) -> OperationGuide {
        OperationGuide::new(OperationGuideParams {
            operation: OperationKey::new(operation).unwrap(),
            title: Label::new("title", "Comment on an issue").unwrap(),
            description: text("Adds a comment to an issue."),
            inputs: inputs
                .into_iter()
                .map(|(name, form)| InputNote::new(field(name), text("an input"), form))
                .collect(),
            outputs: vec![OutputNote::new(
                DataPath::parse("json.html_url").unwrap(),
                text("The comment's page."),
            )],
            preview,
        })
    }

    fn picker_of(filled_by: &str, depends_on: Option<&str>) -> InputForm {
        InputForm::new(InputFormParams {
            block: Block::Picker(Picker::new(PickerParams {
                filled_by: OperationKey::new(filled_by).unwrap(),
                items_at: DataPath::parse("json").unwrap(),
                value_at: DataPath::parse("full_name").unwrap(),
                label_at: DataPath::parse("full_name").unwrap(),
                depends_on: depends_on.map(field),
            })),
            label: Label::new("label", "Repository").unwrap(),
            example: None,
            group: FormGroup::Main,
            style: InputStyle::Normal,
            warning: None,
        })
        .unwrap()
    }

    fn reading(operation: &str, class: ActionClass) -> OperationSpec {
        OperationSpec::new(OperationSpecParams {
            integration: IntegrationKey::new("github").unwrap(),
            operation: OperationKey::new(operation).unwrap(),
            inputs: Vec::new(),
            effect: DeclaredAction::Declared(class),
            account: AccountNeed::Account,
            ceiling: DataClassLevel::Internal,
        })
        .unwrap()
    }

    /// A guide cannot place a required repository input under "More options".
    #[test]
    fn a_required_input_under_more_options_is_refused() {
        let hidden = InputForm::new(InputFormParams {
            block: Block::Text,
            label: Label::new("label", "Repository").unwrap(),
            example: None,
            group: FormGroup::MoreOptions,
            style: InputStyle::Normal,
            warning: None,
        })
        .unwrap();
        let guide = guide_with(
            "comment-on-issue",
            vec![
                ("repository", hidden),
                ("issue", plain("issue")),
                ("body", plain("body")),
            ],
            None,
        );

        assert!(guide.ensure_explains(&comment_spec()).is_err());
    }

    /// The issue picker depends on the repository, which the operation
    /// takes: the guide fits. One depending on a missing input, or two
    /// depending on each other, is refused.
    #[test]
    fn a_picker_depends_only_on_inputs_of_the_same_operation() {
        let fits = guide_with(
            "comment-on-issue",
            vec![
                ("repository", plain("repository")),
                ("issue", picker_of("list-issues", Some("repository"))),
                ("body", plain("body")),
            ],
            None,
        );
        let missing = guide_with(
            "comment-on-issue",
            vec![
                ("repository", plain("repository")),
                ("issue", picker_of("list-issues", Some("workspace"))),
                ("body", plain("body")),
            ],
            None,
        );
        let circle = guide_with(
            "comment-on-issue",
            vec![
                ("repository", picker_of("list-repositories", Some("issue"))),
                ("issue", picker_of("list-issues", Some("repository"))),
                ("body", plain("body")),
            ],
            None,
        );

        assert!(fits.ensure_explains(&comment_spec()).is_ok());
        assert!(missing.ensure_explains(&comment_spec()).is_err());
        assert!(circle.ensure_explains(&comment_spec()).is_err());
    }

    /// Postgres's query, reaching a stream route as the run's person.
    fn data_query_spec() -> OperationSpec {
        OperationSpec::new(OperationSpecParams {
            integration: IntegrationKey::new("postgres").unwrap(),
            operation: OperationKey::new("query").unwrap(),
            inputs: [ROUTE_INPUT, "statement"]
                .into_iter()
                .map(|name| InputSpec::new(field(name), InputNeed::Required))
                .collect(),
            effect: DeclaredAction::Declared(ActionClass::Read),
            account: AccountNeed::RunPersonData,
            ceiling: DataClassLevel::Internal,
        })
        .unwrap()
    }

    fn asked_with(block: Block) -> InputForm {
        InputForm::new(InputFormParams {
            block,
            label: Label::new("label", "Database").unwrap(),
            example: None,
            group: FormGroup::Main,
            style: InputStyle::Normal,
            warning: None,
        })
        .unwrap()
    }

    /// A data query guide accepts a data picker for its route. It rejects an
    /// app picker there and a data picker on its statement input.
    #[test]
    fn a_route_list_asks_only_for_a_route_of_its_kind() {
        let query = |route: Block, statement: Block| {
            let mut guide = guide_with(
                "query",
                vec![
                    (ROUTE_INPUT, asked_with(route)),
                    ("statement", asked_with(statement)),
                ],
                None,
            );
            guide.operation = OperationKey::new("query").unwrap();
            guide.ensure_explains(&data_query_spec())
        };

        let fits = query(Block::DataPicker, Block::Text);
        let apps = query(Block::AppPicker, Block::Text);
        let statement = query(Block::DataPicker, Block::DataPicker);

        assert!(fits.is_ok(), "{fits:?}");
        assert!(apps.is_err());
        assert!(statement.is_err());
    }

    /// A memory search guide accepts a memory picker for its memory input.
    /// It rejects a memory picker on its text input and a data picker on its
    /// memory input.
    #[test]
    fn a_memory_list_asks_only_for_a_memory() {
        let spec = OperationSpec::new(OperationSpecParams {
            integration: IntegrationKey::new("memory").unwrap(),
            operation: OperationKey::new("find-similar").unwrap(),
            inputs: [MEMORY_INPUT, "text"]
                .into_iter()
                .map(|name| InputSpec::new(field(name), InputNeed::Required))
                .collect(),
            effect: DeclaredAction::Declared(ActionClass::Read),
            account: AccountNeed::TenantMemory,
            ceiling: DataClassLevel::Internal,
        })
        .unwrap();
        let find = |memory: Block, text: Block| {
            let mut guide = guide_with(
                "find-similar",
                vec![
                    (MEMORY_INPUT, asked_with(memory)),
                    ("text", asked_with(text)),
                ],
                None,
            );
            guide.operation = OperationKey::new("find-similar").unwrap();
            guide.ensure_explains(&spec)
        };

        let fits = find(Block::MemoryPicker, Block::Text);
        let on_text = find(Block::MemoryPicker, Block::MemoryPicker);
        let routes = find(Block::DataPicker, Block::Text);

        assert!(fits.is_ok(), "{fits:?}");
        assert!(on_text.is_err());
        assert!(routes.is_err());
    }

    /// A picker may be filled by an offered read operation. A write operation
    /// and an operation absent from the offered list are rejected.
    #[test]
    fn a_picker_is_filled_only_by_a_read_operation() {
        let offered = [
            reading("list-issues", ActionClass::Read),
            reading("add-labels", ActionClass::Write),
        ];
        let by = |filled_by: &str| {
            guide_with(
                "comment-on-issue",
                vec![
                    ("repository", plain("repository")),
                    ("issue", picker_of(filled_by, None)),
                    ("body", plain("body")),
                ],
                None,
            )
        };

        assert!(by("list-issues").ensure_pickers_read(&offered).is_ok());
        assert!(by("add-labels").ensure_pickers_read(&offered).is_err());
        assert!(by("list-everything").ensure_pickers_read(&offered).is_err());
    }

    /// A guide rejects a preview whose title names an input the operation
    /// does not declare.
    #[test]
    fn a_preview_shows_only_inputs_of_the_operation() {
        let shows_title = Preview::new(
            PreviewKind::Issue,
            vec![(PreviewPart::Title, field("title"))],
        )
        .unwrap();
        let guide = guide_with(
            "comment-on-issue",
            vec![
                ("repository", plain("repository")),
                ("issue", plain("issue")),
                ("body", plain("body")),
            ],
            Some(shows_title),
        );

        assert!(guide.ensure_explains(&comment_spec()).is_err());
    }

    /// A guide explaining each declared input once, in any order, explains
    /// the operation.
    #[test]
    fn a_guide_explaining_every_input_fits() {
        let guide = guide("comment-on-issue", &["body", "repository", "issue"]);

        assert!(guide.ensure_explains(&comment_spec()).is_ok());
        assert!(guide.input(&field("issue")).is_some());
    }

    /// Operation guides reject a missing input, an extra input, a repeated
    /// input and a different operation name.
    #[test]
    fn a_guide_that_does_not_match_its_operation_is_refused() {
        let spec = comment_spec();

        for wrong in [
            guide("comment-on-issue", &["repository", "body"]),
            guide(
                "comment-on-issue",
                &["repository", "issue", "body", "labels"],
            ),
            guide("comment-on-issue", &["repository", "issue", "body", "body"]),
            guide("create-issue", &["repository", "issue", "body"]),
        ] {
            assert!(wrong.ensure_explains(&spec).is_err());
        }
    }
}
