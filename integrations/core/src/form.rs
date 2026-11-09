//! How an operation's inputs are asked for, and how its step is previewed,
//! written as constants beside the operation and checked as the domain
//! checks them when the integration is built.
//!
//! An input asks with the block its kind suggests unless it says
//! otherwise: a one-line box for text, a number box for a count, a switch
//! for true or false, and pairs of names and values for values handed on.
//! An integration only names blocks, tones and styles: the dashboard draws
//! them in its own theme.

use ianua_domain::domains::workflows::data::{DataPath, FieldName};
use ianua_domain::domains::workflows::integration::OperationKey;
use ianua_domain::domains::workflows::integration::form::{
    Block, Choice, ChoiceValue, FormGroup, InputForm, InputFormParams, InputStyle, Picker,
    PickerParams, Preview, PreviewKind, PreviewPart, Tone,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Label, Text};

/// What kind of value an input takes, as far as asking for it goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suggested {
    /// One line of text.
    Text,
    /// A whole number.
    Number,
    /// True or false.
    Switch,
    /// Pairs of names and values.
    KeyValues,
}

/// How one input is asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormText {
    /// Its label; the input's name, written for people, when left out.
    pub label: Option<&'static str>,
    /// The block it asks with.
    pub ask: Ask,
    /// A value it might take, shown while the box is empty.
    pub example: Option<&'static str>,
    /// Where it is shown.
    pub group: FormGroup,
    /// How its box is drawn.
    pub style: InputStyle,
    /// A note the builder should not miss.
    pub warning: Option<&'static str>,
}

impl FormText {
    /// The form an input asks with when it says nothing more.
    #[must_use]
    pub const fn plain() -> Self {
        Self {
            label: None,
            ask: Ask::AsSuggested,
            example: None,
            group: FormGroup::Main,
            style: InputStyle::Normal,
            warning: None,
        }
    }
}

/// The block an input asks with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ask {
    /// The block its kind suggests.
    AsSuggested,
    /// A box of several lines.
    LongText,
    /// A picker for a calendar day and clock time.
    DateTime,
    /// One of a few options, in order.
    Choices(&'static [ChoiceText]),
    /// One option a read operation lists.
    Picker(PickerText),
    /// Several options a read operation lists.
    MultiPicker(PickerText),
    /// One of the tenant's routes open to workflows, for a Protected apps
    /// step's route.
    AppPicker,
    /// One of the tenant's stream routes open to workflows, for a
    /// Protected data step's route.
    DataPicker,
    /// One of the tenant's memories, as the built-in memory steps name it.
    MemoryPicker,
}

/// One option of a choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChoiceText {
    /// What the input is set to, such as `not_planned`.
    pub value: &'static str,
    /// How it is shown, such as `Not planned`.
    pub label: &'static str,
    /// Semantic emphasis the dashboard renders in its own theme.
    pub tone: Tone,
}

/// Where a picker's options come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PickerText {
    /// The read operation of the same integration that lists them.
    pub filled_by: &'static str,
    /// Where the list is in what it gives back, such as `json`.
    pub items_at: &'static str,
    /// Where each item's value is, such as `full_name`.
    pub value_at: &'static str,
    /// Where each item's label is.
    pub label_at: &'static str,
    /// The input the list depends on, such as `repository`.
    pub depends_on: Option<&'static str>,
}

/// How one operation's step is previewed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreviewText {
    /// Stable action key whose step receives this preview.
    pub operation: &'static str,
    /// What it looks like.
    pub kind: PreviewKind,
    /// Which input fills each part.
    pub parts: &'static [(PreviewPart, &'static str)],
}

/// The form `text` writes for the input `name`, whose kind suggests
/// `suggested`.
///
/// # Errors
///
/// Returns `DomainError::Validation` when a value breaks its rules, such as
/// a choice of one option or a picker path that does not parse.
pub(crate) fn input_form(
    name: &str,
    suggested: Suggested,
    text: &FormText,
) -> Result<InputForm, DomainError> {
    let label = match text.label {
        Some(label) => Label::new("label", label)?,
        None => Label::new("label", label_of(name))?,
    };
    InputForm::new(InputFormParams {
        block: block_of(suggested, text.ask)?,
        label,
        example: text
            .example
            .map(|example| Text::new("example", example))
            .transpose()?,
        group: text.group,
        style: text.style,
        warning: text
            .warning
            .map(|warning| Text::new("warning", warning))
            .transpose()?,
    })
}

/// The preview `text` writes.
///
/// # Errors
///
/// Returns `DomainError::Validation` when an input's name breaks its rules
/// or a part is filled twice.
pub fn preview(text: &PreviewText) -> Result<Preview, DomainError> {
    let parts = text
        .parts
        .iter()
        .map(|(part, input)| Ok((*part, FieldName::new(*input)?)))
        .collect::<Result<Vec<_>, DomainError>>()?;
    Preview::new(text.kind, parts)
}

/// The block `ask` names, or the one `suggested` stands for.
fn block_of(suggested: Suggested, ask: Ask) -> Result<Block, DomainError> {
    Ok(match ask {
        Ask::AsSuggested => match suggested {
            Suggested::Text => Block::Text,
            Suggested::Number => Block::Number,
            Suggested::Switch => Block::Switch,
            Suggested::KeyValues => Block::KeyValues,
        },
        Ask::LongText => Block::LongText,
        Ask::DateTime => Block::DateTime,
        Ask::Choices(choices) => Block::Choices(
            choices
                .iter()
                .map(choice_of)
                .collect::<Result<Vec<_>, DomainError>>()?,
        ),
        Ask::Picker(picker) => Block::Picker(picker_of(&picker)?),
        Ask::MultiPicker(picker) => Block::MultiPicker(picker_of(&picker)?),
        Ask::AppPicker => Block::AppPicker,
        Ask::DataPicker => Block::DataPicker,
        Ask::MemoryPicker => Block::MemoryPicker,
    })
}

/// The option `text` writes.
fn choice_of(text: &ChoiceText) -> Result<Choice, DomainError> {
    Ok(Choice::new(
        ChoiceValue::new(text.value)?,
        Label::new("label", text.label)?,
        text.tone,
    ))
}

/// The picker `text` writes.
fn picker_of(text: &PickerText) -> Result<Picker, DomainError> {
    Ok(Picker::new(PickerParams {
        filled_by: OperationKey::new(text.filled_by)?,
        items_at: DataPath::parse(text.items_at)?,
        value_at: DataPath::parse(text.value_at)?,
        label_at: DataPath::parse(text.label_at)?,
        depends_on: text.depends_on.map(FieldName::new).transpose()?,
    }))
}

/// An input's name written for people: `due_date` and `due-date` read
/// `Due date`.
fn label_of(name: &str) -> String {
    let spaced = name.replace(['_', '-'], " ");
    let mut letters = spaced.chars();
    letters
        .next()
        .map(|first| first.to_uppercase().chain(letters).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An input that says nothing is asked with the block its kind
    /// suggests, labelled with its name written for people.
    #[test]
    fn a_plain_input_asks_as_its_kind_suggests() {
        let form = input_form("due_date", Suggested::Number, &FormText::plain()).unwrap();

        assert_eq!(form.block(), &Block::Number);
        assert_eq!(form.label().as_str(), "Due date");
    }

    /// GitHub's labels are picked from the chosen repository's labels.
    #[test]
    fn a_picker_names_where_its_options_come_from() {
        let text = FormText {
            ask: Ask::MultiPicker(PickerText {
                filled_by: "list-labels",
                items_at: "json",
                value_at: "name",
                label_at: "name",
                depends_on: Some("repository"),
            }),
            ..FormText::plain()
        };

        let form = input_form("labels", Suggested::Text, &text).unwrap();

        let picker = form.block().picker().unwrap();
        assert_eq!(picker.filled_by().as_str(), "list-labels");
        assert_eq!(
            picker.depends_on().map(FieldName::as_str),
            Some("repository")
        );
    }

    /// An input offering only one choice fails form construction.
    #[test]
    fn a_choice_of_one_option_is_refused() {
        let text = FormText {
            ask: Ask::Choices(&[ChoiceText {
                value: "open",
                label: "Open",
                tone: Tone::Success,
            }]),
            ..FormText::plain()
        };

        assert!(input_form("state", Suggested::Text, &text).is_err());
    }

    /// Assigning two inputs to the preview's title prevents preview construction.
    #[test]
    fn a_preview_filling_a_part_twice_is_refused() {
        let text = PreviewText {
            operation: "create-issue",
            kind: PreviewKind::Issue,
            parts: &[(PreviewPart::Title, "title"), (PreviewPart::Title, "body")],
        };

        assert!(preview(&text).is_err());
    }
}
