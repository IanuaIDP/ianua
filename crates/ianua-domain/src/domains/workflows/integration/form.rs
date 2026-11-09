//! How a builder is asked for each input of an operation, and how a step's
//! inputs are previewed so it looks like the product it acts in.
//!
//! An integration names what to ask for from a fixed set of building
//! blocks, tones and styles. It never names colours for text or spacing,
//! markup or layout: the dashboard draws every block in its own theme, so
//! every integration looks like one product and none can make a field
//! unreadable or a button look like something it is not. The one colour an
//! integration gives is its brand colour, held to a contrast it must keep
//! against white.

use crate::domains::workflows::data::{DataPath, FieldName};
use crate::domains::workflows::integration::OperationKey;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;
use crate::shared::validation::{Charset, Rule, TextValue, ValidationError, Validator, text_value};
use crate::types::{Label, Text};

/// The fewest options a choice offers: one option is no choice.
pub(crate) const MIN_CHOICES: usize = 2;

/// The most options a choice offers as buttons. Longer lists are pickers.
pub const MAX_CHOICES: usize = 8;

/// The contrast a brand colour keeps against white, so a white mark on it
/// stays readable. Three to one is the least for large graphics.
pub(crate) const MIN_BRAND_CONTRAST: f64 = 3.0;

text_value! {
    /// The value one option of a choice stands for, such as `not_planned`.
    pub struct ChoiceValue;
}

impl TextValue for ChoiceValue {
    const FIELD: &'static str = "choice";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.length(1..=64).charset(
            Charset::LOWERCASE
                | Charset::UPPERCASE
                | Charset::DIGIT
                | Charset::HYPHEN
                | Charset::UNDERSCORE,
        )
    }
}

/// How an option of a choice is coloured, as a meaning the dashboard maps
/// to its theme.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Tone {
    /// Nothing to tell.
    #[default]
    Neutral,
    /// Worth knowing.
    Info,
    /// Gone well, such as a status that is done.
    Success,
    /// Needs care.
    Warning,
    /// Goes wrong or takes away, such as a status that is blocked.
    Danger,
}

impl Tone {
    /// The name the dashboard maps to its theme.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Neutral => "neutral",
            Self::Info => "info",
            Self::Success => "success",
            Self::Warning => "warning",
            Self::Danger => "danger",
        }
    }
}

/// One option of a choice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    value: ChoiceValue,
    label: Label,
    tone: Tone,
}

impl Choice {
    /// The option `value`, shown as `label` in `tone`.
    #[must_use]
    pub fn new(value: ChoiceValue, label: Label, tone: Tone) -> Self {
        Self { value, label, tone }
    }

    /// What it stands for.
    #[must_use]
    pub fn value(&self) -> &ChoiceValue {
        &self.value
    }

    /// How it is shown.
    #[must_use]
    pub fn label(&self) -> &Label {
        &self.label
    }

    /// How it is coloured.
    #[must_use]
    pub fn tone(&self) -> Tone {
        self.tone
    }
}

/// Where a picker's options come from: a read operation of the same
/// integration, run through the builder's account, and where each option's
/// value and label are in what it gives back.
#[derive(Debug, Clone, PartialEq)]
pub struct Picker {
    filled_by: OperationKey,
    items_at: DataPath,
    value_at: DataPath,
    label_at: DataPath,
    depends_on: Option<FieldName>,
}

/// The values a picker is made from.
pub struct PickerParams {
    /// The read operation that lists the options.
    pub filled_by: OperationKey,
    /// Where the list is in what it gives back, such as `json`.
    pub items_at: DataPath,
    /// Where each item's value is, such as `full_name`.
    pub value_at: DataPath,
    /// Where each item's label is, such as `full_name`.
    pub label_at: DataPath,
    /// The input whose value the list depends on, such as `repository` for
    /// a repository's labels.
    pub depends_on: Option<FieldName>,
}

impl Picker {
    /// The picker `params` describe.
    #[must_use]
    pub fn new(params: PickerParams) -> Self {
        Self {
            filled_by: params.filled_by,
            items_at: params.items_at,
            value_at: params.value_at,
            label_at: params.label_at,
            depends_on: params.depends_on,
        }
    }

    /// The read operation that lists the options.
    #[must_use]
    pub fn filled_by(&self) -> &OperationKey {
        &self.filled_by
    }

    /// Where the list is in what it gives back.
    #[must_use]
    pub fn items_at(&self) -> &DataPath {
        &self.items_at
    }

    /// Where each item's value is.
    #[must_use]
    pub fn value_at(&self) -> &DataPath {
        &self.value_at
    }

    /// Where each item's label is.
    #[must_use]
    pub fn label_at(&self) -> &DataPath {
        &self.label_at
    }

    /// The input the list depends on, if any.
    #[must_use]
    pub fn depends_on(&self) -> Option<&FieldName> {
        self.depends_on.as_ref()
    }
}

/// The building block an input is asked for with. The set is fixed: an
/// integration can only pick one of these.
#[derive(Debug, Clone, PartialEq)]
pub enum Block {
    /// One line, such as a title or an address.
    Text,
    /// Several lines, such as a message.
    LongText,
    /// A whole number.
    Number,
    /// Yes or no.
    Switch,
    /// A few fixed options, shown as buttons.
    Choices(Vec<Choice>),
    /// One value from a list the account fills.
    Picker(Picker),
    /// Several values from a list the account fills.
    MultiPicker(Picker),
    /// A moment, in the tenant's time zone.
    DateTime,
    /// Pairs of a key and a value, such as extra headers.
    KeyValues,
    /// One of the tenant's routes open to workflows, as a Protected apps
    /// step names it: the platform lists them, no account is asked.
    AppPicker,
    /// One of the tenant's stream routes open to workflows, as a Protected
    /// data step names it: the platform lists them, no account is asked.
    DataPicker,
    /// One of the tenant's memories, as a memory step names it.
    MemoryPicker,
}

impl Block {
    /// The block's name, as the dashboard knows it.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::LongText => "long_text",
            Self::Number => "number",
            Self::Switch => "switch",
            Self::Choices(_) => "choices",
            Self::Picker(_) => "picker",
            Self::MultiPicker(_) => "multi_picker",
            Self::DateTime => "date_time",
            Self::KeyValues => "key_values",
            Self::AppPicker => "app_picker",
            Self::DataPicker => "data_picker",
            Self::MemoryPicker => "memory_picker",
        }
    }

    /// The picker filling this block, if it is one.
    #[must_use]
    pub fn picker(&self) -> Option<&Picker> {
        match self {
            Self::Picker(picker) | Self::MultiPicker(picker) => Some(picker),
            Self::Text
            | Self::LongText
            | Self::Number
            | Self::Switch
            | Self::Choices(_)
            | Self::DateTime
            | Self::KeyValues
            | Self::AppPicker
            | Self::DataPicker
            | Self::MemoryPicker => None,
        }
    }
}

/// Where an input is shown.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FormGroup {
    /// With the step's other main inputs.
    #[default]
    Main,
    /// Under "More options", for inputs most steps leave alone.
    MoreOptions,
}

impl FormGroup {
    /// The group's name, as the dashboard knows it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Main => "main",
            Self::MoreOptions => "more_options",
        }
    }
}

/// How an input's box is drawn.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum InputStyle {
    /// As any input.
    #[default]
    Normal,
    /// In a fixed-width font, for code and identifiers.
    Monospace,
    /// Taller, for long messages.
    Tall,
    /// Smaller, for short values beside others.
    Compact,
}

impl InputStyle {
    /// The style's name, as the dashboard knows it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Monospace => "monospace",
            Self::Tall => "tall",
            Self::Compact => "compact",
        }
    }
}

/// How one input is asked for.
#[derive(Debug, Clone, PartialEq)]
pub struct InputForm {
    block: Block,
    label: Label,
    example: Option<Text>,
    group: FormGroup,
    style: InputStyle,
    warning: Option<Text>,
}

/// The values an input's form is made from.
pub struct InputFormParams {
    /// The block it is asked for with.
    pub block: Block,
    /// Its name for people, such as "Labels".
    pub label: Label,
    /// A value it might take, shown as a hint, such as "bug".
    pub example: Option<Text>,
    /// Where it is shown.
    pub group: FormGroup,
    /// How its box is drawn.
    pub style: InputStyle,
    /// A note the builder should not miss, such as "this posts publicly".
    pub warning: Option<Text>,
}

impl InputForm {
    /// The form `params` describe.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when a choice offers fewer than
    ///   `MIN_CHOICES` or more than [`MAX_CHOICES`] options, or one value
    ///   twice.
    pub fn new(params: InputFormParams) -> Result<Self, DomainError> {
        if let Block::Choices(choices) = &params.block {
            ensure_choices_fit(choices)?;
        }
        Ok(Self {
            block: params.block,
            label: params.label,
            example: params.example,
            group: params.group,
            style: params.style,
            warning: params.warning,
        })
    }

    /// A one-line text box labelled `label`, for an input no form was
    /// written for.
    #[must_use]
    pub fn plain(label: Label) -> Self {
        Self {
            block: Block::Text,
            label,
            example: None,
            group: FormGroup::Main,
            style: InputStyle::Normal,
            warning: None,
        }
    }

    /// The block it is asked for with.
    #[must_use]
    pub fn block(&self) -> &Block {
        &self.block
    }

    /// Its name for people.
    #[must_use]
    pub fn label(&self) -> &Label {
        &self.label
    }

    /// A value it might take.
    #[must_use]
    pub fn example(&self) -> Option<&Text> {
        self.example.as_ref()
    }

    /// Where it is shown.
    #[must_use]
    pub fn group(&self) -> FormGroup {
        self.group
    }

    /// How its box is drawn.
    #[must_use]
    pub fn style(&self) -> InputStyle {
        self.style
    }

    /// A note the builder should not miss.
    #[must_use]
    pub fn warning(&self) -> Option<&Text> {
        self.warning.as_ref()
    }
}

/// The kind of preview a step's inputs are shown in, drawn so it looks like
/// the kind of product the step acts in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviewKind {
    /// A message in a chat, as Slack or Teams show one.
    ChatMessage,
    /// An issue, as GitHub or GitLab show one.
    Issue,
    /// A ticket and its status, as Jira or Azure DevOps show one.
    TicketStatus,
    /// Shows the planned meeting as a scheduled item with its time and participants.
    CalendarEvent,
    /// An email as a mail program shows it.
    Email,
    /// A text message as a phone shows it.
    TextMessage,
}

impl PreviewKind {
    /// The kind's name, as the dashboard knows it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ChatMessage => "chat_message",
            Self::Issue => "issue",
            Self::TicketStatus => "ticket_status",
            Self::CalendarEvent => "calendar_event",
            Self::Email => "email",
            Self::TextMessage => "text_message",
        }
    }
}

/// The part of a preview an input fills.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PreviewPart {
    /// Its heading: a title, a subject or a summary.
    Title,
    /// Its main text.
    Body,
    /// Where it goes: a channel, a recipient or a calendar.
    Place,
    /// Who sends it.
    Sender,
    /// Its labels or tags.
    Labels,
    /// The status it moves to.
    Status,
    /// When it starts.
    Start,
    /// When it ends.
    End,
}

impl PreviewPart {
    /// The part's name, as the dashboard knows it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Title => "title",
            Self::Body => "body",
            Self::Place => "place",
            Self::Sender => "sender",
            Self::Labels => "labels",
            Self::Status => "status",
            Self::Start => "start",
            Self::End => "end",
        }
    }
}

/// How a step's inputs are previewed: a kind, and which input fills which
/// part of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preview {
    kind: PreviewKind,
    parts: Vec<(PreviewPart, FieldName)>,
}

impl Preview {
    /// A preview of `kind` whose parts the inputs named fill.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when it fills one part twice.
    pub fn new(
        kind: PreviewKind,
        parts: Vec<(PreviewPart, FieldName)>,
    ) -> Result<Self, DomainError> {
        if first_repeat(parts.iter().map(|(part, _)| *part)).is_some() {
            return Err(DomainError::invalid(message!(
                "workflows-a-preview-fills-each-part-once",
                "a preview fills each part once"
            )));
        }
        Ok(Self { kind, parts })
    }

    /// The presentation layout used to show mapped inputs before execution.
    #[must_use]
    pub fn kind(&self) -> PreviewKind {
        self.kind
    }

    /// Which input fills which part.
    #[must_use]
    pub fn parts(&self) -> &[(PreviewPart, FieldName)] {
        &self.parts
    }
}

text_value! {
    /// An integration's brand colour, as six lowercase hex digits such as
    /// `4a154b`, dark enough that a white mark on it stays readable.
    pub struct BrandColor;
}

impl TextValue for BrandColor {
    const FIELD: &'static str = "brand_color";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .length(6..=6)
            .charset(Charset::DIGIT | Charset::HEX_LETTER)
            .rule(&ReadableUnderWhite)
    }
}

/// Refuses a colour white keeps less than `MIN_BRAND_CONTRAST` on.
struct ReadableUnderWhite;

impl Rule for ReadableUnderWhite {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        if contrast_with_white(value) >= MIN_BRAND_CONTRAST {
            return None;
        }
        Some(ValidationError::Custom {
            field,
            code: "too_light".to_owned(),
            message: message!(
                "workflows-a-brand-colour-is-too-light",
                format!("#{value} is too light for a white mark on it to be read")
            ),
        })
    }
}

/// Refuses a choice of too few or too many options, or one offering an
/// option twice.
fn ensure_choices_fit(choices: &[Choice]) -> Result<(), DomainError> {
    validate_count("choices", choices.len(), MIN_CHOICES..=MAX_CHOICES)?;
    if first_repeat(choices.iter().map(Choice::value)).is_some() {
        return Err(DomainError::invalid(message!(
            "workflows-a-choice-offers-each-option-once",
            "a choice offers each option once"
        )));
    }
    Ok(())
}

/// How much white stands out against the colour `hex`, from 1 (none) to 21,
/// by the relative luminance WCAG defines.
fn contrast_with_white(hex: &str) -> f64 {
    let luminance: f64 = [0..2, 2..4, 4..6]
        .into_iter()
        .zip([0.2126, 0.7152, 0.0722])
        .map(|(digits, weight)| {
            let byte = hex
                .get(digits)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .unwrap_or(0);
            weight * linear(f64::from(byte) / 255.0)
        })
        .sum();
    1.05 / (luminance + 0.05)
}

/// A colour channel from its stored value to its share of light.
fn linear(channel: f64) -> f64 {
    if channel <= 0.039_28 {
        return channel / 12.92;
    }
    ((channel + 0.055) / 1.055).powf(2.4)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn choice(value: &str) -> Choice {
        Choice::new(
            ChoiceValue::new(value).unwrap(),
            Label::new("label", value).unwrap(),
            Tone::Neutral,
        )
    }

    fn choices(values: &[&str]) -> InputFormParams {
        InputFormParams {
            block: Block::Choices(values.iter().map(|value| choice(value)).collect()),
            label: Label::new("label", "Why it is closed").unwrap(),
            example: None,
            group: FormGroup::Main,
            style: InputStyle::Normal,
            warning: None,
        }
    }

    /// A choice of two options, each once, is a form.
    #[test]
    fn a_choice_of_distinct_options_is_a_form() {
        let form = InputForm::new(choices(&["completed", "not_planned"])).unwrap();

        assert_eq!(form.block().as_str(), "choices");
    }

    /// Choice forms reject a single option, nine options and a repeated value.
    #[test]
    fn a_choice_that_is_no_real_choice_is_refused() {
        let nine = ["a", "b", "c", "d", "e", "f", "g", "h", "i"];

        for wrong in [&["done"][..], &nine[..], &["done", "done"][..]] {
            assert!(InputForm::new(choices(wrong)).is_err(), "{wrong:?}");
        }
    }

    /// Slack's purple, GitHub's near black and Jira's blue keep a white
    /// mark readable; a pale yellow does not, and neither does a colour
    /// written with a hash or in capitals.
    #[test]
    fn a_brand_colour_must_keep_white_readable() {
        for dark in ["4a154b", "24292f", "0052cc"] {
            assert!(BrandColor::new(dark).is_ok(), "{dark}");
        }
        for wrong in ["fbca04", "#4a154b", "4A154B", "fff"] {
            assert!(BrandColor::new(wrong).is_err(), "{wrong}");
        }
    }

    /// An issue preview cannot map two inputs to its title.
    #[test]
    fn a_preview_fills_each_part_once() {
        let title = FieldName::new("title").unwrap();
        let summary = FieldName::new("summary").unwrap();

        let twice = Preview::new(
            PreviewKind::Issue,
            vec![(PreviewPart::Title, title), (PreviewPart::Title, summary)],
        );

        assert!(twice.is_err());
    }
}
