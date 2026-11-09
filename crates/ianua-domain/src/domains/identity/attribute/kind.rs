//! What kind of thing an attribute holds.
//!
//! This is the one choice an administrator makes. The rest follows from it.
//! It fixes where the value is stored, how it sorts, which comparisons a
//! filter may use, which control a client shows, and what a valid value is.
//!
//! Money, a percentage and a rating out of five are all stored as numbers.
//! But they are filled in very differently. Keeping the kind apart from the
//! storage lets new kinds be added without changing the database schema.

use crate::domains::identity::attribute::control::AttributeControl;
use crate::domains::identity::attribute::value_type::ValueType;
use crate::domains::identity::metadata_value::MetadataValue;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{CountryCode, Email, HexColor, HttpUrl};

/// Whether a kind draws its values from a declared list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionSupport {
    /// Values are typed, not chosen. Declaring options is an error.
    Forbidden,
    /// Values are chosen from a declared list, which must not be empty.
    Required,
}

/// What an administrator may limit a kind's values by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueLimit {
    /// Nothing beyond the kind's own format.
    None,
    /// A maximum length.
    Length,
    /// A lowest and highest allowed value.
    Bounds,
}

/// Everything that follows from a kind, written down once.
///
/// It is data, not one method per question. So the facts about one kind sit
/// together, and a new kind cannot be added with some of them missing.
#[derive(Debug, Clone, Copy)]
pub struct KindSpec {
    /// Where values of this kind are stored.
    pub value_type: ValueType,
    /// Every control this kind may be rendered with, the default first.
    pub controls: &'static [AttributeControl],
    /// Whether values come from a declared list.
    pub options: OptionSupport,
    /// What its values may be limited by.
    pub limit: ValueLimit,
}

impl KindSpec {
    /// The control shown unless the administrator picks another. It is the
    /// first one this kind lists.
    #[must_use]
    pub fn default_control(&self) -> AttributeControl {
        self.controls
            .first()
            .copied()
            .unwrap_or(AttributeControl::TextInput)
    }
}

/// The facts about each kind, one constant per kind.
mod specs {
    use crate::domains::identity::attribute::control::AttributeControl as C;
    use crate::domains::identity::attribute::kind::{KindSpec, OptionSupport, ValueLimit};
    use crate::domains::identity::attribute::value_type::ValueType as V;

    const fn typed(v: V, controls: &'static [C], limit: ValueLimit) -> KindSpec {
        KindSpec {
            value_type: v,
            controls,
            options: OptionSupport::Forbidden,
            limit,
        }
    }

    const fn chosen(v: V, controls: &'static [C]) -> KindSpec {
        KindSpec {
            value_type: v,
            controls,
            options: OptionSupport::Required,
            limit: ValueLimit::None,
        }
    }

    pub(super) const TEXT: KindSpec =
        typed(V::Text, &[C::TextInput, C::TextArea], ValueLimit::Length);
    pub(super) const LONG_TEXT: KindSpec = typed(V::Text, &[C::TextArea], ValueLimit::Length);
    pub(super) const WHOLE_NUMBER: KindSpec =
        typed(V::Integer, &[C::NumberInput, C::Slider], ValueLimit::Bounds);
    pub(super) const DECIMAL: KindSpec =
        typed(V::Number, &[C::NumberInput, C::Slider], ValueLimit::Bounds);
    pub(super) const MONEY: KindSpec = typed(
        V::Number,
        &[C::CurrencyInput, C::NumberInput],
        ValueLimit::Bounds,
    );
    pub(super) const PERCENT: KindSpec = typed(
        V::Number,
        &[C::PercentInput, C::Slider, C::NumberInput],
        ValueLimit::Bounds,
    );
    pub(super) const YES_NO: KindSpec =
        typed(V::Boolean, &[C::Toggle, C::Checkbox], ValueLimit::None);
    pub(super) const SINGLE_CHOICE: KindSpec = chosen(V::Text, &[C::Select, C::RadioGroup]);
    pub(super) const MULTIPLE_CHOICE: KindSpec =
        chosen(V::TextArray, &[C::MultiSelect, C::CheckboxGroup]);
    pub(super) const TAGS: KindSpec = typed(V::TextArray, &[C::TagInput], ValueLimit::Length);
    pub(super) const DATE: KindSpec = typed(V::Text, &[C::DatePicker], ValueLimit::None);
    pub(super) const DATE_TIME: KindSpec = typed(V::Text, &[C::DateTimePicker], ValueLimit::None);
    pub(super) const EMAIL: KindSpec =
        typed(V::Text, &[C::EmailInput, C::TextInput], ValueLimit::None);
    pub(super) const PHONE: KindSpec =
        typed(V::Text, &[C::PhoneInput, C::TextInput], ValueLimit::None);
    pub(super) const LINK: KindSpec =
        typed(V::Text, &[C::UrlInput, C::TextInput], ValueLimit::None);
    pub(super) const COLOUR: KindSpec =
        typed(V::Text, &[C::ColourPicker, C::TextInput], ValueLimit::None);
    pub(super) const COUNTRY: KindSpec = typed(V::Text, &[C::CountrySelect], ValueLimit::None);
    pub(super) const RATING: KindSpec = typed(
        V::Integer,
        &[C::StarRating, C::NumberInput],
        ValueLimit::None,
    );
}

/// What kind of thing a custom user attribute holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum AttributeKind {
    /// A short line of text.
    Text,
    /// Several lines of text.
    LongText,
    /// A whole number, such as a headcount.
    WholeNumber,
    /// A number with a fractional part.
    Decimal,
    /// An amount of money.
    Money,
    /// A proportion, entered as a percentage.
    Percent,
    /// True or false.
    YesNo,
    /// One option from a declared list.
    SingleChoice,
    /// Several options from a declared list.
    MultipleChoice,
    /// Any tags the person types, not drawn from a list.
    Tags,
    /// A calendar date.
    Date,
    /// A date and a time of day.
    DateTime,
    /// An email address.
    Email,
    /// A telephone number.
    Phone,
    /// Text validated as a web address before an attribute accepts it.
    Link,
    /// Text validated as a hexadecimal display color.
    Colour,
    /// Text validated as a country code.
    Country,
    /// A rating out of five.
    Rating,
}

/// A text format: whether a value meets it, and how to describe one that does.
type TextFormat = (fn(&str) -> bool, &'static str);

/// Lowest and highest rating a star control can show.
const RATING_RANGE: (i64, i64) = (1, 5);

/// Characters a telephone number may be written with.
const PHONE_CHARS: &str = "+()- ";

/// Longest telephone number accepted, in characters.
const PHONE_MAX: usize = 32;

/// Shortest telephone number accepted, in characters.
const PHONE_MIN: usize = 5;

impl AttributeKind {
    /// Every kind, so a client can offer the list without its own copy.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::Text,
            Self::LongText,
            Self::WholeNumber,
            Self::Decimal,
            Self::Money,
            Self::Percent,
            Self::YesNo,
            Self::SingleChoice,
            Self::MultipleChoice,
            Self::Tags,
            Self::Date,
            Self::DateTime,
            Self::Email,
            Self::Phone,
            Self::Link,
            Self::Colour,
            Self::Country,
            Self::Rating,
        ]
    }

    /// The name stored in the `kind` column.
    ///
    /// Each name is written out, not taken from the variant name. So renaming
    /// a variant changes only Rust code and needs no migration.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::LongText => "long_text",
            Self::WholeNumber => "whole_number",
            Self::Decimal => "decimal",
            Self::Money => "money",
            Self::Percent => "percent",
            Self::YesNo => "yes_no",
            Self::SingleChoice => "single_choice",
            Self::MultipleChoice => "multiple_choice",
            Self::Tags => "tags",
            Self::Date => "date",
            Self::DateTime => "date_time",
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Link => "link",
            Self::Colour => "colour",
            Self::Country => "country",
            Self::Rating => "rating",
        }
    }

    /// Reads a stored name back.
    ///
    /// It gives `None` for anything that is not a kind. The caller reports
    /// that as corrupt data. It must not guess, because the kind decides which
    /// column a value lives in.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::all().iter().copied().find(|k| k.as_str() == value)
    }

    /// Everything that follows from this kind.
    #[must_use]
    pub fn spec(self) -> KindSpec {
        match self {
            Self::Text => specs::TEXT,
            Self::LongText => specs::LONG_TEXT,
            Self::WholeNumber => specs::WHOLE_NUMBER,
            Self::Decimal => specs::DECIMAL,
            Self::Money => specs::MONEY,
            Self::Percent => specs::PERCENT,
            Self::YesNo => specs::YES_NO,
            Self::SingleChoice => specs::SINGLE_CHOICE,
            Self::MultipleChoice => specs::MULTIPLE_CHOICE,
            Self::Tags => specs::TAGS,
            Self::Date => specs::DATE,
            Self::DateTime => specs::DATE_TIME,
            Self::Email => specs::EMAIL,
            Self::Phone => specs::PHONE,
            Self::Link => specs::LINK,
            Self::Colour => specs::COLOUR,
            Self::Country => specs::COUNTRY,
            Self::Rating => specs::RATING,
        }
    }

    /// Where values of this kind are stored.
    #[must_use]
    pub fn value_type(self) -> ValueType {
        self.spec().value_type
    }

    /// The control shown unless another is chosen.
    #[must_use]
    pub fn default_control(self) -> AttributeControl {
        self.spec().default_control()
    }

    /// Whether this kind may be shown with `control`.
    #[must_use]
    pub fn permits_control(self, control: AttributeControl) -> bool {
        self.spec().controls.contains(&control)
    }

    /// Whether values of this kind are chosen from a declared list.
    #[must_use]
    pub fn requires_options(self) -> bool {
        self.spec().options == OptionSupport::Required
    }

    /// Whether a maximum length may be declared.
    #[must_use]
    pub fn permits_length_limit(self) -> bool {
        self.spec().limit == ValueLimit::Length
    }

    /// Whether a lowest and highest allowed value may be declared.
    #[must_use]
    pub fn permits_bounds(self) -> bool {
        self.spec().limit == ValueLimit::Bounds
    }

    /// Whether a user list may be sorted by this kind.
    #[must_use]
    pub fn is_orderable(self) -> bool {
        self.value_type().is_orderable()
    }

    /// Checks a value against the format this kind needs, on top of its
    /// type.
    ///
    /// [`ValueType::accepts`] checks the type, such as that a number is a
    /// number. This checks more. The text in an email attribute must be an
    /// email address, a date must read as a date, and a rating must be from
    /// one to five.
    ///
    /// Each format uses the value object that already holds the rule. So an
    /// email in a custom attribute is checked the same as the user's own
    /// email.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the value does not meet the format.
    ///   The message says what was expected.
    pub fn check_format(self, value: &MetadataValue) -> Result<(), DomainError> {
        if self == Self::Rating {
            return Self::check_rating(value);
        }
        let Some(format) = self.text_format() else {
            return Ok(());
        };
        Self::check_text(value, format)
    }

    /// The text format this kind's values must meet, if any. It is a check
    /// and a description of a value that passes it.
    fn text_format(self) -> Option<TextFormat> {
        let format: TextFormat = match self {
            Self::Email => (|t| Email::new(t).is_ok(), "an email address"),
            Self::Link => (|t| HttpUrl::new(t).is_ok(), "a link"),
            Self::Colour => (|t| HexColor::new(t).is_ok(), "a colour such as #1a2b3c"),
            Self::Country => (|t| CountryCode::new(t).is_ok(), "a two-letter country code"),
            Self::Date => (|t| parse_iso_date(t).is_some(), "a date such as 2026-09-17"),
            Self::DateTime => (
                |t| parse_iso_date_time(t).is_some(),
                "a date and time such as 2026-09-17T09:30:00Z",
            ),
            Self::Phone => (is_telephone_number, "a telephone number"),
            Self::Text
            | Self::LongText
            | Self::WholeNumber
            | Self::Decimal
            | Self::Money
            | Self::Percent
            | Self::YesNo
            | Self::SingleChoice
            | Self::MultipleChoice
            | Self::Tags
            | Self::Rating => return None,
        };
        Some(format)
    }

    /// Runs a text format check. On failure it says what the value should
    /// have been.
    fn check_text(value: &MetadataValue, (check, expected): TextFormat) -> Result<(), DomainError> {
        let Some(text) = value.as_str() else {
            return Err(DomainError::invalid(message!(
                "identity-value-must-be-text",
                "value must be text"
            )));
        };
        if !check(text) {
            return Err(DomainError::invalid(message!(
                "identity-value-must-be",
                format!("value must be {expected}")
            )));
        }
        Ok(())
    }

    /// Refuses a filter value this kind could never be compared with as
    /// text, such as `2026-9-1` for a date.
    ///
    /// Dates are compared as text, which is right only for the one spelling
    /// they are stored in. Other kinds take any value of their type.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when a date or date-time value is not
    ///   written the way such values are stored.
    pub fn check_filter_value(self, value: &MetadataValue) -> Result<(), DomainError> {
        match self {
            Self::Date | Self::DateTime => self.check_format(value),
            Self::Text
            | Self::LongText
            | Self::WholeNumber
            | Self::Decimal
            | Self::Money
            | Self::Percent
            | Self::YesNo
            | Self::SingleChoice
            | Self::MultipleChoice
            | Self::Tags
            | Self::Email
            | Self::Phone
            | Self::Link
            | Self::Colour
            | Self::Country
            | Self::Rating => Ok(()),
        }
    }

    /// Refuses a rating that is not a whole number from one to five.
    fn check_rating(value: &MetadataValue) -> Result<(), DomainError> {
        let (lowest, highest) = RATING_RANGE;
        let Some(rating) = value.as_i64() else {
            return Err(DomainError::invalid(message!(
                "identity-value-must-be-a-whole-number",
                "value must be a whole number"
            )));
        };

        if !(lowest..=highest).contains(&rating) {
            return Err(DomainError::invalid(message!(
                "identity-value-must-be-between-and",
                format!("value must be between {lowest} and {highest}")
            )));
        }

        Ok(())
    }
}

/// Parses `YYYY-MM-DD`, the only way a date is stored.
///
/// One spelling keeps a text column sortable. ISO dates sort as text in the
/// same order as dates. So a user list sorted by birthday comes out right
/// without a date column. A looser parser would accept `2026-9-7`, which
/// sorts after `2026-10-01`, and the order would be wrong.
///
/// The fields are read by hand so only that one spelling passes. The
/// calendar then refuses a day that does not exist.
fn parse_iso_date(text: &str) -> Option<()> {
    let (year, rest) = text.split_once('-')?;
    let (month, day) = rest.split_once('-')?;
    if (year.len(), month.len(), day.len()) != (4, 2, 2) {
        return None;
    }

    let year: i32 = digits(year)?.try_into().ok()?;
    let month: u8 = digits(month)?.try_into().ok()?;
    let day: u8 = digits(day)?.try_into().ok()?;

    time::Date::from_calendar_date(year, time::Month::try_from(month).ok()?, day)
        .ok()
        .map(|_| ())
}

/// Reads a run of ASCII digits and refuses anything else. That includes the
/// `+` sign an integer parser would accept.
fn digits(text: &str) -> Option<u32> {
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }

    text.parse().ok()
}

/// Parses a date and time written as `2026-09-17T09:30:00Z`: in UTC, to the
/// second.
///
/// One spelling only. Filters compare stored values as text, so
/// `09:30:00+02:00` beside `08:00:00Z` would put an earlier moment after a
/// later one.
fn parse_iso_date_time(text: &str) -> Option<()> {
    let (date, clock) = text.split_once('T')?;
    parse_iso_date(date)?;
    let clock = clock.strip_suffix('Z')?;
    let mut parts = clock.split(':');
    let (Some(hour), Some(minute), Some(second), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if (hour.len(), minute.len(), second.len()) != (2, 2, 2) {
        return None;
    }
    let part = |text: &str| digits(text).and_then(|n| u8::try_from(n).ok());
    time::Time::from_hms(part(hour)?, part(minute)?, part(second)?)
        .ok()
        .map(|_| ())
}

/// Whether `text` reads as a telephone number.
///
/// It is loose about shape. Numbering plans differ by country, and refusing
/// a real foreign number is worse than accepting an odd one. It checks the
/// length is 5 to 32 characters, that only digits and `+()- ` appear, and
/// that there are at least five digits.
fn is_telephone_number(text: &str) -> bool {
    let length = text.chars().count();
    if !(PHONE_MIN..=PHONE_MAX).contains(&length) {
        return false;
    }

    if !text
        .chars()
        .all(|c| c.is_ascii_digit() || PHONE_CHARS.contains(c))
    {
        return false;
    }

    text.chars().filter(char::is_ascii_digit).count() >= PHONE_MIN
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every kind's default control is one that kind allows. Otherwise a
    /// client would show a control the kind refuses when an administrator
    /// picks it by hand.
    #[test]
    fn every_kinds_default_control_is_one_it_permits() {
        for kind in AttributeKind::all() {
            assert!(
                kind.permits_control(kind.default_control()),
                "{kind:?} defaults to a control it refuses"
            );
        }
    }

    /// No kind has an empty control list, so a client always has something
    /// to show.
    #[test]
    fn every_kind_offers_at_least_one_control() {
        for kind in AttributeKind::all() {
            assert!(
                !kind.spec().controls.is_empty(),
                "{kind:?} offers no control"
            );
        }
    }

    /// Each kind lists its default control first. A client showing the
    /// choices puts the suggested one at the top without asking which it is.
    #[test]
    fn the_default_control_is_listed_first() {
        for kind in AttributeKind::all() {
            assert_eq!(
                kind.spec().controls.first(),
                Some(&kind.default_control()),
                "{kind:?} does not lead with its default"
            );
        }
    }

    /// Money may use a currency input but not a toggle. Yes/no may not use a
    /// currency input, and text may not use stars.
    #[test]
    fn a_kind_permits_no_control_outside_its_list() {
        assert!(AttributeKind::Money.permits_control(AttributeControl::CurrencyInput));
        assert!(!AttributeKind::Money.permits_control(AttributeControl::Toggle));
        assert!(!AttributeKind::YesNo.permits_control(AttributeControl::CurrencyInput));
        assert!(!AttributeKind::Text.permits_control(AttributeControl::StarRating));
    }

    /// A kind needs options exactly when its default control shows a list.
    /// A list control with no options, or options with no list control,
    /// would be a broken form.
    #[test]
    fn the_kinds_drawing_from_a_list_are_the_ones_rendered_with_one() {
        for kind in AttributeKind::all() {
            let presents = kind.default_control().presents_options();
            assert_eq!(
                kind.requires_options(),
                presents,
                "{kind:?} disagrees about whether it draws from a list"
            );
        }
    }

    /// Single and multiple choice need declared options. Tags and text do
    /// not.
    #[test]
    fn only_the_choice_kinds_require_options() {
        assert!(AttributeKind::SingleChoice.requires_options());
        assert!(AttributeKind::MultipleChoice.requires_options());
        assert!(!AttributeKind::Tags.requires_options());
        assert!(!AttributeKind::Text.requires_options());
    }

    /// Tags and multiple choice are both stored as a list of text. Only
    /// multiple choice needs declared options, since tags take any text.
    #[test]
    fn tags_and_multiple_choice_store_alike_and_constrain_differently() {
        assert_eq!(
            AttributeKind::Tags.value_type(),
            AttributeKind::MultipleChoice.value_type()
        );
        assert!(!AttributeKind::Tags.requires_options());
        assert!(AttributeKind::MultipleChoice.requires_options());
    }

    /// Only text, long text and tags may declare a maximum length. An email,
    /// a link or a phone number is limited by its own format, and a second
    /// limit would be one rule kept in two places.
    #[test]
    fn a_length_limit_belongs_only_to_the_free_form_text_kinds() {
        for kind in AttributeKind::all() {
            let free_form_text = matches!(
                kind,
                AttributeKind::Text | AttributeKind::LongText | AttributeKind::Tags
            );
            assert_eq!(
                kind.permits_length_limit(),
                free_form_text,
                "{kind:?} disagrees about a length limit"
            );
        }
    }

    /// Email, phone, link, colour, country, date and date-time are stored as
    /// text but take no length limit. A 100-character nonsense value fails
    /// each format, so the format does the limiting.
    #[test]
    fn a_formatted_kind_is_bounded_by_its_format_not_by_a_limit() {
        for kind in [
            AttributeKind::Email,
            AttributeKind::Phone,
            AttributeKind::Link,
            AttributeKind::Colour,
            AttributeKind::Country,
            AttributeKind::Date,
            AttributeKind::DateTime,
        ] {
            assert_eq!(kind.value_type(), ValueType::Text, "{kind:?}");
            assert!(!kind.permits_length_limit(), "{kind:?}");
            assert!(
                kind.check_format(&MetadataValue::from("\u{fffd}".repeat(100)))
                    .is_err(),
                "{kind:?} accepted a long nonsense value, so its format bounds nothing"
            );
        }
    }

    /// Any kind that allows a lowest and highest value is stored as a whole
    /// or decimal number.
    #[test]
    fn bounds_belong_only_to_the_number_kinds() {
        for kind in AttributeKind::all() {
            if kind.permits_bounds() {
                assert!(
                    matches!(kind.value_type(), ValueType::Integer | ValueType::Number),
                    "{kind:?} permits bounds without being a number"
                );
            }
        }
    }

    /// Tags and multiple choice cannot be sorted on. Every other kind can.
    /// A list of values has no single place in a sort order.
    #[test]
    fn only_the_list_kinds_refuse_to_be_ordered() {
        for kind in AttributeKind::all() {
            let is_list = matches!(kind, AttributeKind::Tags | AttributeKind::MultipleChoice);
            assert_eq!(kind.is_orderable(), !is_list, "{kind:?}");
        }
    }

    /// An email attribute accepts ada@example.com. It refuses "not-an-email"
    /// and the number 42.
    #[test]
    fn an_email_attribute_takes_an_email_and_nothing_else() {
        assert!(
            AttributeKind::Email
                .check_format(&MetadataValue::from("ada@example.com"))
                .is_ok()
        );
        assert!(
            AttributeKind::Email
                .check_format(&MetadataValue::from("not-an-email"))
                .is_err()
        );
        assert!(
            AttributeKind::Email
                .check_format(&MetadataValue::from(42_i64))
                .is_err()
        );
    }

    /// A link attribute accepts `https://example.com/a` and refuses
    /// `example.com`, which has no scheme.
    #[test]
    fn a_link_attribute_takes_a_url() {
        assert!(
            AttributeKind::Link
                .check_format(&MetadataValue::from("https://example.com/a"))
                .is_ok()
        );
        assert!(
            AttributeKind::Link
                .check_format(&MetadataValue::from("example.com"))
                .is_err()
        );
    }

    /// A colour attribute accepts `#1a2b3c` and refuses a colour name such as
    /// "cornflower".
    #[test]
    fn a_colour_attribute_takes_a_hex_colour() {
        assert!(
            AttributeKind::Colour
                .check_format(&MetadataValue::from("#1a2b3c"))
                .is_ok()
        );
        assert!(
            AttributeKind::Colour
                .check_format(&MetadataValue::from("cornflower"))
                .is_err()
        );
    }

    /// A country attribute accepts "NL" and refuses the full name
    /// "Netherlands".
    #[test]
    fn a_country_attribute_takes_a_country_code() {
        assert!(
            AttributeKind::Country
                .check_format(&MetadataValue::from("NL"))
                .is_ok()
        );
        assert!(
            AttributeKind::Country
                .check_format(&MetadataValue::from("Netherlands"))
                .is_err()
        );
    }

    /// A date attribute accepts only `2026-09-17`. Other spellings, a
    /// timestamp, a sign or an underscore are refused, so the text column
    /// stays sortable.
    #[test]
    fn a_date_attribute_takes_one_spelling_only() {
        assert!(
            AttributeKind::Date
                .check_format(&MetadataValue::from("2026-09-17"))
                .is_ok()
        );

        for wrong in [
            "17-09-2026",
            "2026/09/17",
            "17 Sep 2026",
            "2026-9-7",
            "2026-09-17T00:00:00Z",
            "+2026-09-17",
            "2026-09-1_",
            "",
        ] {
            assert!(
                AttributeKind::Date
                    .check_format(&MetadataValue::from(wrong))
                    .is_err(),
                "{wrong:?} must be refused"
            );
        }
    }

    /// `2026-9-7` sorts after `2026-10-01` as text. It is refused, not padded,
    /// so a user list is never sorted wrongly without anyone knowing.
    #[test]
    fn a_short_date_would_sort_wrongly_and_is_refused() {
        assert!(
            "2026-9-7" > "2026-10-01",
            "the hazard being guarded against"
        );

        assert!(
            AttributeKind::Date
                .check_format(&MetadataValue::from("2026-9-7"))
                .is_err()
        );
    }

    /// February 30th, month 13, month 0 and January 32nd are refused, not
    /// rounded. February 29th 2024 is a real leap day and passes.
    #[test]
    fn a_date_that_does_not_exist_is_refused() {
        for impossible in ["2026-02-30", "2026-13-01", "2026-00-10", "2026-01-32"] {
            assert!(
                AttributeKind::Date
                    .check_format(&MetadataValue::from(impossible))
                    .is_err(),
                "{impossible} is not a day"
            );
        }

        assert!(
            AttributeKind::Date
                .check_format(&MetadataValue::from("2024-02-29"))
                .is_ok(),
            "a leap day is a day"
        );
    }

    /// Four ISO dates sorted as plain text come out in date order. That is
    /// why only one spelling is allowed.
    #[test]
    fn iso_dates_sort_as_text_in_date_order() {
        let mut dates = ["2026-01-05", "2025-12-31", "2026-01-10", "2026-02-01"];
        dates.sort_unstable();

        assert_eq!(
            dates,
            ["2025-12-31", "2026-01-05", "2026-01-10", "2026-02-01"]
        );
    }

    /// A date-time attribute accepts `2026-09-17T09:30:00Z` and refuses a
    /// bare date.
    #[test]
    fn a_date_time_attribute_takes_a_timestamp() {
        assert!(
            AttributeKind::DateTime
                .check_format(&MetadataValue::from("2026-09-17T09:30:00Z"))
                .is_ok()
        );
        assert!(
            AttributeKind::DateTime
                .check_format(&MetadataValue::from("2026-09-17"))
                .is_err()
        );
    }

    /// Date-time values reject offsets, lowercase separators, fractional
    /// seconds, absent zones and impossible hours, preserving one spelling.
    #[test]
    fn a_date_time_has_one_spelling() {
        for other in [
            "2026-09-17T11:30:00+02:00",
            "2026-09-17t09:30:00Z",
            "2026-09-17T09:30:00.5Z",
            "2026-09-17T09:30:00",
            "2026-09-17T25:00:00Z",
        ] {
            assert!(
                AttributeKind::DateTime
                    .check_format(&MetadataValue::from(other))
                    .is_err(),
                "{other}"
            );
        }
    }

    /// An unpadded date is refused as a date-filter operand but remains
    /// valid for a plain text comparison.
    #[test]
    fn a_date_filter_value_must_be_spelled_as_dates_are_stored() {
        assert!(
            AttributeKind::Date
                .check_filter_value(&MetadataValue::from("2026-9-1"))
                .is_err()
        );
        assert!(
            AttributeKind::Text
                .check_filter_value(&MetadataValue::from("2026-9-1"))
                .is_ok()
        );
    }

    /// "+1 (555) 123-4567" and "0612345678" pass. Words, a two-digit number,
    /// an "ext." suffix and an empty value are refused.
    #[test]
    fn a_phone_attribute_accepts_how_people_write_numbers() {
        for written in [
            "+31 6 12345678",
            "+1 (555) 123-4567",
            "0612345678",
            "555-1234",
        ] {
            assert!(
                AttributeKind::Phone
                    .check_format(&MetadataValue::from(written))
                    .is_ok(),
                "{written:?} should be accepted"
            );
        }

        for wrong in ["not a number", "12", "+31 6 1234 5678 ext. 9", ""] {
            assert!(
                AttributeKind::Phone
                    .check_format(&MetadataValue::from(wrong))
                    .is_err(),
                "{wrong:?} should be refused"
            );
        }
    }

    /// Ratings 1 to 5 pass. 0, 6, -1 and 1000 are refused, since no such
    /// star exists.
    #[test]
    fn a_rating_lands_on_a_star_that_exists() {
        for rating in 1..=5_i64 {
            assert!(
                AttributeKind::Rating
                    .check_format(&MetadataValue::from(rating))
                    .is_ok()
            );
        }

        for rating in [0_i64, 6, -1, 1_000] {
            assert!(
                AttributeKind::Rating
                    .check_format(&MetadataValue::from(rating))
                    .is_err(),
                "{rating} is not a star"
            );
        }
    }

    /// Text, numbers, yes/no, choices and tags have no format of their own.
    /// The format check passes "anything", because the type check runs
    /// separately.
    #[test]
    fn the_plain_kinds_impose_no_format() {
        for kind in [
            AttributeKind::Text,
            AttributeKind::LongText,
            AttributeKind::WholeNumber,
            AttributeKind::Decimal,
            AttributeKind::Money,
            AttributeKind::Percent,
            AttributeKind::YesNo,
            AttributeKind::SingleChoice,
            AttributeKind::MultipleChoice,
            AttributeKind::Tags,
        ] {
            assert!(
                kind.check_format(&MetadataValue::from("anything")).is_ok(),
                "{kind:?} imposed a format it does not have"
            );
        }
    }

    /// Each kind is stored by name and read back as the same kind. The kind
    /// picks the column, so a wrong read would put a salary where a
    /// department is read.
    #[test]
    fn a_kind_survives_the_round_trip() {
        for kind in AttributeKind::all() {
            assert_eq!(AttributeKind::parse(kind.as_str()), Some(*kind));
        }
    }

    /// `WholeNumber`, `SingleChoice` and `DateTime` are stored as
    /// "whole_number", "single_choice" and "date_time". The names are written
    /// out, so renaming a variant needs no migration.
    #[test]
    fn the_stored_discriminants_are_spelled_out() {
        assert_eq!(AttributeKind::WholeNumber.as_str(), "whole_number");
        assert_eq!(AttributeKind::SingleChoice.as_str(), "single_choice");
        assert_eq!(AttributeKind::DateTime.as_str(), "date_time");
    }

    /// No two kinds share a stored name, so each reads back as itself.
    #[test]
    fn every_kind_has_its_own_discriminant() {
        let mut names: Vec<&str> = AttributeKind::all().iter().map(|k| k.as_str()).collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();

        assert_eq!(names.len(), total, "two kinds share a discriminant");
    }

    /// Stored names such as "Money", "MONEY" or "currency" are not kinds.
    /// Each reads back as nothing, never as a default kind.
    #[test]
    fn an_unknown_kind_is_refused_rather_than_defaulted() {
        for unknown in ["", "Money", "MONEY", "currency", "value_float"] {
            assert!(
                AttributeKind::parse(unknown).is_none(),
                "{unknown:?} was read as a kind"
            );
        }
    }

    /// The full list holds all 18 kinds, none twice. A kind added to the enum
    /// but not the list fails here.
    #[test]
    fn all_lists_every_kind_exactly_once() {
        let mut seen = AttributeKind::all().to_vec();
        let total = seen.len();
        seen.sort_unstable_by_key(|k| format!("{k:?}"));
        seen.dedup();

        assert_eq!(seen.len(), total, "a kind is listed twice");
        assert_eq!(total, 18, "a kind was added without being listed");
    }
}
