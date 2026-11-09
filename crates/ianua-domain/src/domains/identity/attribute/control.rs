//! The form control a client renders for an attribute.
//!
//! It only says how the field looks. It never reaches a query. What may be
//! stored, filtered or sorted comes from the attribute's
//! [`ValueType`](crate::domains::identity::attribute::ValueType) and its permissions instead. So someone
//! who changes a control gets a different form and no more access.
//!
//! It lives in the domain so every client agrees on it. Otherwise each front
//! end would guess on its own which attribute gets a dropdown, and they
//! would drift apart.

/// A form control for entering an attribute's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum AttributeControl {
    /// A single-line text box.
    TextInput,
    /// A multi-line text area.
    TextArea,
    /// A number box with up and down buttons.
    NumberInput,
    /// A number box shown as an amount of money.
    CurrencyInput,
    /// A number box shown as a percentage.
    PercentInput,
    /// A slider across the attribute's allowed range.
    Slider,
    /// An on/off switch.
    Toggle,
    /// A single checkbox.
    Checkbox,
    /// A dropdown offering one of the declared options.
    Select,
    /// Radio buttons offering one of the declared options.
    RadioGroup,
    /// A dropdown accepting several of the declared options.
    MultiSelect,
    /// Checkboxes accepting several of the declared options.
    CheckboxGroup,
    /// A box where any tags are typed and added.
    TagInput,
    /// A calendar picker.
    DatePicker,
    /// A calendar picker that also takes a time of day.
    DateTimePicker,
    /// A text box validated as an email address.
    EmailInput,
    /// A text box validated as a telephone number.
    PhoneInput,
    /// A text box validated as a link.
    UrlInput,
    /// A colour swatch picker.
    ColourPicker,
    /// A dropdown of countries.
    CountrySelect,
    /// A row of stars.
    StarRating,
}

impl AttributeControl {
    /// Every control, so a caller can offer or read back the whole set
    /// without its own copy of the list.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::TextInput,
            Self::TextArea,
            Self::NumberInput,
            Self::CurrencyInput,
            Self::PercentInput,
            Self::Slider,
            Self::Toggle,
            Self::Checkbox,
            Self::Select,
            Self::RadioGroup,
            Self::MultiSelect,
            Self::CheckboxGroup,
            Self::TagInput,
            Self::DatePicker,
            Self::DateTimePicker,
            Self::EmailInput,
            Self::PhoneInput,
            Self::UrlInput,
            Self::ColourPicker,
            Self::CountrySelect,
            Self::StarRating,
        ]
    }

    /// Reads a stored identifier back.
    ///
    /// It gives `None` for anything that is not a control. The caller reports
    /// that as corrupt data and does not pick a default.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::all().iter().copied().find(|c| c.as_str() == value)
    }

    /// A stable identifier for the control, for clients that switch on it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TextInput => "text_input",
            Self::TextArea => "text_area",
            Self::NumberInput => "number_input",
            Self::CurrencyInput => "currency_input",
            Self::PercentInput => "percent_input",
            Self::Slider => "slider",
            Self::Toggle => "toggle",
            Self::Checkbox => "checkbox",
            Self::Select => "select",
            Self::RadioGroup => "radio_group",
            Self::MultiSelect => "multi_select",
            Self::CheckboxGroup => "checkbox_group",
            Self::TagInput => "tag_input",
            Self::DatePicker => "date_picker",
            Self::DateTimePicker => "date_time_picker",
            Self::EmailInput => "email_input",
            Self::PhoneInput => "phone_input",
            Self::UrlInput => "url_input",
            Self::ColourPicker => "colour_picker",
            Self::CountrySelect => "country_select",
            Self::StarRating => "star_rating",
        }
    }

    /// Whether the control asks the person to pick from a declared list
    /// instead of typing a value.
    ///
    /// An attribute shown this way needs options to offer. An attribute that
    /// declares options needs a control that shows them.
    #[must_use]
    pub fn presents_options(self) -> bool {
        matches!(
            self,
            Self::Select | Self::RadioGroup | Self::MultiSelect | Self::CheckboxGroup
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every control has an identifier no other control uses. Clients pick
    /// the form by this string, so a shared one would show the wrong form.
    #[test]
    fn every_control_has_its_own_identifier() {
        let mut names: Vec<&str> = AttributeControl::all().iter().map(|c| c.as_str()).collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();

        assert_eq!(names.len(), total, "two controls share an identifier");
    }

    /// Select, radio group, multi-select and checkbox group offer a list.
    /// Text, tag, number, toggle and date controls take a typed value.
    #[test]
    fn the_choosing_controls_are_the_ones_that_present_options() {
        for control in [
            AttributeControl::Select,
            AttributeControl::RadioGroup,
            AttributeControl::MultiSelect,
            AttributeControl::CheckboxGroup,
        ] {
            assert!(control.presents_options(), "{control:?} offers a list");
        }

        for control in [
            AttributeControl::TextInput,
            AttributeControl::TagInput,
            AttributeControl::NumberInput,
            AttributeControl::Toggle,
            AttributeControl::DatePicker,
        ] {
            assert!(
                !control.presents_options(),
                "{control:?} takes a typed value"
            );
        }
    }

    /// Each control is stored by its identifier and read back. It must come
    /// back as the same control, or a saved form changes shape.
    #[test]
    fn a_control_survives_the_round_trip() {
        for control in AttributeControl::all() {
            assert_eq!(AttributeControl::parse(control.as_str()), Some(*control));
        }
    }

    /// Stored values such as "", "TextInput" or "dropdown" are not controls.
    /// Each reads back as nothing, never as a default control.
    #[test]
    fn an_unknown_control_is_refused_rather_than_defaulted() {
        for unknown in ["", "TextInput", "text input", "dropdown", "value_text"] {
            assert!(
                AttributeControl::parse(unknown).is_none(),
                "{unknown:?} was read as a control"
            );
        }
    }

    /// Each control turns into JSON as its identifier string and reads back
    /// the same. The wire name and the stored name never differ.
    #[cfg(feature = "serde")]
    #[test]
    fn a_control_serializes_as_its_identifier() {
        for control in AttributeControl::all().iter().copied() {
            let json = serde_json::to_string(&control).unwrap();
            assert_eq!(
                json,
                format!("\"{}\"", control.as_str()),
                "the wire name and the identifier must not diverge"
            );

            let restored: AttributeControl = serde_json::from_str(&json).unwrap();
            assert_eq!(restored, control);
        }
    }
}
