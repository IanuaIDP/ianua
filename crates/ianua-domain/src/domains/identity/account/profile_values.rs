//! The values a profile holds beyond the name it shows: the parts of a
//! person's name, the name they go by, their phone number, and what a
//! company's directory records about them.
//!
//! Each feeds a standard claim or attribute: OpenID Connect's
//! `given_name`, `family_name`, `preferred_username` and `phone_number`,
//! and SCIM's `name`, `externalId` and enterprise extension.

use crate::message;
use crate::shared::validation::{Rule, TextValue, ValidationError, Validator, text_value};

/// The most characters a part of a name holds.
const MAX_NAME_CHARS: usize = 100;

/// The most characters a name a person goes by holds.
const MAX_USERNAME_CHARS: usize = 64;

/// The most characters an id from another directory holds.
const MAX_EXTERNAL_ID_CHARS: usize = 255;

/// The most characters an employee number holds.
const MAX_EMPLOYEE_NUMBER_CHARS: usize = 64;

/// The fewest characters a phone number in international form holds: the
/// `+` and seven digits, a country code and a short subscriber number.
const MIN_PHONE_LENGTH: usize = 8;

/// The most characters a phone number holds: the `+` and the fifteen
/// digits E.164 allows.
const MAX_PHONE_LENGTH: usize = 16;

text_value! {
    /// A person's given name, such as `Ann`. OpenID Connect's `given_name`
    /// and SCIM's `name.givenName`.
    pub struct GivenName;
}

impl TextValue for GivenName {
    const FIELD: &'static str = "given_name";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.free_text(MAX_NAME_CHARS)
    }
}

text_value! {
    /// A person's family name, such as `Lovelace`. OpenID Connect's
    /// `family_name` and SCIM's `name.familyName`.
    pub struct FamilyName;
}

impl TextValue for FamilyName {
    const FIELD: &'static str = "family_name";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.free_text(MAX_NAME_CHARS)
    }
}

text_value! {
    /// The short name a person goes by, such as `ann.l`. OpenID Connect's
    /// `preferred_username`.
    ///
    /// It is one word, so an app showing it after an `@` shows all of it.
    /// It is not unique and names nobody for sure: two people may pick the
    /// same one, so no app keys an account by it.
    pub struct PreferredUsername;
}

impl TextValue for PreferredUsername {
    const FIELD: &'static str = "preferred_username";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.free_text(MAX_USERNAME_CHARS).no_whitespace()
    }
}

text_value! {
    /// A phone number in international form, E.164: a `+`, the country code
    /// and the number, such as `+4930123456`.
    ///
    /// Spaces, hyphens, dots and brackets a person types between the digits
    /// are dropped, so `+49 (30) 123-456` is kept as `+4930123456`. The number
    /// is what its holder or an editor wrote: nobody proved it reaches them.
    pub struct PhoneNumber;
}

impl TextValue for PhoneNumber {
    const FIELD: &'static str = "phone_number";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .not_empty()
            .ascii_only()
            .length(MIN_PHONE_LENGTH..=MAX_PHONE_LENGTH)
            .rule(&InternationalForm)
    }

    fn normalized(value: String) -> String {
        value
            .chars()
            .filter(|c| !matches!(c, ' ' | '-' | '.' | '(' | ')'))
            .collect()
    }
}

/// A `+` followed by digits only, the first of them not a zero, as every
/// E.164 country code starts.
struct InternationalForm;

impl Rule for InternationalForm {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let digits = value.strip_prefix('+').unwrap_or_default();
        let only_digits = digits.bytes().all(|b| b.is_ascii_digit());
        let country_code_first = !digits.starts_with('0');
        if value.starts_with('+') && only_digits && country_code_first {
            return None;
        }
        Some(ValidationError::Custom {
            field,
            code: "not_e164".to_owned(),
            message: message!(
                "identity-must-be-a-followed-by-the",
                "must be a + followed by the country code and the number"
            ),
        })
    }
}

text_value! {
    /// What another directory calls an account, such as Okta's or Entra's
    /// id for the person. SCIM's `externalId`.
    ///
    /// The directory that provisions the account sets it and matches its
    /// records on it. It is kept exactly as sent, case included.
    pub struct ExternalId;
}

impl TextValue for ExternalId {
    const FIELD: &'static str = "external_id";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.free_text(MAX_EXTERNAL_ID_CHARS)
    }
}

text_value! {
    /// The department a person works in, such as `Finance`. SCIM's
    /// enterprise `department`.
    pub struct Department;
}

impl TextValue for Department {
    const FIELD: &'static str = "department";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.free_text(MAX_NAME_CHARS)
    }
}

text_value! {
    /// The number a company knows a person by, such as `E-1042`. SCIM's
    /// enterprise `employeeNumber`.
    pub struct EmployeeNumber;
}

impl TextValue for EmployeeNumber {
    const FIELD: &'static str = "employee_number";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.free_text(MAX_EMPLOYEE_NUMBER_CHARS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ann types `+49 (30) 123-456`. It is kept as `+4930123456`, the form
    /// every app reads the same way.
    #[test]
    fn a_phone_number_is_kept_without_its_separators() {
        let number = PhoneNumber::new("+49 (30) 123-456").unwrap();

        assert_eq!(number.as_str(), "+4930123456");
    }

    /// A number without its country code, one with letters, one whose
    /// country code starts with zero, and one past fifteen digits are each
    /// refused.
    #[test]
    fn a_phone_number_not_in_international_form_is_refused() {
        for written in [
            "030123456",
            "+49 30 CALL ME",
            "+0049301234",
            "+1234567890123456",
            "+12345",
            "",
        ] {
            assert!(PhoneNumber::new(written).is_err(), "{written} was accepted");
        }
    }

    /// `+14155550123`, a US number, has eleven digits and is accepted.
    #[test]
    fn a_phone_number_with_its_country_code_is_accepted() {
        assert!(PhoneNumber::new("+14155550123").is_ok());
    }

    /// A preferred username containing a space is refused, while `ann.l`
    /// remains valid as a single name.
    #[test]
    fn a_preferred_username_is_one_word() {
        assert!(PreferredUsername::new("ann admin").is_err());
        assert!(PreferredUsername::new("ann.l").is_ok());
    }

    /// A given name containing a line break is refused; an ordinary family
    /// name remains valid.
    #[test]
    fn a_name_part_holds_no_line_break() {
        assert!(GivenName::new("Ann\nAdmin").is_err());
        assert!(FamilyName::new("Lovelace").is_ok());
    }

    /// Okta sends `00u1abCD` as the external id. It is kept with its case,
    /// since the directory matches on it exactly.
    #[test]
    fn an_external_id_keeps_its_case() {
        assert_eq!(ExternalId::new("00u1abCD").unwrap().as_str(), "00u1abCD");
    }

    /// A blank department and a blank employee number are refused, so
    /// clearing one is saying so, never sending a space.
    #[test]
    fn a_blank_directory_value_is_refused() {
        assert!(Department::new("  ").is_err());
        assert!(EmployeeNumber::new("").is_err());
    }
}
