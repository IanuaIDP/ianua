//! Values that must be one of a fixed list: locales, time zones, country
//! codes.

use crate::message;
use crate::shared::validation::error::ValidationError;
use crate::shared::validation::validator::Validator;

impl Validator<'_> {
    /// Requires the value to be one of the lines of `list`, exactly.
    ///
    /// `kind` names what the list holds, for the error message, such as
    /// "IANA time zone".
    #[must_use]
    pub fn listed(mut self, list: &'static str, kind: &'static str) -> Self {
        if list.lines().any(|line| line == self.value) {
            return self;
        }
        self.errors.push(ValidationError::Custom {
            field: self.field,
            code: format!("unknown_{}", self.field),
            message: message!(
                "values-is-not-a-recognized",
                format!(
                    "{} '{}' is not a recognized {kind}.",
                    self.field, self.value
                )
            ),
        });
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COLOURS: &str = "red\ngreen\n";

    /// `green` is one of the lines of the colour list, so it passes.
    #[test]
    fn a_listed_value_is_accepted() {
        assert!(
            Validator::new("colour", "green")
                .listed(COLOURS, "colour")
                .validate_first()
                .is_ok()
        );
    }

    /// `gre` is only the start of `green`, so it is refused. The error code
    /// is `unknown_colour`, built from the field name.
    #[test]
    fn a_value_not_on_the_list_is_refused_with_its_own_code() {
        let error = Validator::new("colour", "gre")
            .listed(COLOURS, "colour")
            .validate_first()
            .unwrap_err();

        assert_eq!(error.code(), "unknown_colour");
    }
}
