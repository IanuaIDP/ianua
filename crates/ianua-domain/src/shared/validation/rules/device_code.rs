//! The code a person types to approve a device sign-in.

use crate::shared::validation::charset::Charset;
use crate::shared::validation::validator::Validator;

impl Validator<'_> {
    /// Checks the short code a person types to approve a device sign-in.
    ///
    /// This is the RFC 8628 `user_code`. The rules:
    /// - 1 to 20 characters
    /// - uppercase letters, digits and `-` only
    #[must_use]
    pub fn device_user_code(self) -> Self {
        self.not_empty()
            .length(1..=20)
            .charset(Charset::UPPERCASE | Charset::DIGIT | Charset::HYPHEN)
    }
}
