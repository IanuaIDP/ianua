//! Passwords, held to a tenant's password policy.

use crate::message;
use crate::shared::validation::error::ValidationError;
use crate::shared::validation::rule::Rule;
use crate::shared::validation::validator::Validator;
use crate::types::PasswordPolicy;
use crate::types::password_policy::{CharacterRule, MAX_PASSWORD_CHARS};

impl Validator<'_> {
    /// Checks a password against a tenant's [`PasswordPolicy`].
    ///
    /// Only the character rules the tenant turned on are checked. The rules:
    /// - not empty
    /// - character count within `min_length..=MAX_PASSWORD_CHARS`
    /// - an uppercase letter in any script, if the policy asks for one
    /// - a lowercase letter in any script, if the policy asks for one
    /// - an ASCII digit, if the policy asks for one
    /// - a character that is neither a letter, a digit nor whitespace, if
    ///   the policy asks for one
    #[must_use]
    pub fn password(self, policy: &PasswordPolicy) -> Self {
        let require = policy.require();
        let classes: [(CharacterRule, &dyn Rule); 4] = [
            (require.uppercase, &RequireUppercase),
            (require.lowercase, &RequireLowercase),
            (require.digit, &RequireDigit),
            (require.special, &RequireSpecial),
        ];
        let rule_refs: Vec<&dyn Rule> = classes
            .into_iter()
            .filter(|(rule, _)| *rule == CharacterRule::Required)
            .map(|(_, check)| check)
            .collect();

        self.not_empty()
            .char_length(usize::from(policy.min_length())..=MAX_PASSWORD_CHARS)
            .rules(&rule_refs)
    }
}

/// Requires at least one uppercase letter, in any script.
struct RequireUppercase;

impl Rule for RequireUppercase {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        if value.chars().any(char::is_uppercase) {
            return None;
        }
        Some(ValidationError::Custom {
            field,
            code: "missing_uppercase".to_owned(),
            message: message!(
                "values-must-contain-at-least-one-uppercase",
                format!("{field} must contain at least one uppercase letter.")
            ),
        })
    }
}

/// Requires at least one lowercase letter, in any script.
struct RequireLowercase;

impl Rule for RequireLowercase {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        if value.chars().any(char::is_lowercase) {
            return None;
        }
        Some(ValidationError::Custom {
            field,
            code: "missing_lowercase".to_owned(),
            message: message!(
                "values-must-contain-at-least-one-lowercase",
                format!("{field} must contain at least one lowercase letter.")
            ),
        })
    }
}

/// Requires at least one ASCII digit.
struct RequireDigit;

impl Rule for RequireDigit {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        if value.bytes().any(|b| b.is_ascii_digit()) {
            return None;
        }
        Some(ValidationError::Custom {
            field,
            code: "missing_digit".to_owned(),
            message: message!(
                "values-must-contain-at-least-one-digit",
                format!("{field} must contain at least one digit.")
            ),
        })
    }
}

/// Requires at least one character that is neither a letter, a digit nor
/// whitespace, such as punctuation or a symbol.
struct RequireSpecial;

impl Rule for RequireSpecial {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        if value
            .chars()
            .any(|c| !c.is_alphanumeric() && !c.is_whitespace())
        {
            return None;
        }
        Some(ValidationError::Custom {
            field,
            code: "missing_special".to_owned(),
            message: message!(
                "values-must-contain-at-least-one-special",
                format!("{field} must contain at least one special character.")
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CharacterRequirements;

    fn strict_policy() -> PasswordPolicy {
        PasswordPolicy::unchecked(10, CharacterRequirements::strict())
    }

    fn relaxed_policy() -> PasswordPolicy {
        PasswordPolicy::unchecked(6, CharacterRequirements::none())
    }

    fn has(errors: &[ValidationError], code: &str) -> bool {
        errors.iter().any(|e| e.code() == code)
    }

    /// `MyStr0ng!Pass` has 13 characters, an uppercase and a lowercase
    /// letter, a digit and a symbol. It passes the strict ten-character
    /// policy.
    #[test]
    fn password_strong_passes_strict() {
        assert!(
            Validator::new("password", "MyStr0ng!Pass")
                .password(&strict_policy())
                .validate()
                .is_empty()
        );
    }

    /// `simple` passes a six-character policy that asks for no character
    /// classes.
    #[test]
    fn password_simple_passes_relaxed() {
        assert!(
            Validator::new("password", "simple")
                .password(&relaxed_policy())
                .validate()
                .is_empty()
        );
    }

    /// An empty password is refused with the code `required`.
    #[test]
    fn password_rejects_empty() {
        assert!(has(
            &Validator::new("password", "")
                .password(&strict_policy())
                .validate(),
            "required",
        ));
    }

    /// An eight-character password with every class is still refused under
    /// a ten-character minimum, with `invalid_length`.
    #[test]
    fn password_rejects_too_short() {
        assert!(has(
            &Validator::new("password", "Aa1!xxxx")
                .password(&strict_policy())
                .validate(),
            "invalid_length",
        ));
    }

    /// Under the strict policy, a password with no uppercase letter is
    /// refused with `missing_uppercase`.
    #[test]
    fn password_rejects_missing_uppercase() {
        assert!(has(
            &Validator::new("password", "mystr0ng!pass")
                .password(&strict_policy())
                .validate(),
            "missing_uppercase",
        ));
    }

    /// Under the strict policy, a password with no digit is refused with
    /// `missing_digit`.
    #[test]
    fn password_rejects_missing_digit() {
        assert!(has(
            &Validator::new("password", "MyStrong!Pass")
                .password(&strict_policy())
                .validate(),
            "missing_digit",
        ));
    }

    /// Under the strict policy, a password of only letters and digits is
    /// refused with `missing_special`.
    #[test]
    fn password_rejects_missing_special() {
        assert!(has(
            &Validator::new("password", "MyStr0ngPasss")
                .password(&strict_policy())
                .validate(),
            "missing_special",
        ));
    }

    /// A 129-character password is refused with `invalid_length`, one past
    /// [`MAX_PASSWORD_CHARS`].
    #[test]
    fn password_rejects_over_128() {
        let pw = "Aa1!".to_owned() + &"x".repeat(125);
        assert!(has(
            &Validator::new("password", &pw)
                .password(&strict_policy())
                .validate(),
            "invalid_length",
        ));
    }

    /// `aaaa` breaks four strict rules at once. All four errors come back,
    /// so the person can fix everything in one try.
    #[test]
    fn password_collects_all_failures() {
        let e = Validator::new("password", "aaaa")
            .password(&strict_policy())
            .validate();
        assert!(has(&e, "invalid_length"));
        assert!(has(&e, "missing_uppercase"));
        assert!(has(&e, "missing_digit"));
        assert!(has(&e, "missing_special"));
    }

    /// `abcdef` passes the relaxed policy, which asks for no uppercase,
    /// digit or symbol.
    #[test]
    fn password_relaxed_allows_all_lowercase() {
        assert!(
            Validator::new("password", "abcdef")
                .password(&relaxed_policy())
                .validate()
                .is_empty()
        );
    }

    /// Each ASCII punctuation mark, on its own, meets a policy that asks only
    /// for a special character.
    #[test]
    fn password_recognizes_all_ascii_specials() {
        let special_only = PasswordPolicy::unchecked(
            1,
            CharacterRequirements {
                uppercase: CharacterRule::Optional,
                lowercase: CharacterRule::Optional,
                digit: CharacterRule::Optional,
                special: CharacterRule::Required,
            },
        );
        let specials = [
            "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "-", "_", "=", "+", "[", "]", "{",
            "}", "|", "\\", ";", ":", "'", "\"", ",", ".", "<", ">", "/", "?", "`", "~",
        ];
        for s in specials {
            assert!(
                Validator::new("password", s)
                    .password(&special_only)
                    .validate()
                    .is_empty(),
                "expected '{s}' to be recognized as special"
            );
        }
    }

    /// A single space does not count as a special character, so the policy
    /// refuses it with `missing_special`.
    #[test]
    fn password_space_is_not_special() {
        let p = PasswordPolicy::unchecked(
            1,
            CharacterRequirements {
                special: CharacterRule::Required,
                ..CharacterRequirements::none()
            },
        );
        assert!(has(
            &Validator::new("password", " ").password(&p).validate(),
            "missing_special",
        ));
    }

    /// The Cyrillic letter `а` meets a policy that asks for a lowercase
    /// letter. A person typing in their own script need not switch to Latin.
    #[test]
    fn password_cyrillic_satisfies_lowercase() {
        let p = PasswordPolicy::unchecked(
            1,
            CharacterRequirements {
                lowercase: CharacterRule::Required,
                ..CharacterRequirements::none()
            },
        );
        assert!(
            Validator::new("password", "\u{0430}")
                .password(&p)
                .validate()
                .is_empty()
        );
    }

    /// The fullwidth digit one does not meet a policy that asks for a digit.
    /// Only ASCII `0` to `9` count.
    #[test]
    fn password_fullwidth_digit_does_not_satisfy_ascii_digit() {
        let p = PasswordPolicy::unchecked(
            1,
            CharacterRequirements {
                digit: CharacterRule::Required,
                ..CharacterRequirements::none()
            },
        );
        assert!(has(
            &Validator::new("password", "\u{FF11}")
                .password(&p)
                .validate(),
            "missing_digit",
        ));
    }

    /// A password that looks like SQL injection is a valid password. It is
    /// never put into a query, so refusing it would only weaken the choice.
    #[test]
    fn password_sql_injection_is_valid() {
        assert!(
            Validator::new("password", "' OR 1=1; DROP TABLE users;--Aa1!")
                .password(&strict_policy())
                .validate()
                .is_empty()
        );
    }

    /// A password holding a `<script>` tag passes the strict policy. It is
    /// never shown on a page.
    #[test]
    fn password_xss_is_valid() {
        assert!(
            Validator::new("password", "<script>alert(1)</script>Aa1!")
                .password(&strict_policy())
                .validate()
                .is_empty()
        );
    }

    /// The strict policy rejects a 10,004-character password for exceeding its length limit.
    #[test]
    fn password_rejects_extremely_long() {
        let pw = "Aa1!".to_owned() + &"x".repeat(10000);
        assert!(has(
            &Validator::new("password", &pw)
                .password(&strict_policy())
                .validate(),
            "invalid_length",
        ));
    }

    /// A password of six key and lock emoji passes the relaxed policy. The
    /// length counts characters, not bytes.
    #[test]
    fn password_emoji_passes_relaxed() {
        assert!(
            Validator::new("password", "🔑🔒🔓🛡️🗝️🔐")
                .password(&relaxed_policy())
                .validate()
                .is_empty()
        );
    }

    /// Every error for an empty password names the field `password`, so a
    /// form can mark the right input.
    #[test]
    fn password_errors_carry_field_name() {
        for err in &Validator::new("password", "")
            .password(&strict_policy())
            .validate()
        {
            assert_eq!(err.field(), Some("password"));
        }
    }
}
