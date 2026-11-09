//! The rules a password must meet: its length and characters, and what
//! else a new one is checked for.

use time::{Duration, OffsetDateTime};

use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::model::two_cases::two_cases;
use crate::shared::random::RandomSource;
use crate::shared::security::secret::Secret;
use crate::shared::validation::numeric::validate_range;
use crate::shared::validation::{ValidationError, Validator};
use crate::types::Email;

/// The lowest minimum length a policy may set. A shorter password is too
/// easy to guess.
pub const MIN_PASSWORD_LENGTH: u8 = 8;

/// The highest minimum length a policy may set. It fits any passphrase and
/// is still short enough to type.
pub const MAX_PASSWORD_LENGTH: u8 = 128;

/// The longest password accepted, in characters.
///
/// It fits any passphrase. A longer limit would let someone send huge
/// passwords to keep the server busy hashing them.
pub(crate) const MAX_PASSWORD_CHARS: usize = 128;

two_cases! {
    /// Whether a password must hold a character of one class.
    pub enum CharacterRule {
        /// At least one is required.
        Required => true,
        /// None is required.
        Optional => false,
    }
}

/// Which character classes a password must contain.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CharacterRequirements {
    /// Whether at least one uppercase letter is required.
    pub uppercase: CharacterRule,
    /// Whether at least one lowercase letter is required.
    pub lowercase: CharacterRule,
    /// Whether at least one digit is required.
    pub digit: CharacterRule,
    /// Whether at least one special character is required.
    pub special: CharacterRule,
}

impl CharacterRequirements {
    /// All character classes required.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            uppercase: CharacterRule::Required,
            lowercase: CharacterRule::Required,
            digit: CharacterRule::Required,
            special: CharacterRule::Required,
        }
    }

    /// No character class requirements.
    #[must_use]
    pub fn none() -> Self {
        Self {
            uppercase: CharacterRule::Optional,
            lowercase: CharacterRule::Optional,
            digit: CharacterRule::Optional,
            special: CharacterRule::Optional,
        }
    }
}

/// The rules a password must meet in one tenant or organization.
///
/// It matters only when password sign-in, `AuthMethod::Password`, is on.
/// The validator's `password()` check reads its length and character rules.
/// Its [`PasswordHygiene`] says what else a new password is checked for:
/// reuse, age, the person's own name or address, and common passwords.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "StoredPasswordPolicy"))]
pub struct PasswordPolicy {
    /// The shortest password accepted, in characters.
    min_length: u8,
    /// The character classes a password must contain.
    require: CharacterRequirements,
    /// What else a new password is checked for.
    hygiene: PasswordHygiene,
}

/// A policy as stored, before its rules are checked.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct StoredPasswordPolicy {
    min_length: u8,
    require: CharacterRequirements,
    hygiene: PasswordHygiene,
}

#[cfg(feature = "serde")]
impl TryFrom<StoredPasswordPolicy> for PasswordPolicy {
    type Error = ValidationError;

    fn try_from(stored: StoredPasswordPolicy) -> Result<Self, Self::Error> {
        Ok(Self::new(stored.min_length, stored.require)?.with_hygiene(stored.hygiene))
    }
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 12,
            require: CharacterRequirements {
                uppercase: CharacterRule::Required,
                lowercase: CharacterRule::Required,
                digit: CharacterRule::Required,
                special: CharacterRule::Optional,
            },
            hygiene: PasswordHygiene::default(),
        }
    }
}

/// The most earlier passwords a policy may refuse to see again.
pub(crate) const MAX_REUSE_LIMIT: u8 = 24;

/// The longest a policy may let a password live before it must change, in
/// days: two years.
pub(crate) const MAX_EXPIRY_DAYS: u16 = 730;

/// The shortest piece of a person's name or address a password may not
/// hold. Shorter pieces, such as `al`, sit inside too many good passwords.
const MIN_PERSONAL_PIECE: usize = 3;

/// How many of a person's earlier passwords a new one may not repeat, from
/// none to `MAX_REUSE_LIMIT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "u8", into = "u8"))]
pub struct ReuseLimit(u8);

impl ReuseLimit {
    /// Any earlier password may come back.
    pub const NONE: Self = Self(0);

    /// A limit of `count` earlier passwords.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] when `count` is past `MAX_REUSE_LIMIT`.
    pub fn new(count: u8) -> Result<Self, ValidationError> {
        validate_range("password_reuse_limit", count, 0..=MAX_REUSE_LIMIT)?;
        Ok(Self(count))
    }

    /// How many earlier passwords are refused.
    #[must_use]
    pub fn count(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for ReuseLimit {
    type Error = ValidationError;

    fn try_from(count: u8) -> Result<Self, Self::Error> {
        Self::new(count)
    }
}

impl From<ReuseLimit> for u8 {
    fn from(limit: ReuseLimit) -> Self {
        limit.0
    }
}

/// How many days a password lasts, from one to `MAX_EXPIRY_DAYS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "u16", into = "u16"))]
pub struct ExpiryDays(u16);

impl ExpiryDays {
    /// A life of `days` days.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] when `days` is zero or past
    ///   `MAX_EXPIRY_DAYS`.
    pub fn new(days: u16) -> Result<Self, ValidationError> {
        validate_range("password_expiry_days", days, 1..=MAX_EXPIRY_DAYS)?;
        Ok(Self(days))
    }

    /// The life as a duration.
    #[must_use]
    pub fn as_duration(self) -> Duration {
        Duration::days(i64::from(self.0))
    }
}

impl TryFrom<u16> for ExpiryDays {
    type Error = ValidationError;

    fn try_from(days: u16) -> Result<Self, Self::Error> {
        Self::new(days)
    }
}

impl From<ExpiryDays> for u16 {
    fn from(days: ExpiryDays) -> Self {
        days.0
    }
}

/// Whether a password must be changed once it reaches an age.
///
/// NIST SP 800-63B asks for no change on a schedule, only on evidence of
/// compromise, so a new policy never expires. Some regulations still ask
/// for one, so a tenant may choose it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PasswordExpiry {
    /// A password lasts until its holder changes it.
    Never,
    /// A password must be changed once it is this old.
    After(ExpiryDays),
}

impl PasswordExpiry {
    /// Whether a password last changed at `changed_at` must be changed at
    /// `now`.
    #[must_use]
    pub fn is_due(self, changed_at: OffsetDateTime, now: OffsetDateTime) -> bool {
        match self {
            Self::Never => false,
            Self::After(days) => now >= changed_at.saturating_add(days.as_duration()),
        }
    }
}

two_cases! {
    /// Whether a password may hold the person's own name or address.
    pub enum PersonalDataRule {
        /// A password holding a piece of the person's name or address is
        /// refused.
        Refused => true,
        /// Any password is taken.
        Allowed => false,
    }
}

two_cases! {
    /// Whether a password found on a list of common passwords is refused.
    pub enum CommonPasswordRule {
        /// A listed password is refused.
        Refused => true,
        /// Any password is taken.
        Allowed => false,
    }
}

/// What a new password is checked for besides its length and characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PasswordHygiene {
    /// How many earlier passwords a new one may not repeat.
    pub reuse: ReuseLimit,
    /// Whether a password must be changed once it reaches an age.
    pub expiry: PasswordExpiry,
    /// Whether a password may hold the person's own name or address.
    pub personal_data: PersonalDataRule,
    /// Whether a password on a list of common passwords is refused.
    pub common_passwords: CommonPasswordRule,
}

impl PasswordHygiene {
    /// No check at all: any earlier password, any age, any content.
    #[must_use]
    pub fn relaxed() -> Self {
        Self {
            reuse: ReuseLimit::NONE,
            expiry: PasswordExpiry::Never,
            personal_data: PersonalDataRule::Allowed,
            common_passwords: CommonPasswordRule::Allowed,
        }
    }
}

impl Default for PasswordHygiene {
    /// What NIST SP 800-63B asks for: no password the person's name or
    /// address gives away, none from a common list, and no expiry on a
    /// schedule. Reuse is left to each tenant.
    fn default() -> Self {
        Self {
            reuse: ReuseLimit::NONE,
            expiry: PasswordExpiry::Never,
            personal_data: PersonalDataRule::Refused,
            common_passwords: CommonPasswordRule::Refused,
        }
    }
}

/// What a person is called, which their password may not give away.
#[derive(Debug, Clone, Copy)]
pub struct PersonalData<'a> {
    /// The account's address. Its local part counts, and each piece of it.
    pub email: &'a Email,
    /// The names the person goes by, such as a display name or a given and
    /// a family name. Each word counts.
    pub names: &'a [&'a str],
}

impl PersonalData<'_> {
    /// Every piece of the person's name or address a password may not hold,
    /// lower-cased, of at least [`MIN_PERSONAL_PIECE`] characters.
    fn pieces(&self) -> Vec<String> {
        let local = self.email.local_part();
        let name_words = self.names.iter().flat_map(|name| name.split_whitespace());
        std::iter::once(local)
            .chain(local.split(|c: char| !c.is_alphanumeric()))
            .chain(name_words)
            .map(str::to_lowercase)
            .filter(|piece| piece.chars().count() >= MIN_PERSONAL_PIECE)
            .collect()
    }
}

/// What a list of common passwords says of a new one: the list the caller
/// supplies, or the answer of a service that keeps one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommonPassword {
    /// The password is on the list.
    Listed,
    /// The supplied common-password source found no matching entry.
    NotListed,
}

impl CommonPassword {
    /// Whether `password` is on `list`, ignoring case.
    #[must_use]
    pub fn among(password: &str, list: &[&str]) -> Self {
        let lowered = password.to_lowercase();
        if list.iter().any(|common| common.to_lowercase() == lowered) {
            return Self::Listed;
        }
        Self::NotListed
    }
}

impl PasswordPolicy {
    /// A policy requiring at least `min_length` characters and the classes
    /// in `require`.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] if `min_length` is outside
    ///   [`MIN_PASSWORD_LENGTH`]`..=`[`MAX_PASSWORD_LENGTH`].
    pub fn new(min_length: u8, require: CharacterRequirements) -> Result<Self, ValidationError> {
        validate_range(
            "min_length",
            min_length,
            MIN_PASSWORD_LENGTH..=MAX_PASSWORD_LENGTH,
        )?;
        Ok(Self {
            min_length,
            require,
            hygiene: PasswordHygiene::default(),
        })
    }

    /// This policy with `hygiene` in place of what it checked besides
    /// length and characters.
    #[must_use]
    pub fn with_hygiene(self, hygiene: PasswordHygiene) -> Self {
        Self { hygiene, ..self }
    }

    /// A policy for tests that accepts any password of one character or
    /// more.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn relaxed() -> Self {
        Self::unchecked(1, CharacterRequirements::none())
    }

    /// Any policy at all, with no check on `min_length` and nothing checked
    /// besides length and characters. For tests of the character rules that
    /// need a short minimum.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn unchecked(min_length: u8, require: CharacterRequirements) -> Self {
        Self {
            min_length,
            require,
            hygiene: PasswordHygiene::relaxed(),
        }
    }

    /// What a new password is checked for besides length and characters.
    #[must_use]
    pub fn hygiene(&self) -> &PasswordHygiene {
        &self.hygiene
    }

    /// Refuses a password holding a piece of `person`'s name or address,
    /// when the policy asks.
    ///
    /// Ann's address is `ann.lee@acme.com`. A guesser tries `AnnLee2024!`
    /// before anything else, so a password holding `ann`, `lee` or
    /// `ann.lee`, in any case, is refused. Pieces shorter than three
    /// characters are left alone.
    ///
    /// # Errors
    ///
    /// - [`ValidationError::Custom`] with code `contains_personal_data` when
    ///   it holds one.
    pub fn check_personal_data(
        &self,
        password: &str,
        person: PersonalData<'_>,
    ) -> Result<(), ValidationError> {
        if self.hygiene.personal_data == PersonalDataRule::Allowed {
            return Ok(());
        }
        let lowered = password.to_lowercase();
        if !person
            .pieces()
            .iter()
            .any(|piece| lowered.contains(piece.as_str()))
        {
            return Ok(());
        }
        Err(ValidationError::Custom {
            field: "password",
            code: "contains_personal_data".to_owned(),
            message: message!(
                "values-password-must-not-contain-your-name",
                "password must not contain your name or email address"
            ),
        })
    }

    /// Refuses a password a list of common passwords holds, when the policy
    /// asks. `verdict` is that list's answer for the password.
    ///
    /// # Errors
    ///
    /// - [`ValidationError::Custom`] with code `common_password` when the
    ///   password is listed.
    pub fn check_common(&self, verdict: CommonPassword) -> Result<(), ValidationError> {
        match (self.hygiene.common_passwords, verdict) {
            (CommonPasswordRule::Allowed, _) | (_, CommonPassword::NotListed) => Ok(()),
            (CommonPasswordRule::Refused, CommonPassword::Listed) => Err(ValidationError::Custom {
                field: "password",
                code: "common_password".to_owned(),
                message: message!(
                    "values-password-is-too-common-choose-another",
                    "password is too common; choose another"
                ),
            }),
        }
    }

    /// The shortest password accepted, in characters.
    #[must_use]
    pub fn min_length(&self) -> u8 {
        self.min_length
    }

    /// The character classes a password must contain.
    #[must_use]
    pub fn require(&self) -> &CharacterRequirements {
        &self.require
    }

    /// Generates a password that satisfies this policy, drawing on `random`.
    ///
    /// The result has 16 characters, or `min_length` if that is longer. It
    /// holds one character of every required class. It is shuffled so the
    /// required ones are not always first. Look-alike characters such as
    /// `l`, `O`, `0`, `1` and `I` are left out, since people sometimes read
    /// a generated password aloud or copy it by hand.
    ///
    /// It comes back as a [`Secret`], so it is never printed by accident.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] if `random` answers with an index
    ///   at or past the bound it was given. A weaker password is never made
    ///   instead.
    pub fn generate(&self, random: &mut impl RandomSource) -> Result<Secret, DomainError> {
        let mut chars = self
            .required_classes()
            .into_iter()
            .map(|class| pick(class, random))
            .collect::<Result<Vec<u8>, DomainError>>()?;
        let target_len = usize::from(self.min_length).max(MIN_GENERATED_LENGTH);
        let any_class = [LOWER, UPPER, DIGIT, SPECIAL].concat();
        while chars.len() < target_len {
            chars.push(pick(&any_class, random)?);
        }
        shuffle(&mut chars, random)?;
        Ok(Secret::new(
            chars.into_iter().map(char::from).collect::<String>(),
        ))
    }

    /// The character sets this policy requires one character from.
    fn required_classes(&self) -> Vec<&'static [u8]> {
        [
            (self.require.lowercase, LOWER),
            (self.require.uppercase, UPPER),
            (self.require.digit, DIGIT),
            (self.require.special, SPECIAL),
        ]
        .into_iter()
        .filter_map(|(rule, class)| (rule == CharacterRule::Required).then_some(class))
        .collect()
    }

    /// Checks a password against this policy.
    ///
    /// It must have between `min_length` and `MAX_PASSWORD_CHARS`
    /// characters, and a character of every required class.
    ///
    /// # Errors
    ///
    /// - The first [`ValidationError`] the password fails.
    pub fn validate(&self, password: &str) -> Result<(), ValidationError> {
        Validator::new("password", password)
            .password(self)
            .validate_first()
    }
}

/// Lowercase letters a generated password draws on.
const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
/// Uppercase letters a generated password draws on.
const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
/// Digits a generated password draws on.
const DIGIT: &[u8] = b"23456789";
/// Symbols a generated password draws on.
const SPECIAL: &[u8] = b"!@#$%&*?";
/// The shortest password the generator makes, whatever the policy allows.
const MIN_GENERATED_LENGTH: usize = 16;

/// One character of `class`, chosen by `random`.
fn pick(class: &[u8], random: &mut impl RandomSource) -> Result<u8, DomainError> {
    class
        .get(random.index_below(class.len()))
        .copied()
        .ok_or_else(index_out_of_range)
}

/// Shuffles `chars` in place, with the Fisher-Yates method.
fn shuffle(chars: &mut [u8], random: &mut impl RandomSource) -> Result<(), DomainError> {
    for i in (1..chars.len()).rev() {
        let j = random.index_below(i.saturating_add(1));
        if j > i {
            return Err(index_out_of_range());
        }
        chars.swap(i, j);
    }
    Ok(())
}

/// The random source broke its promise to stay below the bound.
fn index_out_of_range() -> DomainError {
    DomainError::infra_msg("the random source gave an index out of range")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::fakes::SequenceRandom;

    /// A hundred passwords generated under the default policy are each long
    /// enough and each pass that same policy.
    #[test]
    fn generated_password_satisfies_default_policy() {
        let policy = PasswordPolicy::default();
        for seed in 0..100 {
            let pw = policy.generate(&mut SequenceRandom::new(seed)).unwrap();
            assert!(pw.expose().len() >= policy.min_length as usize);
            assert!(
                policy.validate(pw.expose()).is_ok(),
                "failed for: {}",
                pw.expose()
            );
        }
    }

    /// A policy wants 20 characters and every class. A hundred generated
    /// passwords each have at least 20 characters and pass it.
    #[test]
    fn generated_password_satisfies_strict_policy() {
        let policy = PasswordPolicy::unchecked(20, CharacterRequirements::strict());
        for seed in 0..100 {
            let pw = policy.generate(&mut SequenceRandom::new(seed)).unwrap();
            assert!(pw.expose().len() >= 20);
            assert!(
                policy.validate(pw.expose()).is_ok(),
                "failed for: {}",
                pw.expose()
            );
        }
    }

    /// A user picks "short" under the default 12-character minimum. It is
    /// refused.
    #[test]
    fn validate_rejects_short_password() {
        let policy = PasswordPolicy::default();
        assert!(policy.validate("short").is_err());
    }

    /// "alllowercase123" is long enough but has no capital letter. The
    /// default policy refuses it.
    #[test]
    fn validate_rejects_missing_uppercase() {
        let policy = PasswordPolicy::default();
        assert!(policy.validate("alllowercase123").is_err());
    }

    /// "AllLettersNoDigit" has both cases but no digit. The default policy
    /// refuses it.
    #[test]
    fn validate_rejects_missing_digit() {
        let policy = PasswordPolicy::default();
        assert!(policy.validate("AllLettersNoDigit").is_err());
    }

    /// A password of eight "é" takes sixteen bytes but has eight characters.
    /// It fails a 12-character minimum, and twelve of them pass.
    #[test]
    fn length_counts_characters_not_bytes() {
        let policy = PasswordPolicy::unchecked(12, CharacterRequirements::none());

        assert!(policy.validate("éééééééé").is_err());
        assert!(policy.validate("éééééééééééé").is_ok());
    }

    /// A German user picks "Ärgerlichöl123". "Ä" counts as a capital and
    /// "ö" as a small letter, so the default policy accepts it.
    #[test]
    fn letters_outside_english_satisfy_the_case_rules() {
        let policy = PasswordPolicy::default();

        assert!(policy.validate("Ärgerlichöl123").is_ok());
    }

    /// The relaxed policy accepts a password at the character limit and
    /// refuses one additional character before hashing.
    #[test]
    fn a_password_past_the_upper_limit_is_refused() {
        let policy = PasswordPolicy::relaxed();

        assert!(policy.validate(&"a".repeat(MAX_PASSWORD_CHARS)).is_ok());
        assert!(
            policy
                .validate(&"a".repeat(MAX_PASSWORD_CHARS + 1))
                .is_err()
        );
    }

    /// A tenant tries minimums of 7 and 129. Both are refused, while
    /// [`MIN_PASSWORD_LENGTH`] and [`MAX_PASSWORD_LENGTH`] themselves are
    /// accepted.
    #[test]
    fn a_minimum_outside_the_allowed_range_cannot_be_set() {
        let none = CharacterRequirements::none;

        assert!(PasswordPolicy::new(MIN_PASSWORD_LENGTH - 1, none()).is_err());
        assert!(PasswordPolicy::new(MIN_PASSWORD_LENGTH, none()).is_ok());
        assert!(PasswordPolicy::new(MAX_PASSWORD_LENGTH, none()).is_ok());
        assert!(PasswordPolicy::new(MAX_PASSWORD_LENGTH + 1, none()).is_err());
    }

    /// A stored policy with a minimum of 4 is read back. It is refused, just
    /// as creating it would be.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stored_policy_below_the_floor_is_refused() {
        let stored = r#"{"min_length":4,"require":{"uppercase":false,"lowercase":false,"digit":false,"special":false}}"#;

        assert!(serde_json::from_str::<PasswordPolicy>(stored).is_err());
    }

    /// "MySecurePass123" has 15 characters, both cases and a digit. The
    /// default policy accepts it.
    #[test]
    fn validate_accepts_compliant_password() {
        let policy = PasswordPolicy::default();
        assert!(policy.validate("MySecurePass123").is_ok());
    }

    /// Under a policy that wants a symbol, "MySecurePass123" is refused.
    /// Adding "!" makes it pass.
    #[test]
    fn validate_rejects_missing_special_character() {
        let policy = PasswordPolicy::unchecked(8, CharacterRequirements::strict());

        assert!(policy.validate("MySecurePass123").is_err());
        assert!(policy.validate("MySecurePass123!").is_ok());
    }

    /// The default policy asks for 12 characters, and the generator gives
    /// 16. A policy asking for 24 gets exactly 24.
    #[test]
    fn a_generated_password_is_exactly_the_length_the_policy_asks_for() {
        assert_eq!(
            PasswordPolicy::default()
                .generate(&mut SequenceRandom::new(1))
                .unwrap()
                .expose()
                .len(),
            16
        );

        let long = PasswordPolicy::unchecked(24, CharacterRequirements::strict());
        assert_eq!(
            long.generate(&mut SequenceRandom::new(1))
                .unwrap()
                .expose()
                .len(),
            24
        );
    }

    /// A random source that always answers past its bound.
    struct Broken;

    impl RandomSource for Broken {
        fn index_below(&mut self, upper: usize) -> usize {
            upper
        }
    }

    /// The random source answers with an index past its bound. No password
    /// is made, so a broken source never yields a weaker one, and nothing
    /// panics.
    #[test]
    fn a_broken_random_source_makes_no_password() {
        let result = PasswordPolicy::default().generate(&mut Broken);

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// The password "a" passes the relaxed test policy and fails the
    /// default one. So tests built on the relaxed policy do not test the
    /// default rules by mistake.
    #[test]
    fn the_relaxed_policy_asks_for_nothing_the_default_one_demands() {
        let relaxed = PasswordPolicy::relaxed();

        assert!(relaxed.validate("a").is_ok());
        assert!(PasswordPolicy::default().validate("a").is_err());
    }

    fn ann_lee() -> Email {
        Email::new("ann.lee@acme.com").unwrap()
    }

    /// Passwords containing pieces of Ann's email address fail the personal-data
    /// check, while a password without those pieces passes.
    #[test]
    fn a_password_holding_the_persons_address_is_refused() {
        let policy = PasswordPolicy::default();
        let email = ann_lee();
        let ann = PersonalData {
            email: &email,
            names: &[],
        };

        assert!(policy.check_personal_data("AnnLee2024!", ann).is_err());
        assert!(
            policy
                .check_personal_data("Correct-Lee-Horse", ann)
                .is_err()
        );
        assert!(policy.check_personal_data("Correct-Horse-9", ann).is_ok());
    }

    /// Bob's surname triggers the personal-data error, while a password
    /// containing only his two-letter name fragment remains acceptable.
    #[test]
    fn a_password_holding_the_persons_name_is_refused() {
        let policy = PasswordPolicy::default();
        let email = Email::new("b@acme.com").unwrap();
        let bob = PersonalData {
            email: &email,
            names: &["Bob Marley", "Jo"],
        };

        let refused = policy.check_personal_data("MarleyRocks1", bob);

        assert_eq!(
            refused.map_err(|error| error.code().to_owned()),
            Err("contains_personal_data".to_owned())
        );
        assert!(policy.check_personal_data("JoJoJoJo-2024", bob).is_ok());
    }

    /// A policy that allows personal data takes Ann's `AnnLee2024!`.
    #[test]
    fn a_policy_allowing_personal_data_takes_it() {
        let policy = PasswordPolicy::default().with_hygiene(PasswordHygiene {
            personal_data: PersonalDataRule::Allowed,
            ..PasswordHygiene::default()
        });
        let email = ann_lee();

        let taken = policy.check_personal_data(
            "AnnLee2024!",
            PersonalData {
                email: &email,
                names: &[],
            },
        );

        assert!(taken.is_ok());
    }

    /// Common-password matching ignores case; the default policy refuses a
    /// listed password and accepts one absent from the supplied list.
    #[test]
    fn a_common_password_is_refused() {
        let policy = PasswordPolicy::default();
        let list = ["password123", "qwerty123"];

        assert_eq!(
            CommonPassword::among("Password123", &list),
            CommonPassword::Listed
        );
        assert!(policy.check_common(CommonPassword::Listed).is_err());
        assert!(
            policy
                .check_common(CommonPassword::among("Tr0ub4dor&3x", &list))
                .is_ok()
        );
    }

    /// A policy allowing common passwords takes a listed one.
    #[test]
    fn a_policy_allowing_common_passwords_takes_one() {
        assert!(
            PasswordPolicy::relaxed()
                .check_common(CommonPassword::Listed)
                .is_ok()
        );
    }

    /// A password changed 90 days ago is due under a 90-day expiry, and
    /// not a moment before. Under no expiry it never is.
    #[test]
    fn a_password_is_due_once_it_reaches_its_age() {
        let changed = crate::shared::clock::now();
        let ninety = PasswordExpiry::After(ExpiryDays::new(90).unwrap());

        assert!(!ninety.is_due(changed, changed + Duration::days(90) - Duration::SECOND));
        assert!(ninety.is_due(changed, changed + Duration::days(90)));
        assert!(!PasswordExpiry::Never.is_due(changed, changed + Duration::days(10_000)));
    }

    /// Expiry from one to 730 days and a reuse limit up to 24 are taken.
    /// Zero days, 731 days and a limit of 25 are refused.
    #[test]
    fn hygiene_numbers_stay_in_range() {
        assert!(ExpiryDays::new(0).is_err());
        assert!(ExpiryDays::new(1).is_ok());
        assert!(ExpiryDays::new(MAX_EXPIRY_DAYS).is_ok());
        assert!(ExpiryDays::new(MAX_EXPIRY_DAYS + 1).is_err());
        assert!(ReuseLimit::new(MAX_REUSE_LIMIT).is_ok());
        assert!(ReuseLimit::new(MAX_REUSE_LIMIT + 1).is_err());
    }

    /// A new policy follows NIST: personal data and common passwords are
    /// refused, and nothing expires on a schedule.
    #[test]
    fn a_new_policy_checks_content_and_never_expires() {
        let hygiene = *PasswordPolicy::default().hygiene();

        assert_eq!(hygiene.personal_data, PersonalDataRule::Refused);
        assert_eq!(hygiene.common_passwords, CommonPasswordRule::Refused);
        assert_eq!(hygiene.expiry, PasswordExpiry::Never);
    }

    /// A policy with a 90-day expiry and a reuse limit of 5 is stored and
    /// read back unchanged. A stored reuse limit of 99 is refused.
    #[cfg(feature = "serde")]
    #[test]
    fn hygiene_round_trips_and_refuses_a_stored_limit_out_of_range() {
        let policy = PasswordPolicy::default().with_hygiene(PasswordHygiene {
            reuse: ReuseLimit::new(5).unwrap(),
            expiry: PasswordExpiry::After(ExpiryDays::new(90).unwrap()),
            ..PasswordHygiene::default()
        });

        let mut stored = serde_json::to_value(&policy).unwrap();
        assert_eq!(
            serde_json::from_value::<PasswordPolicy>(stored.clone()).unwrap(),
            policy
        );
        stored["hygiene"]["reuse"] = serde_json::json!(99);
        assert!(serde_json::from_value::<PasswordPolicy>(stored).is_err());
    }
}
