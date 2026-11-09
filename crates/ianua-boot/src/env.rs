//! The process environment, read one setting at a time, every read naming
//! the variable it reads.
//!
//! Unset and blank are the same: the setting's default, or a refusal when
//! it has none. A value that does not read as what the setting takes is
//! refused naming the variable, never replaced by the default. A secret
//! may be given in the variable itself or, as `NAME_FILE`, in a file whose
//! path the variable holds, for secrets mounted by Kubernetes or Docker;
//! giving both is refused, and no refusal ever repeats a secret.
//!
//! A refusal repeats the value only where it is a short token the operator
//! typed to say how much or which: a number, a duration, an on or off, a
//! choice. Text that may carry a credential, such as a URL with a password
//! in it, is refused by name and reason alone.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::fmt::Display;
use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use ianua_domain::shared::security::secret::Secret;

/// Why the configuration was refused. Each names the setting at fault and
/// never a secret's value.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A setting with no default was not set.
    #[error("{name} must be set")]
    Missing {
        /// The setting.
        name: String,
    },
    /// A setting's value is not what it takes.
    #[error("{name} {expected}")]
    Invalid {
        /// The setting.
        name: String,
        /// What it takes, with the value given when it is no secret.
        expected: String,
    },
    /// A setting's value was refused by the type it is read into.
    #[error("{name} is not usable")]
    Rejected {
        /// The setting.
        name: String,
        /// Why the type refused it.
        #[source]
        cause: Box<dyn std::error::Error + Send + Sync>,
    },
    /// A setting names a file that cannot be read.
    #[error("{name}: the file {path} cannot be read")]
    Unreadable {
        /// The setting.
        name: String,
        /// The file it names.
        path: String,
        /// Why it cannot be read.
        #[source]
        cause: std::io::Error,
    },
    /// A setting does not fit with the others set beside it.
    #[error("{name} {why}")]
    Contradicts {
        /// The setting at fault.
        name: String,
        /// What it contradicts.
        why: String,
    },
}

impl ConfigError {
    /// A refusal of `name` for not fitting with the rest: `why` says what.
    #[must_use]
    pub fn contradicts(name: &str, why: impl Into<String>) -> Self {
        Self::Contradicts {
            name: name.to_owned(),
            why: why.into(),
        }
    }

    /// A refusal of `name`'s value: `expected` says what it takes.
    #[must_use]
    pub fn invalid(name: &str, expected: impl Into<String>) -> Self {
        Self::Invalid {
            name: name.to_owned(),
            expected: expected.into(),
        }
    }

    /// A refusal of `name` by the type it is read into, keeping `cause`.
    #[must_use]
    pub fn rejected(name: &str, cause: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Rejected {
            name: name.to_owned(),
            cause: Box::new(cause),
        }
    }

    /// A refusal for `name` being unset.
    #[must_use]
    pub fn missing(name: &str) -> Self {
        Self::Missing {
            name: name.to_owned(),
        }
    }
}

/// What a reader answers: the setting, or why it was refused.
pub type Read<T> = Result<T, ConfigError>;

/// The environment the configuration is read from, held once so every
/// reader sees the same values.
#[derive(Debug, Default)]
pub struct Env {
    vars: HashMap<String, String>,
    not_text: BTreeSet<String>,
    set: RefCell<BTreeSet<String>>,
}

impl Env {
    /// The process's environment, with the `.vars` file in the working
    /// directory, when there is one, under it: a variable the process was
    /// given wins over the file's.
    #[must_use]
    pub fn from_process() -> Self {
        let mut vars = Self::default();
        let file = dotenvy::dotenv_iter().into_iter().flatten().flatten();
        for (name, value) in file {
            vars.vars.insert(name, value);
        }
        for (name, value) in std::env::vars_os() {
            let Some(name) = name.to_str().map(str::to_owned) else {
                continue;
            };
            match value.into_string() {
                Ok(value) => {
                    vars.vars.insert(name, value);
                }
                Err(_) => {
                    vars.vars.remove(&name);
                    vars.not_text.insert(name);
                }
            }
        }
        vars
    }

    /// An environment holding exactly `pairs`, for tests and tools.
    #[must_use]
    pub fn of<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        Self {
            vars: pairs
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
            ..Self::default()
        }
    }

    /// The names of the settings read that were set, in order, for the
    /// start-up log. Never their values.
    #[must_use]
    pub fn set_names(&self) -> Vec<String> {
        self.set.borrow().iter().cloned().collect()
    }

    /// `name`'s value, trimmed, or `None` when it is unset or blank.
    fn value(&self, name: &str) -> Read<Option<String>> {
        if self.not_text.contains(name) {
            return Err(ConfigError::invalid(name, "is not UTF-8 text"));
        }
        let Some(value) = self.vars.get(name).map(|value| value.trim()) else {
            return Ok(None);
        };
        if value.is_empty() {
            return Ok(None);
        }
        self.set.borrow_mut().insert(name.to_owned());
        Ok(Some(value.to_owned()))
    }

    /// `name`'s text, or `None` when it is unset.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] when the value is not UTF-8.
    pub fn optional(&self, name: &str) -> Read<Option<String>> {
        self.value(name)
    }

    /// `name`'s text, or `default` when it is unset.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] when the value is not UTF-8.
    pub fn text(&self, name: &str, default: &str) -> Read<String> {
        Ok(self.value(name)?.unwrap_or_else(|| default.to_owned()))
    }

    /// `name`'s text, which must be set.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Missing`] when it is unset.
    pub fn required(&self, name: &str) -> Read<String> {
        self.value(name)?.ok_or_else(|| ConfigError::missing(name))
    }

    /// `name` read by `parse`, or `None` when it is unset.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Rejected`] carrying what `parse` refused it for.
    pub fn parsed<T, E>(
        &self,
        name: &str,
        parse: impl FnOnce(String) -> Result<T, E>,
    ) -> Read<Option<T>>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        self.value(name)?
            .map(|value| parse(value).map_err(|cause| ConfigError::rejected(name, cause)))
            .transpose()
    }

    /// `name` read by `parse`, which must be set.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Missing`] when it is unset, [`ConfigError::Rejected`]
    /// when `parse` refuses it.
    pub fn required_parsed<T, E>(
        &self,
        name: &str,
        parse: impl FnOnce(String) -> Result<T, E>,
    ) -> Read<T>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        self.parsed(name, parse)?
            .ok_or_else(|| ConfigError::missing(name))
    }

    /// `name` as a number, or `default` when it is unset.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] when it is not a number of that kind.
    pub fn number<T: FromStr>(&self, name: &str, default: T) -> Read<T> {
        let Some(value) = self.value(name)? else {
            return Ok(default);
        };
        value.parse().map_err(|_| {
            ConfigError::invalid(name, format!("must be a whole number, got {value:?}"))
        })
    }

    /// `name` as a number within `range`, or `default` when it is unset.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] when it is not a number or lies outside
    /// `range`.
    pub fn number_in<T>(&self, name: &str, default: T, range: RangeInclusive<T>) -> Read<T>
    where
        T: FromStr + PartialOrd + Display,
    {
        let number = self.number(name, default)?;
        if !range.contains(&number) {
            return Err(ConfigError::invalid(
                name,
                format!(
                    "must be from {} to {}, got {number}",
                    range.start(),
                    range.end()
                ),
            ));
        }
        Ok(number)
    }

    /// `name` as a fraction from 0 to 1, or `default` when it is unset.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] when it is not a number from 0 to 1.
    pub fn fraction(&self, name: &str, default: f32) -> Read<f32> {
        let Some(value) = self.value(name)? else {
            return Ok(default);
        };
        let refused = || ConfigError::invalid(name, format!("must be from 0 to 1, got {value:?}"));
        let fraction: f32 = value.parse().map_err(|_| refused())?;
        if !(0.0..=1.0).contains(&fraction) {
            return Err(refused());
        }
        Ok(fraction)
    }

    /// `name` as a duration of whole `unit`s, or `default` when unset.
    fn duration_of(&self, name: &str, default: Duration, unit: Unit) -> Read<Duration> {
        let Some(value) = self.value(name)? else {
            return Ok(default);
        };
        let count: u64 = value.parse().map_err(|_| {
            ConfigError::invalid(
                name,
                format!("must be a whole number of {}, got {value:?}", unit.plural()),
            )
        })?;
        unit.of(count)
            .ok_or_else(|| ConfigError::invalid(name, "is too long a time"))
    }

    /// `name` in whole milliseconds, or `default` when it is unset.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] when it is not a whole number.
    pub fn millis(&self, name: &str, default: Duration) -> Read<Duration> {
        self.duration_of(name, default, Unit::Millis)
    }

    /// `name` in whole seconds, or `default` when it is unset.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] when it is not a whole number.
    pub fn seconds(&self, name: &str, default: Duration) -> Read<Duration> {
        self.duration_of(name, default, Unit::Seconds)
    }

    /// `name` in whole minutes, or `default` when it is unset.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] when it is not a whole number.
    pub fn minutes(&self, name: &str, default: Duration) -> Read<Duration> {
        self.duration_of(name, default, Unit::Minutes)
    }

    /// `name` in whole hours, or `default` when it is unset.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] when it is not a whole number.
    pub fn hours(&self, name: &str, default: Duration) -> Read<Duration> {
        self.duration_of(name, default, Unit::Hours)
    }

    /// `name` in whole days, or `default` when it is unset.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] when it is not a whole number.
    pub fn days(&self, name: &str, default: Duration) -> Read<Duration> {
        self.duration_of(name, default, Unit::Days)
    }

    /// `name` in whole seconds within `range`, or `default` when it is
    /// unset.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] when it is not a whole number or lies
    /// outside `range`.
    pub fn seconds_in(
        &self,
        name: &str,
        default: Duration,
        range: RangeInclusive<u64>,
    ) -> Read<Duration> {
        let read = self.seconds(name, default)?;
        ensure_within(name, read.as_secs(), &range, Unit::Seconds)?;
        Ok(read)
    }

    /// `name` in whole milliseconds within `range`, or `default` when it is
    /// unset.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] when it is not a whole number or lies
    /// outside `range`.
    pub fn millis_in(
        &self,
        name: &str,
        default: Duration,
        range: RangeInclusive<u64>,
    ) -> Read<Duration> {
        let read = self.millis(name, default)?;
        let millis = u64::try_from(read.as_millis()).unwrap_or(u64::MAX);
        ensure_within(name, millis, &range, Unit::Millis)?;
        Ok(read)
    }

    /// `name` as comma-separated whole seconds, or `default` when unset.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] when an entry is not a whole number.
    pub fn seconds_list(&self, name: &str, default: &[Duration]) -> Read<Vec<Duration>> {
        let Some(value) = self.value(name)? else {
            return Ok(default.to_vec());
        };
        value
            .split(',')
            .map(|step| {
                step.trim().parse().map(Duration::from_secs).map_err(|_| {
                    ConfigError::invalid(name, format!("must list whole seconds, got {value:?}"))
                })
            })
            .collect()
    }

    /// `name` as on or off, or `default` when it is unset: `true`, `1`,
    /// `yes` or `on`; `false`, `0`, `no` or `off`.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] for any other value.
    pub fn flag(&self, name: &str, default: bool) -> Read<bool> {
        let Some(value) = self.value(name)? else {
            return Ok(default);
        };
        match value.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Ok(true),
            "false" | "0" | "no" | "off" => Ok(false),
            _ => Err(ConfigError::invalid(
                name,
                format!("must be true or false, got {value:?}"),
            )),
        }
    }

    /// `name` as one of `choices`, matched without regard to case, or
    /// `default` when it is unset.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] naming every choice for any other value.
    pub fn choice<T: Copy>(&self, name: &str, default: T, choices: &[(&str, T)]) -> Read<T> {
        let Some(value) = self.value(name)? else {
            return Ok(default);
        };
        let lowered = value.to_ascii_lowercase();
        choices
            .iter()
            .find(|(word, _)| *word == lowered)
            .map(|(_, choice)| *choice)
            .ok_or_else(|| {
                let words: Vec<&str> = choices.iter().map(|(word, _)| *word).collect();
                ConfigError::invalid(
                    name,
                    format!("must be one of {}, got {value:?}", words.join(", ")),
                )
            })
    }

    /// `name` as a comma-separated list, blanks dropped; empty when unset.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] when the value is not UTF-8.
    pub fn list(&self, name: &str) -> Read<Vec<String>> {
        Ok(self
            .value(name)?
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|entry| !entry.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default())
    }

    /// `name` as an absolute `http` or `https` URL holding no user or
    /// password, or `None` when unset. A URL is printed with the
    /// configuration, so a credential goes in a secret setting of its own;
    /// and since the value may hold one, no refusal repeats it.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] when it is not one, or holds a user or
    /// password.
    pub fn url(&self, name: &str) -> Read<Option<url::Url>> {
        let Some(value) = self.value(name)? else {
            return Ok(None);
        };
        let refused = || ConfigError::invalid(name, "must be an http or https URL");
        let url = url::Url::parse(&value).map_err(|_| refused())?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return Err(refused());
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ConfigError::invalid(
                name,
                "must not hold a user or password; give the credential in its own setting",
            ));
        }
        Ok(Some(url))
    }

    /// `name` as a path, or `None` when it is unset.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] when the value is not UTF-8.
    pub fn path(&self, name: &str) -> Read<Option<PathBuf>> {
        Ok(self.value(name)?.map(PathBuf::from))
    }

    /// The text of the file `name` names, or `None` when it is unset.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Unreadable`] when the file cannot be read.
    pub fn file_text(&self, name: &str) -> Read<Option<String>> {
        let Some(path) = self.value(name)? else {
            return Ok(None);
        };
        std::fs::read_to_string(&path)
            .map(Some)
            .map_err(|cause| ConfigError::Unreadable {
                name: name.to_owned(),
                path,
                cause,
            })
    }

    /// The secret `name` holds, or the file `NAME_FILE` names holds, with
    /// one trailing line break dropped, or `None` when neither is set.
    ///
    /// # Errors
    ///
    /// - [`ConfigError::Contradicts`] when both are set.
    /// - [`ConfigError::Unreadable`] when the file cannot be read.
    /// - [`ConfigError::Invalid`] when the file is empty.
    pub fn secret(&self, name: &str) -> Read<Option<Secret>> {
        let file_name = format!("{name}_FILE");
        let given = self.value(name)?;
        let file = self.value(&file_name)?;
        match (given, file) {
            (Some(_), Some(_)) => Err(ConfigError::contradicts(
                name,
                format!("and {file_name} are both set; set one"),
            )),
            (Some(value), None) => Ok(Some(Secret::new(value))),
            (None, Some(path)) => secret_in_file(&file_name, path).map(Some),
            (None, None) => Ok(None),
        }
    }

    /// The secret `name` or `NAME_FILE` holds, which must be set.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Missing`] naming both when neither is set; otherwise
    /// as [`secret`](Self::secret).
    pub fn required_secret(&self, name: &str) -> Read<Secret> {
        self.secret(name)?
            .ok_or_else(|| ConfigError::missing(&format!("{name} or {name}_FILE")))
    }
}

/// The secret in the file at `path`, which `name` named.
fn secret_in_file(name: &str, path: String) -> Read<Secret> {
    let contents = std::fs::read_to_string(&path).map_err(|cause| ConfigError::Unreadable {
        name: name.to_owned(),
        path,
        cause,
    })?;
    let secret = contents
        .strip_suffix('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .unwrap_or(&contents);
    if secret.is_empty() {
        return Err(ConfigError::invalid(name, "names an empty file"));
    }
    Ok(Secret::new(secret))
}

/// Refuses `count` of `unit` outside `range` for `name`.
fn ensure_within(name: &str, count: u64, range: &RangeInclusive<u64>, unit: Unit) -> Read<()> {
    if range.contains(&count) {
        return Ok(());
    }
    Err(ConfigError::invalid(
        name,
        format!(
            "must be from {} to {} {}, got {count}",
            range.start(),
            range.end(),
            unit.plural()
        ),
    ))
}

/// The unit a duration setting counts in.
#[derive(Debug, Clone, Copy)]
enum Unit {
    Millis,
    Seconds,
    Minutes,
    Hours,
    Days,
}

impl Unit {
    /// The unit's name, for a refusal.
    fn plural(self) -> &'static str {
        match self {
            Self::Millis => "milliseconds",
            Self::Seconds => "seconds",
            Self::Minutes => "minutes",
            Self::Hours => "hours",
            Self::Days => "days",
        }
    }

    /// `count` of this unit, or `None` when it overflows.
    fn of(self, count: u64) -> Option<Duration> {
        let seconds = match self {
            Self::Millis => return Some(Duration::from_millis(count)),
            Self::Seconds => Some(count),
            Self::Minutes => count.checked_mul(60),
            Self::Hours => count.checked_mul(3600),
            Self::Days => count.checked_mul(86_400),
        };
        seconds.map(Duration::from_secs)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    /// Missing text and numeric variables preserve the fallback chosen by their caller.
    #[test]
    fn an_unset_setting_reads_as_its_default() {
        let vars = Env::of([]);

        assert_eq!(vars.text("HOST", "0.0.0.0").unwrap(), "0.0.0.0");
        assert_eq!(vars.number("PORT", 3000_u16).unwrap(), 3000);
    }

    /// Whitespace-only input yields the numeric fallback and no optional value.
    #[test]
    fn a_blank_setting_reads_as_unset() {
        let vars = Env::of([("PORT", "   ")]);

        assert_eq!(vars.number("PORT", 3000_u16).unwrap(), 3000);
        assert!(vars.optional("PORT").unwrap().is_none());
    }

    /// A mistyped port is refused with its setting and value in the error,
    /// rather than replaced by the default.
    #[test]
    fn a_number_that_does_not_read_is_refused_by_name() {
        let vars = Env::of([("PORT", "30OO")]);

        let read = vars.number("PORT", 3000_u16);

        let message = read.unwrap_err().to_string();
        assert!(message.starts_with("PORT "));
        assert!(message.contains("30OO"));
    }

    /// A number outside its range is refused, naming the range.
    #[test]
    fn a_number_outside_its_range_is_refused() {
        let vars = Env::of([("JOB_PER_TENANT", "0")]);

        let read = vars.number_in("JOB_PER_TENANT", 10_u32, 1..=1000);

        assert!(matches!(read, Err(ConfigError::Invalid { name, .. }) if name == "JOB_PER_TENANT"));
    }

    /// A required setting left unset is refused as missing.
    #[test]
    fn a_required_setting_left_unset_is_refused() {
        let vars = Env::of([]);

        let read = vars.required("DATABASE_URL");

        assert_eq!(read.unwrap_err().to_string(), "DATABASE_URL must be set");
    }

    /// Each duration reader counts in the unit its name says.
    #[test]
    fn each_duration_reader_counts_in_its_unit() {
        let vars = Env::of([
            ("A_MS", "250"),
            ("B_S", "2"),
            ("C_M", "3"),
            ("D_H", "4"),
            ("E_D", "5"),
        ]);

        assert_eq!(
            vars.millis("A_MS", Duration::ZERO).unwrap(),
            Duration::from_millis(250)
        );
        assert_eq!(
            vars.seconds("B_S", Duration::ZERO).unwrap(),
            Duration::from_secs(2)
        );
        assert_eq!(
            vars.minutes("C_M", Duration::ZERO).unwrap(),
            Duration::from_secs(180)
        );
        assert_eq!(
            vars.hours("D_H", Duration::ZERO).unwrap(),
            Duration::from_secs(4 * 3600)
        );
        assert_eq!(
            vars.days("E_D", Duration::ZERO).unwrap(),
            Duration::from_secs(5 * 86_400)
        );
    }

    /// A day count that would overflow its duration is refused.
    #[test]
    fn a_duration_too_long_to_hold_is_refused() {
        let vars = Env::of([("X_DAYS", "18446744073709551615")]);

        assert!(vars.days("X_DAYS", Duration::ZERO).is_err());
    }

    /// A list of seconds reads each entry, and a bad entry refuses it.
    #[test]
    fn a_list_of_seconds_reads_each_entry() {
        let vars = Env::of([("BACKOFF", "1, 2,3"), ("BAD", "1,x")]);

        assert_eq!(
            vars.seconds_list("BACKOFF", &[]).unwrap(),
            [1, 2, 3].map(Duration::from_secs)
        );
        assert!(vars.seconds_list("BAD", &[]).is_err());
    }

    /// A flag takes its usual spellings and refuses any other.
    #[test]
    fn a_flag_takes_its_usual_spellings_only() {
        let vars = Env::of([("A", "YES"), ("B", "off"), ("C", "maybe")]);

        assert!(vars.flag("A", false).unwrap());
        assert!(!vars.flag("B", true).unwrap());
        assert!(vars.flag("C", false).is_err());
    }

    /// A choice matches without regard to case, and a refusal lists every
    /// choice.
    #[test]
    fn a_choice_matches_any_case_and_lists_the_choices_when_refused() {
        let vars = Env::of([("MODE", "Worker"), ("BAD", "both")]);
        let choices = [("api", 1), ("worker", 2)];

        assert_eq!(vars.choice("MODE", 0, &choices).unwrap(), 2);
        let message = vars.choice("BAD", 0, &choices).unwrap_err().to_string();
        assert!(message.contains("api, worker"));
    }

    /// A list drops blank entries and trims the rest.
    #[test]
    fn a_list_drops_blanks_and_trims() {
        let vars = Env::of([("LIST", " a, ,b ,")]);

        assert_eq!(vars.list("LIST").unwrap(), ["a", "b"]);
    }

    /// A URL must be absolute and http or https.
    #[test]
    fn a_url_must_be_absolute_http() {
        let vars = Env::of([
            ("GOOD", "https://example.com/x"),
            ("PLAIN", "example.com"),
            ("FTP", "ftp://example.com"),
        ]);

        assert!(vars.url("GOOD").unwrap().is_some());
        assert!(vars.url("PLAIN").is_err());
        assert!(vars.url("FTP").is_err());
    }

    /// Credential-bearing URLs are refused, including malformed URLs and
    /// unsupported schemes, without exposing the password in the error.
    #[test]
    fn a_url_with_a_password_is_refused_without_repeating_it() {
        let vars = Env::of([
            ("HELD", "https://user:hunter2@example.com/x"),
            ("UNREADABLE", "ftp://user:hunter2@example.com"),
            ("BROKEN", "https://user:hunter2@[example"),
        ]);

        for name in ["HELD", "UNREADABLE", "BROKEN"] {
            let message = vars.url(name).unwrap_err().to_string();

            assert!(message.starts_with(name), "{message}");
            assert!(!message.contains("hunter2"), "{message}");
        }
    }

    /// A ranged duration is taken within its range and refused outside it,
    /// naming its unit.
    #[test]
    fn a_ranged_duration_is_held_to_its_range() {
        let vars = Env::of([("A_SECONDS", "0"), ("B_SECONDS", "7"), ("C_MS", "250")]);

        let message = vars
            .seconds_in("A_SECONDS", Duration::from_secs(5), 1..=10)
            .unwrap_err()
            .to_string();

        assert_eq!(message, "A_SECONDS must be from 1 to 10 seconds, got 0");
        assert_eq!(
            vars.seconds_in("B_SECONDS", Duration::ZERO, 1..=10)
                .unwrap(),
            Duration::from_secs(7)
        );
        assert_eq!(
            vars.millis_in("C_MS", Duration::ZERO, 1..=1000).unwrap(),
            Duration::from_millis(250)
        );
        assert!(vars.millis_in("C_MS", Duration::ZERO, 1..=100).is_err());
    }

    /// A secret given in its variable is read from it.
    #[test]
    fn a_secret_is_read_from_its_variable() {
        let vars = Env::of([("TOKEN", "abc")]);

        assert_eq!(vars.secret("TOKEN").unwrap().unwrap().expose(), "abc");
    }

    /// A secret given as a file is read from it, its line break dropped.
    #[test]
    fn a_secret_is_read_from_its_file() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "from-a-file").unwrap();
        let path = file.path().to_str().unwrap().to_owned();
        let vars = Env::of([("TOKEN_FILE", path.as_str())]);

        assert_eq!(
            vars.secret("TOKEN").unwrap().unwrap().expose(),
            "from-a-file"
        );
    }

    /// Setting both a secret and its file is refused as contradictory.
    #[test]
    fn a_secret_given_twice_is_refused() {
        let vars = Env::of([("TOKEN", "abc"), ("TOKEN_FILE", "/run/secrets/token")]);

        assert!(matches!(
            vars.secret("TOKEN"),
            Err(ConfigError::Contradicts { .. })
        ));
    }

    /// An empty mounted file is refused as an invalid secret.
    #[test]
    fn an_empty_secret_file_is_refused() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_str().unwrap().to_owned();
        let vars = Env::of([("TOKEN_FILE", path.as_str())]);

        assert!(matches!(
            vars.secret("TOKEN"),
            Err(ConfigError::Invalid { .. })
        ));
    }

    /// A secret file that is not there is refused, naming the file
    /// setting.
    #[test]
    fn a_missing_secret_file_is_refused() {
        let vars = Env::of([("TOKEN_FILE", "/nonexistent/ianua/token")]);

        let read = vars.secret("TOKEN");

        assert!(matches!(read, Err(ConfigError::Unreadable { name, .. }) if name == "TOKEN_FILE"));
    }

    /// A required secret left unset names both ways to give it.
    #[test]
    fn a_required_secret_left_unset_names_both_ways_to_give_it() {
        let vars = Env::of([]);

        let message = vars.required_secret("HMAC_SECRET").unwrap_err().to_string();

        assert_eq!(message, "HMAC_SECRET or HMAC_SECRET_FILE must be set");
    }

    /// The names of the settings that were set are kept for the start-up
    /// log, and nothing of their values.
    #[test]
    fn the_names_of_set_settings_are_kept_without_values() {
        let vars = Env::of([("PORT", "8080"), ("HOST", ""), ("TOKEN", "abc")]);
        vars.number("PORT", 3000_u16).unwrap();
        vars.text("HOST", "0.0.0.0").unwrap();
        vars.secret("TOKEN").unwrap();

        assert_eq!(vars.set_names(), ["PORT", "TOKEN"]);
    }

    /// A fraction must lie from 0 to 1.
    #[test]
    fn a_fraction_must_lie_from_zero_to_one() {
        let vars = Env::of([("GOOD", "0.5"), ("BAD", "1.5")]);

        assert!((vars.fraction("GOOD", 0.0).unwrap() - 0.5).abs() < f32::EPSILON);
        assert!(vars.fraction("BAD", 0.0).is_err());
    }
}
