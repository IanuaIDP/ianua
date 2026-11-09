//! What the process logs and how it writes it, and the log output set up
//! once from it.

use tracing_subscriber::EnvFilter;

use crate::env::{ConfigError, Env, Read};
use crate::environment::Environment;

/// Why the logs could not be set up.
#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    /// The level is no filter, which a configuration read by
    /// [`LoggingConfig::read`] never holds.
    #[error("the log level is not a filter")]
    Level(#[source] ConfigError),
    /// The process's logs were set up already.
    #[error("the logs were set up already")]
    Installed(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Sends the process's logs to standard output, filtered and written as
/// `config` says.
///
/// # Errors
///
/// [`LoggingError::Installed`] when logs were set up already, and
/// [`LoggingError::Level`] when the level is no filter.
pub fn init(config: &LoggingConfig) -> Result<(), LoggingError> {
    let filter = config.filter().map_err(LoggingError::Level)?;
    let logs = tracing_subscriber::fmt().with_env_filter(filter);
    let set = match config.format {
        LogFormat::Json => logs.json().try_init(),
        LogFormat::Text => logs.try_init(),
    };
    set.map_err(LoggingError::Installed)
}

/// How log lines are written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// One JSON object a line, for a log collector.
    Json,
    /// Plain text, for a person reading a terminal.
    Text,
}

/// What the process logs and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggingConfig {
    /// `LOG_LEVEL`: which lines are written, as `info` or
    /// `info,ianua_infra=debug`; `info` by default.
    pub level: String,
    /// `LOG_FORMAT`: `json` in production and `text` in development by
    /// default.
    pub format: LogFormat,
}

impl LoggingConfig {
    /// The logging `vars` asks for in `environment`.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Rejected`] when `LOG_LEVEL` is not a filter, and
    /// [`ConfigError::Invalid`] when `LOG_FORMAT` is neither format.
    pub fn read(vars: &Env, environment: Environment) -> Read<Self> {
        let level = vars.text("LOG_LEVEL", "info")?;
        EnvFilter::try_new(&level).map_err(|cause| ConfigError::rejected("LOG_LEVEL", cause))?;
        let default_format = match environment {
            Environment::Production => LogFormat::Json,
            Environment::Development => LogFormat::Text,
        };
        let format = vars.choice(
            "LOG_FORMAT",
            default_format,
            &[("json", LogFormat::Json), ("text", LogFormat::Text)],
        )?;
        Ok(Self { level, format })
    }

    /// The filter `level` writes.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Rejected`] when the level is not a filter, which a
    /// configuration read by [`read`](Self::read) never holds.
    pub fn filter(&self) -> Read<EnvFilter> {
        EnvFilter::try_new(&self.level).map_err(|cause| ConfigError::rejected("LOG_LEVEL", cause))
    }
}

/// `error` and every cause under it, one a line, for the last words of a
/// process that could not start, written before any log is set up.
#[must_use]
pub fn described(error: &dyn std::error::Error) -> String {
    let mut lines = vec![error.to_string()];
    let mut cause = error.source();
    while let Some(next) = cause {
        lines.push(format!("  caused by: {next}"));
        cause = next.source();
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Production writes JSON at `info` unless told otherwise.
    #[test]
    fn production_writes_json_at_info() {
        let config = LoggingConfig::read(&Env::of([]), Environment::Production).unwrap();

        assert_eq!(config.level, "info");
        assert_eq!(config.format, LogFormat::Json);
    }

    /// Development writes plain text unless told otherwise.
    #[test]
    fn development_writes_text() {
        let config = LoggingConfig::read(&Env::of([]), Environment::Development).unwrap();

        assert_eq!(config.format, LogFormat::Text);
    }

    /// A level that is no filter is refused, naming the setting.
    #[test]
    fn a_level_that_is_no_filter_is_refused() {
        let read = LoggingConfig::read(
            &Env::of([("LOG_LEVEL", "ianua=loud")]),
            Environment::Production,
        );

        assert!(matches!(read, Err(ConfigError::Rejected { name, .. }) if name == "LOG_LEVEL"));
    }

    /// An unsupported LOG_FORMAT cannot silently select a different log encoding.
    #[test]
    fn a_format_that_is_neither_is_refused() {
        let read = LoggingConfig::read(&Env::of([("LOG_FORMAT", "xml")]), Environment::Production);

        assert!(read.is_err());
    }
}
