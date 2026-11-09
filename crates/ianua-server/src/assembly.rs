//! The use cases' adapters and settings: built once from the platform and
//! the configuration, for every caller the server starts to take its use
//! cases from through `ianua_assembly`.

mod adapters;
mod outward;
pub(crate) mod settings;

use ianua_assembly::deps::{Adapters, Settings};

use crate::config::Config;
use crate::error::ServerError;
use crate::platform::Platform;

/// The adapter behind every port the use cases need, over `platform`, and
/// the settings they are built with, from `config`.
pub(crate) struct Assembly {
    /// The adapter behind each port.
    pub adapters: Adapters,
    /// The settings the use cases are built with.
    pub settings: Settings,
}

/// The assembly `platform` and `config` make. Built once a process.
///
/// # Errors
///
/// [`ServerError::Config`] naming a setting the type it is read into
/// refuses, and [`ServerError::Platform`] naming an adapter whose client
/// could not be built.
pub(crate) fn assembly(platform: &Platform, config: &Config) -> Result<Assembly, ServerError> {
    let settings = settings::settings(config)?;
    let adapters = adapters::adapters(platform, config, &settings)?;
    Ok(Assembly { adapters, settings })
}
