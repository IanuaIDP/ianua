//! What a person chose to hear about.

pub(crate) mod get;
pub(crate) mod update;

pub use get::{GetPreferencesPorts, GetPreferencesUseCase};
pub use update::{
    PreferenceUpdate, UpdatePreferencesPorts, UpdatePreferencesRequest, UpdatePreferencesUseCase,
};
