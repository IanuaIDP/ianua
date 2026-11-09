//! SCIM provisioning for the tenant: reading how it is set up, switching it
//! on and off, its token and settings.

pub(crate) mod disable;
pub(crate) mod enable;
pub(crate) mod get;
pub(crate) mod rotate_token;
pub(crate) mod update_settings;

pub use disable::{DisablePorts, DisableUseCase};
pub use enable::{EnablePorts, EnableUseCase, SwitchedOn};
pub use get::{GetPorts, GetUseCase, Status};
pub use rotate_token::{RotateTokenPorts, RotateTokenUseCase};
pub use update_settings::{ScimSettings, UpdateSettingsPorts, UpdateSettingsUseCase};
