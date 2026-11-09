//! Signing people in on a service's own domain.

pub mod accepted;
pub mod app;
pub mod hosts;
pub mod return_path;

use crate::shared::validation::ValidationError;

/// The error every app sign-in setting is refused with, naming `field`.
fn invalid(field: &'static str, message: &str) -> ValidationError {
    ValidationError::Custom {
        field,
        code: "invalid_app_sign_in".to_owned(),
        message: message.into(),
    }
}
