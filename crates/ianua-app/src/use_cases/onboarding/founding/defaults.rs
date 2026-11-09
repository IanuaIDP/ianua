//! What a founding fills in when the founder left it out: the timezone and
//! the locale a new organization and its first tenant start with.

use ianua_domain::shared::validation::ValidationError;
use ianua_domain::types::{Locale, Timezone};

use crate::error::AppError;

/// `timezone`, or UTC when none was given.
///
/// # Errors
///
/// - `AppError::Domain` never in practice: UTC is a valid timezone.
pub(in crate::use_cases::onboarding) fn timezone_or_utc(
    timezone: Option<&Timezone>,
) -> Result<Timezone, AppError> {
    match timezone {
        Some(tz) => Ok(tz.clone()),
        None => Timezone::new("UTC").map_err(invalid),
    }
}

/// `locale`, or `en-US` when none was given.
///
/// # Errors
///
/// - `AppError::Domain` never in practice: `en-US` is a valid locale.
pub(in crate::use_cases::onboarding) fn locale_or_default(
    locale: Option<&Locale>,
) -> Result<Locale, AppError> {
    match locale {
        Some(l) => Ok(l.clone()),
        None => Locale::new("en-US").map_err(invalid),
    }
}

/// A founding detail that breaks its value's rule, refused as the domain
/// refuses it.
pub(super) fn invalid(error: ValidationError) -> AppError {
    AppError::from_domain(error.into())
}
