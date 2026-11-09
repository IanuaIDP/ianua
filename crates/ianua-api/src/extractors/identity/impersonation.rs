//! The header a tenant admin names a support impersonation with, so a
//! request acts as the person through it.
//!
//! The header only names the impersonation. Whether the admin may act
//! through it now (their own session counts, the person approved, the
//! window is open, the account may sign in) is the app's question, asked
//! again on every request through `ActAsUseCase`.

use axum::http::HeaderMap;
use ianua_app::error::AppError;
use ianua_domain::message;
use ianua_domain::types::SupportImpersonationId;

use crate::error::ApiError;

/// The header naming the impersonation a request acts through.
pub(crate) const IMPERSONATION_HEADER: &str = "ianua-support-impersonation";

/// The impersonation `headers` name, when they name one.
///
/// # Errors
///
/// `422` when the header is there but is not an impersonation id: a request
/// meant to act as someone else is never quietly run as the admin.
pub(crate) fn named_impersonation(
    headers: &HeaderMap,
) -> Result<Option<SupportImpersonationId>, ApiError> {
    let Some(value) = headers.get(IMPERSONATION_HEADER) else {
        return Ok(None);
    };
    value
        .to_str()
        .ok()
        .and_then(|raw| raw.trim().parse::<uuid::Uuid>().ok())
        .map(|id| Some(SupportImpersonationId::from_uuid(id)))
        .ok_or_else(|| {
            ApiError(AppError::Domain(
                ianua_domain::shared::errors::DomainError::invalid(message!(
                    "api-must-name-an-impersonation-by-its",
                    format!("{IMPERSONATION_HEADER} must name an impersonation by its id")
                )),
            ))
        })
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    /// Headers carrying `value` as the impersonation header.
    fn naming(value: &'static str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(IMPERSONATION_HEADER, HeaderValue::from_static(value));
        headers
    }

    /// A request without the header acts as the admin themselves.
    #[test]
    fn no_header_names_no_impersonation() {
        assert!(matches!(named_impersonation(&HeaderMap::new()), Ok(None)));
    }

    /// The header's id is read as the impersonation to act through.
    #[test]
    fn the_header_names_an_impersonation_by_id() {
        let id = "0190c6f6-0000-7000-8000-000000000001";

        let named = named_impersonation(&naming(id));

        assert!(matches!(named, Ok(Some(found)) if found.as_uuid().to_string() == id));
    }

    /// An impersonation header that is not a valid identifier is rejected.
    #[test]
    fn a_header_that_is_no_id_is_refused() {
        assert!(named_impersonation(&naming("not-an-id")).is_err());
    }
}
