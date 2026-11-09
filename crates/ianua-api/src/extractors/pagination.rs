//! Page query-parameter extractor: `?after=<cursor>&limit=<n>`.
//!
//! Lists are keyset paged. The first request names no `after`; each answer
//! carries a `next_cursor` the next request passes back as `after`. The
//! cursor is opaque to callers.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use ianua_app::error::AppError;
use ianua_app::listing::{Cursor, Limit, PageRequest};
use ianua_domain::shared::errors::DomainError;
use serde::Deserialize;

use crate::error::ApiError;
use crate::extractors::query::{Query, QueryRefusal};

/// The page query parameters, as the API documents them.
///
/// Read through [`Paging`], which checks them; this type only describes
/// them.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct PaginationParams {
    /// The `next_cursor` of the page before; absent for the first page. A
    /// cursor only works with the sort it was given out for.
    pub after: Option<String>,
    /// The most items to return, from 1 to 100 (default 20).
    pub limit: Option<u32>,
}

/// Extractor yielding the checked [`PageRequest`] a list asks for.
///
/// A malformed cursor or a limit outside 1 to 100 is refused as a
/// validation error naming `after` or `limit`.
pub(crate) struct Paging(pub PageRequest);

impl<S: Send + Sync> FromRequestParts<S> for Paging {
    type Rejection = QueryRefusal;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Query(raw) = Query::<PaginationParams>::from_request_parts(parts, state).await?;
        Ok(Self(raw.page_request().map_err(refused)?))
    }
}

impl PaginationParams {
    /// The page these parameters ask for.
    fn page_request(&self) -> Result<PageRequest, DomainError> {
        let limit = self.limit.map(Limit::new).transpose()?.unwrap_or_default();
        let after = self.after.as_deref().map(Cursor::decode).transpose()?;
        Ok(PageRequest::new(after, limit))
    }
}

/// A refused page parameter, answered as the validation error it is.
fn refused(error: DomainError) -> ApiError {
    AppError::from_domain(error).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The page asked for with the query `after` and `limit`.
    fn asked(after: Option<&str>, limit: Option<u32>) -> Result<PageRequest, DomainError> {
        PaginationParams {
            after: after.map(str::to_owned),
            limit,
        }
        .page_request()
    }

    /// A caller naming nothing gets the first page of twenty.
    #[test]
    fn no_parameters_ask_for_the_first_usual_page() {
        assert_eq!(asked(None, None).unwrap(), PageRequest::default());
    }

    /// A request for 500 items fails page-size validation.
    #[test]
    fn a_limit_above_one_hundred_is_refused() {
        assert!(matches!(
            asked(None, Some(500)),
            Err(DomainError::Validation(_))
        ));
    }

    /// An invented cursor produces a validation error.
    #[test]
    fn a_made_up_cursor_is_refused() {
        assert!(matches!(
            asked(Some("bogus!"), None),
            Err(DomainError::Validation(_))
        ));
    }
}
