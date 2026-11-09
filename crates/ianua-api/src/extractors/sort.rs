//! Sort query-parameter extractor.
//!
//! Parses the compact `?sort=` grammar (`-created_at,display_name`) into a
//! validated [`SortOrder`] at the request boundary, so handlers receive a
//! strongly-typed ordering instead of a raw string and never repeat parsing.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use ianua_app::listing::{SortField, SortOrder};
use serde::Deserialize;

use crate::error::ApiError;
use crate::extractors::query::{Query, QueryRefusal};

/// Extractor yielding a validated [`SortOrder`] for the sortable field set `F`.
///
/// An unknown sort field is rejected with `422 Unprocessable Entity`; an
/// absent `sort` parameter yields the field's default ordering.
pub(crate) struct SortQuery<F: SortField>(pub SortOrder<F>);

/// The raw `sort` key, deserialized before field-name validation.
#[derive(Deserialize)]
struct SortRaw {
    sort: Option<String>,
}

impl<S, F> FromRequestParts<S> for SortQuery<F>
where
    S: Send + Sync,
    F: SortField,
{
    type Rejection = QueryRefusal;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Query(raw) = Query::<SortRaw>::from_request_parts(parts, state).await?;
        let order = SortOrder::<F>::parse(raw.sort.as_deref()).map_err(ApiError::validation)?;
        Ok(Self(order))
    }
}

impl<F: SortField> utoipa::IntoParams for SortQuery<F> {
    fn into_params(
        _parameter_in_provider: impl Fn() -> Option<utoipa::openapi::path::ParameterIn>,
    ) -> Vec<utoipa::openapi::path::Parameter> {
        use utoipa::openapi::Required;
        use utoipa::openapi::path::{ParameterBuilder, ParameterIn};
        use utoipa::openapi::schema::{ObjectBuilder, Schema, Type};

        let description = format!(
            "Comma-separated sort fields, applied left to right. Prefix a field with `-` for \
             descending order (default ascending). Allowed: {}.",
            F::allowed_tokens().join(", ")
        );

        vec![
            ParameterBuilder::new()
                .name("sort")
                .parameter_in(ParameterIn::Query)
                .required(Required::False)
                .description(Some(description))
                .schema(Some(Schema::Object(
                    ObjectBuilder::new().schema_type(Type::String).build(),
                )))
                .build(),
        ]
    }
}
