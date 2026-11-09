//! A handler's use cases together with the limits that validate its input.

use std::convert::Infallible;

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use ianua_domain::shared::config::DomainLimits;

use crate::state::ApiState;

/// The use cases and validation limits needed to map submitted data.
pub(crate) struct InputState<T> {
    /// The handler's existing context-specific use cases.
    pub use_cases: T,
    /// The domain limits applied when mapping the input.
    pub limits: DomainLimits,
}

impl<T> FromRequestParts<ApiState> for InputState<T>
where
    T: FromRef<ApiState> + Send,
{
    type Rejection = Infallible;

    async fn from_request_parts(
        _parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self {
            use_cases: T::from_ref(state),
            limits: DomainLimits::from_ref(state),
        })
    }
}
