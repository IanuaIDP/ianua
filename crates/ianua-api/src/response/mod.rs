//! Shared response types for consistent API output.

pub mod files;
pub mod oauth;
pub mod relay;
pub mod runtime;
pub mod scim;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use ianua_app::listing::{Cursor, Page};
use serde::Serialize;

/// JSON response with 201 Created.
pub struct Created<T: Serialize>(pub T);

impl<T: Serialize> IntoResponse for Created<T> {
    fn into_response(self) -> Response {
        (StatusCode::CREATED, axum::Json(self.0)).into_response()
    }
}

/// JSON response with 202 Accepted: the resource was created and work started,
/// but has not finished.
pub struct Accepted<T: Serialize>(pub T);

impl<T: Serialize> IntoResponse for Accepted<T> {
    fn into_response(self) -> Response {
        (StatusCode::ACCEPTED, axum::Json(self.0)).into_response()
    }
}

/// 302 Found, sending the browser on to the address it holds.
///
/// The OAuth authorization endpoint answers this way: the protocol sends a
/// browser on, it does not hand it a body to read.
pub struct Found(pub String);

impl IntoResponse for Found {
    fn into_response(self) -> Response {
        (StatusCode::FOUND, [(axum::http::header::LOCATION, self.0)]).into_response()
    }
}

/// 204 No Content: used for successful mutations with no body.
pub(crate) struct NoContent;

impl IntoResponse for NoContent {
    fn into_response(self) -> Response {
        StatusCode::NO_CONTENT.into_response()
    }
}

/// 204 No Content when there is nothing to hand back, or 200 with a JSON
/// body when there is.
pub(crate) enum MaybeBody<T: Serialize> {
    /// 204 No Content.
    Nothing,
    /// 200 OK with this body.
    Body(T),
}

impl<T: Serialize> From<Option<T>> for MaybeBody<T> {
    fn from(body: Option<T>) -> Self {
        body.map_or(Self::Nothing, Self::Body)
    }
}

impl<T: Serialize> IntoResponse for MaybeBody<T> {
    fn into_response(self) -> Response {
        match self {
            Self::Nothing => StatusCode::NO_CONTENT.into_response(),
            Self::Body(body) => (StatusCode::OK, axum::Json(body)).into_response(),
        }
    }
}

/// One page of a list, and where the next one starts.
///
/// Pass `next_cursor` back as `?after=` for the next page, with the same
/// `sort`. It is `null` on the last page.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PageResponse<T: Serialize> {
    /// The items on this page, in the list's order.
    pub items: Vec<T>,
    /// The cursor of the next page, or `null` when this is the last one.
    pub next_cursor: Option<String>,
    /// The most items a page holds.
    pub limit: u32,
}

impl<T: Serialize> PageResponse<T> {
    /// Builds a page response by mapping domain items to DTOs.
    pub(crate) fn from_page<S>(page: Page<S>, mapper: impl FnMut(S) -> T) -> Self {
        Self {
            next_cursor: page.next.as_ref().map(Cursor::encode),
            limit: page.limit.get(),
            items: page.items.into_iter().map(mapper).collect(),
        }
    }

    /// Builds a page response from items already turned into DTOs, keeping
    /// `page`'s cursor and limit.
    pub(crate) fn with_items<S>(page: &Page<S>, items: Vec<T>) -> Self {
        Self {
            next_cursor: page.next.as_ref().map(Cursor::encode),
            limit: page.limit.get(),
            items,
        }
    }
}
