//! The WebSocket handshake of a live stream, taken so the handler can admit
//! the caller before it answers it.

use std::convert::Infallible;
use std::future::Future;

use axum::extract::FromRequestParts;
use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::{WebSocket, WebSocketUpgrade};
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};

use crate::state::ApiState;

/// The most a client may send in one message or frame. The streams only
/// send; a client sends control frames and nothing else, so a large frame is
/// only memory spent for nothing.
const CLIENT_FRAME_LIMIT: usize = 4 * 1024;

/// A request to open a live stream, which may or may not be a valid
/// WebSocket handshake.
///
/// It never refuses the request itself: the handler first asks the app
/// whether the caller may watch the stream, so a refused caller is told why
/// in the API's own error body, and only an admitted one is upgraded. A
/// request that is no handshake then gets the upgrade's own refusal.
pub(crate) struct Handshake(Result<WebSocketUpgrade, WebSocketUpgradeRejection>);

impl FromRequestParts<ApiState> for Handshake {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(
            WebSocketUpgrade::from_request_parts(parts, state).await,
        ))
    }
}

impl Handshake {
    /// Upgrades the connection and hands the socket to `serve`, or answers
    /// the reason the request is no WebSocket handshake.
    pub(crate) fn accept<F, Fut>(self, serve: F) -> Response
    where
        F: FnOnce(WebSocket) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        match self.0 {
            Ok(upgrade) => upgrade
                .max_message_size(CLIENT_FRAME_LIMIT)
                .max_frame_size(CLIENT_FRAME_LIMIT)
                .on_upgrade(serve),
            Err(refused) => refused.into_response(),
        }
    }
}
