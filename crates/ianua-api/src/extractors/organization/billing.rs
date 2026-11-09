//! A notice the payment provider posts: its body byte for byte and the
//! signature it came with, nobody signed in.
//!
//! Nothing is read from the notice here. The provider's adapter checks the
//! signature over the exact bytes before the app reads anything, and a
//! notice without a signature is handed on with an empty one, which it
//! refuses like a forged one.

use axum::body::Bytes;
use axum::extract::{FromRequest, Request};
use ianua_app::auditor::RequestAuditor;
use ianua_app::ports::organization::{PaymentSignature, PaymentWebhook};
use ianua_domain::message;

use crate::error::ApiError;
use crate::state::ApiState;

/// The header the payment provider signs its notices in.
pub(crate) const PAYMENT_SIGNATURE_HEADER: &str = "stripe-signature";

/// A payment provider's notice, as it arrived.
pub(crate) struct PaymentNoticeRequest {
    /// The body and its signature.
    pub webhook: PaymentWebhook,
    /// Records what the notice changes, by the platform.
    pub auditor: RequestAuditor,
}

impl FromRequest<ApiState> for PaymentNoticeRequest {
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &ApiState) -> Result<Self, Self::Rejection> {
        let signature = request
            .headers()
            .get(PAYMENT_SIGNATURE_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let payload = Bytes::from_request(request, state).await.map_err(|_| {
            ApiError::validation(message!(
                "api-the-notice-s-body-could-not",
                "the notice's body could not be read"
            ))
        })?;
        Ok(Self {
            webhook: PaymentWebhook {
                payload: payload.to_vec(),
                signature: PaymentSignature::new(signature),
            },
            auditor: RequestAuditor::system(state.event_dispatcher.clone()),
        })
    }
}
