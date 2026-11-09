//! Bodies of the device flow (RFC 8628): the codes a device is handed, and
//! the person's answer on another screen. The device collects its tokens
//! at the token endpoint.

use ianua_app::use_cases::oauth::flows::DeviceCodeResult;
use ianua_domain::types::DeviceUserCode;
use serde::{Deserialize, Serialize};
use url::form_urlencoded::Serializer;

use crate::error::ApiError;

/// The codes a device is handed (RFC 8628 3.2).
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct DeviceCodeResponse {
    /// The device code the device polls the token endpoint with.
    pub device_code: String,
    /// The short code the person types on the other screen.
    pub user_code: String,
    /// Where the person goes to type it.
    pub verification_uri: String,
    /// The same page with the code already filled in, for a QR code.
    pub verification_uri_complete: String,
    /// The shortest wait between polls, in seconds.
    pub interval: u16,
    /// How long the codes stay valid, in seconds.
    pub expires_in: i64,
}

impl From<DeviceCodeResult> for DeviceCodeResponse {
    fn from(result: DeviceCodeResult) -> Self {
        let page = result.verification_uri.as_str();
        let code = result.user_code.as_str();
        let joiner = if page.contains('?') { '&' } else { '?' };
        let query = Serializer::new(String::new())
            .append_pair("user_code", code)
            .finish();
        Self {
            device_code: result.device_code.expose().to_owned(),
            user_code: code.to_owned(),
            verification_uri: page.to_owned(),
            verification_uri_complete: format!("{page}{joiner}{query}"),
            interval: result.interval.as_secs(),
            expires_in: result.expires_in.whole_seconds(),
        }
    }
}

/// Request body for answering a device request.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct DeviceAnswerBody {
    /// The code the device shows.
    pub user_code: String,
}

impl DeviceAnswerBody {
    /// The code, checked.
    ///
    /// # Errors
    ///
    /// - [`ApiError::validation`] when it is not in the shape of a user
    ///   code.
    pub(crate) fn user_code(self) -> Result<DeviceUserCode, ApiError> {
        DeviceUserCode::new(self.user_code).map_err(ApiError::validation)
    }
}
