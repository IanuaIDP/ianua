//! The gateway's sign-in addresses on an app's own host, called as a page
//! on that host calls them: JSON, from the same origin.

use super::Request;
use crate::net::Call;
use crate::wire::app_sign_in::{AppFactorCode, AppLogIn, AppSignedIn, AppToken, TokenFor};

/// The prefix every sign-in address answers under unless moved.
pub const PREFIX: &str = "/.ianua";

/// `call` as a page on `host` sends it: from the same origin.
fn from_the_page(call: Call, host: &str) -> Call {
    call.header("origin", &format!("https://{host}"))
        .header("sec-fetch-site", "same-origin")
}

/// `GET /.ianua/login` on `host`: the sign-in page, read for its status
/// alone, which says whether the app's sign-in is set up there yet.
#[must_use]
pub fn sign_in_page(host: &str) -> Request<serde::de::IgnoredAny> {
    Request::of(Call::get(format!("https://{host}{PREFIX}/login")))
}

/// `POST /.ianua/login` on `host`.
#[must_use]
pub fn log_in(host: &str, log_in: &AppLogIn) -> Request<AppSignedIn> {
    let call = Call::post(format!("https://{host}{PREFIX}/login")).json(log_in);
    Request::of(from_the_page(call, host))
}

/// `POST /.ianua/mfa` on `host`: the authenticator code a sign-in there
/// still owes.
#[must_use]
pub fn answer_factor(host: &str, code: &AppFactorCode) -> Request<AppSignedIn> {
    let call = Call::post(format!("https://{host}{PREFIX}/mfa")).json(code);
    Request::of(from_the_page(call, host))
}

/// `POST /.ianua/token` on `host`: a token for another service's audience.
#[must_use]
pub fn token(host: &str, wanted: &TokenFor) -> Request<AppToken> {
    let call = Call::post(format!("https://{host}{PREFIX}/token")).json(wanted);
    Request::of(from_the_page(call, host))
}

/// `POST /.ianua/logout` on `host`.
#[must_use]
pub fn log_out(host: &str) -> Request<serde::de::IgnoredAny> {
    let call = Call::post(format!("https://{host}{PREFIX}/logout")).json(&serde_json::json!({}));
    Request::of(from_the_page(call, host))
}
