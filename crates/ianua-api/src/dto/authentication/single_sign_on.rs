//! The browser's side of single sign-on: the cookie it keeps while it is at
//! the identity provider, and where it is sent next.
//!
//! Every answer from an identity provider ends in a redirect to the
//! dashboard, never an error page from here: with a one-time code when the
//! sign-in worked, or with `?sso=failed` when it did not. The reason for a
//! failure is logged, not shown, so the page says nothing a forger can use.

use axum::http::header::{CACHE_CONTROL, LOCATION, REFERRER_POLICY, SET_COOKIE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use ianua_app::error::AppError;
use ianua_app::use_cases::authentication::federation::single_sign_on::{SsoSignIn, SsoStart};

use crate::extractors::authentication::{SSO_COOKIE, SsoWayBack};

/// Sends the browser to the identity provider, holding the secret that
/// proves it is the one coming back for as long as a request waits for its
/// answer.
///
/// `SameSite=None` because a SAML answer arrives as a cross-site POST, which
/// a `Lax` cookie would not ride along with.
pub(crate) struct ToIdentityProvider {
    location: String,
    cookie: String,
}

impl ToIdentityProvider {
    /// The redirect that starts `start`, on the way `way` describes.
    #[must_use]
    pub(crate) fn new(start: &SsoStart, way: &SsoWayBack) -> Self {
        Self {
            location: start.url.as_str().to_owned(),
            cookie: format!(
                "{SSO_COOKIE}={}; Path={}; Max-Age={}; HttpOnly; Secure; SameSite=None",
                start.binding.expose(),
                way.cookie_path,
                way.cookie_lifetime_secs,
            ),
        }
    }
}

impl IntoResponse for ToIdentityProvider {
    fn into_response(self) -> Response {
        redirect(&self.location, &self.cookie)
    }
}

/// Sends the browser back to the dashboard with the outcome, and drops the
/// secret it no longer needs.
pub(crate) struct BackToDashboard {
    location: String,
    cookie: String,
}

impl BackToDashboard {
    /// The redirect that ends a single sign-on with `outcome`.
    #[must_use]
    pub(crate) fn new(way: &SsoWayBack, outcome: Result<SsoSignIn, AppError>) -> Self {
        Self {
            location: dashboard_address(&way.dashboard, outcome),
            cookie: format!(
                "{SSO_COOKIE}=; Path={}; Max-Age=0; HttpOnly; Secure; SameSite=None",
                way.cookie_path,
            ),
        }
    }
}

impl IntoResponse for BackToDashboard {
    fn into_response(self) -> Response {
        redirect(&self.location, &self.cookie)
    }
}

/// The dashboard page `outcome` sends the browser to: the one-time code's
/// page when the sign-in worked, the sign-in page saying it failed when it
/// did not.
fn dashboard_address(dashboard: &str, outcome: Result<SsoSignIn, AppError>) -> String {
    match outcome {
        Ok(signed_in) => format!("{dashboard}/sso?code={}", signed_in.code.expose()),
        Err(error) => {
            tracing::warn!(error = %error, "single sign-on refused");
            format!("{dashboard}/login?sso=failed")
        }
    }
}

/// A `303` to `location` that sets `cookie` and is never cached or sent on
/// as a referrer. A value that cannot be a header is a `500`.
fn redirect(location: &str, cookie: &str) -> Response {
    let (Ok(location), Ok(cookie)) = (
        HeaderValue::from_str(location),
        HeaderValue::from_str(cookie),
    ) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    (
        StatusCode::SEE_OTHER,
        [
            (LOCATION, location),
            (SET_COOKIE, cookie),
            (CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (REFERRER_POLICY, HeaderValue::from_static("no-referrer")),
        ],
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::federation::ServiceProvider;
    use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{HttpsUrl, SamlEntityId, UserId};

    use super::*;

    /// The way back for the `acme` organization's `prod` tenant.
    fn way() -> SsoWayBack {
        SsoWayBack {
            oidc_callback: HttpsUrl::new(
                "https://ianua.example.com/api/v1/organizations/acme/tenants/prod/federation/oidc/callback",
            )
            .unwrap(),
            service_provider: ServiceProvider {
                entity_id: SamlEntityId::new("https://ianua.example.com").unwrap(),
                acs_url: HttpsUrl::new(
                    "https://ianua.example.com/api/v1/organizations/acme/tenants/prod/federation/saml/acs",
                )
                .unwrap(),
            },
            dashboard: "https://ianua.example.com/organizations/acme/tenants/prod".to_owned(),
            cookie_path: "/api/v1/organizations/acme/tenants/prod/federation".to_owned(),
            cookie_lifetime_secs: 600,
        }
    }

    /// The value of a header the response must carry.
    fn header(response: &Response, name: axum::http::HeaderName) -> &str {
        response.headers().get(name).unwrap().to_str().unwrap()
    }

    /// Ann signs in through her company's provider and is sent back to the
    /// dashboard with a one-time code to trade for her session.
    #[test]
    fn a_sign_in_goes_back_with_its_one_time_code() {
        let response = BackToDashboard::new(
            &way(),
            Ok(SsoSignIn {
                code: Secret::new("the-code"),
                user_id: UserId::new(),
                jit_provisioned: false,
                second_factor: SecondFactor::NotOwed,
            }),
        )
        .into_response();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            header(&response, LOCATION),
            "https://ianua.example.com/organizations/acme/tenants/prod/sso?code=the-code"
        );
    }

    /// A refused sign-in redirects to the login page with only the failure flag.
    #[test]
    fn a_refusal_goes_back_to_the_sign_in_page_saying_nothing_of_why() {
        let response = BackToDashboard::new(
            &way(),
            Err(AppError::Forbidden(
                "SAML assertion rejected".to_owned().into(),
            )),
        )
        .into_response();

        assert_eq!(
            header(&response, LOCATION),
            "https://ianua.example.com/organizations/acme/tenants/prod/login?sso=failed"
        );
    }

    /// Coming back from the provider clears the browser's sign-in secret,
    /// so it cannot be used twice.
    #[test]
    fn coming_back_drops_the_secret() {
        let response = BackToDashboard::new(
            &way(),
            Err(AppError::Forbidden("refused".to_owned().into())),
        )
        .into_response();

        assert!(header(&response, SET_COOKIE).starts_with("ianua_sso=; "));
        assert!(header(&response, SET_COOKIE).contains("Max-Age=0"));
    }

    /// Ann is sent to her provider with a short-lived secret cookie that her
    /// browser sends only to the federation paths she comes back on.
    #[test]
    fn going_out_hands_the_browser_its_secret_for_the_way_back_only() {
        let start = SsoStart {
            url: HttpsUrl::new("https://idp.example.com/sso?SAMLRequest=x").unwrap(),
            binding: Secret::new("secret"),
        };

        let response = ToIdentityProvider::new(&start, &way()).into_response();

        let cookie = header(&response, SET_COOKIE);
        assert_eq!(
            header(&response, LOCATION),
            "https://idp.example.com/sso?SAMLRequest=x"
        );
        assert!(cookie.starts_with("ianua_sso=secret; "));
        assert!(cookie.contains("Max-Age=600;"));
        assert!(cookie.contains("Path=/api/v1/organizations/acme/tenants/prod/federation;"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
    }
}
