//! A signed-out browser on a protected page of a host with app sign-in.

use http::request::Parts;
use http::uri::PathAndQuery;
use http::{Method, StatusCode};
use ianua_domain::domains::routing::sign_in::app::{AppSignIn, SignInAction, SignedOutBrowsers};
use ianua_domain::types::DomainName;

use super::fields::header;

/// Where to send a signed-out browser refused with `status` on `host`, if
/// anywhere.
///
/// Only a browser loading a page is sent, and only when the sign-in says
/// so: a `401` on a `GET` or `HEAD` that accepts HTML and, when it says, is
/// a navigation. A script, a `403`, or a host set to refuse keeps its
/// answer. The browser comes back to the page it asked for, which is a path
/// on this host by construction; the API holds it to the rules before use.
#[must_use]
pub(crate) fn login_redirect(
    sign_in: &AppSignIn,
    host: &DomainName,
    parts: &Parts,
    status: StatusCode,
) -> Option<String> {
    if status != StatusCode::UNAUTHORIZED {
        return None;
    }
    if sign_in.signed_out_browsers() != SignedOutBrowsers::Redirect || !is_page_load(parts) {
        return None;
    }
    let came_from = parts.uri.path_and_query().map_or("/", PathAndQuery::as_str);
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("return_to", came_from)
        .finish();
    Some(format!(
        "https://{host}{}?{query}",
        sign_in.path(SignInAction::LogIn)
    ))
}

/// Whether a browser is loading a page: a `GET` or `HEAD` accepting HTML,
/// navigating when it says how it fetches.
fn is_page_load(parts: &Parts) -> bool {
    let navigating = header(&parts.headers, "sec-fetch-mode").is_none_or(|mode| mode == "navigate");
    let wants_page =
        header(&parts.headers, "accept").is_some_and(|accept| accept.contains("text/html"));
    matches!(parts.method, Method::GET | Method::HEAD) && wants_page && navigating
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ianua_domain::domains::routing::sign_in::app::AppSignInParams;
    use ianua_domain::types::Setting;

    use super::*;

    fn sign_in(signed_out_browsers: SignedOutBrowsers) -> AppSignIn {
        AppSignIn::new(AppSignInParams {
            hosts: vec![host()],
            prefix: Setting::Unset,
            moved: BTreeMap::new(),
            after_sign_in: Setting::Unset,
            signed_out_browsers,
        })
        .unwrap()
    }

    fn host() -> DomainName {
        DomainName::new("shop.example.com").unwrap()
    }

    fn parts(method: Method, headers: &[(&str, &str)]) -> Parts {
        let builder = headers.iter().fold(
            http::Request::builder().method(method).uri("/orders?id=1"),
            |builder, (name, value)| builder.header(*name, *value),
        );
        builder.body(()).unwrap().into_parts().0
    }

    const PAGE_LOAD: [(&str, &str); 2] = [("accept", "text/html"), ("sec-fetch-mode", "navigate")];

    #[test]
    fn a_signed_out_browser_loading_a_page_is_sent_to_log_in_and_back() {
        let redirect = login_redirect(
            &sign_in(SignedOutBrowsers::Redirect),
            &host(),
            &parts(Method::GET, &PAGE_LOAD),
            StatusCode::UNAUTHORIZED,
        );

        assert_eq!(
            redirect.as_deref(),
            Some("https://shop.example.com/.ianua/login?return_to=%2Forders%3Fid%3D1")
        );
    }

    #[test]
    fn a_host_set_to_refuse_keeps_its_answer() {
        let redirect = login_redirect(
            &sign_in(SignedOutBrowsers::Refuse),
            &host(),
            &parts(Method::GET, &PAGE_LOAD),
            StatusCode::UNAUTHORIZED,
        );

        assert_eq!(redirect, None);
    }

    #[test]
    fn a_script_a_post_or_a_forbidden_page_keeps_its_answer() {
        let sign_in = sign_in(SignedOutBrowsers::Redirect);

        for (method, headers, status) in [
            (
                Method::GET,
                vec![("accept", "application/json")],
                StatusCode::UNAUTHORIZED,
            ),
            (
                Method::GET,
                vec![("accept", "text/html"), ("sec-fetch-mode", "cors")],
                StatusCode::UNAUTHORIZED,
            ),
            (Method::POST, PAGE_LOAD.to_vec(), StatusCode::UNAUTHORIZED),
            (Method::GET, PAGE_LOAD.to_vec(), StatusCode::FORBIDDEN),
        ] {
            let redirect = login_redirect(&sign_in, &host(), &parts(method, &headers), status);

            assert_eq!(redirect, None);
        }
    }
}
