//! Which page sent a request, as the browser says in `Sec-Fetch-Site` and
//! `Origin`.
//!
//! The gateway only reports it; whether a cookie request from that page
//! may change anything is the domain's `CookieRequest` to decide.

use http::HeaderMap;
use ianua_domain::domains::proxy::request::cross_site::PageOrigin;
use ianua_domain::types::HostOrigin;

use crate::request::host::RequestHost;

/// The page that sent a request to `host`: one on the host itself, or on
/// one of `trusted` origins (`https://shop.acme.com`), is trusted.
///
/// A browser says it in `Sec-Fetch-Site`; one too old to send that still
/// sends `Origin` on a post. `same-site` alone is not enough, since a
/// sibling subdomain is the same site and is not this app. A request that
/// says nothing is from elsewhere.
pub(crate) fn page_origin(
    headers: &HeaderMap,
    host: &RequestHost,
    trusted: &[HostOrigin],
) -> PageOrigin {
    if from_host_itself(headers, host) || from_trusted(headers, trusted) {
        return PageOrigin::Trusted;
    }
    PageOrigin::Elsewhere
}

/// Whether a page on `host` itself sent the request.
fn from_host_itself(headers: &HeaderMap, host: &RequestHost) -> bool {
    if let Some(site) = text(headers, "sec-fetch-site") {
        return site == "same-origin";
    }
    let own = format!("https://{}", host.as_str());
    origin(headers).is_some_and(|sent| sent.eq_ignore_ascii_case(&own))
}

/// Whether the request's `Origin` is one of `trusted`.
fn from_trusted(headers: &HeaderMap, trusted: &[HostOrigin]) -> bool {
    origin(headers).is_some_and(|sent| trusted.iter().any(|own| own.as_str() == sent))
}

fn origin(headers: &HeaderMap) -> Option<&str> {
    text(headers, "origin")
}

fn text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;
    use ianua_domain::types::DomainName;

    use super::*;

    fn host(name: &str) -> RequestHost {
        RequestHost::new(DomainName::new(name).unwrap()).unwrap()
    }

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_static(value));
        }
        map
    }

    #[test]
    fn a_page_on_the_host_itself_is_trusted() {
        let shop = host("shop.example.com");

        assert_eq!(
            page_origin(&headers(&[("sec-fetch-site", "same-origin")]), &shop, &[]),
            PageOrigin::Trusted
        );
        assert_eq!(
            page_origin(
                &headers(&[("origin", "https://shop.example.com")]),
                &shop,
                &[]
            ),
            PageOrigin::Trusted
        );
    }

    /// A sibling blog origin remains untrusted even when the browser labels
    /// its request same-site.
    #[test]
    fn a_sibling_on_the_same_site_is_elsewhere() {
        let shop = host("shop.example.com");
        let sent = headers(&[
            ("sec-fetch-site", "same-site"),
            ("origin", "https://blog.example.com"),
        ]);

        assert_eq!(page_origin(&sent, &shop, &[]), PageOrigin::Elsewhere);
    }

    /// The owner's pages call the host of a service's own cookie, and are
    /// trusted there by name.
    #[test]
    fn an_origin_the_host_trusts_is_trusted() {
        let api = host("api.example.com");
        let sent = headers(&[
            ("sec-fetch-site", "same-site"),
            ("origin", "https://shop.example.com"),
        ]);

        assert_eq!(
            page_origin(
                &sent,
                &api,
                &[HostOrigin::new("https://shop.example.com").unwrap()]
            ),
            PageOrigin::Trusted
        );
    }

    #[test]
    fn a_request_that_says_nothing_is_from_elsewhere() {
        assert_eq!(
            page_origin(&HeaderMap::new(), &host("shop.example.com"), &[]),
            PageOrigin::Elsewhere
        );
    }
}
