//! Who sent a sign-in request: a page on the app's own host, or anyone.
//!
//! A sign-in form that any site could post to would sign a person in to an
//! account of the sender's choosing, so every action a page sends is held to
//! the page's own origin. A link opened from a mailbox and a provider sending
//! the browser back come from elsewhere by nature; what they carry is
//! checked against the browser's cookies instead.

use http::HeaderMap;
use ianua_domain::types::HostOrigin;

use super::fields::header;

/// Whether a page on `host` itself sent the request.
///
/// A browser says so in `Sec-Fetch-Site`; one too old to send it still sends
/// `Origin` on a post. `same-site` is not enough: a sibling subdomain is the
/// same site and is not this app. A request saying neither is refused.
#[must_use]
pub(crate) fn from_same_origin(headers: &HeaderMap, host: &str) -> bool {
    if let Some(site) = header(headers, "sec-fetch-site") {
        return site == "same-origin";
    }
    header(headers, "origin").is_some_and(|origin| is_https_origin_of(origin, host))
}

/// Whether `next` is an `https` address under one of `origins`.
pub(super) fn leads_to(next: &str, origins: &[HostOrigin]) -> bool {
    let Ok(next) = url::Url::parse(next) else {
        return false;
    };
    let next_origin = next.origin().ascii_serialization();
    next.scheme() == "https" && origins.iter().any(|origin| origin.as_str() == next_origin)
}

fn is_https_origin_of(origin: &str, host: &str) -> bool {
    origin
        .strip_prefix("https://")
        .is_some_and(|rest| rest.eq_ignore_ascii_case(host))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(*name, value.parse().unwrap());
        }
        headers
    }

    #[test]
    fn a_page_on_the_host_itself_is_same_origin() {
        assert!(from_same_origin(
            &headers(&[("sec-fetch-site", "same-origin")]),
            "shop.example.com"
        ));
        assert!(from_same_origin(
            &headers(&[("origin", "https://shop.example.com")]),
            "shop.example.com"
        ));
    }

    /// A sibling subdomain is the same site, and still not this app.
    #[test]
    fn a_sibling_foreign_or_silent_page_is_not() {
        for pairs in [
            vec![("sec-fetch-site", "same-site")],
            vec![("sec-fetch-site", "cross-site")],
            vec![("sec-fetch-site", "none")],
            vec![("origin", "https://evil.example.com")],
            vec![("origin", "http://shop.example.com")],
            vec![("origin", "null")],
            vec![
                ("sec-fetch-site", "same-site"),
                ("origin", "https://shop.example.com"),
            ],
            vec![],
        ] {
            assert!(
                !from_same_origin(&headers(&pairs), "shop.example.com"),
                "{pairs:?}"
            );
        }
    }

    /// A hop sends the browser on only within its own sign-in, so it cannot
    /// be used to send people anywhere.
    #[test]
    fn a_hop_leads_only_to_an_origin_of_its_sign_in() {
        let origins = vec![HostOrigin::new("https://shop.example.com").unwrap()];

        assert!(leads_to("https://shop.example.com/orders?id=1", &origins));
        assert!(!leads_to("https://evil.example.com/", &origins));
        assert!(!leads_to("http://shop.example.com/", &origins));
        assert!(!leads_to("https://shop.example.com.evil.com/", &origins));
        assert!(!leads_to("//shop.example.com/", &origins));
    }
}
