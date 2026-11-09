//! The headers a proxy vouches for itself, which no client and no tenant
//! may set.
//!
//! Everything that reads or writes headers on the way through uses this
//! list. The proxy strips these headers from inbound requests and refuses
//! them to tenant transforms. Routing refuses a URL parameter rule that
//! would name one.

/// Headers that name the client's address, which the proxy owns.
///
/// The proxy strips every owned header from the inbound request. Then it
/// sets the ones it asserts itself. So an upstream can trust
/// `x-forwarded-user` to mean what the proxy decided, not what a client
/// typed. Tenant transforms may not write them either. The upstream trusts
/// the proxy, not the tenant admin.
///
/// Every `x-forwarded-` and `x-ianua-` header is owned too, as a family in
/// [`PROXY_OWNED_PREFIXES`]. So a new member of either is covered without
/// being listed here. This list holds the rest: the standard `Forwarded`,
/// and the headers other proxies, CDNs and frameworks read as the client's
/// address.
const CLIENT_ADDRESS_HEADERS: [&str; 15] = [
    "forwarded",
    "forwarded-for",
    "x-forwarded",
    "x-real-ip",
    "true-client-ip",
    "x-client-ip",
    "client-ip",
    "x-cluster-client-ip",
    "cf-connecting-ip",
    "fastly-client-ip",
    "x-original-forwarded-for",
    "x-originating-ip",
    "x-remote-ip",
    "x-remote-addr",
    "x-envoy-external-address",
];

/// Headers upstream frameworks read as the request's real method, path or
/// host, in place of the ones the policy decided on.
///
/// Under `x-http-method-override`, a `GET` a route allowed runs as a
/// `DELETE`. Under `x-original-url`, a request routed as `/public` is served
/// as `/admin`.
const OVERRIDE_HEADERS: [&str; 8] = [
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
    "x-original-url",
    "x-rewrite-url",
    "x-original-uri",
    "x-original-host",
    "x-host",
];

/// Header families the proxy owns whole.
///
/// Whatever follows the prefix, an upstream expects the proxy to have set
/// it, not the client.
const PROXY_OWNED_PREFIXES: [&str; 2] = ["x-forwarded-", "x-ianua-"];

/// Whether the proxy asserts this header itself, so a client's copy is
/// stripped from every inbound request and no tenant transform may write it.
///
/// The forwarding adapter strips by this rule instead of keeping a list of
/// its own. Two lists edited in different crates would soon disagree.
///
/// The name is compared without regard to case, with `_` read as `-`. CGI,
/// WSGI and PHP hand headers to code as `HTTP_X_FORWARDED_USER`, which turns
/// both into the same name. So `X_Forwarded_User` reaches them as the header
/// the proxy vouches for.
#[must_use]
pub fn is_proxy_owned(name: &str) -> bool {
    let name = header_spelling(name);
    CLIENT_ADDRESS_HEADERS.contains(&name.as_str())
        || OVERRIDE_HEADERS.contains(&name.as_str())
        || PROXY_OWNED_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

/// `name` as every server reads it: lower case, with `_` read as `-`.
pub(crate) fn header_spelling(name: &str) -> String {
    name.to_ascii_lowercase().replace('_', "-")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Forwarded identity, Ianua and client-address headers are classified as
    /// proxy-owned, while request IDs and unrelated application headers are not.
    #[test]
    fn every_header_naming_the_client_or_the_proxy_is_owned() {
        for name in [
            "x-forwarded-user",
            "X-Forwarded-For",
            "x-forwarded-port",
            "x-forwarded-prefix",
            "x-forwarded-anything-new",
            "x-ianua-assertion",
            "forwarded",
            "Forwarded",
            "true-client-ip",
            "x-client-ip",
            "x-original-forwarded-for",
            "x-real-ip",
        ] {
            assert!(is_proxy_owned(name), "{name} is not owned");
        }
        assert!(!is_proxy_owned("x-request-id"));
        assert!(!is_proxy_owned("forwarded-by-app"));
    }

    /// Underscore aliases of proxy-owned headers retain that classification
    /// because upstream frameworks may read them as the hyphenated names.
    #[test]
    fn an_underscore_spelling_of_an_owned_header_is_owned() {
        for name in [
            "X_Forwarded_User",
            "x_forwarded_for",
            "X_Real_IP",
            "x_http_method_override",
            "X_Ianua_Assertion",
            "true_client_ip",
        ] {
            assert!(is_proxy_owned(name), "{name} is not owned");
        }
    }

    /// `X-Forwarded` and `Forwarded-For`, with no suffix, are owned. Some
    /// libraries read either one as the client's address.
    #[test]
    fn the_bare_forwarded_aliases_are_owned() {
        assert!(is_proxy_owned("X-Forwarded"));
        assert!(is_proxy_owned("Forwarded-For"));
    }

    /// Method, path, host and client-address override headers are classified
    /// as proxy-owned so forwarding can protect the request that policy checked.
    #[test]
    fn headers_that_override_the_method_path_host_or_address_are_owned() {
        for name in [
            "X-HTTP-Method-Override",
            "x-http-method",
            "x-method-override",
            "X-Original-URL",
            "x-rewrite-url",
            "x-original-uri",
            "x-original-host",
            "x-host",
            "Client-IP",
            "x-originating-ip",
            "x-remote-ip",
            "x-remote-addr",
            "x-envoy-external-address",
        ] {
            assert!(is_proxy_owned(name), "{name} is not owned");
        }
    }
}
