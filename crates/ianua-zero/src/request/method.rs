//! The method a request was sent with, as routes and policy name it.

use ianua_domain::types::HttpMethod;

/// The method `method` names, or `None` for one the gateway does not serve.
///
/// `*` is what a route writes for "every method". Sent as a request's own
/// method it would match only the routes that take every method, which no
/// real method selects that way, so it is refused like any unknown token.
pub(crate) fn request_method(method: &http::Method) -> Option<HttpMethod> {
    HttpMethod::parse(method.as_str()).filter(|parsed| *parsed != HttpMethod::Any)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_method_the_gateway_serves_is_read() {
        for (sent, read) in [
            (http::Method::GET, HttpMethod::Get),
            (http::Method::POST, HttpMethod::Post),
            (http::Method::PUT, HttpMethod::Put),
            (http::Method::PATCH, HttpMethod::Patch),
            (http::Method::DELETE, HttpMethod::Delete),
            (http::Method::HEAD, HttpMethod::Head),
            (http::Method::OPTIONS, HttpMethod::Options),
        ] {
            assert_eq!(request_method(&sent), Some(read));
        }
    }

    /// A lower-case `get` is another token in HTTP, not `GET`.
    #[test]
    fn an_unknown_token_is_not_a_method() {
        for token in ["*", "get", "CONNECT", "TRACE"] {
            let method = http::Method::from_bytes(token.as_bytes()).unwrap();

            assert_eq!(request_method(&method), None, "{token}");
        }
    }
}
