/// HTTP request methods.
///
/// Used by route matching and impersonation action logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum HttpMethod {
    /// GET request.
    Get,
    /// POST request.
    Post,
    /// PUT request.
    Put,
    /// PATCH request.
    Patch,
    /// DELETE request.
    Delete,
    /// HEAD request.
    Head,
    /// OPTIONS request.
    Options,
    /// Matches any HTTP method, in route matching.
    Any,
}

impl HttpMethod {
    /// The method this wire token names, or `None` for anything outside the
    /// set the proxy knows.
    ///
    /// A client may send any token at all. A caller that labels or matches
    /// on a method has to handle the unknown ones. Turning an unknown token
    /// into a known method would give it a wrong answer.
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        match token {
            "GET" => Some(Self::Get),
            "POST" => Some(Self::Post),
            "PUT" => Some(Self::Put),
            "PATCH" => Some(Self::Patch),
            "DELETE" => Some(Self::Delete),
            "HEAD" => Some(Self::Head),
            "OPTIONS" => Some(Self::Options),
            "*" => Some(Self::Any),
            _ => None,
        }
    }

    /// Whether the method only reads: `GET`, `HEAD` and `OPTIONS`.
    ///
    /// Everything else may change state, and `Any` is no real method, so
    /// neither counts as safe.
    #[must_use]
    pub fn is_safe(self) -> bool {
        matches!(self, Self::Get | Self::Head | Self::Options)
    }

    /// The method as it is sent on the wire, such as `"GET"`.
    ///
    /// `Any` is not a real HTTP method. It renders as `"*"`, the wildcard
    /// route matchers use.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
            Self::Any => "*",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each method prints as its upper-case wire name, and `Any` prints as
    /// the wildcard `*`.
    #[test]
    fn as_str_returns_the_wire_method_name() {
        assert_eq!(HttpMethod::Get.as_str(), "GET");
        assert_eq!(HttpMethod::Post.as_str(), "POST");
        assert_eq!(HttpMethod::Put.as_str(), "PUT");
        assert_eq!(HttpMethod::Patch.as_str(), "PATCH");
        assert_eq!(HttpMethod::Delete.as_str(), "DELETE");
        assert_eq!(HttpMethod::Head.as_str(), "HEAD");
        assert_eq!(HttpMethod::Options.as_str(), "OPTIONS");
        assert_eq!(HttpMethod::Any.as_str(), "*");
    }

    /// Every method, `Any` included, parses back from its own wire name.
    #[test]
    fn every_known_token_parses_back_to_its_method() {
        for method in [
            HttpMethod::Get,
            HttpMethod::Post,
            HttpMethod::Put,
            HttpMethod::Patch,
            HttpMethod::Delete,
            HttpMethod::Head,
            HttpMethod::Options,
            HttpMethod::Any,
        ] {
            assert_eq!(HttpMethod::parse(method.as_str()), Some(method));
        }
    }

    /// A client sends `PROPFIND`, lower-case `get` or an empty method. Each
    /// parses to nothing, so the caller handles it as unknown instead of
    /// as some other method.
    #[test]
    fn an_unknown_token_does_not_parse() {
        assert_eq!(HttpMethod::parse("PROPFIND"), None);
        assert_eq!(HttpMethod::parse("get"), None);
        assert_eq!(HttpMethod::parse(""), None);
    }
}
