//! Where a request asks to go, read strictly from what the service sent:
//! the authority of a `CONNECT`, or the host, port and path of a plain
//! HTTP request in absolute form. The host is held to the domain's
//! [`EgressTarget`] rules, so nothing a lenient parser would read as
//! another host gets past the comparison with a policy's list.

use http::{Method, Request, Uri};
use ianua_domain::domains::routing::egress::EgressTarget;

/// How the service asks to go out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Form {
    /// A `CONNECT`: a tunnel the egress gateway never sees inside.
    Tunnel,
    /// A plain HTTP request, sent on to this origin-form path.
    Relay(String),
}

/// Where a request asks to go, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asked {
    /// The host and port.
    pub target: EgressTarget,
    /// How.
    pub form: Form,
}

/// Where `request` asks to go, or `None` when it names no target the
/// egress gateway can judge.
#[must_use]
pub fn asked_of<B>(request: &Request<B>) -> Option<Asked> {
    match *request.method() {
        Method::CONNECT => tunnel(request.uri()),
        _ => relay(request.uri()),
    }
}

/// The target of a `CONNECT host:port`.
fn tunnel(uri: &Uri) -> Option<Asked> {
    let authority = uri.authority()?;
    let bare = uri.scheme().is_none() && uri.path_and_query().is_none_or(|path| path == "/");
    if !bare {
        return None;
    }
    Some(Asked {
        target: EgressTarget::new(authority.host(), authority.port_u16()?).ok()?,
        form: Form::Tunnel,
    })
}

/// The target of an absolute-form request (`GET http://host/path`) and the
/// path it is sent on with. Plain HTTP only: HTTPS goes through `CONNECT`.
fn relay(uri: &Uri) -> Option<Asked> {
    if uri.scheme_str() != Some("http") {
        return None;
    }
    let authority = uri.authority()?;
    if authority.as_str().contains('@') {
        return None;
    }
    let port = authority.port_u16().unwrap_or(80);
    let path = uri.path_and_query().map_or("/", |path| path.as_str());
    Some(Asked {
        target: EgressTarget::new(authority.host(), port).ok()?,
        form: Form::Relay(path.to_owned()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asked(method: &str, uri: &str) -> Option<Asked> {
        let request = Request::builder().method(method).uri(uri).body(()).ok()?;
        asked_of(&request)
    }

    /// A `CONNECT API.GitHub.com:443` asks for a tunnel to
    /// `api.github.com:443`.
    #[test]
    fn a_connect_names_a_tunnel_to_its_host_and_port() {
        let asked = asked("CONNECT", "API.GitHub.com:443").unwrap();

        assert_eq!(asked.target.to_string(), "api.github.com:443");
        assert_eq!(asked.form, Form::Tunnel);
    }

    /// `GET http://example.org/a?b=1` asks for `example.org:80`, sent on
    /// as `/a?b=1`.
    #[test]
    fn an_absolute_request_names_its_host_port_and_path() {
        let asked = asked("GET", "http://example.org/a?b=1").unwrap();

        assert_eq!(asked.target.to_string(), "example.org:80");
        assert_eq!(asked.form, Form::Relay("/a?b=1".to_owned()));
    }

    /// IP addresses, wildcards, missing tunnel ports, user info, HTTPS
    /// relay URLs and relative paths yield no acceptable egress target.
    #[test]
    fn odd_targets_name_nothing() {
        for (method, uri) in [
            ("CONNECT", "169.254.169.254:80"),
            ("CONNECT", "[::1]:443"),
            ("CONNECT", "example.org"),
            ("CONNECT", "*.example.org:443"),
            ("GET", "https://example.org/"),
            ("GET", "http://user@example.org/"),
            ("GET", "http://10.0.0.1/"),
            ("GET", "/relative"),
        ] {
            assert!(asked(method, uri).is_none(), "{method} {uri}");
        }
    }
}
