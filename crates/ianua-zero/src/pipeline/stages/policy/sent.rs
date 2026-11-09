//! What the Policy stage reads of one request beyond its context: what was
//! sent, and what the stages before it established.

use std::net::IpAddr;

use http::HeaderMap;
use http::header::CONTENT_TYPE;
use ianua_app::use_cases::proxy::credentials::Identification;
use ianua_domain::domains::proxy::access::question::{
    Asked, Circumstances, DpopBinding, MethodClaim, PostureFinding,
};
use ianua_domain::domains::proxy::request::context::{Authentication, PipelineContext};
use ianua_domain::types::{Fact, HostName};

use crate::pipeline::facts::RequestFacts;

/// Headers some frameworks read to treat a request as another method.
const METHOD_OVERRIDE_HEADERS: [&str; 3] = [
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
];

/// Body types frameworks read a `_method` field from.
const FORM_CONTENT_TYPES: [&str; 2] = ["application/x-www-form-urlencoded", "multipart/form-data"];

/// The query key frameworks read as the method the request is meant as.
const METHOD_PARAMETER: &str = "_method";

/// What the request `facts` describe asks for, as the access decision
/// reads it.
pub(crate) fn asked(facts: &RequestFacts) -> Asked {
    let admitted = &facts.admitted;
    Asked {
        method: Fact::Known(admitted.method()),
        path: Fact::Known(admitted.path().clone()),
        method_claim: method_claim(facts),
        host: Fact::from_option(HostName::new(admitted.host().as_str()).ok()),
    }
}

/// Whether the upstream might read the request as another method: an
/// override header, a `_method` query key however it is encoded, or a form
/// body, which several frameworks read a `_method` field from.
///
/// A form body is judged by its type rather than read: the gateway decides
/// on metadata and does not buffer bodies to find out.
fn method_claim(facts: &RequestFacts) -> MethodClaim {
    let overridden = names_an_override_header(&facts.headers)
        || facts.query().is_some_and(names_a_method_parameter)
        || carries_a_form(&facts.headers);
    if overridden {
        return MethodClaim::Overridden;
    }
    MethodClaim::AsSent
}

/// What the stages before Policy established about the request.
pub(crate) struct EarlierFindings {
    /// Who the Identity stage proved the caller is, with what they hold
    /// and whether they proved the key their credential is bound to.
    pub identification: Identification,
    /// What a device posture check found.
    pub posture: PostureFinding,
}

impl EarlierFindings {
    /// What is known around the request: what earlier stages wrote on the
    /// context and what they established here. Whatever no stage found is
    /// unknown, which the decision never reads as harmless.
    pub(super) fn circumstances(&self, ctx: &PipelineContext) -> Circumstances {
        Circumstances {
            binding: self.identification.binding(),
            ..held_circumstances(ctx, self.posture)
        }
    }

    /// Whether the proof handed over names the caller the Identity stage
    /// wrote on the context: nobody in both, or the same principal.
    pub(super) fn agrees_with(&self, ctx: &PipelineContext) -> bool {
        match (ctx.authentication(), &self.identification) {
            (Authentication::Anonymous, Identification::Anonymous) => true,
            (Authentication::Authenticated(verified), Identification::Proven(proven)) => {
                verified.caller.principal() == proven.verified.caller.principal()
            }
            (Authentication::Anonymous, Identification::Proven(_))
            | (Authentication::Authenticated(_), Identification::Anonymous) => false,
        }
    }
}

/// What is known around a request or a connection it opened: its address
/// and country, and `posture` as its device check found it. Whatever no
/// stage found is unknown, and whether a key was proven is decided later.
pub(crate) fn held_circumstances(ctx: &PipelineContext, posture: PostureFinding) -> Circumstances {
    Circumstances {
        country: ctx.country_code.clone(),
        source_ip: Fact::from_option(source_ip(ctx)),
        device: Fact::Unknown,
        risk: Fact::Unknown,
        sensitivity: Fact::Unknown,
        binding: DpopBinding::Unbound,
        posture,
    }
}

/// The client's address as the edge saw it, when it reads as one.
fn source_ip(ctx: &PipelineContext) -> Option<IpAddr> {
    ctx.ip_address.known()?.as_str().parse().ok()
}

fn names_an_override_header(headers: &HeaderMap) -> bool {
    METHOD_OVERRIDE_HEADERS
        .iter()
        .any(|name| headers.contains_key(*name))
}

fn names_a_method_parameter(query: &str) -> bool {
    url::form_urlencoded::parse(query.as_bytes())
        .any(|(key, _)| key.trim().eq_ignore_ascii_case(METHOD_PARAMETER))
}

fn carries_a_form(headers: &HeaderMap) -> bool {
    headers
        .get_all(CONTENT_TYPE)
        .iter()
        .map(|value| String::from_utf8_lossy(value.as_bytes()).to_ascii_lowercase())
        .any(|value| {
            FORM_CONTENT_TYPES
                .iter()
                .any(|form| value.trim_start().starts_with(form))
        })
}

#[cfg(test)]
mod tests {
    use http::{HeaderValue, Request};

    use super::*;

    struct Shape {
        headers: HeaderMap,
        query: Option<&'static str>,
    }

    fn claim_of(shape: &Shape) -> MethodClaim {
        let request = Request::get("/orders").header("host", "shop.acme.com");
        let mut facts = RequestFacts::sent(request.body(()).unwrap());
        facts.query = shape.query.map(str::to_owned);
        facts.headers = shape.headers.clone();
        asked(&facts).method_claim
    }

    fn with_header(name: &'static str, value: &'static str) -> Shape {
        let mut headers = HeaderMap::new();
        headers.insert(name, HeaderValue::from_static(value));
        Shape {
            headers,
            query: None,
        }
    }

    #[test]
    fn a_plain_request_is_read_as_sent() {
        let plain = Shape {
            headers: HeaderMap::new(),
            query: Some("page=2"),
        };

        assert_eq!(claim_of(&plain), MethodClaim::AsSent);
    }

    /// Each supported override header marks a GET as overridden when it names DELETE.
    #[test]
    fn an_override_header_reads_as_overridden() {
        for name in METHOD_OVERRIDE_HEADERS {
            assert_eq!(
                claim_of(&with_header(name, "DELETE")),
                MethodClaim::Overridden,
                "{name}"
            );
        }
    }

    /// Encoded, uppercase and valueless method query parameters all mark the request as overridden.
    #[test]
    fn a_method_parameter_however_encoded_reads_as_overridden() {
        for query in [
            "_method=DELETE",
            "%5Fmethod=DELETE",
            "_METHOD=put",
            "a=1&_method",
        ] {
            let shape = Shape {
                headers: HeaderMap::new(),
                query: Some(query),
            };

            assert_eq!(claim_of(&shape), MethodClaim::Overridden, "{query}");
        }
    }

    /// A multipart form content type marks the request as overridden without inspecting its body.
    #[test]
    fn a_form_body_reads_as_overridden() {
        let form = with_header("content-type", "Multipart/Form-Data; boundary=x");

        assert_eq!(claim_of(&form), MethodClaim::Overridden);
    }
}
