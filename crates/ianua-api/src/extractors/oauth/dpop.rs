//! The `DPoP` header a request carries (RFC 9449 4.1): a proof the client
//! signs with the key its tokens are bound to, made for this one request.
//!
//! Reading it only takes it out of the request, with the method and the
//! address it was sent to. Whether it holds is the app's question.

use axum::http::{HeaderMap, Method};
use ianua_app::use_cases::oauth::sender::{DpopHeader, SenderEvidence};
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::Issuer;

/// The header a `DPoP` proof is sent in.
const DPOP: &str = "dpop";

/// A `DPoP` header that cannot be a proof: sent more than once, empty, or
/// not readable as text. A request carries exactly one proof (RFC 9449
/// 4.3), so it is refused rather than read as carrying none.
#[derive(Debug)]
pub(crate) struct UnusableDpop;

/// The `DPoP` header of `headers`.
///
/// # Errors
///
/// - [`UnusableDpop`] when it is sent more than once, empty or unreadable.
pub(crate) fn dpop_header(headers: &HeaderMap) -> Result<DpopHeader, UnusableDpop> {
    let mut sent = headers.get_all(DPOP).iter();
    let Some(first) = sent.next() else {
        return Ok(DpopHeader::NotSent);
    };
    if sent.next().is_some() {
        return Err(UnusableDpop);
    }
    let proof = first.to_str().map_err(|_| UnusableDpop)?.trim();
    if proof.is_empty() {
        return Err(UnusableDpop);
    }
    Ok(DpopHeader::Sent(Secret::new(proof)))
}

/// Where a request was sent: its method, and the tenant endpoint at `path`
/// under `issuer`, as this platform publishes it.
pub(crate) struct SentTo<'a> {
    /// The request's method.
    pub method: &'a Method,
    /// The tenant's issuer.
    pub issuer: &'a Issuer,
    /// The endpoint's path under the issuer, such as `/oauth/token`.
    pub path: &'a str,
}

/// What a request with `headers`, sent as `to` says, carried to prove its
/// holder.
///
/// # Errors
///
/// - [`UnusableDpop`] when its `DPoP` header cannot be a proof.
pub(crate) fn sender_evidence(
    headers: &HeaderMap,
    to: &SentTo<'_>,
) -> Result<SenderEvidence, UnusableDpop> {
    Ok(evidence(dpop_header(headers)?, to))
}

/// What a request sent as `to` says carried `dpop` to prove its holder.
#[must_use]
pub(crate) fn evidence(dpop: DpopHeader, to: &SentTo<'_>) -> SenderEvidence {
    SenderEvidence {
        dpop,
        method: to.method.as_str().to_owned(),
        url: format!("{}{}", to.issuer.as_str(), to.path),
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    /// A request with no `DPoP` header carries no proof.
    #[test]
    fn no_header_carries_no_proof() {
        assert!(matches!(
            dpop_header(&HeaderMap::new()),
            Ok(DpopHeader::NotSent)
        ));
    }

    /// One header is the proof, as sent.
    #[test]
    fn one_header_is_the_proof() {
        let mut headers = HeaderMap::new();
        headers.insert(DPOP, HeaderValue::from_static("a.b.c"));

        let Ok(DpopHeader::Sent(proof)) = dpop_header(&headers) else {
            panic!("one header is read as the proof");
        };
        assert_eq!(proof.expose(), "a.b.c");
    }

    /// Two DPoP headers are rejected rather than selecting one proof.
    #[test]
    fn two_headers_are_refused() {
        let mut headers = HeaderMap::new();
        headers.append(DPOP, HeaderValue::from_static("a.b.c"));
        headers.append(DPOP, HeaderValue::from_static("d.e.f"));

        assert!(dpop_header(&headers).is_err());
    }

    /// An empty header is refused rather than read as none.
    #[test]
    fn an_empty_header_is_refused() {
        let mut headers = HeaderMap::new();
        headers.insert(DPOP, HeaderValue::from_static(" "));

        assert!(dpop_header(&headers).is_err());
    }
}
