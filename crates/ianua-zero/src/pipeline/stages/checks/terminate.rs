//! A fixed answer served by the gateway itself: a maintenance window, a
//! route retired behind a `410`, a backend that does not exist yet.
//!
//! It answers rather than refuses, so it passes: a denial is the pipeline
//! refusing the request, this is the pipeline answering it, and the audit
//! record tells the two apart.

use ianua_domain::domains::proxy::request::context::ReadyResponse;
use ianua_domain::domains::proxy::stages::decision::HeaderEntry;
use ianua_domain::domains::proxy::stages::stage::TerminateConfig;
use ianua_domain::shared::validation::ValidationError;
use ianua_domain::types::HeaderName;

/// The response `config` answers with.
///
/// # Errors
///
/// - [`ValidationError`] when the `Content-Type` header cannot be named,
///   which a checked configuration never causes.
pub(super) fn ready(config: &TerminateConfig) -> Result<ReadyResponse, ValidationError> {
    let content_type = HeaderName::new("content-type")?;
    Ok(ReadyResponse {
        status: config.status(),
        headers: vec![HeaderEntry::new(
            content_type,
            config.content_type().clone(),
        )],
        body: config.body().as_bytes().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_configured_answer_is_made_ready() {
        let config = TerminateConfig::new(503, "application/json", r#"{"status":"down"}"#).unwrap();

        let answer = ready(&config).unwrap();

        assert_eq!(answer.status, 503);
        assert_eq!(answer.body, br#"{"status":"down"}"#);
        assert_eq!(answer.headers[0].name().as_str(), "content-type");
        assert_eq!(answer.headers[0].value().as_str(), "application/json");
    }
}
