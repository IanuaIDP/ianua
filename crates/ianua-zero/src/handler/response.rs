//! The answer a client gets once its request was let through: the one a
//! stage had ready, or the upstream's, run through the pipeline's response
//! stages in the order the domain gives.
//!
//! An answer no response stage reads streams through untouched. One that a
//! stage reads was read whole by the forwarder, up to the largest cap of
//! the stages that read it, and a longer one is refused. Each stage is
//! handed as much as its own cap and told when that is not all of it: the
//! canary scan withholds an answer it could not read to the end. The answer
//! is rewritten as the stages say; a stage that withholds it refuses the
//! request. Every answer carries the headers the pipeline set
//! for its client, never overriding one the answer sets itself.

use http::header::{CONTENT_LENGTH, HeaderName, HeaderValue};
use http::{HeaderMap, Response, StatusCode};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Bytes;
use ianua_app::ports::pages::ErrorPageKind;
use ianua_app::ports::proxy::{ResponseMeta, ResponseStageExecutor as _, ResponseStageOutcome};
use ianua_domain::domains::proxy::observation::GatewayCheck;
use ianua_domain::domains::proxy::pipeline::Pipeline;
use ianua_domain::domains::proxy::request::body::{BodyExtent, ByteCap, CapturedBody};
use ianua_domain::domains::proxy::request::context::{PipelineContext, ReadyResponse};
use ianua_domain::domains::proxy::request::transform::ResponseMutation;
use ianua_domain::domains::proxy::stages::decision::HeaderEntry;
use ianua_domain::domains::proxy::stages::stage::{ResponseSlot, StageConfig};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types;

use super::{GatewayBody, Refused, RequestBounds, whole};
use crate::forward::{ResponseBody, ResponseInspection};
use crate::listen::BodyError;
use crate::pipeline::executor::RequestRun;

/// An answer and the status it carries, for the request's record.
pub(super) type Answer = (Response<GatewayBody>, u16);

/// The answer a stage had ready, with the pipeline's headers. Response
/// stages do not run on it: nothing came from an upstream.
pub(super) fn ready(ready: &ReadyResponse, ctx: &PipelineContext) -> Answer {
    let status = StatusCode::from_u16(ready.status).unwrap_or(StatusCode::OK);
    let mut response = Response::new(Full::new(Bytes::from(ready.body.clone())));
    *response.status_mut() = status;
    set_all(response.headers_mut(), &ready.headers);
    keep_unset(response.headers_mut(), &ctx.response_headers);
    (whole(response), status.as_u16())
}

/// A pipeline's response stages, in the order they run, each with the most
/// of an answer it reads.
pub(super) struct ResponseReads<'a> {
    stages: Vec<(&'a StageConfig, ByteCap)>,
}

impl<'a> ResponseReads<'a> {
    /// `pipeline`'s response stages, read as far as `bounds` lets each.
    pub(super) fn of(pipeline: &'a Pipeline<ResolvedTenant>, bounds: &RequestBounds) -> Self {
        let stages = pipeline
            .response_stages()
            .into_iter()
            .map(|stage| (stage, read_cap(stage, bounds)))
            .collect();
        Self { stages }
    }

    /// How much of the backend's answer the forwarder holds: as much as
    /// the stage that reads most, or none of it when no stage reads it.
    pub(super) fn inspection(&self) -> ResponseInspection {
        self.stages
            .iter()
            .map(|(_, cap)| *cap)
            .max_by_key(|cap| cap.get())
            .map_or(ResponseInspection::Streamed, ResponseInspection::Inspected)
    }
}

/// The upstream's answer, run through the response stages `reads` names
/// by `run`, with the pipeline's headers.
///
/// # Errors
///
/// A `502` when the answer the stages read cannot be read whole, and the
/// refusal of a stage that withholds it.
pub(super) async fn upstream(
    run: &RequestRun,
    reads: &ResponseReads<'_>,
    ctx: &PipelineContext,
    answer: Response<ResponseBody>,
) -> Result<Answer, Refused> {
    if reads.stages.is_empty() {
        return Ok(streamed(answer, ctx));
    }
    let mut read = Read::collect(answer).await?;
    read.apply(run, reads, ctx).await?;
    Ok(read.answer(ctx))
}

/// An answer as the response stages read and change it.
struct Read {
    parts: http::response::Parts,
    meta: ResponseMeta,
    body: Vec<u8>,
}

impl Read {
    /// Collects an answer already bounded by the forwarder's inspection limit.
    async fn collect(answer: Response<ResponseBody>) -> Result<Self, Refused> {
        let (parts, body) = answer.into_parts();
        let body = body
            .collect()
            .await
            .map_err(|_| unread())?
            .to_bytes()
            .to_vec();
        Ok(Self {
            meta: ResponseMeta {
                status: parts.status.as_u16(),
                headers: entries_of(&parts.headers),
            },
            parts,
            body,
        })
    }

    /// Applies response stages in order, making each mutation visible to the next.
    async fn apply(
        &mut self,
        run: &RequestRun,
        reads: &ResponseReads<'_>,
        ctx: &PipelineContext,
    ) -> Result<(), Refused> {
        for &(stage, cap) in &reads.stages {
            let captured = captured(&self.body, cap);
            let outcome = run
                .execute_response(stage, ctx, &self.meta, captured)
                .await
                .map_err(|_| unread())?;
            match outcome {
                ResponseStageOutcome::Pass { .. } => {}
                ResponseStageOutcome::Change { headers, body, .. } => {
                    self.change(&headers, body);
                }
                ResponseStageOutcome::Block { status, reason } => {
                    return Err(Refused::by_stage(status, &reason, stage));
                }
            }
        }
        Ok(())
    }

    /// Drops the obsolete length and adds pipeline headers after all stages pass.
    fn answer(mut self, ctx: &PipelineContext) -> Answer {
        self.parts.headers.remove(CONTENT_LENGTH);
        keep_unset(&mut self.parts.headers, &ctx.response_headers);
        let status = self.parts.status.as_u16();
        (
            whole(Response::from_parts(
                self.parts,
                Full::new(Bytes::from(self.body)),
            )),
            status,
        )
    }

    /// Applies a stage's change: headers dropped and set on `headers` and
    /// on what the next stage reads, and the body replaced when it gave
    /// one.
    fn change(&mut self, mutation: &ResponseMutation, body: Option<Vec<u8>>) {
        let headers = &mut self.parts.headers;
        for name in mutation.remove_headers() {
            headers.remove(name.as_str());
        }
        set_all(headers, mutation.headers_to_set());
        self.meta.headers = entries_of(headers);
        if let Some(body) = body {
            self.body = body;
        }
    }
}

/// The upstream's answer streaming through, with the pipeline's headers.
fn streamed(answer: Response<ResponseBody>, ctx: &PipelineContext) -> Answer {
    let (mut parts, body) = answer.into_parts();
    keep_unset(&mut parts.headers, &ctx.response_headers);
    let status = parts.status.as_u16();
    let body = body
        .map_err(|error| -> BodyError { Box::new(error) })
        .boxed_unsync();
    (Response::from_parts(parts, body), status)
}

/// `headers` as the response stages read them; a header the domain cannot
/// hold, such as one that is not text, is left out of what they read and
/// kept on the answer.
fn entries_of(headers: &HeaderMap) -> Vec<HeaderEntry> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            let value = value.to_str().ok()?;
            Some(HeaderEntry::new(
                types::HeaderName::new(name.as_str()).ok()?,
                types::HeaderValue::new(value).ok()?,
            ))
        })
        .collect()
}

/// Sets every one of `entries` on `headers`, replacing what was there.
fn set_all(headers: &mut HeaderMap, entries: &[HeaderEntry]) {
    for entry in entries {
        let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(entry.name().as_str().as_bytes()),
            HeaderValue::from_str(entry.value().as_str()),
        ) else {
            continue;
        };
        headers.insert(name, value);
    }
}

/// Adds every one of `entries` the answer does not set itself.
fn keep_unset(headers: &mut HeaderMap, entries: &[HeaderEntry]) {
    for entry in entries {
        let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(entry.name().as_str().as_bytes()),
            HeaderValue::from_str(entry.value().as_str()),
        ) else {
            continue;
        };
        headers.entry(name).or_insert(value);
    }
}

/// The most of an answer `stage` reads: the canary scan reads as far as
/// its own cap, every other response stage as far as theirs.
fn read_cap(stage: &StageConfig, bounds: &RequestBounds) -> ByteCap {
    match stage.kind().kind_name().response_slot() {
        Some(ResponseSlot::CanaryScan) => bounds.canary_scan,
        Some(
            ResponseSlot::Redact
            | ResponseSlot::ChargeTokens
            | ResponseSlot::Transform
            | ResponseSlot::Sign
            | ResponseSlot::CacheStore,
        )
        | None => bounds.response_stages,
    }
}

/// The part of `body` a stage reading at most `cap` bytes is handed, and
/// whether it is all of it.
fn captured(body: &[u8], cap: ByteCap) -> CapturedBody<'_> {
    let cap = usize::try_from(cap.get()).unwrap_or(usize::MAX);
    let Some(prefix) = body.get(..cap).filter(|prefix| prefix.len() < body.len()) else {
        return CapturedBody::new(body, BodyExtent::Whole);
    };
    CapturedBody::new(prefix, BodyExtent::Prefix)
}

/// The refusal of an answer the response stages could not read.
fn unread() -> Refused {
    Refused::at_gateway(
        ErrorPageKind::UpstreamDown,
        GatewayCheck::Upstream,
        "answer_unread",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, value: &str) -> HeaderEntry {
        HeaderEntry::new(
            types::HeaderName::new(name).unwrap(),
            types::HeaderValue::new(value).unwrap(),
        )
    }

    /// A pipeline header the answer sets itself stays as the answer set it;
    /// one it does not is added.
    #[test]
    fn a_pipeline_header_never_overrides_the_answers_own() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("text/html"));

        keep_unset(
            &mut headers,
            &[
                entry("content-type", "application/json"),
                entry("retry-after", "30"),
            ],
        );

        assert_eq!(headers["content-type"], "text/html");
        assert_eq!(headers["retry-after"], "30");
    }

    /// A capture shorter than the response is marked as a prefix, while
    /// a capture exactly as long as the response is marked whole.
    #[test]
    fn a_stage_is_told_when_it_reads_less_than_the_whole_answer() {
        let body = b"0123456789";

        let short = captured(body, ByteCap::new(4).unwrap());
        let exact = captured(body, ByteCap::new(10).unwrap());

        assert_eq!(short.bytes, b"0123");
        assert!(!short.is_whole());
        assert!(exact.is_whole());
    }

    /// An answer a stage had ready is served with its status, headers and
    /// body, and the pipeline's headers beside them.
    #[test]
    fn a_ready_answer_is_served_as_the_stage_made_it() {
        let mut ctx = PipelineContext::new(
            types::TenantId::new(),
            types::PipelineId::new(),
            types::CorrelationId::new(),
        );
        ctx.response_headers = vec![entry("x-frame-options", "DENY")];
        let made = ReadyResponse {
            status: 418,
            headers: vec![entry("content-type", "text/plain")],
            body: b"short and stout".to_vec(),
        };

        let (answer, status) = ready(&made, &ctx);

        assert_eq!(status, 418);
        assert_eq!(answer.headers()["content-type"], "text/plain");
        assert_eq!(answer.headers()["x-frame-options"], "DENY");
    }
}
