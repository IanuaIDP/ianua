//! The walk one request takes, step by step, each step returning early
//! with the refusal it makes.

use std::sync::Arc;

use http::request::Parts;
use hyper::body::Incoming;
use ianua_app::auditor::RequestAuditor;
use ianua_app::ports::pages::ErrorPageKind;
use ianua_app::use_case::Query as _;
use ianua_app::use_cases::proxy::{PipelineResult, PipelineVerdict};
use ianua_domain::domains::proxy::observation::{GatewayCheck, ObservedPrincipal};
use ianua_domain::domains::proxy::request::body::BodyNeed;
use ianua_domain::domains::proxy::request::context::{Caller, PipelineContext, RouteRequirements};
use ianua_domain::domains::proxy::stages::decision::{AnswerAt, StageDecision};
use ianua_domain::shared::clock;
use ianua_domain::types::{DenialStatus, Fact, IpAddress, UserAgent};

use super::arrival::Arrival;
use super::pipeline_store::MatchedPipeline;
use super::resolution::{self, Here, OnHost, Reach, Resolved};
use super::response::ResponseReads;
use super::upstream::Outbound;
use super::{GatewayParts, Refused, Served, response};
use crate::app_sign_in;
use crate::listen::ConnectionFacts;
use crate::observability::{RequestAudit, TunnelCloseRecord};
use crate::pipeline::executor::RequestRun;
use crate::pipeline::facts::RequestFacts;
use crate::pipeline::stages::counters::ReconOutcome;
use crate::pipeline::stages::identity::verified_certificate;
use crate::request::{self, Admitted, BodyRead, ListenerRole, PeekError};
use crate::resolve::MatchedRoute;

/// The client facts captured before admitting or rewriting its request.
pub(super) struct RequestOrigin<'a> {
    /// Correlation and client information established when the request arrived.
    pub arrival: &'a Arrival,
    /// Facts verified while opening the connection.
    pub connection: &'a Arc<ConnectionFacts>,
}

/// A request body and its head, retained for rendering any refusal.
pub(super) struct RequestMessage<'a, B> {
    /// The head retained for both forwarding and refusal rendering.
    pub parts: &'a mut Parts,
    /// The unread or prefix-captured body passed onward without copying.
    pub body: B,
}

/// A request let through the pipeline, and the record a tunnel it opens
/// closes with.
struct AdmittedMessage<'a, B> {
    /// The request's head and body.
    message: RequestMessage<'a, B>,
    /// Written when a tunnel opened for this request ends.
    closing: TunnelCloseRecord,
}

/// One request, from its admission to its answer, counted toward its
/// client's recon score once a tenant is known, whatever the answer.
pub(super) async fn served(
    gateway: &GatewayParts,
    origin: RequestOrigin<'_>,
    message: RequestMessage<'_, Incoming>,
    audit: &mut RequestAudit,
) -> Served {
    let RequestOrigin {
        arrival,
        connection,
    } = origin;
    let RequestMessage { parts, body } = message;
    let (admitted, resolved) = match arrived(gateway, parts, connection).await {
        Ok(arrived) => arrived,
        Err(refused) => return Served::Refused(refused),
    };
    audit.record_tenant(*resolved.tenant);
    let walk = Walk {
        gateway,
        arrival,
        admitted: &admitted,
        resolved: &resolved,
        connection,
    };
    let served = match walk.walked(parts, body, audit).await {
        Ok(served) => served,
        Err(refused) => Served::Refused(noted(gateway, refused)),
    };
    walk.record_recon(served.status()).await;
    served
}

/// `refused`, noted in the log when it refused a workflow's call, so the
/// reason a run's step failed can be found. The pass itself is never
/// logged.
fn noted(gateway: &GatewayParts, refused: Refused) -> Refused {
    if matches!(gateway.listener, ListenerRole::ByRunPass) {
        tracing::info!(reason = refused.reason(), "a workflow's call was refused");
    }
    refused
}

/// The request admitted, and the tenant its host belongs to, or on the
/// workflow listener the tenant its run pass names.
///
/// # Errors
///
/// The refusal of a request that cannot be read, of a host its connection
/// was not opened for, of a host no single tenant answers on, or of a
/// pass that does not check out.
async fn arrived(
    gateway: &GatewayParts,
    parts: &mut Parts,
    connection: &ConnectionFacts,
) -> Result<(Admitted, Resolved), Refused> {
    let admitted = resolution::admitted(parts, connection)?;
    let routing = gateway.tables.current();
    let resolved = match gateway.listener {
        ListenerRole::ByHost => resolution::tenant(&routing, &admitted)?,
        ListenerRole::ByRunPass => resolution::by_pass(gateway, &routing, parts).await?,
    };
    Ok((admitted, resolved))
}

/// A request whose tenant is known, on its way.
struct Walk<'a> {
    gateway: &'a GatewayParts,
    arrival: &'a Arrival,
    admitted: &'a Admitted,
    resolved: &'a Resolved,
    connection: &'a Arc<ConnectionFacts>,
}

impl Walk<'_> {
    /// The walk: answered here or routed, run through its pipeline, and
    /// forwarded.
    async fn walked(
        &self,
        parts: &mut Parts,
        body: Incoming,
        audit: &mut RequestAudit,
    ) -> Result<Served, Refused> {
        let (body, matched) = match self.found(parts, body).await? {
            Found::Answered(answer) => return Ok(Served::Answered(answer)),
            Found::App(body, matched) => (body, matched),
        };
        audit.record_route(*matched.route_id(), *matched.service_id());
        let routed = Routed {
            gateway: self.gateway,
            arrival: self.arrival,
            resolved: self.resolved,
            admitted: self.admitted,
            matched: &matched,
            connection: self.connection,
        };
        routed.through_pipeline(parts, body, audit).await
    }

    /// What the request is for: an answer the gateway gives itself on a
    /// tenant's host, or the route it takes, found by its host or named by
    /// its run pass. A pass's route is never answered for by a host.
    async fn found(&self, parts: &Parts, body: Incoming) -> Result<Found, Refused> {
        let table = &self.resolved.table;
        if let Reach::Named(route_id) = self.resolved.reach {
            let matched = resolution::named_route(table, &route_id, self.admitted, parts)?;
            return Ok(Found::App(body, matched));
        }
        let here = Here {
            parts,
            admitted: self.admitted,
            client: self.arrival.client,
        };
        let body = match resolution::on_host(self.gateway, self.resolved, &here, body).await? {
            OnHost::Answered(answer) => return Ok(Found::Answered(answer)),
            OnHost::App(body) => body,
        };
        let matched = resolution::route(table, self.admitted, parts)?;
        Ok(Found::App(body, matched))
    }

    /// Counts the finished request, answered with `status`, toward its
    /// client's recon score, when the tenant's pipelines score recon.
    async fn record_recon(&self, status: u16) {
        let Some(window) = self.resolved.table.recon_window() else {
            return;
        };
        let outcome = ReconOutcome {
            tenant: *self.resolved.tenant,
            client: self.arrival.client,
            path: self.admitted.path().as_str(),
            status,
            window,
        };
        self.gateway.dispatch.record_recon(outcome).await;
    }
}

/// What a request is for, before its pipeline runs.
enum Found {
    /// The gateway answered it itself.
    Answered(hyper::Response<super::GatewayBody>),
    /// It takes this route, its body untouched.
    App(Incoming, MatchedRoute),
}

/// A request that matched a route.
struct Routed<'a> {
    gateway: &'a GatewayParts,
    arrival: &'a Arrival,
    resolved: &'a Resolved,
    admitted: &'a Admitted,
    matched: &'a MatchedRoute,
    connection: &'a Arc<ConnectionFacts>,
}

impl Routed<'_> {
    /// Reads what the pipeline needs of the body, runs the pipeline, and
    /// answers or forwards as it decided. The tokens a limit set aside are
    /// given back whatever became of the request.
    async fn through_pipeline(
        &self,
        parts: &mut Parts,
        body: Incoming,
        audit: &mut RequestAudit,
    ) -> Result<Served, Refused> {
        let need = self.body_need();
        let peeked = request::peek(body, need, self.gateway.bounds.body_read)
            .await
            .map_err(|error| self.refused(body_refusal(&error)))?;
        let (read, body) = peeked.into_parts();
        let mut ctx = self.context(parts);
        self.unless_under_attack(&mut ctx).await?;
        let run = self.gateway.dispatch.for_request(self.facts(parts, read));
        let evaluated = self.evaluated(&run, ctx.clone()).await;
        let result = match evaluated {
            Ok(result) => result,
            Err(refused) => {
                run.release_unspent(&ctx).await;
                return Err(refused);
            }
        };
        let ctx = result.context.clone();
        audit.record_principal(principal_of(&ctx));
        audit.record_ruling(&ctx.tenant_ruling);
        audit.record_classification(ctx.classification_levels.clone());
        let closing = audit.tunnel_close_record();
        let admitted = AdmittedMessage {
            message: RequestMessage { parts, body },
            closing,
        };
        let answered = self.answered(&run, &result, admitted).await;
        run.release_unspent(&ctx).await;
        answered
    }

    /// Refuses a request to a route in attack mode that does not pass its
    /// check: an address flagged anywhere or unknown, one over attack
    /// mode's limit, or a count that could not be read. A route not in
    /// attack mode goes on as its pipeline says.
    async fn unless_under_attack(&self, ctx: &mut PipelineContext) -> Result<(), Refused> {
        let route = self.matched.route();
        if !route.attack_mode().in_force_at(clock::now()) {
            return Ok(());
        }
        let decision = self.gateway.dispatch.under_attack(route.id(), ctx).await;
        let status = match decision {
            Ok(StageDecision::Pass { .. }) => return Ok(()),
            Ok(StageDecision::Deny { status, .. }) => status,
            Ok(StageDecision::Challenge { .. } | StageDecision::Transform { .. }) | Err(_) => {
                DenialStatus::SERVICE_UNAVAILABLE
            }
        };
        let refused = Refused::at_gateway(
            ErrorPageKind::Forbidden,
            GatewayCheck::AttackMode,
            "attack_mode_refused",
        )
        .answered_with(status);
        Err(self.refused(refused).carrying(ctx.response_headers.clone()))
    }

    /// The pipeline's walk over the request, within its timeout.
    ///
    /// # Errors
    ///
    /// A `503` when it fails or does not finish in time: never a pass.
    async fn evaluated(
        &self,
        run: &Arc<RequestRun>,
        ctx: PipelineContext,
    ) -> Result<PipelineResult, Refused> {
        let pipelines = Arc::new(MatchedPipeline::new(
            *self.resolved.tenant,
            self.matched.shared_pipeline(),
        ));
        let evaluation = run.evaluation(pipelines);
        let walked = tokio::time::timeout(
            self.gateway.bounds.pipeline,
            evaluation.execute(&self.resolved.tenant, ctx),
        )
        .await;
        decided(walked).map_err(|refused| self.refused(refused))
    }

    /// The answer the pipeline's verdict comes to: its refusal, the answer
    /// a stage had ready, or the upstream's.
    async fn answered(
        &self,
        run: &RequestRun,
        result: &PipelineResult,
        admitted: AdmittedMessage<'_, request::PrefixThenBody<Incoming>>,
    ) -> Result<Served, Refused> {
        let ctx = &result.context;
        if result.verdict == PipelineVerdict::Denied {
            return Err(self.denied(result, admitted.message.parts));
        }
        if let Some(ready) = ctx.response.ready() {
            let (answer, status) = response::ready(ready, ctx);
            return Ok(Served::Forwarded(answer, status));
        }
        self.forwarded(run, ctx, admitted).await
    }

    /// What forwarding this request needs to know about it.
    fn outbound<'b>(
        &'b self,
        run: &'b RequestRun,
        ctx: &'b PipelineContext,
        closing: TunnelCloseRecord,
    ) -> Outbound<'b> {
        Outbound {
            gateway: self.gateway,
            arrival: self.arrival,
            tenant: self.resolved.tenant,
            host: self.admitted.host().as_str(),
            matched: self.matched,
            ctx,
            run,
            closing,
        }
    }

    /// Forwards an admitted request and applies the route's response stages.
    async fn forwarded(
        &self,
        run: &RequestRun,
        ctx: &PipelineContext,
        admitted: AdmittedMessage<'_, request::PrefixThenBody<Incoming>>,
    ) -> Result<Served, Refused> {
        let AdmittedMessage { message, closing } = admitted;
        let RequestMessage { parts, body } = message;
        let reads = ResponseReads::of(self.matched.pipeline(), &self.gateway.bounds);
        let outbound = self.outbound(run, ctx, closing);
        let kept = headers_only(parts);
        let head = std::mem::replace(parts, kept);
        let prepared = outbound
            .prepared(head, body, reads.inspection())
            .await
            .map_err(|refused| self.refused(refused))?;
        let answer = self
            .gateway
            .forwarder
            .forward(prepared.request, prepared.target)
            .await
            .map_err(|error| self.refused(upstream_failed(&error)))?;
        let (answer, status) = response::upstream(run, &reads, ctx, answer)
            .await
            .map_err(|refused| self.refused(refused).carrying(ctx.response_headers.clone()))?;
        Ok(Served::Forwarded(answer, status))
    }

    /// The refusal the pipeline came to, sent to sign in where the host's
    /// app sign-in asks for a browser to be.
    fn denied(&self, result: &PipelineResult, parts: &Parts) -> Refused {
        let ctx = &result.context;
        let stages = self.matched.pipeline().active_stages();
        let deciding = result
            .decisions
            .len()
            .checked_sub(1)
            .and_then(|at| stages.get(at));
        let refused = match (result.decisions.last(), deciding) {
            (Some(StageDecision::Deny { status, reason }), Some(stage)) => {
                Refused::by_stage(*status, reason, stage).under(ctx.refusing_rule.clone())
            }
            (
                Some(StageDecision::Challenge {
                    answer_at, reason, ..
                }),
                Some(stage),
            ) => Refused::by_stage(DenialStatus::UNAUTHORIZED, reason, stage)
                .signing_in_at(challenge_page(answer_at)),
            _ => Refused::at_gateway(
                ErrorPageKind::Forbidden,
                GatewayCheck::PipelineOff,
                "access_not_granted",
            ),
        };
        let login = self.login_redirect(parts, refused.status());
        let refused = match login {
            Some(address) => refused.signing_in_at(Some(address)),
            None => refused,
        };
        self.refused(refused).carrying(ctx.response_headers.clone())
    }

    /// Where a browser loading a page is sent to sign in, when the host's
    /// app sign-in asks for that on a `401`.
    fn login_redirect(&self, parts: &Parts, status: DenialStatus) -> Option<String> {
        let host = self
            .resolved
            .table
            .sign_in()
            .on_host(self.admitted.host())?;
        let status = http::StatusCode::from_u16(status.code()).ok()?;
        app_sign_in::login_redirect(host.sign_in(), self.admitted.host().name(), parts, status)
    }

    /// How much of the body the pipeline reads before deciding.
    fn body_need(&self) -> BodyNeed {
        self.matched.pipeline().body_need(
            self.matched.route().parameter_rules(),
            &self.gateway.bounds.bodies,
        )
    }

    /// The pipeline's context as the request arrived: its tenant, route,
    /// client, and what the route asks of the caller.
    fn context(&self, parts: &Parts) -> PipelineContext {
        let mut ctx = PipelineContext::new(
            *self.resolved.tenant,
            *self.matched.pipeline().id(),
            self.arrival.correlation_id,
        );
        ctx.ip_address = Fact::from_option(IpAddress::new(self.arrival.client.to_string()).ok());
        ctx.user_agent = Fact::from_option(
            parts
                .headers
                .get(http::header::USER_AGENT)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| UserAgent::new(value).ok()),
        );
        ctx.client_cert_fingerprint = verified_certificate(self.connection);
        ctx.route = self.requirements();
        ctx
    }

    /// What the matched route asks of the caller: the tenant's issuer, the
    /// service's audience and identity, the route's policy, the kind of
    /// action it takes, and which route it is and whether workflows may
    /// reach it, for a run pass.
    fn requirements(&self) -> RouteRequirements {
        let upstream = self.matched.service().upstream();
        let route = self.matched.route();
        RouteRequirements {
            expected_issuer: Fact::Known(self.resolved.table.issuer().clone()),
            token_audience: upstream.token_audience().clone(),
            identity: upstream.identity(),
            policy: Fact::Known(route.policy().clone()),
            action_class: route.action_class(),
            route_id: Fact::Known(*route.id()),
            stream_route_id: Fact::Unknown,
            workflow_use: route.workflow_use(),
        }
    }

    /// The request as the stages read it.
    fn facts(&self, parts: &Parts, body: BodyRead) -> RequestFacts {
        let tenant = self.resolved.tenant;
        let table = &self.resolved.table;
        RequestFacts {
            tenant,
            auditor: RequestAuditor::system(Arc::clone(&self.gateway.events)).with_tenant(*tenant),
            route: self.matched.shared_route(),
            admitted: self.admitted.clone(),
            query: parts.uri.query().map(str::to_owned),
            headers: parts.headers.clone(),
            body,
            captured: self.matched.captured().to_vec(),
            cookies: table
                .sign_in()
                .session_cookies(self.matched.service_id(), self.admitted.host()),
            connection: ConnectionFacts::clone(self.connection),
            scheme: self.gateway.scheme,
            listener: self.gateway.listener,
            decoy: table.decoy_lifetime(self.admitted.path()),
            recon_window: table.recon_window(),
        }
    }

    /// `refused`, its page wearing the tenant's look.
    fn refused(&self, refused: Refused) -> Refused {
        refused.wearing(self.resolved.table.branding())
    }
}

/// Who the pipeline proved the caller to be, as the request's record names
/// them.
fn principal_of(ctx: &PipelineContext) -> ObservedPrincipal {
    match ctx.authentication().caller() {
        None => ObservedPrincipal::Anonymous,
        Some(Caller::User { user_id, .. }) => ObservedPrincipal::User(*user_id),
        Some(Caller::Agent {
            agent_id,
            delegation_id,
            acting_for,
            ..
        }) => ObservedPrincipal::Agent {
            agent_id: *agent_id,
            delegation_id: *delegation_id,
            on_behalf_of: *acting_for,
        },
        Some(Caller::Consumer {
            consumer_id,
            credential,
        }) => ObservedPrincipal::Consumer {
            consumer_id: *consumer_id,
            credential: *credential,
        },
    }
}

/// Where a challenge is answered, when it names a page a browser goes to.
fn challenge_page(answer_at: &AnswerAt) -> Option<String> {
    match answer_at {
        AnswerAt::Page(page) => Some(page.as_str().to_owned()),
        AnswerAt::Retry => None,
    }
}

/// The refusal of a body the pipeline could not read.
fn body_refusal<E>(error: &PeekError<E>) -> Refused {
    match error {
        PeekError::TimedOut => Refused::at_gateway(
            ErrorPageKind::BadRequest,
            GatewayCheck::BodyLimit,
            "body_timed_out",
        )
        .answered_with(request_timeout()),
        PeekError::Body(_) => Refused::at_gateway(
            ErrorPageKind::BadRequest,
            GatewayCheck::BodyLimit,
            "body_unreadable",
        ),
    }
}

/// `408 Request Timeout`.
fn request_timeout() -> DenialStatus {
    DenialStatus::new(408).unwrap_or(DenialStatus::BAD_REQUEST)
}

/// What the pipeline's walk came to: its result, or a `503` when it failed
/// or ran out of time. Never a pass.
pub(super) fn decided<E: std::fmt::Display>(
    walked: Result<Result<PipelineResult, E>, tokio::time::error::Elapsed>,
) -> Result<PipelineResult, Refused> {
    match walked {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(error)) => {
            tracing::warn!(%error, "a pipeline could not run; refusing");
            Err(pipeline_failed("pipeline_failed"))
        }
        Err(_) => Err(pipeline_failed("pipeline_timed_out")),
    }
}

/// The refusal of a pipeline that could not decide.
fn pipeline_failed(reason: &'static str) -> Refused {
    Refused::at_gateway(
        ErrorPageKind::Unavailable,
        GatewayCheck::PipelineOff,
        reason,
    )
}

/// The refusal of a request its upstream did not answer.
fn upstream_failed(error: &crate::forward::ForwardError) -> Refused {
    tracing::info!(%error, "the upstream did not answer");
    let refused = Refused::at_gateway(
        ErrorPageKind::UpstreamDown,
        GatewayCheck::Upstream,
        "upstream_failed",
    );
    match DenialStatus::new(error.status().as_u16()) {
        Ok(status) => refused.answered_with(status),
        Err(_) => refused,
    }
}

/// A head holding only `parts`' headers: what is left for answering a
/// refusal in the form the client reads once the request itself has gone
/// to its upstream.
fn headers_only(parts: &Parts) -> Parts {
    let (mut kept, ()) = http::Request::new(()).into_parts();
    kept.headers = parts.headers.clone();
    kept
}
