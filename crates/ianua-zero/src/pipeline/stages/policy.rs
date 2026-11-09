//! The policy group: the access decision, the agent controls that follow
//! it, and data classification.
//!
//! Nothing here decides. The Policy stage hands the app's
//! `DecideAccessUseCase` what the Identity stage proved, the route, what
//! the request asks for and what is known around it, and enforces the
//! answer: only a permit lets the request on. An agent's permitted request
//! is then put to `AdmitActionUseCase` and recorded through
//! `RecordActionUseCase` before it may go on. DataClassify tags the request
//! with the levels the tenant's classification rules define.
//!
//! Every error, every answer that does not come in time and every answer
//! that is not a clear permit refuses.

mod agent;
mod carried;
mod classify;
mod refusals;
mod sent;
mod verdict;

use std::sync::Arc;
use std::time::Duration;

use ianua_app::ports::data_classification::ClassificationStore;
use ianua_app::ports::shared::EventDispatcher;
use ianua_app::tenancy::ScopedTenant;
use ianua_app::use_case::Query;
use ianua_app::use_cases::agents::enforcement::AdmitActionUseCase;
use ianua_app::use_cases::proxy::{DecideAccessRequest, DecideAccessUseCase};
use ianua_domain::domains::proxy::access::decision::{AccessDecision, SettledBy, TenantRuling};
use ianua_domain::domains::proxy::request::context::PipelineContext;
use ianua_domain::domains::proxy::stages::decision::StageDecision;
use ianua_domain::domains::proxy::stages::stage::ClassificationConfig;
use ianua_domain::shared::errors::DomainError;

use self::agent::{AgentAction, AgentControls};
use self::classify::Classifier;
use self::refusals::TurnedAway;
pub(crate) use self::sent::{EarlierFindings, asked, held_circumstances};
use self::verdict::{Verdict, callers_disagree, verdict_of};
use crate::pipeline::facts::RequestFacts;

/// What [`PolicyStages`] is built from.
pub(crate) struct PolicyStagesParts {
    /// Decides whether a request may pass.
    pub decide_access: Arc<DecideAccessUseCase>,
    /// Applies the controls only agents are held to.
    pub admit_action: Arc<AdmitActionUseCase>,
    /// The tenants' classification rules.
    pub classifications: Arc<dyn ClassificationStore>,
    /// Where a person turned away is recorded, through the gateway's inbox.
    pub events: Arc<dyn EventDispatcher>,
    /// The longest any call out of the gateway may take: the access
    /// decision, the agent controls with their approval question, an
    /// action's record, a rule set read.
    pub call_timeout: Duration,
}

/// The Policy and DataClassify stages, holding what they need.
pub(crate) struct PolicyStages {
    decide_access: Arc<DecideAccessUseCase>,
    agents: AgentControls,
    classifier: Classifier,
    turned_away: TurnedAway,
    call_timeout: Duration,
}

impl PolicyStages {
    /// The group, built from `parts`.
    #[must_use]
    pub(crate) fn new(parts: PolicyStagesParts) -> Self {
        Self {
            decide_access: parts.decide_access,
            agents: AgentControls::new(parts.admit_action, parts.call_timeout),
            classifier: Classifier::new(parts.classifications, parts.call_timeout),
            turned_away: TurnedAway::new(parts.events, parts.call_timeout),
            call_timeout: parts.call_timeout,
        }
    }

    /// The Policy stage: asks whether the request `facts` describe may pass,
    /// given what the stages before it found, and enforces the answer. A
    /// permitted request is marked authorized on `ctx` and passes; an
    /// agent's only once its controls admitted it and its action was
    /// recorded. An agent's refused action is recorded as refused.
    ///
    /// # Errors
    ///
    /// None: every failure below is a refusal, never an error the pipeline
    /// could read otherwise.
    pub(crate) async fn policy(
        &self,
        ctx: &mut PipelineContext,
        facts: &RequestFacts,
        earlier: EarlierFindings,
    ) -> Result<StageDecision, DomainError> {
        if !earlier.agrees_with(ctx) {
            tracing::error!(
                correlation_id = %ctx.correlation_id,
                "the proof handed to the Policy stage names another caller; refusing"
            );
            return Ok(callers_disagree());
        }
        let question = DecideAccessRequest {
            route_id: *facts.route.id(),
            asked: asked(facts),
            circumstances: earlier.circumstances(ctx),
            identification: earlier.identification,
        };
        let decision = self.decide(&facts.tenant, question).await;
        log_decision(ctx, decision.as_ref());
        record_ruling(ctx, decision.as_ref());
        Ok(self.enforce(ctx, facts, decision.as_ref()).await)
    }

    /// Enforces the access result and the agent controls before marking the context authorized.
    async fn enforce(
        &self,
        ctx: &mut PipelineContext,
        facts: &RequestFacts,
        decision: Option<&AccessDecision>,
    ) -> StageDecision {
        let action = AgentAction::of(ctx.authentication().caller(), facts);
        let outcome = decision.map(AccessDecision::outcome);
        if let Verdict::Refuse(refusal) = verdict_of(outcome) {
            self.agents
                .record_refused(action.as_ref(), refusal.reason())
                .await;
            self.turned_away.record(ctx, facts, outcome).await;
            return refusal;
        }
        if let Some(refusal) = self.agents.refusal_of_permitted(action.as_ref()).await {
            return refusal;
        }
        ctx.authorize();
        StageDecision::Pass {
            reason: "access_permitted".to_owned(),
        }
    }

    /// Records that a later stage refused an agent's request with
    /// `refusal`, when `ctx` names an agent caller, so an agent probing
    /// past its task is seen whichever stage stops it. A record that cannot
    /// be written is logged: the request is refused either way.
    pub(crate) async fn record_agent_refusal(
        &self,
        ctx: &PipelineContext,
        facts: &RequestFacts,
        refusal: &StageDecision,
    ) {
        let action = AgentAction::of(ctx.authentication().caller(), facts);
        self.agents
            .record_refused(action.as_ref(), refusal.reason())
            .await;
    }

    /// The DataClassify stage: tags `ctx` and the forwarded request with
    /// the levels `tenant`'s classification rules define. Rules that cannot
    /// be read refuse.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] if the levels cannot be written as a
    ///   header, which every level's name can.
    pub(crate) async fn data_classify(
        &self,
        ctx: &mut PipelineContext,
        tenant: &ScopedTenant,
        config: &ClassificationConfig,
    ) -> Result<StageDecision, DomainError> {
        self.classifier.classify(ctx, tenant, config).await
    }

    /// The access decision on `question`, or `None` when it did not come
    /// in time.
    async fn decide(
        &self,
        tenant: &ScopedTenant,
        question: DecideAccessRequest,
    ) -> Option<AccessDecision> {
        let deciding = self.decide_access.execute(tenant, question);
        let Ok(decision) = tokio::time::timeout(self.call_timeout, deciding).await else {
            tracing::warn!("the access decision did not come in time; refusing");
            return None;
        };
        Some(decision)
    }
}

/// Notes on `ctx` what the tenant's policy had to do with `decision`, and
/// the rule that refused, for the request's record. A decision that never
/// came leaves both as they were: nothing ruled.
fn record_ruling(ctx: &mut PipelineContext, decision: Option<&AccessDecision>) {
    let Some(decision) = decision else {
        return;
    };
    ctx.tenant_ruling = decision.ruling().clone();
    ctx.refusing_rule = decision.refusing_rule();
}

/// Logs what decided the request and what the tenant's policy had to do
/// with it, by correlation id: the decision is observable, the credential
/// never is.
fn log_decision(ctx: &PipelineContext, decision: Option<&AccessDecision>) {
    let Some(decision) = decision else {
        return;
    };
    let TenantRuling::Decided {
        version,
        settled_by,
        audit,
    } = decision.ruling()
    else {
        tracing::debug!(
            correlation_id = %ctx.correlation_id,
            outcome = ?decision.outcome(),
            ruling = ?decision.ruling(),
            "access decided"
        );
        return;
    };
    tracing::debug!(
        correlation_id = %ctx.correlation_id,
        outcome = ?decision.outcome(),
        policy_version = version.number(),
        settled_by = settled_by_name(settled_by),
        audit = ?audit,
        "access decided"
    );
}

fn settled_by_name(settled_by: &SettledBy) -> &str {
    match settled_by {
        SettledBy::Rule(rule) => rule.as_str(),
        SettledBy::Default => "default",
    }
}

#[cfg(test)]
mod tests;
