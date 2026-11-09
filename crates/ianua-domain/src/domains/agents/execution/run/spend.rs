//! What a run's model calls use and cost, the spend limit that stops it,
//! and the amount past which it waits for a person.

use crate::domains::agents::events::steering::{AgentRunHeldAtSpend, AgentRunStoppedOverBudget};
use crate::domains::agents::execution::model_provider::ModelProvider;
use crate::domains::agents::execution::run::AgentRun;
use crate::domains::agents::execution::run::status::{RunState, RunStatus};
use crate::domains::agents::execution::usage::{ModelTokens, ModelUsage, Spend};
use crate::domains::agents::identity::agent::AgentIdentity;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::model::restriction::Restriction;
use crate::types::EventLabel;

/// Where a run waits for a person before it spends more on its model.
///
/// Ann lets her agent spend one unit on its own and up to five in all.
/// Once it has spent one, it pauses before its next model call. Ann, or
/// the agent's owner, resumes it to let it go on, or stops it. It asks
/// once: after she resumed it, it spends on to its limit without asking
/// again. A call whose cost cannot be told makes it ask too, since it
/// cannot tell whether it passed the amount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendCheck {
    /// It never waits for a person over what it spent.
    Off,
    /// It asks once it has spent this much.
    AskAt(Spend),
    /// It asks before its next model call: it spent this much, or what a
    /// call cost could not be told.
    Due(Spend),
    /// It asked at this much once, and does not ask again.
    Asked(Spend),
}

impl SpendCheck {
    /// The check a run starts with: asking once it spent `ask_past`, or
    /// never.
    #[must_use]
    pub fn starting_at(ask_past: Restriction<Spend>) -> Self {
        match ask_past {
            Restriction::To(mark) => Self::AskAt(mark),
            Restriction::Unrestricted => Self::Off,
        }
    }

    /// The amount it asks at, or asked at, when it has one.
    #[must_use]
    pub fn mark(self) -> Option<Spend> {
        match self {
            Self::Off => None,
            Self::AskAt(mark) | Self::Due(mark) | Self::Asked(mark) => Some(mark),
        }
    }
}

/// What a model call cost, as far as it can be told.
enum CallCost {
    /// The provider reported its tokens and has a price.
    Known(ModelTokens, Spend),
    /// The provider reported its tokens but has no price.
    Unpriced(ModelTokens),
    /// The provider reported nothing.
    Unreported,
}

impl<T: TenantScope> AgentRun<T> {
    /// Counts what one call to `provider` used, as `usage` says, and stops
    /// the run once it spent its limit.
    ///
    /// The tokens are always counted, even for a run that has ended, since
    /// they were spent. A run under a spend limit stops as over budget once
    /// it spent the limit. It stops too when the call's cost cannot be told,
    /// because the provider reported nothing or has no price: a limit that
    /// cannot be measured is not kept. Ann caps a run at five currency
    /// units. Without that, a provider that stops reporting usage lets the
    /// run spend without end.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `provider` is not the run's.
    pub fn record_model_usage(
        &mut self,
        agent: &AgentIdentity<T>,
        provider: &ModelProvider<T>,
        usage: ModelUsage,
    ) -> Result<(), DomainError> {
        if provider.id() != &self.provider_id {
            return Err(DomainError::forbidden(message!(
                "agents-the-run-reasons-with-another-model",
                "the run reasons with another model provider"
            )));
        }
        let cost = match usage {
            ModelUsage::Unreported => CallCost::Unreported,
            ModelUsage::Reported(tokens) => provider
                .pricing()
                .cost_of(tokens)
                .map_or(CallCost::Unpriced(tokens), |spend| {
                    CallCost::Known(tokens, spend)
                }),
        };
        self.count(&cost);
        if self.over_budget(&cost) {
            self.settle_over_budget(agent);
        }
        if !self.status().is_terminal() {
            self.spend_check = self.check_after(&cost);
        }
        self.touch();
        Ok(())
    }

    /// Adds what `cost` says the call used and cost.
    fn count(&mut self, cost: &CallCost) {
        match cost {
            CallCost::Known(tokens, spend) => {
                self.usage = self.usage.plus(*tokens);
                self.spent = self.spent.plus(*spend);
            }
            CallCost::Unpriced(tokens) => self.usage = self.usage.plus(*tokens),
            CallCost::Unreported => {}
        }
    }

    /// Whether the run must stop after a call that cost `cost`: it has a
    /// limit, and either spent it or cannot tell what it spent.
    fn over_budget(&self, cost: &CallCost) -> bool {
        let Restriction::To(limit) = self.spend_limit else {
            return false;
        };
        match cost {
            CallCost::Known(..) => self.spent >= limit,
            CallCost::Unpriced(_) | CallCost::Unreported => true,
        }
    }

    /// The spend check once a call that cost `cost` is counted: due when
    /// the run reached the amount it asks at, or cannot tell whether it did.
    fn check_after(&self, cost: &CallCost) -> SpendCheck {
        let SpendCheck::AskAt(mark) = self.spend_check else {
            return self.spend_check;
        };
        match cost {
            CallCost::Known(..) if self.spent < mark => self.spend_check,
            CallCost::Known(..) | CallCost::Unpriced(_) | CallCost::Unreported => {
                SpendCheck::Due(mark)
            }
        }
    }

    /// Pauses the run before its next model call once a person must say
    /// it may spend more, and says whether it paused.
    ///
    /// It pauses only while running, and only once: a person who resumes
    /// it lets it spend on to its limit. The pause is a person's to lift
    /// as any other, by whoever may resume the run.
    ///
    /// Raises `agents.run_held_at_spend`.
    pub fn pause_at_spend_check(&mut self, agent: &AgentIdentity<T>) -> bool {
        let SpendCheck::Due(mark) = self.spend_check else {
            return false;
        };
        let RunState::Running(next) = &self.state else {
            return false;
        };
        self.state = RunState::Paused(next.clone());
        self.spend_check = SpendCheck::Asked(mark);
        self.touch();
        self.raised.raise(AgentRunHeldAtSpend {
            run_id: self.id,
            agent_id: self.agent_id,
            agent_label: EventLabel::of(agent.name().as_str()),
            spent: self.spent,
            mark,
            occurred_at: self.updated_at,
        });
        true
    }

    /// Ends the run as over budget, unless it has already ended, and
    /// records that it stopped.
    fn settle_over_budget(&mut self, agent: &AgentIdentity<T>) {
        if self.status().try_transition(RunStatus::OverBudget).is_err() {
            return;
        }
        self.state = RunState::OverBudget;
        let Restriction::To(limit) = self.spend_limit else {
            return;
        };
        self.raised.raise(AgentRunStoppedOverBudget {
            run_id: self.id,
            agent_id: self.agent_id,
            agent_label: EventLabel::of(agent.name().as_str()),
            spent: self.spent,
            limit,
            occurred_at: crate::shared::clock::now(),
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::domains::agents::execution::model_provider::{
        ModelChange, ModelName, ModelProvider,
    };
    use crate::domains::agents::execution::run::tests::fixtures::{
        agent, ann, by_ann, constraints, delegation, params, provider, started,
    };
    use crate::domains::agents::execution::run::{AgentRun, RunStatus, SpendCheck, StartRunParams};
    use crate::domains::agents::execution::tool::tests::fixtures::{MANAGE, holding, person};
    use crate::domains::agents::execution::usage::{ModelPricing, ModelTokens, ModelUsage, Spend};
    use crate::domains::agents::identity::agent::AgentIdentity;
    use crate::domains::data_classification::level::DataClassLevel;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::errors::DomainError;
    use crate::shared::model::restriction::Restriction;
    use crate::test_support::events::raised_names;

    /// A call of 300 tokens in and 200 out: 500 millionths on the priced
    /// provider.
    fn call() -> ModelUsage {
        ModelUsage::Reported(ModelTokens::new(300, 200))
    }

    /// A provider priced at one millionth per token in and out.
    fn priced_provider() -> ModelProvider<ResolvedTenant> {
        let bob = person("bob@corp.test");
        let mut model = provider(DataClassLevel::Restricted);
        model
            .change_model(
                &holding(&bob, &MANAGE),
                ModelChange {
                    model: ModelName::new("deepseek-chat").unwrap(),
                    pricing: ModelPricing::PerMillionTokens {
                        input: Spend::from_micros(1_000_000),
                        output: Spend::from_micros(1_000_000),
                    },
                },
            )
            .unwrap();
        model
    }

    /// A run on `model` allowed to spend `limit`.
    fn run_on(
        model: &ModelProvider<ResolvedTenant>,
        limit: Restriction<Spend>,
    ) -> AgentRun<ResolvedTenant> {
        started(StartRunParams {
            provider_id: *model.id(),
            spend_limit: limit,
            ..params(5)
        })
        .0
    }

    /// A run on `model` allowed to spend `limit`, pausing for a person once
    /// it spent `ask_past`, with its agent.
    fn asking_run(
        model: &ModelProvider<ResolvedTenant>,
        limit: u64,
        ask_past: u64,
    ) -> (AgentRun<ResolvedTenant>, AgentIdentity<ResolvedTenant>) {
        started(StartRunParams {
            provider_id: *model.id(),
            spend_limit: Restriction::To(Spend::from_micros(limit)),
            ask_past: Restriction::To(Spend::from_micros(ask_past)),
            ..params(5)
        })
    }

    /// Ann lets her run spend 2,000 millionths, asking her past 600. After
    /// one call of 500 it goes on. After the second, at 1,000, it pauses
    /// before asking its model again. She resumes it, and it does not ask
    /// her again on its next call.
    #[test]
    fn a_run_pauses_once_it_spent_what_it_may_spend_unasked() {
        let model = priced_provider();
        let (mut r, agent) = asking_run(&model, 2_000, 600);

        r.record_model_usage(&agent, &model, call()).unwrap();
        let after_first = r.pause_at_spend_check(&agent);
        r.record_model_usage(&agent, &model, call()).unwrap();
        let after_second = r.pause_at_spend_check(&agent);
        let while_paused = r.status();
        r.resume(&holding(&ann(), &[]), &agent).unwrap();
        r.record_model_usage(&agent, &model, call()).unwrap();
        let after_resume = r.pause_at_spend_check(&agent);

        assert!(!after_first);
        assert!(after_second);
        assert_eq!(while_paused, RunStatus::Paused);
        assert!(!after_resume);
        assert_eq!(r.status(), RunStatus::Running);
        assert_eq!(r.spend_check(), SpendCheck::Asked(Spend::from_micros(600)));
        assert_eq!(
            raised_names(&mut r),
            ["agents.run_held_at_spend", "agents.run_resumed"]
        );
    }

    /// Two calls take a run past both its asking threshold and spending cap.
    /// It ends over budget and cannot pause for permission to spend more.
    #[test]
    fn a_run_past_its_limit_stops_rather_than_asks() {
        let model = priced_provider();
        let (mut r, agent) = asking_run(&model, 900, 600);

        r.record_model_usage(&agent, &model, call()).unwrap();
        r.record_model_usage(&agent, &model, call()).unwrap();
        let paused = r.pause_at_spend_check(&agent);

        assert!(!paused);
        assert_eq!(r.status(), RunStatus::OverBudget);
    }

    /// An unpriced call makes a run with an asking threshold pause, since
    /// its reported tokens cannot establish whether the threshold was reached.
    #[test]
    fn a_run_that_cannot_tell_what_it_spent_asks() {
        let model = provider(DataClassLevel::Restricted);
        let (mut r, agent) = started(StartRunParams {
            provider_id: *model.id(),
            ask_past: Restriction::To(Spend::from_micros(600)),
            ..params(5)
        });

        r.record_model_usage(&agent, &model, call()).unwrap();
        let paused = r.pause_at_spend_check(&agent);

        assert!(paused);
        assert_eq!(r.status(), RunStatus::Paused);
    }

    /// A run asking at nothing would pause before its first call, and one
    /// asking at its limit would stop before anyone was asked. Both are
    /// refused when started.
    #[test]
    fn a_run_asks_at_more_than_nothing_and_less_than_its_limit() {
        let agent = agent();
        let start = |ask_past: u64| {
            AgentRun::start(
                by_ann(),
                StartRunParams {
                    spend_limit: Restriction::To(Spend::from_micros(1_000)),
                    ask_past: Restriction::To(Spend::from_micros(ask_past)),
                    ..params(5)
                },
                &delegation(&agent, constraints()),
                &agent,
            )
        };

        assert!(matches!(start(0), Err(DomainError::Validation(_))));
        assert!(matches!(start(1_000), Err(DomainError::Validation(_))));
        assert!(start(999).is_ok());
    }

    /// A call of 300 tokens in and 200 out at one millionth each is
    /// counted: 500 tokens used, 500 millionths spent.
    #[test]
    fn a_reported_call_is_counted_in_tokens_and_spend() {
        let model = priced_provider();
        let mut r = run_on(&model, Restriction::Unrestricted);

        r.record_model_usage(
            &agent(),
            &model,
            ModelUsage::Reported(ModelTokens::new(300, 200)),
        )
        .unwrap();

        assert_eq!(r.usage(), ModelTokens::new(300, 200));
        assert_eq!(r.spent(), Spend::from_micros(500));
        assert_eq!(r.status(), RunStatus::Running);
    }

    /// A run stays active below its cap, then ends over budget and cannot
    /// step after a second call takes its spending past that cap. Its stop
    /// is recorded, so a workflow can start from it.
    #[test]
    fn a_run_that_spent_its_limit_stops() {
        let model = priced_provider();
        let mut r = run_on(&model, Restriction::To(Spend::from_micros(600)));
        let call = ModelUsage::Reported(ModelTokens::new(300, 200));
        raised_names(&mut r);

        r.record_model_usage(&agent(), &model, call).unwrap();
        let after_first = r.status();
        r.record_model_usage(&agent(), &model, call).unwrap();

        assert_eq!(after_first, RunStatus::Running);
        assert_eq!(r.status(), RunStatus::OverBudget);
        assert!(!r.can_step());
        assert_eq!(raised_names(&mut r), ["agents.run_stopped_over_budget"]);
    }

    /// Unreported usage ends a capped run as over budget because its spending
    /// cannot be measured against the cap.
    #[test]
    fn a_capped_run_whose_spend_cannot_be_told_stops() {
        let model = priced_provider();
        let mut r = run_on(&model, Restriction::To(Spend::from_micros(1_000_000)));

        r.record_model_usage(&agent(), &model, ModelUsage::Unreported)
            .unwrap();

        assert_eq!(r.status(), RunStatus::OverBudget);
    }

    /// A capped run on an unpriced provider counts reported tokens and ends
    /// over budget because their cost is unknown.
    #[test]
    fn a_capped_run_on_an_unpriced_provider_stops() {
        let model = provider(DataClassLevel::Restricted);
        let mut r = run_on(&model, Restriction::To(Spend::from_micros(1_000_000)));

        r.record_model_usage(
            &agent(),
            &model,
            ModelUsage::Reported(ModelTokens::new(10, 10)),
        )
        .unwrap();

        assert_eq!(r.usage(), ModelTokens::new(10, 10));
        assert_eq!(r.status(), RunStatus::OverBudget);
    }

    /// A run with no limit on an unpriced provider goes on, its tokens
    /// counted and nothing spent.
    #[test]
    fn an_uncapped_run_goes_on_whatever_it_cannot_price() {
        let model = provider(DataClassLevel::Restricted);
        let mut r = run_on(&model, Restriction::Unrestricted);

        r.record_model_usage(
            &agent(),
            &model,
            ModelUsage::Reported(ModelTokens::new(10, 10)),
        )
        .unwrap();

        assert_eq!(r.status(), RunStatus::Running);
        assert_eq!(r.spent(), Spend::from_micros(0));
    }

    /// Usage attributed to another provider is forbidden and leaves the
    /// run's token counts at zero.
    #[test]
    fn usage_from_another_provider_is_refused() {
        let model = priced_provider();
        let mut r = run_on(&model, Restriction::Unrestricted);

        let result = r.record_model_usage(
            &agent(),
            &priced_provider(),
            ModelUsage::Reported(ModelTokens::new(1, 1)),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(r.usage(), ModelTokens::default());
    }

    /// A completed run's late usage is still counted, and it stays
    /// completed even past its limit.
    #[test]
    fn an_ended_run_counts_late_usage_and_keeps_how_it_ended() {
        let model = priced_provider();
        let mut r = run_on(&model, Restriction::To(Spend::from_micros(1)));
        r.complete("done").unwrap();

        r.record_model_usage(
            &agent(),
            &model,
            ModelUsage::Reported(ModelTokens::new(5, 5)),
        )
        .unwrap();

        assert_eq!(r.status(), RunStatus::Completed);
        assert_eq!(r.spent(), Spend::from_micros(10));
    }
}
