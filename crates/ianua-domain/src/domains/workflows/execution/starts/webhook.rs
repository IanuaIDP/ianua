//! Starting a workflow because its webhook was called with its secret.

use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::workflows::data::FlowData;
use crate::domains::workflows::design::workflow::Workflow;
use crate::domains::workflows::execution::record::ExecutionRecord;
use crate::domains::workflows::execution::{
    ActingAuthority, Cause, StartExecutionParams, WorkflowExecution,
};
use crate::domains::workflows::triggers::secret::WebhookCall;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;

/// The values a webhook call starts an execution with.
pub struct WebhookStartParams {
    /// The person it acts for, with what they hold right now: whoever
    /// published the version in service. Anyone else is refused.
    pub acting_for: ActingAuthority,
    /// The data the call carried.
    pub input: FlowData,
    /// The most sensitive data in it, as the adapter that received the
    /// call classed it.
    pub exposure: DataClassLevel,
}

impl<T: TenantScope> WorkflowExecution<T> {
    /// Starts an execution of `workflow` because its webhook was called
    /// with its secret, as `call` proves, and runs every step the domain
    /// finishes itself, as far as they go.
    ///
    /// It acts for the person who published the version, as a schedule's
    /// run does.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `call` was admitted for another
    ///   workflow or version.
    /// - [`DomainError::Conflict`] when `workflow` is not published.
    /// - [`DomainError::Validation`] when `workflow` does not start on its
    ///   webhook.
    /// - [`DomainError::Forbidden`] when the person it would act for may
    ///   not run workflows now, or is not the person who published it.
    pub fn start_on_webhook(
        workflow: &Workflow<T>,
        call: WebhookCall,
        params: WebhookStartParams,
    ) -> Result<(Self, Vec<ExecutionRecord>), DomainError> {
        if !call.admits(workflow) {
            return Err(DomainError::forbidden(message!(
                "workflows-the-webhook-call-was-admitted-for",
                "the webhook call was admitted for another workflow or version"
            )));
        }
        Self::start_checked(
            workflow,
            StartExecutionParams {
                acting_for: params.acting_for,
                cause: Cause::Webhook,
                input: params.input,
                exposure: params.exposure,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::workflows::design::node::Join;
    use crate::domains::workflows::execution::tests::fixtures::{
        Check, Execution, SeesAll, acting, ann, bob, draft_with, managing, publish_as, transform,
        trigger_data,
    };
    use crate::domains::workflows::triggers::Trigger;
    use crate::domains::workflows::triggers::secret::WorkflowTriggerSecret;
    use crate::isolation::scope::ResolvedTenant;
    use crate::types::{Human, TokenHash};

    /// Ann's webhook workflow, published by Ann.
    fn hooked() -> Workflow<ResolvedTenant> {
        let mut workflow = draft_with(
            vec![transform("tidy", Join::All)],
            Vec::new(),
            Trigger::Webhook,
        );
        publish_as(&mut workflow, &ann(), &[], &SeesAll).unwrap();
        workflow
    }

    /// A call of `workflow`'s webhook with the secret Ann issued for it.
    fn called(workflow: &Workflow<ResolvedTenant>) -> WebhookCall {
        let digest = TokenHash::from_stored("s3cret".to_owned());
        WorkflowTriggerSecret::issue(workflow, digest.clone(), &managing(&ann()))
            .unwrap()
            .admit(&digest, workflow)
            .unwrap()
    }

    /// A webhook start acting for `person`, with data that passes.
    fn acting_for(person: &Human) -> WebhookStartParams {
        WebhookStartParams {
            acting_for: acting(person),
            input: trigger_data(Check::Passes),
            exposure: DataClassLevel::Public,
        }
    }

    /// A call with Ann's secret starts her webhook workflow, acting for
    /// her, as a webhook start.
    #[test]
    fn a_call_with_the_secret_starts_the_workflow_for_its_publisher() {
        let workflow = hooked();

        let (execution, _) =
            Execution::start_on_webhook(&workflow, called(&workflow), acting_for(&ann())).unwrap();

        assert_eq!(execution.acting_for(), &ann());
        assert_eq!(execution.cause(), Cause::Webhook);
    }

    /// A webhook call admitted for Ann's first workflow cannot start her
    /// second workflow and returns a forbidden error.
    #[test]
    fn a_call_admitted_for_one_workflow_does_not_start_another() {
        let first = hooked();
        let second = hooked();

        let started = Execution::start_on_webhook(&second, called(&first), acting_for(&ann()));

        assert!(matches!(started, Err(DomainError::Forbidden(_))));
    }

    /// Ann's webhook call cannot start a run acting for Bob instead of its
    /// publisher; the start returns a forbidden error.
    #[test]
    fn a_webhook_run_acts_only_for_the_publisher() {
        let workflow = hooked();

        let started = Execution::start_on_webhook(&workflow, called(&workflow), acting_for(&bob()));

        assert!(matches!(started, Err(DomainError::Forbidden(_))));
    }
}
