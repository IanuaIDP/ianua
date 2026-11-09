//! Starting a workflow because an integration's service sent the event it
//! starts on, through a registration that admitted the delivery.

use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::workflows::data::FlowData;
use crate::domains::workflows::design::workflow::Workflow;
use crate::domains::workflows::execution::record::ExecutionRecord;
use crate::domains::workflows::execution::{
    ActingAuthority, Cause, StartExecutionParams, WorkflowExecution,
};
use crate::domains::workflows::triggers::subscription::ServiceDelivery;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;

/// The values a service's event starts an execution with.
pub struct ServiceStartParams {
    /// The person it acts for, with what they hold right now: whoever
    /// published the version in service. Anyone else is refused.
    pub acting_for: ActingAuthority,
    /// The event's values, as the integration read them.
    pub input: FlowData,
    /// The most sensitive data in it, as the integration classed it.
    pub exposure: DataClassLevel,
}

impl<T: TenantScope> WorkflowExecution<T> {
    /// Starts an execution of `workflow` because its service sent the event
    /// it starts on, as `delivery` proves, and runs every step the domain
    /// finishes itself, as far as they go.
    ///
    /// It acts for the person who published the version, as a schedule's
    /// run does.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `delivery` was admitted for another
    ///   workflow or version.
    /// - [`DomainError::Conflict`] when `workflow` is not published.
    /// - [`DomainError::Validation`] when `workflow` does not start on a
    ///   service's event.
    /// - [`DomainError::Forbidden`] when the person it would act for may not
    ///   run workflows now, or is not the person who published it.
    pub fn start_on_service_event(
        workflow: &Workflow<T>,
        delivery: ServiceDelivery,
        params: ServiceStartParams,
    ) -> Result<(Self, Vec<ExecutionRecord>), DomainError> {
        if !delivery.admits(workflow) {
            return Err(DomainError::forbidden(message!(
                "workflows-the-delivery-was-admitted-for-another-version",
                "the service's event was admitted for another workflow or version"
            )));
        }
        Self::start_checked(
            workflow,
            StartExecutionParams {
                acting_for: params.acting_for,
                cause: Cause::Service,
                input: params.input,
                exposure: params.exposure,
            },
        )
    }
}
