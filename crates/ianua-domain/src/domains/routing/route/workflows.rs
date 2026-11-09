//! Whether workflows may call a route, as a Protected apps step does.
//!
//! A route is closed to workflows until an administrator opens it, so
//! nobody automates against Payroll just because they can reach it. Opening
//! it changes nothing about who may reach it: each call a workflow makes is
//! still decided by the route's policy as the run's person, and a route
//! that was private stays private.

use crate::domains::routing::control::{RoutingControl, RoutingRight};
use crate::domains::routing::events::{RouteClosedToWorkflows, RouteOpenedToWorkflows};
use crate::domains::routing::route::Route;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;

/// Whether workflows may call a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WorkflowUse {
    /// Workflows may not call it, as every route starts.
    #[default]
    Closed,
    /// A Protected apps step may call it, decided as the run's person.
    Open,
}

impl WorkflowUse {
    /// The stored form, `closed` or `open`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open => "open",
        }
    }
}

impl<T: TenantScope> Route<T> {
    /// Whether workflows may call this route.
    #[must_use]
    pub fn workflow_use(&self) -> WorkflowUse {
        self.workflow_use
    }

    /// Lets workflows call this route. Raises
    /// `routing.route_opened_to_workflows`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    /// - [`DomainError::InvalidTransition`] when it is open already.
    pub fn open_to_workflows(&mut self, by: &RoutingControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        if self.workflow_use == WorkflowUse::Open {
            return Err(DomainError::invalid_transition(message!(
                "routing-the-route-is-open-to-workflows-already",
                "the route is open to workflows already"
            )));
        }
        self.workflow_use = WorkflowUse::Open;
        self.touch();
        self.raised.raise(RouteOpenedToWorkflows {
            route_id: self.id,
            name: self.name.clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Stops workflows calling this route; a call already sent is not
    /// recalled. Raises `routing.route_closed_to_workflows`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not update routing.
    /// - [`DomainError::InvalidTransition`] when it is closed already.
    pub fn close_to_workflows(&mut self, by: &RoutingControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(RoutingRight::Update)?;
        if self.workflow_use == WorkflowUse::Closed {
            return Err(DomainError::invalid_transition(message!(
                "routing-the-route-is-closed-to-workflows-already",
                "the route is closed to workflows already"
            )));
        }
        self.workflow_use = WorkflowUse::Closed;
        self.touch();
        self.raised.raise(RouteClosedToWorkflows {
            route_id: self.id,
            name: self.name.clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }
}
