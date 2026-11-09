//! Who may change how the tenant's traffic is routed.
//!
//! Routes, services, stream routes, egress policies and request pipelines
//! decide what every caller reaches, under which policy, through which
//! checks, and where a service may itself go.
//! So every change to one names who makes it and needs the routing right
//! for it. Only a person signed in to the tenant holds one, so an agent or a
//! machine caller never changes routing at all.

use crate::domains::authorization::authority::TenantAuthority;
use crate::domains::authorization::permission::{PipelineAction, RoutingAction, SystemPermission};
use crate::shared::errors::DomainError;
use crate::types::Human;

/// What a change to routing needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingRight {
    /// Adding a route, a service, a stream route or an egress policy. It
    /// needs the create right.
    Create,
    /// Any change to one, turning it on or off among them. It needs the
    /// update right.
    Update,
    /// Deleting a route, a service, a stream route or an egress policy. It
    /// needs the delete right.
    Delete,
    /// Making a request pipeline. It needs the full pipeline right.
    CreatePipeline,
    /// Any change to a pipeline or its stages. It needs the pipeline update
    /// right.
    ChangePipeline,
    /// Deleting a request pipeline. It needs the full pipeline right, since
    /// there is no narrower one for it.
    DeletePipeline,
}

impl RoutingRight {
    /// The built-in permission this right is.
    #[must_use]
    pub fn permission(self) -> SystemPermission {
        match self {
            Self::Create => SystemPermission::Routing(RoutingAction::Create),
            Self::Update => SystemPermission::Routing(RoutingAction::Update),
            Self::Delete => SystemPermission::Routing(RoutingAction::Delete),
            Self::CreatePipeline | Self::DeletePipeline => {
                SystemPermission::Pipeline(PipelineAction::Manage)
            }
            Self::ChangePipeline => SystemPermission::Pipeline(PipelineAction::Update),
        }
    }
}

/// A person changing the tenant's routing, with what they hold.
///
/// Sam may only view routing. Without this check, he makes the route to the
/// payroll records public, or points its service at his own server.
#[derive(Debug, Clone, Copy)]
pub struct RoutingControl<'a> {
    authority: &'a TenantAuthority,
}

impl<'a> RoutingControl<'a> {
    /// The person `authority` names, acting with what it says they hold.
    #[must_use]
    pub fn new(authority: &'a TenantAuthority) -> Self {
        Self { authority }
    }

    /// The person acting.
    #[must_use]
    pub fn by(&self) -> &'a Human {
        self.authority.who()
    }

    /// Refuses the change unless the person holds `right`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when they do not hold it.
    pub fn ensure_may(&self, right: RoutingRight) -> Result<(), DomainError> {
        self.authority.ensure_holds(right.permission())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::routing::fixtures::holding;

    /// Routing view permission grants none of the create, update or delete
    /// rights.
    #[test]
    fn the_view_right_changes_nothing() {
        let control = holding(&[SystemPermission::Routing(RoutingAction::View)]);

        for right in [
            RoutingRight::Create,
            RoutingRight::Update,
            RoutingRight::Delete,
        ] {
            assert!(
                matches!(control.ensure_may(right), Err(DomainError::Forbidden(_))),
                "{right:?}"
            );
        }
    }

    /// Routing update permission allows updates but refuses creation and
    /// deletion.
    #[test]
    fn the_update_right_edits_but_does_not_create_or_delete() {
        let control = holding(&[SystemPermission::Routing(RoutingAction::Update)]);

        assert!(control.ensure_may(RoutingRight::Update).is_ok());
        for right in [RoutingRight::Create, RoutingRight::Delete] {
            assert!(
                matches!(control.ensure_may(right), Err(DomainError::Forbidden(_))),
                "{right:?}"
            );
        }
    }

    /// Fay manages routing. She may create, change and delete routing.
    #[test]
    fn the_full_routing_right_covers_every_change() {
        let control = holding(&[SystemPermission::ManageRouting]);

        for right in [
            RoutingRight::Create,
            RoutingRight::Update,
            RoutingRight::Delete,
        ] {
            assert!(control.ensure_may(right).is_ok(), "{right:?}");
        }
    }

    /// Pipeline update permission does not allow pipeline deletion.
    #[test]
    fn deleting_a_pipeline_needs_the_full_pipeline_right() {
        let control = holding(&[SystemPermission::Pipeline(PipelineAction::Update)]);

        assert!(matches!(
            control.ensure_may(RoutingRight::DeletePipeline),
            Err(DomainError::Forbidden(_))
        ));
    }
}
