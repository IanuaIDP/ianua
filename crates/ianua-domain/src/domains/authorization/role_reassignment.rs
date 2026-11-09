//! Moving every holder of a role onto another, as the role is deleted.

use crate::domains::authorization::events::roles::RoleReassigned;
use crate::domains::authorization::granter::HeldByGranter;
use crate::domains::authorization::role::Role;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::types::{EventLabel, RoleId};

/// Every holder of one role moved onto another, before the first is
/// deleted.
///
/// The move happens in storage, all holders at once, so no single
/// assignment changes in memory. This is the change the audit trail
/// records instead: which role was vacated, which one received the holders,
/// and how many moved.
#[derive(Debug)]
pub struct RoleReassignment<T: TenantScope> {
    from: (RoleId, EventLabel),
    to: (RoleId, EventLabel),
    raised: Raised<T>,
}

impl<T: TenantScope> RoleReassignment<T> {
    /// Plans moving the holders of `from` onto `to`, for `granter`.
    ///
    /// Moving the holders hands them everything `to` grants. So `granter`
    /// must be able to hand all of it out, or the right to delete roles
    /// alone would give out the admin role by naming it as the replacement.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `to` is the role being vacated.
    /// - [`DomainError::Forbidden`] when `granter` may not hand out
    ///   everything `to` grants.
    pub fn plan(
        from: &Role<T>,
        to: &Role<T>,
        granter: &HeldByGranter<'_>,
    ) -> Result<Self, DomainError> {
        if from.id() == to.id() {
            return Err(DomainError::invalid(message!(
                "authorization-replacement-role-must-differ-from-the",
                "replacement role must differ from the role being deleted"
            )));
        }
        granter.ensure_may_give(&to.grants())?;
        Ok(Self {
            from: (*from.id(), from.label()),
            to: (*to.id(), to.label()),
            raised: Raised::default(),
        })
    }

    /// Records that `count` holders moved. Raises
    /// `authorization.role_reassigned`.
    pub fn record_reassignment(&mut self, count: u64) {
        self.raised.raise(RoleReassigned {
            from_role_id: self.from.0,
            from_role_label: self.from.1.clone(),
            to_role_id: self.to.0,
            to_role_label: self.to.1.clone(),
            reassigned_count: count,
            occurred_at: crate::shared::clock::now(),
        });
    }
}

impl<T: TenantScope> Raises for RoleReassignment<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::permission::{SystemPermission, UserAction};
    use crate::domains::authorization::role::{DefaultAssignment, NewRole};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::test_support::builders::label;
    use crate::test_support::events::{raised, raised_names};

    fn role(name: &str, system: Vec<SystemPermission>) -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id: RoleId::new(),
            name: label(name),
            system_permissions: system,
            custom_permissions: Vec::new(),
            assignment: DefaultAssignment::Manual,
        })
    }

    fn owner() -> HeldByGranter<'static> {
        HeldByGranter::assumed(SystemPermission::all(), &[])
    }

    /// The text a reassignment event stores under `key`.
    fn text_at(event: &DomainEvent, key: &str) -> String {
        match event.payload().value(key) {
            Some(FieldValue::Text(value)) => value.clone(),
            other => panic!("{key} is not text: {other:?}"),
        }
    }

    /// Ann deletes the "contractor" role and moves its three holders onto
    /// "viewer". The move is raised with both roles and the count.
    #[test]
    fn carrying_out_raises_authorization_role_reassigned() {
        let mut moved = RoleReassignment::plan(
            &role("contractor", Vec::new()),
            &role("viewer", Vec::new()),
            &owner(),
        )
        .unwrap();

        moved.record_reassignment(3);
        let events = raised(&mut moved);

        assert_eq!(
            events[0].event_type().to_string(),
            "authorization.role_reassigned"
        );
        assert_eq!(text_at(&events[0], "reassigned_count"), "3");
    }

    /// A planned move that was never carried out raises nothing.
    #[test]
    fn a_plan_alone_raises_nothing() {
        let mut moved = RoleReassignment::plan(
            &role("contractor", Vec::new()),
            &role("viewer", Vec::new()),
            &owner(),
        )
        .unwrap();

        assert!(raised_names(&mut moved).is_empty());
    }

    /// Reassigning holders to the role being vacated is rejected as invalid.
    #[test]
    fn holders_move_only_onto_another_role() {
        let contractor = role("contractor", Vec::new());

        let result = RoleReassignment::plan(&contractor, &contractor, &owner());

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// Sam's view-only rights cannot authorize moving holders to a role that
    /// manages users.
    #[test]
    fn holders_move_only_onto_a_role_the_granter_could_give() {
        let sam = HeldByGranter::assumed(&[SystemPermission::Users(UserAction::View)], &[]);

        let result = RoleReassignment::plan(
            &role("contractor", Vec::new()),
            &role("admin", vec![SystemPermission::ManageUsers]),
            &sam,
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }
}
