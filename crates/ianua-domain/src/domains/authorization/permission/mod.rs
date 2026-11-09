/// Maximum length for resource or action strings in custom permissions.
const MAX_SEGMENT_LENGTH: usize = 64;

/// The realm segment every tenant-plane scope must name.
const REALM: &str = "idp:";

/// The action every area has that covers all its other actions.
const MANAGE: &str = "manage";

/// The action that reads an area without changing it.
const VIEW: &str = "view";

mod actions;
mod custom;
mod segment;
mod system;
mod written;

pub use actions::*;
pub use custom::CustomPermission;
pub use segment::PermissionSegment;
pub use system::SystemPermission;

/// A set of permissions of one kind, moved together.
///
/// The two kinds are never mixed. What a permission means, and who may grant
/// it, depends on its kind. The kind is the variant, so a "system" set of
/// custom values cannot be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PermissionSet {
    /// Permissions the `IdP` defines and enforces.
    System(Vec<SystemPermission>),
    /// Permissions the tenant's own application defines and enforces.
    Custom(Vec<CustomPermission>),
}

impl PermissionSet {
    /// The kind, as the audit trail and the wire spell it.
    #[must_use]
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::System(_) => "system",
            Self::Custom(_) => "custom",
        }
    }

    /// How many permissions the set holds.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::System(permissions) => permissions.len(),
            Self::Custom(permissions) => permissions.len(),
        }
    }

    /// Whether the set holds nothing, as after a save that changed nothing.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Each permission written out, in the order it was given.
    #[must_use]
    pub(crate) fn values(&self) -> Vec<String> {
        match self {
            Self::System(permissions) => permissions.iter().map(ToString::to_string).collect(),
            Self::Custom(permissions) => permissions.iter().map(ToString::to_string).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PermissionName;
    /// "Manage users" and the app permission `project:read` are written out.
    /// The two strings differ, so neither kind can be mistaken for the other.
    #[test]
    fn system_and_custom_are_different_types() {
        let system: SystemPermission = SystemPermission::ManageUsers;
        let custom: CustomPermission = CustomPermission::new("project", "read").unwrap();
        assert_ne!(system.to_string(), custom.to_string());
    }

    /// A set of built-in permissions reports `system`, and a set of app
    /// permissions reports `custom`. The kind comes from the variant, so it
    /// always matches the values.
    #[test]
    fn a_set_reports_the_kind_of_what_it_holds() {
        let system = PermissionSet::System(vec![SystemPermission::ManageUsers]);
        let custom = PermissionSet::Custom(vec![CustomPermission::new("billing", "read").unwrap()]);

        assert_eq!(system.kind(), "system");
        assert_eq!(custom.kind(), "custom");
    }

    /// A set holds "manage users" then "view audit log". It writes them out
    /// in that order.
    #[test]
    fn a_set_writes_each_permission_out_in_order() {
        let set = PermissionSet::System(vec![
            SystemPermission::ManageUsers,
            SystemPermission::ViewAuditLog,
        ]);

        assert_eq!(
            set.values(),
            vec![
                SystemPermission::ManageUsers.to_string(),
                SystemPermission::ViewAuditLog.to_string(),
            ]
        );
    }

    /// A set of app permissions holding billing read writes it out as
    /// `billing:read`.
    #[test]
    fn a_custom_set_writes_resource_and_action() {
        let set = PermissionSet::Custom(vec![CustomPermission::new("billing", "read").unwrap()]);

        assert_eq!(set.values(), vec!["billing:read".to_owned()]);
    }

    /// A system set and a custom set with no values are both empty, and a
    /// set with one value is not. Callers raise no event for an empty set.
    #[test]
    fn an_empty_set_is_empty_whatever_its_kind() {
        assert!(PermissionSet::System(Vec::new()).is_empty());
        assert!(PermissionSet::Custom(Vec::new()).is_empty());
        assert!(!PermissionSet::System(vec![SystemPermission::ManageUsers]).is_empty());
    }

    /// A set holding two built-in permissions counts two.
    #[test]
    fn a_set_counts_what_it_holds() {
        let set = PermissionSet::System(vec![
            SystemPermission::ManageUsers,
            SystemPermission::ViewAuditLog,
        ]);

        assert_eq!(set.len(), 2);
    }

    mod held_in {
        use super::*;

        fn held(permissions: &[&str]) -> Vec<PermissionName> {
            permissions
                .iter()
                .map(|p| PermissionName::new(*p).unwrap())
                .collect()
        }

        /// A caller holds `idp:users:manage`. They may view and delete
        /// users, but not update roles.
        #[test]
        fn manage_grants_every_action_in_its_area() {
            let held = held(&["idp:users:manage"]);

            assert!(SystemPermission::Users(UserAction::View).held_in(&held));
            assert!(SystemPermission::Users(UserAction::Delete).held_in(&held));
            assert!(!SystemPermission::Roles(RoleAction::Update).held_in(&held));
        }

        /// A caller holds `idp:users:view`. They may view users but not
        /// update them.
        #[test]
        fn a_fine_grained_permission_grants_only_itself() {
            let held = held(&["idp:users:view"]);

            assert!(SystemPermission::Users(UserAction::View).held_in(&held));
            assert!(!SystemPermission::Users(UserAction::Update).held_in(&held));
        }

        /// `project:read` is held through `project:*`, `*:read` or `*:*`.
        /// It is not held through `invoice:*` or `project:write`.
        #[test]
        fn a_custom_wildcard_grants_what_it_covers() {
            let read = CustomPermission::new("project", "read").unwrap();

            assert!(read.held_in(&held(&["project:*"])));
            assert!(read.held_in(&held(&["*:read"])));
            assert!(read.held_in(&held(&["*:*"])));
            assert!(!read.held_in(&held(&["invoice:*"])));
            assert!(!read.held_in(&held(&["project:write"])));
        }

        /// Custom `users:view` and built-in `idp:users:view` permissions do not
        /// satisfy checks for each other.
        #[test]
        fn system_and_custom_permissions_never_stand_in_for_each_other() {
            let custom = CustomPermission::new("users", "view").unwrap();
            let system = SystemPermission::Users(UserAction::View);

            assert!(!custom.held_in(&held(&["idp:users:view"])));
            assert!(!system.held_in(&held(&["users:view"])));
        }
    }
}
