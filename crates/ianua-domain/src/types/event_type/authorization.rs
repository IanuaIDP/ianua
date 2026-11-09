event_types! {
    /// The events the authorization context publishes.
    pub enum AuthorizationEvent {
        /// A new role was created.
        RoleCreated => "authorization.role_created",
        /// A role was assigned to a user.
        RoleAssigned => "authorization.role_assigned",
        /// A role was removed from a user.
        RoleRevoked => "authorization.role_revoked",
        /// A role was deleted.
        RoleDeleted => "authorization.role_deleted",
        /// A role's holders were reassigned to another role.
        RoleReassigned => "authorization.role_reassigned",
        /// A role was renamed.
        RoleRenamed => "authorization.role_renamed",
        /// Whether every new user gets a role changed.
        RoleDefaultAssignmentChanged => "authorization.role_default_assignment_changed",
        /// A permission was granted to a role.
        PermissionGranted => "authorization.permission_granted",
        /// A permission was revoked from a role.
        PermissionRevoked => "authorization.permission_revoked",
        /// A group was created.
        GroupCreated => "authorization.group_created",
        /// A group was deleted.
        GroupDeleted => "authorization.group_deleted",
        /// A group was renamed.
        GroupRenamed => "authorization.group_renamed",
        /// A role was assigned to a group.
        GroupRoleAssigned => "authorization.group_role_assigned",
        /// A role was removed from a group.
        GroupRoleUnassigned => "authorization.group_role_unassigned",
        /// A user was added to a group.
        GroupMemberAdded => "authorization.group_member_added",
        /// A user was removed from a group.
        GroupMemberRemoved => "authorization.group_member_removed",
        /// A group was moved under another group, or to the top.
        GroupMoved => "authorization.group_moved",
        /// A policy rule was added.
        PolicyRuleAdded => "authorization.policy_rule_added",
        /// A policy rule was removed.
        PolicyRuleRemoved => "authorization.policy_rule_removed",
        /// A policy rule was turned on or off.
        PolicyRuleSwitched => "authorization.policy_rule_switched",
        /// A policy's fallback action, used when no rule matches, changed.
        PolicyDefaultActionChanged => "authorization.policy_default_action_changed",
        /// A new draft of the policy was started.
        PolicyDraftStarted => "authorization.policy_draft_started",
        /// What a tenant's users may give themselves in an emergency changed.
        BreakGlassPolicyChanged => "authorization.break_glass_policy_changed",
        /// A policy was submitted for review.
        PolicySubmittedForReview => "authorization.policy_submitted_for_review",
        /// A policy was approved and put into use.
        PolicyActivated => "authorization.policy_activated",
        /// A policy was rejected and sent back to draft.
        PolicyRejected => "authorization.policy_rejected",
        /// A policy was archived.
        PolicyArchived => "authorization.policy_archived",
        /// A policy simulation was run.
        PolicySimulated => "authorization.policy_simulated",
        /// A resource type was declared in the tenant's permission catalogue.
        ResourceTypeDeclared => "authorization.resource_type_declared",
        /// A resource type's name, description or action ladder changed.
        ResourceTypeUpdated => "authorization.resource_type_updated",
        /// A resource type was removed from the catalogue.
        ResourceTypeDeleted => "authorization.resource_type_deleted",
        /// A rule of a draft policy was rewritten in place.
        PolicyRuleChanged => "authorization.policy_rule_changed",
        /// The rules of a draft policy were put in a new order.
        PolicyRulesReordered => "authorization.policy_rules_reordered",
        /// A role given until a time reached it and was taken away.
        RoleAssignmentExpired => "authorization.role_assignment_expired",
        /// A group membership given until a time reached it and ended.
        GroupMembershipExpired => "authorization.group_membership_expired",
        /// Someone asked for a role or a group for a while.
        AccessRequested => "authorization.access_requested",
        /// A request for access was approved.
        AccessRequestApproved => "authorization.access_request_approved",
        /// A request for access was denied.
        AccessRequestDenied => "authorization.access_request_denied",
        /// A request for access was withdrawn by the person who asked.
        AccessRequestCancelled => "authorization.access_request_cancelled",
        /// A request for access was left unanswered until it ran out.
        AccessRequestExpired => "authorization.access_request_expired",
        /// The longest a tenant's people may ask for access changed.
        AccessRequestPolicyChanged => "authorization.access_request_policy_changed",
        /// A relation on an object of the tenant's app was written.
        RelationshipAdded => "authorization.relationship_added",
        /// A relation on an object of the tenant's app was removed.
        RelationshipRemoved => "authorization.relationship_removed",
        /// An access review was started.
        AccessReviewStarted => "authorization.access_review_started",
        /// A reviewer decided whether someone keeps their access.
        AccessReviewDecided => "authorization.access_review_decided",
        /// Keep or remove was suggested beside holders of an access review.
        AccessReviewSuggested => "authorization.access_review_suggested",
        /// An access review was completed and its removals settled.
        AccessReviewCompleted => "authorization.access_review_completed",
        /// An access review was called off.
        AccessReviewCancelled => "authorization.access_review_cancelled",
        /// Two roles were declared that nobody may hold together.
        SeparationRuleAdded => "authorization.separation_rule_added",
        /// A separation-of-duties rule was removed.
        SeparationRuleRemoved => "authorization.separation_rule_removed",
        /// Holding a permission was made to clear its holder for a data class.
        ClearanceRuleAdded => "authorization.clearance_rule_added",
        /// The data class a clearance rule clears for changed.
        ClearanceRuleChanged => "authorization.clearance_rule_changed",
        /// A clearance rule was removed.
        ClearanceRuleRemoved => "authorization.clearance_rule_removed",
    }
}

impl AuthorizationEvent {
    /// Whether other members hear about this event.
    ///
    /// A policy simulation changes nothing. It goes in the audit trail but
    /// not in colleagues' feeds. Sam runs a hundred simulations while writing
    /// one rule. If each were told, his colleagues would see only that.
    ///
    /// A tenant's app writes relationships on its objects as its people
    /// share documents, and a reviewer decides one holder at a time. Both
    /// come in hundreds, so they are audited and told to no one; the
    /// review's start and completion are. Suggestions prepare a review
    /// for its reviewers: the workflow that makes them tells whom it
    /// chooses, so the feed is not told as well.
    #[must_use]
    pub fn is_notifiable(&self) -> bool {
        !matches!(
            self,
            Self::PolicySimulated
                | Self::RelationshipAdded
                | Self::RelationshipRemoved
                | Self::AccessReviewDecided
                | Self::AccessReviewSuggested
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Policy simulations are excluded from notifications so repeated trials
    /// do not fill colleagues' feeds.
    #[test]
    fn a_policy_simulation_is_not_notified() {
        assert!(!AuthorizationEvent::PolicySimulated.is_notifiable());
    }

    /// An admin assigns a role. Colleagues are notified.
    #[test]
    fn a_role_assignment_is_notified() {
        assert!(AuthorizationEvent::RoleAssigned.is_notifiable());
    }

    /// Relationship changes and individual review decisions or suggestions
    /// send no feed notice, while an approved access request remains notifiable.
    #[test]
    fn high_volume_authorization_records_are_not_notified() {
        assert!(!AuthorizationEvent::RelationshipAdded.is_notifiable());
        assert!(!AuthorizationEvent::RelationshipRemoved.is_notifiable());
        assert!(!AuthorizationEvent::AccessReviewDecided.is_notifiable());
        assert!(!AuthorizationEvent::AccessReviewSuggested.is_notifiable());
        assert!(AuthorizationEvent::AccessRequestApproved.is_notifiable());
    }
}
