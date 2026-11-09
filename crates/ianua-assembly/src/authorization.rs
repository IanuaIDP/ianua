//! The authorization use cases the API serves: a tenant's roles and who
//! holds them, its groups, its access policy and its versions, its
//! permission catalogue, and the governance around them: separation of
//! duties, access requests and reviews, relationships on single objects,
//! access checks with their records, and data clearance.

use std::sync::Arc;

use ianua_app::use_cases::authorization::{
    access_requests, access_reviews, checks, clearance, groups, holdings, policies, relationships,
    resource_types, roles, separation,
};

use crate::deps::Adapters;

/// The authorization use cases, one group per app folder.
#[derive(Clone)]
pub struct AuthorizationState {
    /// A tenant's roles.
    pub roles: RoleUseCases,
    /// A tenant's groups.
    pub groups: GroupUseCases,
    pub policies: PolicyUseCases,
    pub resource_types: ResourceTypeUseCases,
    pub holdings: HoldingUseCases,
    pub separation: SeparationUseCases,
    pub access_requests: AccessRequestUseCases,
    pub access_reviews: AccessReviewUseCases,
    pub relationships: RelationshipUseCases,
    pub checks: CheckUseCases,
    pub clearance: ClearanceUseCases,
}

/// A tenant's roles, and who holds them.
#[derive(Clone)]
pub struct RoleUseCases {
    /// Defines a new role.
    pub create: Arc<roles::CreateUseCase>,
    pub list: Arc<roles::ListUseCase>,
    pub get: Arc<roles::GetUseCase>,
    pub update: Arc<roles::UpdateUseCase>,
    pub delete: Arc<roles::DeleteUseCase>,
    pub assign: Arc<roles::AssignUseCase>,
    pub revoke: Arc<roles::RevokeUseCase>,
}

/// A tenant's groups, their place in the tree, members and roles.
#[derive(Clone)]
pub struct GroupUseCases {
    /// Makes a new group.
    pub create: Arc<groups::CreateUseCase>,
    pub list: Arc<groups::ListUseCase>,
    pub get: Arc<groups::GetUseCase>,
    pub rename: Arc<groups::RenameUseCase>,
    pub move_group: Arc<groups::MoveUseCase>,
    pub delete: Arc<groups::DeleteUseCase>,
    /// Puts someone in a group.
    pub add_member: Arc<groups::AddMemberUseCase>,
    pub list_members: Arc<groups::ListMembersUseCase>,
    pub remove_member: Arc<groups::RemoveMemberUseCase>,
    /// Gives a group a role.
    pub assign_role: Arc<groups::AssignRoleUseCase>,
    pub unassign_role: Arc<groups::UnassignRoleUseCase>,
}

/// A tenant's access policy: its live version and the draft beside it,
/// tried out, with its versions and the rules of its draft.
#[derive(Clone)]
pub struct PolicyUseCases {
    pub get: Arc<policies::GetUseCase>,
    pub simulate: Arc<policies::SimulateUseCase>,
    pub versions: PolicyVersionUseCases,
    pub rules: PolicyRuleUseCases,
}

/// A policy's versions: drafted, moved through review, read back.
#[derive(Clone)]
pub struct PolicyVersionUseCases {
    pub get: Arc<policies::GetVersionUseCase>,
    pub list: Arc<policies::ListVersionsUseCase>,
    pub start_draft: Arc<policies::StartDraftUseCase>,
    pub change_status: Arc<policies::ChangeStatusUseCase>,
}

/// The rules of a draft: added, changed, removed, reordered, switched, and
/// the fallback for a request none of them matched.
#[derive(Clone)]
pub struct PolicyRuleUseCases {
    pub add: Arc<policies::AddRuleUseCase>,
    pub change: Arc<policies::ChangeRuleUseCase>,
    pub remove: Arc<policies::RemoveRuleUseCase>,
    pub reorder: Arc<policies::ReorderRulesUseCase>,
    pub switch: Arc<policies::SwitchRuleUseCase>,
    pub change_default_action: Arc<policies::ChangeDefaultActionUseCase>,
}

/// A tenant's permission catalogue.
#[derive(Clone)]
pub struct ResourceTypeUseCases {
    pub declare: Arc<resource_types::DeclareUseCase>,
    pub list: Arc<resource_types::ListUseCase>,
    pub update: Arc<resource_types::UpdateUseCase>,
    pub delete: Arc<resource_types::DeleteUseCase>,
}

/// Who holds what: a role's holders and a principal's access.
#[derive(Clone)]
pub struct HoldingUseCases {
    pub role_holders: Arc<holdings::ListRoleHoldersUseCase>,
    pub principal_access: Arc<holdings::GetPrincipalAccessUseCase>,
}

/// The pairs of roles nobody in a tenant holds together.
#[derive(Clone)]
pub struct SeparationUseCases {
    pub add_rule: Arc<separation::AddRuleUseCase>,
    pub list_rules: Arc<separation::ListRulesUseCase>,
    pub remove_rule: Arc<separation::RemoveRuleUseCase>,
}

/// Just-in-time access: asking for a role or a group for a while, the
/// answers, and the tenant's limit on how long one may ask for.
#[derive(Clone)]
pub struct AccessRequestUseCases {
    pub request: Arc<access_requests::RequestAccessUseCase>,
    pub list: Arc<access_requests::ListUseCase>,
    pub get: Arc<access_requests::GetUseCase>,
    pub approve: Arc<access_requests::ApproveUseCase>,
    pub deny: Arc<access_requests::DenyUseCase>,
    pub cancel: Arc<access_requests::CancelUseCase>,
    pub get_policy: Arc<access_requests::GetPolicyUseCase>,
    pub change_policy: Arc<access_requests::ChangePolicyUseCase>,
}

/// Access reviews: who keeps a role or a place in a group.
#[derive(Clone)]
pub struct AccessReviewUseCases {
    pub start: Arc<access_reviews::StartUseCase>,
    pub list: Arc<access_reviews::ListUseCase>,
    pub get: Arc<access_reviews::GetUseCase>,
    pub items: Arc<access_reviews::ItemsUseCase>,
    pub decide: Arc<access_reviews::DecideUseCase>,
    pub complete: Arc<access_reviews::CompleteUseCase>,
    pub cancel: Arc<access_reviews::CancelUseCase>,
    /// Suggests keep or remove beside a review's holders.
    pub suggest: Arc<access_reviews::SuggestUseCase>,
}

/// Relationships on single objects of a tenant's app.
#[derive(Clone)]
pub struct RelationshipUseCases {
    pub write: Arc<relationships::WriteUseCase>,
    pub list: Arc<relationships::ListUseCase>,
    pub delete: Arc<relationships::DeleteUseCase>,
}

/// Access checks for a tenant's apps, and the records of every decision.
#[derive(Clone)]
pub struct CheckUseCases {
    pub access: Arc<checks::AccessUseCase>,
    pub search_decisions: Arc<checks::SearchDecisionsUseCase>,
}

/// Data clearance from the tenant's own app permissions.
#[derive(Clone)]
pub struct ClearanceUseCases {
    pub get_rules: Arc<clearance::GetRulesUseCase>,
    pub add_rule: Arc<clearance::AddRuleUseCase>,
    pub change_rule: Arc<clearance::ChangeRuleUseCase>,
    pub remove_rule: Arc<clearance::RemoveRuleUseCase>,
}

/// Builds the authorization use cases over `a`.
pub fn build(a: &Adapters) -> AuthorizationState {
    AuthorizationState {
        roles: role_use_cases(a),
        groups: group_use_cases(a),
        policies: policy_use_cases(a),
        resource_types: resource_type_use_cases(a),
        holdings: holding_use_cases(a),
        separation: separation_use_cases(a),
        access_requests: access_request_use_cases(a),
        access_reviews: access_review_use_cases(a),
        relationships: relationship_use_cases(a),
        checks: check_use_cases(a),
        clearance: clearance_use_cases(a),
    }
}

/// The use cases for a tenant's roles and who holds them.
fn role_use_cases(a: &Adapters) -> RoleUseCases {
    RoleUseCases {
        create: Arc::new(roles::CreateUseCase::new(roles::CreatePorts {
            role_store: a.role_store.clone(),
            resource_type_store: a.resource_type_store.clone(),
            limit_enforcer: a.limit_enforcer.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
            guard: crate::workflows::change_guard(a),
        })),
        list: Arc::new(roles::ListUseCase::new(roles::ListPorts {
            role_store: a.role_store.clone(),
            role_assignment_store: a.role_assignment_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        get: Arc::new(roles::GetUseCase::new(roles::GetPorts {
            role_store: a.role_store.clone(),
            role_assignment_store: a.role_assignment_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        update: Arc::new(roles::UpdateUseCase::new(roles::UpdatePorts {
            role_store: a.role_store.clone(),
            resource_type_store: a.resource_type_store.clone(),
            access_records: a.access_record_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
            guard: crate::workflows::change_guard(a),
        })),
        delete: Arc::new(delete_role(a)),
        assign: Arc::new(assign_role(a)),
        revoke: Arc::new(revoke_role(a)),
    }
}

/// Deletes a role and its dependent references through the dedicated unit of work.
fn delete_role(a: &Adapters) -> roles::DeleteUseCase {
    roles::DeleteUseCase::new(roles::DeletePorts {
        role_store: a.role_store.clone(),
        assignment_store: a.role_assignment_store.clone(),
        group_store: a.group_store.clone(),
        invitation_store: a.invitation_store.clone(),
        connection_store: a.connection_store.clone(),
        scim_store: a.scim_store.clone(),
        unit_of_work: a.role_deletion_unit_of_work.clone(),
        access_records: a.access_record_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Assigns roles with principal checks, access records and separation rules.
fn assign_role(a: &Adapters) -> roles::AssignUseCase {
    roles::AssignUseCase::new(roles::AssignPorts {
        role_store: a.role_store.clone(),
        assignment_store: a.role_assignment_store.clone(),
        user_checker: a.user_existence_checker.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        audit_label_resolver: a.audit_label_resolver.clone(),
        access_records: a.access_record_store.clone(),
        separation_rules: a.separation_rule_store.clone(),
        guard: crate::workflows::change_guard(a),
    })
}

/// Revokes role assignments with access-record updates and audit labels.
fn revoke_role(a: &Adapters) -> roles::RevokeUseCase {
    roles::RevokeUseCase::new(roles::RevokePorts {
        assignment_store: a.role_assignment_store.clone(),
        role_store: a.role_store.clone(),
        access_records: a.access_record_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        audit_label_resolver: a.audit_label_resolver.clone(),
    })
}

/// The use cases for a tenant's groups, their place in the tree, their
/// members and their roles.
fn group_use_cases(a: &Adapters) -> GroupUseCases {
    GroupUseCases {
        create: Arc::new(groups::CreateUseCase::new(groups::CreatePorts {
            group_store: a.group_store.clone(),
            access_records: a.access_record_store.clone(),
            limit_enforcer: a.limit_enforcer.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        list: Arc::new(groups::ListUseCase::new(groups::ListPorts {
            group_store: a.group_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        get: Arc::new(groups::GetUseCase::new(groups::GetPorts {
            group_store: a.group_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        rename: Arc::new(groups::RenameUseCase::new(groups::RenamePorts {
            group_store: a.group_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        move_group: Arc::new(move_group(a)),
        delete: Arc::new(delete_group(a)),
        add_member: Arc::new(add_group_member(a)),
        list_members: Arc::new(list_group_members(a)),
        remove_member: Arc::new(remove_group_member(a)),
        assign_role: Arc::new(assign_group_role(a)),
        unassign_role: Arc::new(unassign_group_role(a)),
    }
}

/// Moves groups while checking effective access and separation rules.
fn move_group(a: &Adapters) -> groups::MoveUseCase {
    groups::MoveUseCase::new(groups::MovePorts {
        group_store: a.group_store.clone(),
        access_records: a.access_record_store.clone(),
        separation_rules: a.separation_rule_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Deletes groups with access records and provider connection references.
fn delete_group(a: &Adapters) -> groups::DeleteUseCase {
    groups::DeleteUseCase::new(groups::DeletePorts {
        group_store: a.group_store.clone(),
        access_records: a.access_record_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        connection_store: a.connection_store.clone(),
    })
}

/// Adds checked principals to groups with access records, labels and separation rules.
fn add_group_member(a: &Adapters) -> groups::AddMemberUseCase {
    groups::AddMemberUseCase::new(groups::AddMemberPorts {
        group_store: a.group_store.clone(),
        membership_store: a.group_membership_store.clone(),
        access_records: a.access_record_store.clone(),
        principal_checker: a.principal_existence_checker.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        audit_label_resolver: a.audit_label_resolver.clone(),
        control_plane_label_resolver: a.control_plane_label_resolver.clone(),
        separation_rules: a.separation_rule_store.clone(),
        guard: crate::workflows::change_guard(a),
    })
}

/// Lists group members with audit and control-plane labels under tenant authority.
fn list_group_members(a: &Adapters) -> groups::ListMembersUseCase {
    groups::ListMembersUseCase::new(groups::ListMembersPorts {
        group_store: a.group_store.clone(),
        membership_store: a.group_membership_store.clone(),
        audit_label_resolver: a.audit_label_resolver.clone(),
        control_plane_label_resolver: a.control_plane_label_resolver.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Removes group members with access-record updates and the relevant actor labels.
fn remove_group_member(a: &Adapters) -> groups::RemoveMemberUseCase {
    groups::RemoveMemberUseCase::new(groups::RemoveMemberPorts {
        group_store: a.group_store.clone(),
        membership_store: a.group_membership_store.clone(),
        access_records: a.access_record_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        audit_label_resolver: a.audit_label_resolver.clone(),
        control_plane_label_resolver: a.control_plane_label_resolver.clone(),
    })
}

/// Assigns group roles while checking effective access and separation rules.
fn assign_group_role(a: &Adapters) -> groups::AssignRoleUseCase {
    groups::AssignRoleUseCase::new(groups::AssignRolePorts {
        group_store: a.group_store.clone(),
        role_store: a.role_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        access_records: a.access_record_store.clone(),
        separation_rules: a.separation_rule_store.clone(),
        guard: crate::workflows::change_guard(a),
    })
}

/// Removes group roles with access-record updates under tenant authority.
fn unassign_group_role(a: &Adapters) -> groups::UnassignRoleUseCase {
    groups::UnassignRoleUseCase::new(groups::UnassignRolePorts {
        group_store: a.group_store.clone(),
        role_store: a.role_store.clone(),
        access_records: a.access_record_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// The use cases that read a tenant's access policy, try a version out,
/// and work on its versions and the rules of its draft.
fn policy_use_cases(a: &Adapters) -> PolicyUseCases {
    PolicyUseCases {
        get: Arc::new(policies::GetUseCase::new(policies::GetPorts {
            policy_store: a.policy_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        simulate: Arc::new(policies::SimulateUseCase::new(policies::SimulatePorts {
            policy_store: a.policy_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        versions: policy_version_use_cases(a),
        rules: policy_rule_use_cases(a),
    }
}

/// The use cases that read a policy's versions, open a draft and move it
/// through its lifecycle.
fn policy_version_use_cases(a: &Adapters) -> PolicyVersionUseCases {
    PolicyVersionUseCases {
        get: Arc::new(policies::GetVersionUseCase::new(
            policies::GetVersionPorts {
                policy_store: a.policy_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        list: Arc::new(policies::ListVersionsUseCase::new(
            policies::ListVersionsPorts {
                policy_store: a.policy_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        start_draft: Arc::new(policies::StartDraftUseCase::new(
            policies::StartDraftPorts {
                policy_store: a.policy_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        change_status: Arc::new(policies::ChangeStatusUseCase::new(
            policies::ChangeStatusPorts {
                policy_store: a.policy_store.clone(),
                access_records: a.access_record_store.clone(),
                users: a.user_store.clone(),
                organizations: a.organization_store.clone(),
                member_roster: a.tenant_member_roster.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
    }
}

/// The use cases that edit the rules of a tenant's draft policy.
fn policy_rule_use_cases(a: &Adapters) -> PolicyRuleUseCases {
    PolicyRuleUseCases {
        add: Arc::new(policies::AddRuleUseCase::new(policies::AddRulePorts {
            policy_store: a.policy_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        change: Arc::new(policies::ChangeRuleUseCase::new(
            policies::ChangeRulePorts {
                policy_store: a.policy_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        remove: Arc::new(policies::RemoveRuleUseCase::new(
            policies::RemoveRulePorts {
                policy_store: a.policy_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        reorder: Arc::new(policies::ReorderRulesUseCase::new(
            policies::ReorderRulesPorts {
                policy_store: a.policy_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        switch: Arc::new(switch_rule(a)),
        change_default_action: Arc::new(change_default_action(a)),
    }
}

/// Switches draft policy rules under tenant authority.
fn switch_rule(a: &Adapters) -> policies::SwitchRuleUseCase {
    policies::SwitchRuleUseCase::new(policies::SwitchRulePorts {
        policy_store: a.policy_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Changes the policy fallback under tenant authority.
fn change_default_action(a: &Adapters) -> policies::ChangeDefaultActionUseCase {
    policies::ChangeDefaultActionUseCase::new(policies::ChangeDefaultActionPorts {
        policy_store: a.policy_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// The use cases that declare, list, change and remove a tenant's resource
/// types.
fn resource_type_use_cases(a: &Adapters) -> ResourceTypeUseCases {
    ResourceTypeUseCases {
        declare: Arc::new(resource_types::DeclareUseCase::new(
            resource_types::DeclarePorts {
                resource_type_store: a.resource_type_store.clone(),
                limit_enforcer: a.limit_enforcer.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        list: Arc::new(resource_types::ListUseCase::new(
            resource_types::ListPorts {
                resource_type_store: a.resource_type_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        update: Arc::new(resource_types::UpdateUseCase::new(
            resource_types::UpdatePorts {
                resource_type_store: a.resource_type_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        delete: Arc::new(resource_types::DeleteUseCase::new(
            resource_types::DeletePorts {
                resource_type_store: a.resource_type_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
    }
}

/// The use cases that read who holds a role and what a principal holds.
fn holding_use_cases(a: &Adapters) -> HoldingUseCases {
    HoldingUseCases {
        role_holders: Arc::new(holdings::ListRoleHoldersUseCase::new(
            holdings::ListRoleHoldersPorts {
                role_store: a.role_store.clone(),
                role_holder_queries: a.role_holder_queries.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        principal_access: Arc::new(holdings::GetPrincipalAccessUseCase::new(
            holdings::GetPrincipalAccessPorts {
                access_records: a.access_record_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
    }
}

/// The use cases that declare, list and lift separation-of-duties rules.
fn separation_use_cases(a: &Adapters) -> SeparationUseCases {
    SeparationUseCases {
        add_rule: Arc::new(separation::AddRuleUseCase::new(separation::AddRulePorts {
            separation_rules: a.separation_rule_store.clone(),
            role_store: a.role_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        list_rules: Arc::new(separation::ListRulesUseCase::new(
            separation::ListRulesPorts {
                separation_rules: a.separation_rule_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        remove_rule: Arc::new(separation::RemoveRuleUseCase::new(
            separation::RemoveRulePorts {
                separation_rules: a.separation_rule_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
    }
}

/// The use cases that ask for access, answer and withdraw the asking, and
/// read and set the tenant's limit on it.
fn access_request_use_cases(a: &Adapters) -> AccessRequestUseCases {
    AccessRequestUseCases {
        request: Arc::new(request_access(a)),
        list: Arc::new(access_requests::ListUseCase::new(
            access_requests::ListPorts {
                request_store: a.access_request_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        get: Arc::new(access_requests::GetUseCase::new(
            access_requests::GetPorts {
                request_store: a.access_request_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        approve: Arc::new(approve_access(a)),
        deny: Arc::new(deny_access(a)),
        cancel: Arc::new(access_requests::CancelUseCase::new(
            access_requests::CancelPorts {
                request_store: a.access_request_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        get_policy: Arc::new(access_requests::GetPolicyUseCase::new(
            access_requests::GetPolicyPorts {
                policy_store: a.access_request_policy_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        change_policy: Arc::new(change_request_policy(a)),
    }
}

/// Requests temporary access against roles, groups and the tenant's request policy.
fn request_access(a: &Adapters) -> access_requests::RequestAccessUseCase {
    access_requests::RequestAccessUseCase::new(access_requests::RequestAccessPorts {
        request_store: a.access_request_store.clone(),
        role_store: a.role_store.clone(),
        group_store: a.group_store.clone(),
        policy_store: a.access_request_policy_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Approves access with membership writes and separation-of-duties checks.
fn approve_access(a: &Adapters) -> access_requests::ApproveUseCase {
    access_requests::ApproveUseCase::new(access_requests::ApprovePorts {
        request_store: a.access_request_store.clone(),
        role_store: a.role_store.clone(),
        group_store: a.group_store.clone(),
        access_records: a.access_record_store.clone(),
        assignment_store: a.role_assignment_store.clone(),
        membership_store: a.group_membership_store.clone(),
        separation_rules: a.separation_rule_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Denies requests with their target roles, groups and effective access records.
fn deny_access(a: &Adapters) -> access_requests::DenyUseCase {
    access_requests::DenyUseCase::new(access_requests::DenyPorts {
        request_store: a.access_request_store.clone(),
        role_store: a.role_store.clone(),
        group_store: a.group_store.clone(),
        access_records: a.access_record_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Changes temporary-access policy through tenant authority checks.
fn change_request_policy(a: &Adapters) -> access_requests::ChangePolicyUseCase {
    access_requests::ChangePolicyUseCase::new(access_requests::ChangePolicyPorts {
        policy_store: a.access_request_policy_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// The use cases that start, read, decide, complete and call off access
/// reviews.
fn access_review_use_cases(a: &Adapters) -> AccessReviewUseCases {
    AccessReviewUseCases {
        start: Arc::new(start_review(a)),
        list: Arc::new(access_reviews::ListUseCase::new(
            access_reviews::ListPorts {
                review_store: a.access_review_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        get: Arc::new(access_reviews::GetUseCase::new(access_reviews::GetPorts {
            review_store: a.access_review_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        items: Arc::new(access_reviews::ItemsUseCase::new(
            access_reviews::ItemsPorts {
                review_store: a.access_review_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        decide: Arc::new(decide_review(a)),
        complete: Arc::new(complete_review(a)),
        cancel: Arc::new(access_reviews::CancelUseCase::new(
            access_reviews::CancelPorts {
                review_store: a.access_review_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        suggest: Arc::new(suggest_review(a)),
    }
}

/// Starts reviews using effective access and the current roles, groups and users.
fn start_review(a: &Adapters) -> access_reviews::StartUseCase {
    access_reviews::StartUseCase::new(access_reviews::StartPorts {
        review_store: a.access_review_store.clone(),
        access_records: a.access_record_store.clone(),
        role_store: a.role_store.clone(),
        group_store: a.group_store.clone(),
        user_store: a.user_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Records review decisions with tenant authority and actor-label resolution.
fn decide_review(a: &Adapters) -> access_reviews::DecideUseCase {
    access_reviews::DecideUseCase::new(access_reviews::DecidePorts {
        review_store: a.access_review_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        audit_label_resolver: a.audit_label_resolver.clone(),
        control_plane_label_resolver: a.control_plane_label_resolver.clone(),
    })
}

/// Completes reviews and applies membership changes through one unit of work.
fn complete_review(a: &Adapters) -> access_reviews::CompleteUseCase {
    access_reviews::CompleteUseCase::new(access_reviews::CompletePorts {
        unit_of_work: a.unit_of_work.clone(),
        review_store: a.access_review_store.clone(),
        access_records: a.access_record_store.clone(),
        assignment_store: a.role_assignment_store.clone(),
        membership_store: a.group_membership_store.clone(),
        role_store: a.role_store.clone(),
        group_store: a.group_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        audit_label_resolver: a.audit_label_resolver.clone(),
        control_plane_label_resolver: a.control_plane_label_resolver.clone(),
    })
}

/// Suggests review outcomes under tenant authority.
fn suggest_review(a: &Adapters) -> access_reviews::SuggestUseCase {
    access_reviews::SuggestUseCase::new(access_reviews::SuggestPorts {
        review_store: a.access_review_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// The use cases that write, list and remove relationships on objects.
fn relationship_use_cases(a: &Adapters) -> RelationshipUseCases {
    RelationshipUseCases {
        write: Arc::new(relationships::WriteUseCase::new(
            relationships::WritePorts {
                relationship_store: a.relationship_store.clone(),
                resource_type_store: a.resource_type_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        list: Arc::new(relationships::ListUseCase::new(relationships::ListPorts {
            relationship_store: a.relationship_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        delete: Arc::new(relationships::DeleteUseCase::new(
            relationships::DeletePorts {
                relationship_store: a.relationship_store.clone(),
                resource_type_store: a.resource_type_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
    }
}

/// The use cases that answer an app's access checks and search the
/// records of every decision.
fn check_use_cases(a: &Adapters) -> CheckUseCases {
    CheckUseCases {
        access: Arc::new(checks::AccessUseCase::new(checks::AccessPorts {
            access_records: a.access_record_store.clone(),
            relationship_store: a.relationship_store.clone(),
            decision_records: a.decision_record_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        search_decisions: Arc::new(checks::SearchDecisionsUseCase::new(
            checks::SearchDecisionsPorts {
                decision_records: a.decision_record_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
    }
}

/// The use cases that read and edit a tenant's clearance rules.
fn clearance_use_cases(a: &Adapters) -> ClearanceUseCases {
    ClearanceUseCases {
        get_rules: Arc::new(clearance::GetRulesUseCase::new(clearance::GetRulesPorts {
            clearance_rules: a.clearance_rule_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        add_rule: Arc::new(clearance::AddRuleUseCase::new(clearance::AddRulePorts {
            clearance_rules: a.clearance_rule_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        change_rule: Arc::new(clearance::ChangeRuleUseCase::new(
            clearance::ChangeRulePorts {
                clearance_rules: a.clearance_rule_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
        remove_rule: Arc::new(clearance::RemoveRuleUseCase::new(
            clearance::RemoveRulePorts {
                clearance_rules: a.clearance_rule_store.clone(),
                tenant_authorities: a.tenant_authorities.clone(),
            },
        )),
    }
}
