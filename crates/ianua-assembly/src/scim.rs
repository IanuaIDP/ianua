//! The SCIM provisioning use cases the API serves: a tenant's directory
//! keeping the tenant's users and groups in step with its own.

use std::sync::Arc;

use ianua_app::services::authorization::grant_revocation::GrantRevocation;
use ianua_app::services::identity::link_scopes::TenantLinkScopes;
use ianua_app::use_cases::identity::email::{
    VerificationLinkStores, VerificationLinks, VerificationPolicy,
};
use ianua_app::use_cases::identity::users::StandingRemoval;
use ianua_app::use_cases::scim::{groups, users};
use ianua_domain::shared::config::DomainLimits;

use crate::deps::{Adapters, Settings};

/// The SCIM use cases, and the limits a directory's names and group writes
/// are held to.
#[derive(Clone)]
pub struct ScimState {
    pub domain_limits: DomainLimits,
    pub member_cap: groups::MemberCap,
    pub list_users: Arc<users::ListScimUseCase>,
    pub get_user: Arc<users::GetScimUseCase>,
    pub create_user: Arc<users::CreateScimUseCase>,
    pub update_user: Arc<users::UpdateScimUseCase>,
    pub replace_user: Arc<users::ReplaceScimUseCase>,
    pub remove_user: Arc<users::RemoveScimUseCase>,
    pub list_groups: Arc<groups::ListScimUseCase>,
    pub get_group: Arc<groups::GetScimUseCase>,
    pub create_group: Arc<groups::CreateScimUseCase>,
    pub update_group: Arc<groups::UpdateScimUseCase>,
    pub replace_group: Arc<groups::ReplaceScimUseCase>,
    pub remove_group: Arc<groups::RemoveScimUseCase>,
}

/// The user use cases of [`ScimState`].
struct UserCases {
    list: Arc<users::ListScimUseCase>,
    get: Arc<users::GetScimUseCase>,
    create: Arc<users::CreateScimUseCase>,
    update: Arc<users::UpdateScimUseCase>,
    replace: Arc<users::ReplaceScimUseCase>,
    remove: Arc<users::RemoveScimUseCase>,
}

/// The group use cases of [`ScimState`].
struct GroupCases {
    list: Arc<groups::ListScimUseCase>,
    get: Arc<groups::GetScimUseCase>,
    create: Arc<groups::CreateScimUseCase>,
    update: Arc<groups::UpdateScimUseCase>,
    replace: Arc<groups::ReplaceScimUseCase>,
    remove: Arc<groups::RemoveScimUseCase>,
}

/// Builds the SCIM use cases over `a`, mailing confirmation links as `s`
/// says.
pub fn build(a: &Adapters, s: &Settings) -> ScimState {
    let users = user_cases(a, s);
    let member_cap = s.tunables.scim_group_member_cap;
    let groups = group_cases(a, member_cap);
    ScimState {
        domain_limits: s.domain_limits.clone(),
        member_cap,
        list_users: users.list,
        get_user: users.get,
        create_user: users.create,
        update_user: users.update,
        replace_user: users.replace,
        remove_user: users.remove,
        list_groups: groups.list,
        get_group: groups.get,
        create_group: groups.create,
        update_group: groups.update,
        replace_group: groups.replace,
        remove_group: groups.remove,
    }
}

/// The user use cases over `a`, mailing confirmation links as `s` says.
fn user_cases(a: &Adapters, s: &Settings) -> UserCases {
    let links = verification_links(a, s);
    let update = Arc::new(users::UpdateScimUseCase::new(users::UpdateScimPorts {
        scim_authorities: a.scim_authorities.clone(),
        scim_store: a.scim_store.clone(),
        verification_links: links.clone(),
        reset_requests: a.reset_request_store.clone(),
        link_scopes: link_scopes(a),
        user_store: a.user_store.clone(),
        access_records: a.access_record_store.clone(),
        removal: removal(a),
    }));
    UserCases {
        list: Arc::new(users::ListScimUseCase::new(users::ListScimPorts {
            scim_authorities: a.scim_authorities.clone(),
            user_queries: a.scim_user_queries.clone(),
        })),
        get: Arc::new(users::GetScimUseCase::new(users::GetScimPorts {
            scim_authorities: a.scim_authorities.clone(),
            user_store: a.user_store.clone(),
        })),
        create: Arc::new(create_user(a, links)),
        replace: Arc::new(users::ReplaceScimUseCase::new(users::ReplaceScimPorts {
            update: update.clone(),
        })),
        update,
        remove: Arc::new(remove_user(a)),
    }
}

/// Opening an account for a person the directory sends.
fn create_user(a: &Adapters, links: Arc<VerificationLinks>) -> users::CreateScimUseCase {
    users::CreateScimUseCase::new(users::CreateScimPorts {
        scim_authorities: a.scim_authorities.clone(),
        scim_store: a.scim_store.clone(),
        verification_links: links,
        link_scopes: link_scopes(a),
        user_store: a.user_store.clone(),
        access_records: a.access_record_store.clone(),
        separation_rules: a.separation_rule_store.clone(),
        role_store: a.role_store.clone(),
        assignment_store: a.role_assignment_store.clone(),
        plan_limits: a.plan_limits_source.clone(),
        limit_enforcer: a.limit_enforcer.clone(),
    })
}

/// Removing a person the directory no longer keeps.
fn remove_user(a: &Adapters) -> users::RemoveScimUseCase {
    users::RemoveScimUseCase::new(users::RemoveScimPorts {
        scim_authorities: a.scim_authorities.clone(),
        scim_store: a.scim_store.clone(),
        user_store: a.user_store.clone(),
        access_records: a.access_record_store.clone(),
        removal: removal(a),
    })
}

/// The group use cases over `a`, each write naming at most `cap` members.
fn group_cases(a: &Adapters, cap: groups::MemberCap) -> GroupCases {
    let update = Arc::new(update_group(a, cap));
    GroupCases {
        list: Arc::new(groups::ListScimUseCase::new(groups::ListScimPorts {
            scim_authorities: a.scim_authorities.clone(),
            group_queries: a.scim_group_queries.clone(),
            memberships: a.group_membership_store.clone(),
        })),
        get: Arc::new(groups::GetScimUseCase::new(groups::GetScimPorts {
            scim_authorities: a.scim_authorities.clone(),
            group_store: a.group_store.clone(),
            membership_store: a.group_membership_store.clone(),
        })),
        create: Arc::new(create_group(a, cap)),
        replace: Arc::new(groups::ReplaceScimUseCase::new(groups::ReplaceScimPorts {
            update: update.clone(),
        })),
        update,
        remove: Arc::new(groups::RemoveScimUseCase::new(groups::RemoveScimPorts {
            scim_authorities: a.scim_authorities.clone(),
            scim_store: a.scim_store.clone(),
            group_store: a.group_store.clone(),
            membership_store: a.group_membership_store.clone(),
            access_records: a.access_record_store.clone(),
        })),
    }
}

/// Renaming a directory's group and changing who is in it, at most `cap`
/// members a write.
fn update_group(a: &Adapters, cap: groups::MemberCap) -> groups::UpdateScimUseCase {
    let ports = groups::UpdateScimPorts {
        scim_authorities: a.scim_authorities.clone(),
        scim_store: a.scim_store.clone(),
        group_store: a.group_store.clone(),
        membership_store: a.group_membership_store.clone(),
        user_store: a.user_store.clone(),
        access_records: a.access_record_store.clone(),
        separation_rules: a.separation_rule_store.clone(),
    };
    groups::UpdateScimUseCase::new(ports, cap)
}

/// Making a group the directory keeps, with at most `cap` members.
fn create_group(a: &Adapters, cap: groups::MemberCap) -> groups::CreateScimUseCase {
    let ports = groups::CreateScimPorts {
        scim_authorities: a.scim_authorities.clone(),
        scim_store: a.scim_store.clone(),
        group_store: a.group_store.clone(),
        membership_store: a.group_membership_store.clone(),
        user_store: a.user_store.clone(),
        plan_limits: a.plan_limits_source.clone(),
        limit_enforcer: a.limit_enforcer.clone(),
    };
    groups::CreateScimUseCase::new(ports, cap)
}

/// The links that confirm an address SCIM sent, mailed under the
/// deployment's base URL.
fn verification_links(a: &Adapters, s: &Settings) -> Arc<VerificationLinks> {
    Arc::new(VerificationLinks::new(
        a.refresh_token_generator.clone(),
        VerificationPolicy {
            lifetime: s.tunables.verification_lifetime,
            base_url: s.app_base_url.clone(),
            resend_cooldown: s.tunables.resend_cooldown,
        },
        VerificationLinkStores {
            tokens: a.verification_token_store.clone(),
            mailer: a.mailer.clone(),
            mail: a.mail_setup.clone(),
        },
    ))
}

/// Where the links mailed to a tenant's users point, from its stored slugs.
pub(crate) fn link_scopes(a: &Adapters) -> TenantLinkScopes {
    TenantLinkScopes {
        tenants: a.tenant_store.clone(),
        organizations: a.organization_store.clone(),
    }
}

/// What ends everything a user SCIM shuts out or removes does.
fn removal(a: &Adapters) -> StandingRemoval {
    StandingRemoval {
        session_store: a.session_store.clone(),
        grant_revocation: GrantRevocation::new(a.delegation_store.clone()),
        exports: a.data_export_store.clone(),
        export_files: a.data_export_files.clone(),
    }
}
