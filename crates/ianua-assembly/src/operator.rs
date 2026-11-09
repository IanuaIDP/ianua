//! The operator use cases the API serves: operator accounts, an operator's
//! own keys, their impersonation grants, and the jobs the platform gave up
//! on, which an operator may retry.

use std::sync::Arc;

use ianua_app::services::authentication::password_hashing::PasswordHashing;
use ianua_app::use_cases::identity::email::EmailChangePolicy;
use ianua_app::use_cases::operator::{accounts, impersonation, keys};
use ianua_app::use_cases::scheduling;

use crate::authentication::{password_hashing, sign_in_counts};
use crate::deps::{Adapters, Settings};

/// The operator use cases.
#[derive(Clone)]
pub struct OperatorState {
    /// Hashes a new operator's password before the use case stores it,
    /// under the node's cap on hashes running at once.
    pub password_hashing: PasswordHashing,
    pub create: Arc<accounts::CreateOperatorUseCase>,
    pub list: Arc<accounts::ListOperatorsUseCase>,
    pub get: Arc<accounts::GetOperatorUseCase>,
    pub enable: Arc<accounts::EnableOperatorUseCase>,
    pub disable: Arc<accounts::DisableOperatorUseCase>,
    pub change_email: Arc<accounts::ChangeOperatorEmailUseCase>,
    pub sign_in: Arc<keys::OperatorSignInUseCase>,
    pub create_key: Arc<keys::CreateOperatorUseCase>,
    pub revoke_key: Arc<keys::RevokeOperatorUseCase>,
    pub revoke_all_keys: Arc<keys::RevokeAllOperatorUseCase>,
    pub grant_impersonation: Arc<impersonation::GrantUseCase>,
    pub revoke_impersonation: Arc<impersonation::RevokeUseCase>,
    pub act_through_grant: Arc<impersonation::ActThroughGrantUseCase>,
    pub list_dead_jobs: Arc<scheduling::ListDeadUseCase>,
    pub retry_dead_job: Arc<scheduling::RetryDeadUseCase>,
}

/// Builds the operator use cases over `a`, tuned by `s`.
pub fn build(a: &Adapters, s: &Settings) -> OperatorState {
    OperatorState {
        password_hashing: password_hashing(a),
        create: Arc::new(create(a)),
        list: Arc::new(list(a)),
        get: Arc::new(get(a)),
        enable: Arc::new(enable(a)),
        disable: Arc::new(disable(a)),
        change_email: Arc::new(change_email(a, s)),
        sign_in: Arc::new(sign_in(a, s)),
        create_key: Arc::new(create_key(a)),
        revoke_key: Arc::new(keys::RevokeOperatorUseCase::new(key_revocation(a))),
        revoke_all_keys: Arc::new(keys::RevokeAllOperatorUseCase::new(key_revocation(a))),
        grant_impersonation: Arc::new(grant_impersonation(a)),
        revoke_impersonation: Arc::new(revoke_impersonation(a)),
        act_through_grant: Arc::new(act_through_grant(a)),
        list_dead_jobs: Arc::new(list_dead_jobs(a)),
        retry_dead_job: Arc::new(retry_dead_job(a)),
    }
}

/// Lets an operator act on a tenant through a grant given to them.
fn act_through_grant(a: &Adapters) -> impersonation::ActThroughGrantUseCase {
    impersonation::ActThroughGrantUseCase::new(impersonation::ActThroughGrantPorts {
        grant_store: a.impersonation_grant_store.clone(),
        operator_authorities: a.operator_authorities.clone(),
    })
}

/// Lists the jobs the platform gave up on.
fn list_dead_jobs(a: &Adapters) -> scheduling::ListDeadUseCase {
    scheduling::ListDeadUseCase::new(scheduling::ListDeadPorts {
        queue: a.job_queue.clone(),
        operator_authorities: a.operator_authorities.clone(),
    })
}

/// Hands a job the platform gave up on back to the queue.
fn retry_dead_job(a: &Adapters) -> scheduling::RetryDeadUseCase {
    scheduling::RetryDeadUseCase::new(scheduling::RetryDeadPorts {
        queue: a.job_queue.clone(),
        operator_authorities: a.operator_authorities.clone(),
    })
}

/// Creates operator accounts under the requesting operator's authority.
fn create(a: &Adapters) -> accounts::CreateOperatorUseCase {
    accounts::CreateOperatorUseCase::new(accounts::CreateOperatorPorts {
        operator_store: a.operator_store.clone(),
        operator_authorities: a.operator_authorities.clone(),
    })
}

/// Lists operator accounts visible to the requesting operator.
fn list(a: &Adapters) -> accounts::ListOperatorsUseCase {
    accounts::ListOperatorsUseCase::new(accounts::ListOperatorsPorts {
        operator_store: a.operator_store.clone(),
        operator_authorities: a.operator_authorities.clone(),
    })
}

/// Reads an operator account after resolving platform authority.
fn get(a: &Adapters) -> accounts::GetOperatorUseCase {
    accounts::GetOperatorUseCase::new(accounts::GetOperatorPorts {
        operator_store: a.operator_store.clone(),
        operator_authorities: a.operator_authorities.clone(),
    })
}

/// Re-enables an operator through the account's authority checks.
fn enable(a: &Adapters) -> accounts::EnableOperatorUseCase {
    accounts::EnableOperatorUseCase::new(accounts::EnableOperatorPorts {
        operator_store: a.operator_store.clone(),
        operator_authorities: a.operator_authorities.clone(),
    })
}

/// Disables an operator together with its impersonation grants.
fn disable(a: &Adapters) -> accounts::DisableOperatorUseCase {
    accounts::DisableOperatorUseCase::new(accounts::DisableOperatorPorts {
        operator_store: a.operator_store.clone(),
        grant_store: a.impersonation_grant_store.clone(),
        operator_authorities: a.operator_authorities.clone(),
    })
}

/// Requests a mailbox change with expiring, rate-limited confirmation links.
fn change_email(a: &Adapters, s: &Settings) -> accounts::ChangeOperatorEmailUseCase {
    accounts::ChangeOperatorEmailUseCase::new(accounts::ChangeOperatorEmailPorts {
        operator_store: a.operator_store.clone(),
        change_store: a.org_email_change_store.clone(),
        operator_authorities: a.operator_authorities.clone(),
        mailer: a.mailer.clone(),
        token_generator: a.refresh_token_generator.clone(),
        policy: EmailChangePolicy {
            lifetime: s.tunables.email_change_lifetime,
            base_url: s.app_base_url.clone(),
            resend_cooldown: s.tunables.resend_cooldown,
        },
    })
}

/// Signs operators in with bounded password hashing and expiring API keys.
fn sign_in(a: &Adapters, s: &Settings) -> keys::OperatorSignInUseCase {
    keys::OperatorSignInUseCase::new(
        keys::OperatorSignInPorts {
            operator_store: a.operator_store.clone(),
            key_store: a.operator_key_store.clone(),
            key_generator: a.api_key_generator.clone(),
            attempts: sign_in_counts(a),
            hashing: password_hashing(a),
            operator_authorities: a.operator_authorities.clone(),
        },
        keys::OperatorSignInSettings {
            key_lifetime: s.tunables.operator_key_lifetime,
        },
    )
}

/// Issues an operator key after resolving its account and authority.
fn create_key(a: &Adapters) -> keys::CreateOperatorUseCase {
    keys::CreateOperatorUseCase::new(keys::CreateOperatorPorts {
        operator_store: a.operator_store.clone(),
        key_store: a.operator_key_store.clone(),
        key_generator: a.api_key_generator.clone(),
        operator_authorities: a.operator_authorities.clone(),
    })
}

/// Grants impersonation after checking the target tenant and user.
fn grant_impersonation(a: &Adapters) -> impersonation::GrantUseCase {
    impersonation::GrantUseCase::new(impersonation::GrantPorts {
        grant_store: a.impersonation_grant_store.clone(),
        tenant_store: a.tenant_store.clone(),
        user_checker: a.cross_tenant_user_checker.clone(),
        audit_label_resolver: a.audit_label_resolver.clone(),
        operator_authorities: a.operator_authorities.clone(),
    })
}

/// Revokes impersonation with the tenant and audit labels available.
fn revoke_impersonation(a: &Adapters) -> impersonation::RevokeUseCase {
    impersonation::RevokeUseCase::new(impersonation::RevokePorts {
        grant_store: a.impersonation_grant_store.clone(),
        tenant_store: a.tenant_store.clone(),
        audit_label_resolver: a.audit_label_resolver.clone(),
        operator_authorities: a.operator_authorities.clone(),
    })
}

/// What revokes an operator's keys and stops them working at once.
fn key_revocation(a: &Adapters) -> keys::RevokeOperatorPorts {
    keys::RevokeOperatorPorts {
        key_store: a.operator_key_store.clone(),
        control_plane_label_resolver: a.control_plane_label_resolver.clone(),
        operator_authorities: a.operator_authorities.clone(),
    }
}
