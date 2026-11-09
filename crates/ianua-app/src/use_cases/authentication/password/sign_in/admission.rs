//! The tenant's say on a password sign-in, and the rules the attempt runs
//! under: its lockout and its sessions.

use ianua_domain::domains::authentication::admission::SignInAdmitted;
use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::authentication::operations::password_login::PasswordLogin;
use ianua_domain::domains::authentication::risk_engine::rate_limit::RateLimitPolicy;
use ianua_domain::domains::authentication::sessions::timeout::SessionTimeoutPolicy;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::types::Fact;

use crate::error::AppError;
use crate::ports::tenant::TenantStore;
use crate::services::authentication::sign_in_gate;
use crate::tenancy::ScopedTenant;
use crate::use_cases::authentication::password::sign_in::login::LoginRequest;

/// The rules the tenant sets for an attempt.
pub(in crate::use_cases::authentication::password) struct TenantRules {
    /// When repeated failures lock the address.
    pub(in crate::use_cases::authentication::password) rate: RateLimitPolicy,
    /// How long the session may last and sit idle.
    pub(in crate::use_cases::authentication::password) timeout: SessionTimeoutPolicy,
}

/// An attempt the tenant admitted, with the rules it runs under.
pub(in crate::use_cases::authentication::password) struct Admitted {
    /// The tenant as it stands.
    pub(in crate::use_cases::authentication::password) record: Tenant,
    /// The domain's attempt.
    pub(in crate::use_cases::authentication::password) login: PasswordLogin,
    /// Its lockout and session rules.
    pub(in crate::use_cases::authentication::password) rules: TenantRules,
}

/// `request` as `tenant` admits it, with the rules it runs under.
///
/// # Errors
///
/// - `AppError::TenantUnavailable` when the tenant is suspended, archived
///   or deleted.
/// - `AppError::Forbidden` when the tenant does not take password sign-in,
///   or not from where the request came from.
/// - `AppError::NotFound` when the tenant does not exist.
/// - `AppError::Internal` when the tenant cannot be read, or its limits
///   make no policy.
/// - `AppError::Domain` when the attempt cannot be made for the address.
pub(in crate::use_cases::authentication::password) async fn admitted(
    tenants: &dyn TenantStore,
    tenant: &ScopedTenant,
    request: &LoginRequest,
) -> Result<Admitted, AppError> {
    let client_ip = request.origin.ip_address.as_ref();
    let (record, admitted) =
        sign_in_gate::admit(tenants, tenant, AuthMethod::Password, client_ip).await?;
    let rules = tenant_rules(&record)?;
    let login = password_login(&record, request, admitted)?;
    Ok(Admitted {
        record,
        login,
        rules,
    })
}

/// The lockout and session rules the tenant's limits make.
///
/// # Errors
///
/// Returns `AppError::Internal` when the tenant's limits make no policy.
pub(in crate::use_cases::authentication::password) fn tenant_rules(
    record: &Tenant,
) -> Result<TenantRules, AppError> {
    let limits = record.auth_config().limits();
    Ok(TenantRules {
        rate: limits.lockout().map_err(AppError::internal)?,
        timeout: limits.session_timeout().map_err(AppError::internal)?,
    })
}

/// The domain's attempt, for the account `request` names in `record`.
fn password_login(
    record: &Tenant,
    request: &LoginRequest,
    admitted: SignInAdmitted,
) -> Result<PasswordLogin, AppError> {
    let user_agent = Fact::from_option(request.origin.user_agent.clone());
    PasswordLogin::new(*record.id(), request.email.clone(), admitted, user_agent)
        .map_err(AppError::from_domain)
}
