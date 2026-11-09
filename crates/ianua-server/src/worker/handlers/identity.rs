//! The handlers of user imports: each import worked through chunk by chunk,
//! every chunk counted against the tenant's plan as it runs.

use std::sync::Arc;

use ianua_app::email::ResendCooldown;
use ianua_app::services::limits::enforcer::PlanLimitEnforcer;
use ianua_app::services::limits::plan::StoredPlanLimits;
use ianua_app::use_cases::identity::email::{
    VerificationLinkStores, VerificationLinks, VerificationPolicy,
};
use ianua_app::use_cases::identity::imports::{ImportHandler, RunPorts, RunUseCase};
use ianua_app::use_cases::scheduling::JobHandler;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::types::Lifetime;
use ianua_infra::postgres::authentication::PgCredentialStore;
use ianua_infra::postgres::authorization::{PgRoleAssignmentStore, PgRoleStore};
use ianua_infra::postgres::identity::{PgUserImportStore, PgUserStore, PgVerificationTokenStore};
use ianua_infra::postgres::limits::{PgOrgResourceCounter, PgResourceCounter};

use crate::error::{PlatformError, ServerError};
use crate::worker::parts::Parts;

/// The handlers of user imports.
///
/// # Errors
///
/// [`ServerError`] when one cannot be built.
pub(super) fn handlers(parts: &Parts<'_>) -> Result<Vec<Arc<dyn JobHandler>>, ServerError> {
    Ok(vec![imports(parts)?])
}

/// The handler working an import through.
fn imports(parts: &Parts<'_>) -> Result<Arc<dyn JobHandler>, ServerError> {
    let platform = parts.platform;
    let databases = &platform.databases;
    let run = RunUseCase::new(RunPorts {
        import_store: Arc::new(PgUserImportStore::new(
            Arc::clone(databases),
            DomainLimits::default(),
        )),
        user_store: Arc::new(PgUserStore::new(
            Arc::clone(databases),
            DomainLimits::default(),
        )),
        credential_store: Arc::new(PgCredentialStore::new(Arc::clone(databases))),
        role_store: Arc::new(PgRoleStore::new(Arc::clone(databases))),
        assignment_store: Arc::new(PgRoleAssignmentStore::new(Arc::clone(databases))),
        plan_limits: Arc::new(StoredPlanLimits::new(
            Arc::clone(&parts.tenants),
            Arc::clone(&parts.organizations),
        )),
        limit_enforcer: Arc::new(PlanLimitEnforcer::new(
            Arc::new(PgResourceCounter::new(Arc::clone(databases))),
            Arc::new(PgOrgResourceCounter::new(Arc::clone(databases))),
        )),
        verification_links: Arc::new(verification_links(parts)?),
        unit_of_work: Arc::clone(&platform.unit_of_work),
    });
    let handler = ImportHandler::new(run).map_err(PlatformError::of("the import handler"))?;
    Ok(Arc::new(handler))
}

/// The links confirming each imported address, lasting as long as
/// `EMAIL_VERIFICATION_TTL_SECONDS` says.
fn verification_links(parts: &Parts<'_>) -> Result<VerificationLinks, ServerError> {
    let platform = parts.platform;
    let config = parts.config;
    let lifetime = time::Duration::try_from(config.mail.links.verification)
        .map_err(PlatformError::of("the verification links' lifetime"))?;
    let resend = time::Duration::try_from(config.mail.resend_cooldown)
        .map_err(PlatformError::of("the verification links' cooldown"))?;
    let policy = VerificationPolicy {
        lifetime: Lifetime::new(lifetime).map_err(PlatformError::of("the verification links"))?,
        base_url: config.deployment.app_base_url.clone(),
        resend_cooldown: ResendCooldown::new(resend),
    };
    Ok(VerificationLinks::new(
        platform.digests.refresh_tokens.clone(),
        policy,
        VerificationLinkStores {
            tokens: Arc::new(PgVerificationTokenStore::new(Arc::clone(
                &platform.databases,
            ))),
            mailer: Arc::clone(&parts.mail.mailer),
            mail: Arc::new(platform.mail.platform.mail_setup()),
        },
    ))
}
