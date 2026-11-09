//! Get task template: one kind of task someone has written down.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::task_template::TaskTemplate;
use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::TaskTemplateId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::agents::TaskTemplateStore;
use crate::use_case::Query;
use crate::use_cases::agents::lookup::existing_task_template;

/// The ports [`GetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// Keeps templates.
    pub template_store: Arc<dyn TaskTemplateStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads one task template of the caller's tenant.
pub struct GetUseCase {
    ports: GetPorts,
}

impl GetUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetUseCase {
    type Caller = CallerContext;
    type Input = TaskTemplateId;
    type Output = Result<TaskTemplate<ResolvedTenant>, AppError>;

    /// The template `template_id`, for a caller who may view agents.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view agents.
    /// - `AppError::NotFound` when the tenant has no such template.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        template_id: TaskTemplateId,
    ) -> Result<TaskTemplate<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Agents(AgentAction::View))
            .map_err(AppError::from_domain)?;
        existing_task_template(
            self.ports.template_store.as_ref(),
            &ctx.tenant(),
            &template_id,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{someone_else, template_proposed_by, templates_holding};
    use crate::test_support::{block_on, test_ctx};

    fn get(ports: GetPorts, id: TaskTemplateId) -> Result<TaskTemplate<ResolvedTenant>, AppError> {
        block_on(GetUseCase::new(ports).execute(&test_ctx(), id))
    }

    /// The tenant keeping Bob's monthly reports template, and its id.
    fn with_one_template() -> (GetPorts, TaskTemplateId) {
        let template = template_proposed_by(someone_else());
        let id = *template.id();
        let ports = GetPorts {
            template_store: Arc::new(templates_holding([template])),
            ..GetPorts::fakes()
        };
        (ports, id)
    }

    /// Ann reads the monthly reports template.
    #[test]
    fn a_template_is_read() {
        let (ports, id) = with_one_template();

        let template = get(ports, id).unwrap();

        assert_eq!(template.name().as_str(), "monthly reports");
    }

    /// Ann reads a template the tenant does not have. It is not found.
    #[test]
    fn an_unknown_template_is_not_found() {
        let (ports, _) = with_one_template();

        let result = get(ports, TaskTemplateId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Reading a task template requires the agent view right.
    #[test]
    fn a_caller_who_may_not_view_agents_is_refused() {
        let (ports, id) = with_one_template();
        let ports = GetPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..ports
        };

        assert!(matches!(get(ports, id), Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller is refused access to a stored task template.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (ports, id) = with_one_template();
        let ports = GetPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports
        };

        assert!(matches!(get(ports, id), Err(AppError::Unauthenticated)));
    }
}
