//! List task templates: the kinds of task people have written down.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::task_template::TaskTemplate;
use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::TaskTemplateStore;
use crate::use_case::Query;

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Keeps templates.
    pub template_store: Arc<dyn TaskTemplateStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the task templates of the caller's tenant.
pub struct ListUseCase {
    ports: ListPorts,
}

impl ListUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<Vec<TaskTemplate<ResolvedTenant>>, AppError>;

    /// Every template in the tenant, newest first, for a caller who may
    /// view agents.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view agents.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        (): (),
    ) -> Result<Vec<TaskTemplate<ResolvedTenant>>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Agents(AgentAction::View))
            .map_err(AppError::from_domain)?;
        self.ports
            .template_store
            .list(&ctx.tenant())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        caller_person, someone_else, template_proposed_by, templates_holding,
    };
    use crate::test_support::{block_on, test_ctx};

    fn list(ports: ListPorts) -> Result<Vec<TaskTemplate<ResolvedTenant>>, AppError> {
        block_on(ListUseCase::new(ports).execute(&test_ctx(), ()))
    }

    fn with_two_templates() -> ListPorts {
        ListPorts {
            template_store: Arc::new(templates_holding([
                template_proposed_by(caller_person()),
                template_proposed_by(someone_else()),
            ])),
            ..ListPorts::fakes()
        }
    }

    /// Ann lists the templates. She sees both, hers and Bob's.
    #[test]
    fn lists_every_template_in_the_tenant() {
        let listed = list(with_two_templates()).unwrap();

        assert_eq!(listed.len(), 2);
    }

    /// A caller without the agent view right cannot list task templates.
    #[test]
    fn a_caller_who_may_not_view_agents_is_refused() {
        let ports = ListPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..with_two_templates()
        };

        assert!(matches!(list(ports), Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller is refused the tenant's template list.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let ports = ListPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..with_two_templates()
        };

        assert!(matches!(list(ports), Err(AppError::Unauthenticated)));
    }
}
