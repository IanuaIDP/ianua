//! List integrations: every integration installed, as it presents itself
//! to the people building workflows, and how an account is connected to
//! it, for someone who may view workflows.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::integration::profile::IntegrationProfile;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::{IntegrationCatalog, PlaceAsked, ServiceSignIn};
use crate::use_case::Query;

/// How an account is connected to an integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Connecting {
    /// By signing in at its service, through the deployment's app, asked
    /// for this besides the account's name.
    SignIn(PlaceAsked),
    /// By handing over a credential.
    Credential,
}

/// One integration installed, as it presents itself, and how an account
/// is connected to it.
#[derive(Debug, Clone)]
pub struct ListedIntegration {
    /// How it presents itself.
    pub profile: IntegrationProfile,
    /// How an account is connected to it.
    pub connecting: Connecting,
}

/// The ports [`ListIntegrationsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListIntegrationsPorts {
    /// The integrations installed.
    pub catalog: Arc<dyn IntegrationCatalog>,
    /// The services a person may sign in at to connect an account.
    pub sign_in: Arc<dyn ServiceSignIn>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the integrations a workflow's builder may use.
pub struct ListIntegrationsUseCase {
    ports: ListIntegrationsPorts,
}

impl ListIntegrationsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListIntegrationsPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListIntegrationsUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<Vec<ListedIntegration>, AppError>;

    /// Every integration installed, with its title, description and icon,
    /// and whether an account is connected by signing in at its service or
    /// with a credential.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view workflows.
    /// - `AppError::Internal` when the catalog cannot be read.
    async fn execute(
        &self,
        ctx: &CallerContext,
        (): (),
    ) -> Result<Vec<ListedIntegration>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        WorkflowControl::new(&authority)
            .ensure_may(WorkflowAction::View)
            .map_err(AppError::from_domain)?;
        let installed = self.ports.catalog.installed().await.or_internal()?;
        Ok(installed
            .into_iter()
            .map(|profile| {
                let sign_in = self.ports.sign_in.as_ref();
                let connecting = match sign_in.offers(profile.key()) {
                    true => Connecting::SignIn(sign_in.asks_for(profile.key())),
                    false => Connecting::Credential,
                };
                ListedIntegration {
                    profile,
                    connecting,
                }
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::types::ActionClass;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::workflows::{
        FakeIntegrationCatalog, FakeServiceSignIn, SHEETS, append_row,
    };
    use crate::test_support::{block_on, test_ctx};

    fn listed_with(
        authorities: FakeTenantAuthorities,
        sign_in: FakeServiceSignIn,
    ) -> Result<Vec<ListedIntegration>, AppError> {
        let use_case = ListIntegrationsUseCase::new(ListIntegrationsPorts {
            catalog: Arc::new(FakeIntegrationCatalog::offering(vec![
                append_row(ActionClass::Write),
                append_row(ActionClass::Read),
            ])),
            sign_in: Arc::new(sign_in),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), ()))
    }

    fn list(authorities: FakeTenantAuthorities) -> Result<Vec<ListedIntegration>, AppError> {
        listed_with(
            authorities,
            FakeServiceSignIn::issuing("github", "no code", "no credential"),
        )
    }

    fn viewer() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)])
    }

    /// Ann builds a workflow and sees the sheets integration once, with its
    /// title and icon, however many operations it offers, connected with a
    /// credential since the deployment has no sign-in for it.
    #[test]
    fn each_installed_integration_is_listed_once_with_its_profile() {
        let listed = list(viewer()).unwrap();

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].profile.key().as_str(), SHEETS);
        assert!(!listed[0].profile.title().as_str().is_empty());
        assert_eq!(listed[0].connecting, Connecting::Credential);
    }

    /// The deployment registered an app with the sheets service, so Ann is
    /// offered to connect by signing in there.
    #[test]
    fn an_integration_with_a_sign_in_is_connected_by_signing_in() {
        let listed = listed_with(
            viewer(),
            FakeServiceSignIn::issuing(SHEETS, "no code", "no credential"),
        )
        .unwrap();

        assert_eq!(
            listed[0].connecting,
            Connecting::SignIn(PlaceAsked::Nothing)
        );
    }

    /// Bob is told connecting the sheets service by signing in asks for
    /// the workspace the account works in, so his form has that box.
    #[test]
    fn a_sign_in_asking_for_a_place_says_so() {
        let listed = listed_with(
            viewer(),
            FakeServiceSignIn::issuing(SHEETS, "no code", "no credential").asking_for("workspace"),
        )
        .unwrap();

        assert_eq!(
            listed[0].connecting,
            Connecting::SignIn(PlaceAsked::Named("workspace"))
        );
    }

    /// A caller without workflow rights cannot list installed integrations.
    #[test]
    fn a_caller_who_may_not_view_workflows_is_refused() {
        let result = list(FakeTenantAuthorities::holding(&[]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot list installed integrations.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = list(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
