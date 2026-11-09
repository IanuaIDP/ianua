//! Reading the caller's own organization.

use std::sync::Arc;

use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::permission::{OrgPermission, OrganizationAction};

use crate::acting::OrgActors;
use crate::context::OrgCaller;
use crate::error::AppError;
use crate::use_case::Query;

/// The ports [`GetOrganizationUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetOrganizationPorts {
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Reads the organization the caller is a member of.
pub struct GetOrganizationUseCase {
    ports: GetOrganizationPorts,
}

impl GetOrganizationUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetOrganizationPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetOrganizationUseCase {
    type Caller = OrgCaller;
    type Input = ();
    type Output = Result<Organization, AppError>;

    /// The organization `caller` is a member of, as it stands now.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts, or the organization no longer exists.
    /// - `AppError::Forbidden` when the caller may not view the
    ///   organization.
    /// - `AppError::Internal` on storage failure.
    async fn execute(&self, caller: &OrgCaller, (): ()) -> Result<Organization, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        actor
            .control()?
            .ensure_may(
                organization.id(),
                OrgPermission::Organization(OrganizationAction::View),
            )
            .map_err(AppError::from_domain)?;
        Ok(organization)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::{block_on, test_org_caller};

    fn get_as(actors: FakeOrgActors) -> Result<Organization, AppError> {
        let use_case = GetOrganizationUseCase::new(GetOrganizationPorts {
            org_actors: Arc::new(actors),
        });
        block_on(use_case.execute(&test_org_caller(), ()))
    }

    /// Sam, a plain member of Acme, reads his organization. He gets Acme.
    #[test]
    fn a_member_reads_their_own_organization() {
        let organization = get_as(FakeOrgActors::in_role(OrgRole::Member)).unwrap();

        assert_eq!(organization.id(), &test_org_caller().organization_id());
    }

    /// An owner's key without the view right cannot read the organization.
    #[test]
    fn a_key_without_the_view_right_is_refused() {
        let result = get_as(FakeOrgActors::through_key(OrgRole::Owner, Vec::new()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller must authenticate before reading the organization.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = get_as(FakeOrgActors::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Refused organization authority prevents reading organization details.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let result = get_as(FakeOrgActors::refusing(Refusal::Forbidden));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
