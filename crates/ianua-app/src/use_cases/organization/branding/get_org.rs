//! Reading how the organization's own dashboard and mail look.

use std::sync::Arc;

use ianua_domain::domains::organization::branding::OrgBranding;
use ianua_domain::domains::organization::members::permission::{OrgBrandingAction, OrgPermission};

use crate::acting::OrgActors;
use crate::context::OrgCaller;
use crate::error::AppError;
use crate::ports::organization::OrgBrandingStore;
use crate::use_case::Query;
use crate::use_cases::organization::branding::lookup::current_org_branding;

/// The ports [`GetOrgUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetOrgPorts {
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// Organizations' branding.
    pub branding: Arc<dyn OrgBrandingStore>,
}

/// Reads the caller's organization's branding.
pub struct GetOrgUseCase {
    ports: GetOrgPorts,
}

impl GetOrgUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetOrgPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetOrgUseCase {
    type Caller = OrgCaller;
    type Input = ();
    type Output = Result<OrgBranding, AppError>;

    /// The branding of the caller's organization, or the platform's own
    /// look when it was never changed.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view the branding.
    /// - `AppError::Internal` on storage failure.
    async fn execute(&self, caller: &OrgCaller, (): ()) -> Result<OrgBranding, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        actor
            .control()?
            .ensure_may(
                organization.id(),
                OrgPermission::Branding(OrgBrandingAction::View),
            )
            .map_err(AppError::from_domain)?;
        current_org_branding(self.ports.branding.as_ref(), organization.id()).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::branding::OrgBrandingRow;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{HexColor, Setting};

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::FakeOrgBrandingStore;
    use crate::test_support::{block_on, test_org_caller};

    /// Acme's branding, with its buttons in its own blue.
    fn acmes_blue() -> OrgBranding {
        let now = clock::now();
        OrgBranding::reconstitute(OrgBrandingRow {
            organization_id: test_org_caller().organization_id(),
            logo_url: Setting::Unset,
            primary_color: Setting::Set(HexColor::new("#0055ff").unwrap()),
            sender_name: Setting::Unset,
            created_at: now,
            updated_at: now,
        })
        .unwrap()
    }

    fn get_as(actors: FakeOrgActors, store: FakeOrgBrandingStore) -> Result<OrgBranding, AppError> {
        let use_case = GetOrgUseCase::new(GetOrgPorts {
            org_actors: Arc::new(actors),
            branding: Arc::new(store),
        });
        block_on(use_case.execute(&test_org_caller(), ()))
    }

    /// Sam, a plain member of Acme, reads its branding. He sees Acme's blue.
    #[test]
    fn a_member_reads_the_organizations_branding() {
        let branding = get_as(
            FakeOrgActors::in_role(OrgRole::Member),
            FakeOrgBrandingStore::holding(acmes_blue()),
        )
        .unwrap();

        assert_eq!(
            branding.primary_color(),
            Some(&HexColor::new("#0055ff").unwrap())
        );
    }

    /// Acme never changed its look. Sam reads the platform's, with nothing
    /// of Acme's in it.
    #[test]
    fn an_organization_never_branded_reads_the_platforms_look() {
        let branding = get_as(
            FakeOrgActors::in_role(OrgRole::Member),
            FakeOrgBrandingStore::empty(),
        )
        .unwrap();

        assert_eq!(
            branding.organization_id(),
            &test_org_caller().organization_id()
        );
        assert!(branding.primary_color().is_none());
        assert!(branding.logo_url().is_none());
    }

    /// The billing role gives no permission to read stored branding.
    #[test]
    fn a_billing_contact_is_refused() {
        let result = get_as(
            FakeOrgActors::in_role(OrgRole::Billing),
            FakeOrgBrandingStore::holding(acmes_blue()),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Reading branding requires authentication even when none is stored.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = get_as(
            FakeOrgActors::refusing(Refusal::SignedOut),
            FakeOrgBrandingStore::empty(),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
