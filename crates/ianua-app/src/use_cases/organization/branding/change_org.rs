//! Changing how the organization's own dashboard and mail look: its logo,
//! its color and the name its mail goes out under. Only the parts a request
//! names change.

use std::sync::Arc;

use ianua_domain::domains::organization::branding::OrgBranding;
use ianua_domain::domains::organization::members::control::OrgControl;
use ianua_domain::domains::organization::members::permission::{OrgBrandingAction, OrgPermission};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActorRef, HexColor, HttpsUrl, Label, OrganizationId};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::input::FieldUpdate;
use crate::ports::organization::OrgBrandingStore;
use crate::use_case::Command;
use crate::use_cases::organization::branding::lookup::current_org_branding;

/// The parts to change. Each is a [`FieldUpdate`]: `Keep` leaves it as it
/// is, `Clear` returns it to the platform's, `Set` replaces it.
pub struct ChangeOrgRequest {
    /// The image address used when rendering organization branding.
    pub logo_url: FieldUpdate<HttpsUrl>,
    /// The color of buttons and links.
    pub primary_color: FieldUpdate<HexColor>,
    /// The name the organization's mail goes out under.
    pub sender_name: FieldUpdate<Label>,
}

impl ChangeOrgRequest {
    /// Whether every part is left as it is.
    fn changes_nothing(&self) -> bool {
        self.logo_url.is_keep() && self.primary_color.is_keep() && self.sender_name.is_keep()
    }

    /// Changes every part this request names on `branding`, as `by`.
    fn apply_to(&self, branding: &mut OrgBranding, by: &OrgControl<'_>) -> Result<(), DomainError> {
        if let Some(logo) = self.logo_url.setting() {
            branding.change_logo(logo, by)?;
        }
        if let Some(color) = self.primary_color.setting() {
            branding.change_primary_color(color, by)?;
        }
        if let Some(name) = self.sender_name.setting() {
            branding.change_sender_name(name, by)?;
        }
        Ok(())
    }
}

/// The ports [`ChangeOrgUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeOrgPorts {
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// Organizations' branding.
    pub branding: Arc<dyn OrgBrandingStore>,
}

/// Changes the caller's organization's branding.
pub struct ChangeOrgUseCase {
    ports: ChangeOrgPorts,
}

impl ChangeOrgUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: ChangeOrgPorts) -> Self {
        Self { ports }
    }
}

impl Command for ChangeOrgUseCase {
    type Caller = OrgCaller;
    type Input = ChangeOrgRequest;
    type Output = Result<(), AppError>;

    /// Changes the parts `request` names and records
    /// `organization.branding_updated` for each. Starts from the platform's
    /// look when the organization never changed it. A request that changes
    /// nothing saves and records nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change the branding.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request: ChangeOrgRequest,
    ) -> Result<(), AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        ensure_may_change(&control, organization.id())?;
        if request.changes_nothing() {
            return Ok(());
        }
        let store = self.ports.branding.as_ref();
        let mut branding = current_org_branding(store, organization.id()).await?;
        request
            .apply_to(&mut branding, &control)
            .map_err(AppError::from_domain)?;
        store.save(&branding).await.or_internal()?;
        auditor
            .dispatch_by(&ActorRef::OrgUser(*caller.member()), branding.take_events())
            .await
            .or_internal()
    }
}

/// Refuses a caller who may not change the branding of `organization_id`,
/// before anything is read.
fn ensure_may_change(
    control: &OrgControl<'_>,
    organization_id: &OrganizationId,
) -> Result<(), AppError> {
    control
        .ensure_may(
            organization_id,
            OrgPermission::Branding(OrgBrandingAction::Update),
        )
        .map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::FakeOrgBrandingStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Setup {
        uc: ChangeOrgUseCase,
        store: Arc<FakeOrgBrandingStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn as_caller(actors: FakeOrgActors) -> Self {
            let store = Arc::new(FakeOrgBrandingStore::empty());
            Self {
                uc: ChangeOrgUseCase::new(ChangeOrgPorts {
                    org_actors: Arc::new(actors),
                    branding: store.clone(),
                }),
                store,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn change(&self, request: ChangeOrgRequest) -> Result<(), AppError> {
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                request,
            ))
        }

        fn stored(&self) -> Option<OrgBranding> {
            self.store.stored(&test_org_caller().organization_id())
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn blue_and_named() -> ChangeOrgRequest {
        ChangeOrgRequest {
            logo_url: FieldUpdate::Keep,
            primary_color: FieldUpdate::Set(HexColor::new("#0055ff").unwrap()),
            sender_name: FieldUpdate::Set(Label::new("sender_name", "Acme Admin").unwrap()),
        }
    }

    /// Ada, an admin, colors Acme's buttons blue and names its mail "Acme
    /// Admin". Both are saved, the logo stays the platform's, and each
    /// change is recorded.
    #[test]
    fn an_admin_changes_the_parts_named() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Admin));

        setup.change(blue_and_named()).unwrap();

        let stored = setup.stored().unwrap();
        assert_eq!(
            stored.primary_color(),
            Some(&HexColor::new("#0055ff").unwrap())
        );
        assert_eq!(stored.sender_name().map(Label::as_str), Some("Acme Admin"));
        assert!(stored.logo_url().is_none());
        assert_eq!(
            setup.recorded(),
            [
                "organization.branding_updated",
                "organization.branding_updated"
            ]
        );
    }

    /// Ada asks to change nothing. Nothing is saved or recorded.
    #[test]
    fn a_request_changing_nothing_saves_nothing() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Admin));

        setup
            .change(ChangeOrgRequest {
                logo_url: FieldUpdate::Keep,
                primary_color: FieldUpdate::Keep,
                sender_name: FieldUpdate::Keep,
            })
            .unwrap();

        assert!(setup.stored().is_none());
        assert!(setup.recorded().is_empty());
    }

    /// A plain member cannot change the color or sender name; no branding
    /// is saved and no change is recorded.
    #[test]
    fn a_member_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Member));

        let result = setup.change(blue_and_named());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.stored().is_none());
        assert!(setup.recorded().is_empty());
    }

    /// An admin's key without branding scope cannot change the branding,
    /// and no branding is saved.
    #[test]
    fn a_key_without_the_branding_scope_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::through_key(OrgRole::Admin, Vec::new()));

        let result = setup.change(blue_and_named());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.stored().is_none());
    }

    /// A signed-out caller must authenticate before changing branding.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::refusing(Refusal::SignedOut));

        let result = setup.change(blue_and_named());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
