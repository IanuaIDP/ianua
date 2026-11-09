//! Changing the organization's name, display name and contact address.
//!
//! Only a field given with a new value changes, so a form that sends back
//! unchanged values records nothing and notifies nobody.

use std::sync::Arc;

use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::control::OrgControl;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActorRef, DisplayName, Email, Label};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::OrganizationStore;
use crate::use_case::Command;

/// The fields to change. A field left out stays as it is.
pub struct UpdateOrganizationRequest {
    /// The new name.
    pub name: Option<Label>,
    /// The new contact address.
    pub contact_email: Option<Email>,
    /// The new display name.
    pub display_name: Option<DisplayName>,
}

/// The ports [`UpdateOrganizationUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdateOrganizationPorts {
    /// Loads and saves the organization's editable details.
    pub organizations: Arc<dyn OrganizationStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Changes the caller's organization's names and contact address.
pub struct UpdateOrganizationUseCase {
    ports: UpdateOrganizationPorts,
}

impl UpdateOrganizationUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: UpdateOrganizationPorts) -> Self {
        Self { ports }
    }
}

impl Command for UpdateOrganizationUseCase {
    type Caller = OrgCaller;
    type Input = UpdateOrganizationRequest;
    type Output = Result<(), AppError>;

    /// Applies each field of `request` that differs from what the
    /// organization holds, saves it, and records one event per field
    /// changed. Nothing different is no change at all.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update the
    ///   organization.
    /// - `AppError::Domain` when the organization is closed.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request: UpdateOrganizationRequest,
    ) -> Result<(), AppError> {
        let (mut organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        let mut change = Change {
            organization: &mut organization,
            control: &control,
        };
        let changed = [
            change.renamed(request.name)?,
            change.contact_email_changed(request.contact_email)?,
            change.display_name_changed(request.display_name)?,
        ];
        if !changed.contains(&Changed::Yes) {
            return Ok(());
        }
        self.ports
            .organizations
            .save(&organization)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(
                &ActorRef::OrgUser(*actor.member().id()),
                organization.take_events(),
            )
            .await
            .or_internal()
    }
}

/// Whether a field given changed the organization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Changed {
    Yes,
    No,
}

/// One field change after another to the organization, by one member.
struct Change<'a> {
    organization: &'a mut Organization,
    control: &'a OrgControl<'a>,
}

impl Change<'_> {
    /// Renames the organization when `name` differs.
    fn renamed(&mut self, name: Option<Label>) -> Result<Changed, AppError> {
        let Some(name) = name.filter(|name| name != self.organization.name()) else {
            return Ok(Changed::No);
        };
        self.organization
            .rename(name, self.control)
            .map_err(AppError::from_domain)?;
        Ok(Changed::Yes)
    }

    /// Changes the contact address when `email` differs.
    fn contact_email_changed(&mut self, email: Option<Email>) -> Result<Changed, AppError> {
        let Some(email) = email.filter(|email| email != self.organization.contact_email()) else {
            return Ok(Changed::No);
        };
        self.organization
            .change_contact_email(email, self.control)
            .map_err(AppError::from_domain)?;
        Ok(Changed::Yes)
    }

    /// Changes the display name when `display_name` differs.
    fn display_name_changed(
        &mut self,
        display_name: Option<DisplayName>,
    ) -> Result<Changed, AppError> {
        let Some(display_name) =
            display_name.filter(|display_name| display_name != self.organization.display_name())
        else {
            return Ok(Changed::No);
        };
        self.organization
            .change_display_name(display_name, self.control)
            .map_err(AppError::from_domain)?;
        Ok(Changed::Yes)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{FakeOrganizationStore, cfg};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Setup {
        uc: UpdateOrganizationUseCase,
        orgs: Arc<FakeOrganizationStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn as_member(actors: FakeOrgActors) -> Self {
            let orgs = Arc::new(FakeOrganizationStore::empty());
            Self {
                uc: UpdateOrganizationUseCase::new(UpdateOrganizationPorts {
                    organizations: orgs.clone(),
                    org_actors: Arc::new(actors),
                }),
                orgs,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn owner() -> Self {
            Self::as_member(FakeOrgActors::in_role(OrgRole::Owner))
        }

        fn update(&self, request: UpdateOrganizationRequest) -> Result<(), AppError> {
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                request,
            ))
        }

        fn stored(&self) -> Option<Organization> {
            self.orgs.stored(&test_org_caller().organization_id())
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn nothing() -> UpdateOrganizationRequest {
        UpdateOrganizationRequest {
            name: None,
            contact_email: None,
            display_name: None,
        }
    }

    fn name(value: &str) -> Label {
        Label::new("org_name", value).unwrap()
    }

    fn display(value: &str) -> DisplayName {
        DisplayName::new(value, &cfg().display_name).unwrap()
    }

    /// Olivia, Acme's owner, renames it Acme Industries. The new name is
    /// saved and the rename recorded.
    #[test]
    fn update_name_and_audits() {
        let setup = Setup::owner();

        setup
            .update(UpdateOrganizationRequest {
                name: Some(name("Acme Industries")),
                ..nothing()
            })
            .unwrap();

        assert_eq!(setup.stored().unwrap().name().as_str(), "Acme Industries");
        assert_eq!(setup.recorded(), vec!["organization.renamed"]);
    }

    /// Olivia changes all three fields at once. Each change is recorded.
    #[test]
    fn update_multiple_fields_emits_multiple_events() {
        let setup = Setup::owner();

        setup
            .update(UpdateOrganizationRequest {
                name: Some(name("New Name")),
                contact_email: Some(Email::new("new@acme.com").unwrap()),
                display_name: Some(display("New Display")),
            })
            .unwrap();

        assert_eq!(setup.recorded().len(), 3);
    }

    /// Olivia saves the form without changing anything. Nothing is saved
    /// and nothing recorded.
    #[test]
    fn update_with_unchanged_values_emits_no_events() {
        let setup = Setup::owner();

        setup
            .update(UpdateOrganizationRequest {
                name: Some(name("Acme")),
                contact_email: Some(Email::new("owner@acme.test").unwrap()),
                display_name: Some(display("Acme")),
            })
            .unwrap();

        assert!(setup.recorded().is_empty());
        assert!(setup.stored().is_none());
    }

    /// Olivia sends back the old name with a new contact address. Only the
    /// address change is recorded.
    #[test]
    fn update_emits_events_only_for_fields_that_changed() {
        let setup = Setup::owner();

        setup
            .update(UpdateOrganizationRequest {
                name: Some(name("Acme")),
                contact_email: Some(Email::new("new@acme.com").unwrap()),
                ..nothing()
            })
            .unwrap();

        assert_eq!(setup.recorded(), vec!["organization.contact_email_changed"]);
    }

    /// Olivia sends no field at all. Nothing changes.
    #[test]
    fn update_no_fields_is_noop() {
        let setup = Setup::owner();

        setup.update(nothing()).unwrap();

        assert!(setup.recorded().is_empty());
    }

    /// A plain member cannot rename the organization, and no rename is recorded.
    #[test]
    fn a_plain_member_is_refused() {
        let setup = Setup::as_member(FakeOrgActors::in_role(OrgRole::Member));

        let result = setup.update(UpdateOrganizationRequest {
            name: Some(name("Hacked")),
            ..nothing()
        });

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.recorded().is_empty());
    }

    /// A signed-out caller must authenticate before renaming the organization.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::as_member(FakeOrgActors::refusing(Refusal::SignedOut));

        let result = setup.update(UpdateOrganizationRequest {
            name: Some(name("Hacked")),
            ..nothing()
        });

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Refused organization authority prevents a rename and produces no
    /// audit record.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let setup = Setup::as_member(FakeOrgActors::refusing(Refusal::Forbidden));

        let result = setup.update(UpdateOrganizationRequest {
            name: Some(name("Hacked")),
            ..nothing()
        });

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.recorded().is_empty());
    }
}
