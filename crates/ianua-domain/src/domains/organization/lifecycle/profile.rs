//! How an organization is named and reached: its name, display name and
//! contact address, which a member who may update the organization
//! changes while it is open.
//!
//! Each change raises its record with the value it replaced.

use crate::domains::organization::events::organization::{
    OrganizationContactEmailChanged, OrganizationDisplayNameChanged, OrganizationRenamed,
};
use crate::domains::organization::lifecycle::Organization;
use crate::domains::organization::members::control::OrgControl;
use crate::domains::organization::members::permission::{OrgPermission, OrganizationAction};
use crate::shared::errors::DomainError;
use crate::types::{DisplayName, Email, Label};

/// The right to change the organization's names and contact.
const UPDATE: OrgPermission = OrgPermission::Organization(OrganizationAction::Update);

impl Organization {
    /// Renames the organization, as `by` decides. Raises
    /// `organization.renamed` with the name it replaced.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when the organization is closed.
    /// - [`DomainError::Forbidden`] when `by` may not update the organization.
    pub fn rename(&mut self, name: Label, by: &OrgControl<'_>) -> Result<(), DomainError> {
        self.ensure_may_update(by)?;
        let old_name = std::mem::replace(&mut self.name, name);
        self.touch();
        self.raised.raise_organization(OrganizationRenamed {
            organization_id: self.id,
            old_name,
            new_name: self.name.clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Updates the display name, as `by` decides. Raises
    /// `organization.display_name_changed` with the name it replaced.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when the organization is closed.
    /// - [`DomainError::Forbidden`] when `by` may not update the organization.
    pub fn change_display_name(
        &mut self,
        display_name: DisplayName,
        by: &OrgControl<'_>,
    ) -> Result<(), DomainError> {
        self.ensure_may_update(by)?;
        let old_display_name = std::mem::replace(&mut self.display_name, display_name);
        self.touch();
        self.raised
            .raise_organization(OrganizationDisplayNameChanged {
                organization_id: self.id,
                old_display_name,
                new_display_name: self.display_name.clone(),
                occurred_at: self.updated_at,
            });
        Ok(())
    }

    /// Updates the contact email, as `by` decides. Raises
    /// `organization.contact_email_changed` with the address it replaced.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when the organization is closed.
    /// - [`DomainError::Forbidden`] when `by` may not update the organization.
    pub fn change_contact_email(
        &mut self,
        email: Email,
        by: &OrgControl<'_>,
    ) -> Result<(), DomainError> {
        self.ensure_may_update(by)?;
        let old_email = std::mem::replace(&mut self.contact_email, email);
        self.touch();
        self.raised
            .raise_organization(OrganizationContactEmailChanged {
                organization_id: self.id,
                old_email,
                new_email: self.contact_email.clone(),
                occurred_at: self.updated_at,
            });
        Ok(())
    }

    /// Refuses a change to the names or contact unless the organization is
    /// open and `by` may update it.
    fn ensure_may_update(&self, by: &OrgControl<'_>) -> Result<(), DomainError> {
        self.ensure_open()?;
        by.ensure_may(&self.id, UPDATE)
    }
}
