//! How the organization's own dashboard and mail look: its logo, its color
//! and the name its mail goes out under.
//!
//! Members see it every time they sign in, and invitations carry it to
//! people who have not joined yet. So every change names the member who
//! makes it and needs the organization's branding right.

use time::OffsetDateTime;

use crate::domains::organization::events::branding::{
    OrgBrandingPart, OrgBrandingReset, OrgBrandingUpdated,
};
use crate::domains::organization::members::control::OrgControl;
use crate::domains::organization::members::permission::{OrgBrandingAction, OrgPermission};
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{RaisedEvents, RaisesComplete};
use crate::shared::model::row_check::RowCheck;
use crate::types::{HexColor, HttpsUrl, Label, OrganizationId, Setting};

/// The right every change to the organization's branding needs.
const CHANGES_BRANDING: OrgPermission = OrgPermission::Branding(OrgBrandingAction::Update);

/// An organization's branding as stored, for rebuilding it with
/// [`OrgBranding::reconstitute`].
pub struct OrgBrandingRow {
    /// The organization it belongs to.
    pub organization_id: OrganizationId,
    /// The logo, or the platform's.
    pub logo_url: Setting<HttpsUrl>,
    /// The color of buttons and links, or the platform's.
    pub primary_color: Setting<HexColor>,
    /// The name its mail goes out under, or the platform's.
    pub sender_name: Setting<Label>,
    /// When it was first made.
    pub created_at: OffsetDateTime,
    /// When it last changed.
    pub updated_at: OffsetDateTime,
}

/// An organization's own look.
///
/// Each part is the organization's when set and the platform's when unset.
/// A tenant keeps branding of its own, for the pages its users see.
#[derive(Debug, Clone)]
pub struct OrgBranding {
    organization_id: OrganizationId,
    logo_url: Setting<HttpsUrl>,
    primary_color: Setting<HexColor>,
    sender_name: Setting<Label>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: RaisedEvents,
}

impl OrgBranding {
    /// The platform's own look for `organization_id`, before anyone changed
    /// it. It shows nothing of the organization's, so nobody decides
    /// anything by making it.
    #[must_use]
    pub fn platform_default(organization_id: OrganizationId) -> Self {
        let now = crate::shared::clock::now();
        Self {
            organization_id,
            logo_url: Setting::Unset,
            primary_color: Setting::Unset,
            sender_name: Setting::Unset,
            created_at: now,
            updated_at: now,
            raised: RaisedEvents::default(),
        }
    }

    /// Rebuilds an organization's branding from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says it changed before
    ///   it was made.
    pub fn reconstitute(row: OrgBrandingRow) -> Result<Self, DomainError> {
        RowCheck::of("organization branding")
            .in_order(row.created_at, row.updated_at, "changed before it was made")
            .finish()?;
        Ok(Self {
            organization_id: row.organization_id,
            logo_url: row.logo_url,
            primary_color: row.primary_color,
            sender_name: row.sender_name,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: RaisedEvents::default(),
        })
    }

    /// The organization it belongs to.
    #[must_use]
    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// The logo, when the organization set one.
    #[must_use]
    pub fn logo_url(&self) -> Option<&HttpsUrl> {
        self.logo_url.value()
    }

    /// The color of buttons and links, when the organization set one.
    #[must_use]
    pub fn primary_color(&self) -> Option<&HexColor> {
        self.primary_color.value()
    }

    /// The name its mail goes out under, when the organization set one.
    #[must_use]
    pub fn sender_name(&self) -> Option<&Label> {
        self.sender_name.value()
    }

    /// When it was first made.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When it last changed.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// Shows `logo`, or the platform's when unset, as `by` decides. Raises
    /// `organization.branding_updated`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change the branding.
    pub fn change_logo(
        &mut self,
        logo: Setting<HttpsUrl>,
        by: &OrgControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(&self.organization_id, CHANGES_BRANDING)?;
        self.logo_url = logo;
        self.record_change(OrgBrandingPart::Logo);
        Ok(())
    }

    /// Colors buttons and links `color`, or the platform's when unset, as
    /// `by` decides. Raises `organization.branding_updated`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change the branding.
    pub fn change_primary_color(
        &mut self,
        color: Setting<HexColor>,
        by: &OrgControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(&self.organization_id, CHANGES_BRANDING)?;
        self.primary_color = color;
        self.record_change(OrgBrandingPart::PrimaryColor);
        Ok(())
    }

    /// Sends the organization's mail under `name`, or the platform's when
    /// unset, as `by` decides. Raises `organization.branding_updated`.
    ///
    /// The address stays the platform's. Only a tenant proves a domain to
    /// send from, so an organization cannot make mail look as if it came
    /// from a bank.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change the branding.
    pub fn change_sender_name(
        &mut self,
        name: Setting<Label>,
        by: &OrgControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(&self.organization_id, CHANGES_BRANDING)?;
        self.sender_name = name;
        self.record_change(OrgBrandingPart::SenderName);
        Ok(())
    }

    /// Returns every part to the platform's, as `by` decides. Raises
    /// `organization.branding_reset`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change the branding.
    pub fn reset(&mut self, by: &OrgControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(&self.organization_id, CHANGES_BRANDING)?;
        self.logo_url = Setting::Unset;
        self.primary_color = Setting::Unset;
        self.sender_name = Setting::Unset;
        self.updated_at = crate::shared::clock::now();
        self.raised.raise_organization(OrgBrandingReset {
            organization_id: self.organization_id,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Records that `part` changed now.
    fn record_change(&mut self, part: OrgBrandingPart) {
        self.updated_at = crate::shared::clock::now();
        self.raised.raise_organization(OrgBrandingUpdated {
            organization_id: self.organization_id,
            part,
            occurred_at: self.updated_at,
        });
    }
}

impl RaisesComplete for OrgBranding {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::organization::members::control::tests::{
        acting, founder, joined_as, session_of,
    };
    use crate::domains::organization::members::membership::OrgRole;
    use crate::domains::organization::members::org_user::OrgUser;
    use crate::test_support::builders::label;
    use crate::test_support::events::raised_complete_names;

    /// What `member` gets back doing `change` through a fresh session.
    fn by<R>(member: &OrgUser, change: impl FnOnce(&OrgControl<'_>) -> R) -> R {
        let session = session_of(member);
        change(&acting(member, &session))
    }

    /// Ann, an owner, sets Acme's logo, color and sender name. Each shows,
    /// and each change is on record.
    #[test]
    fn an_owner_brands_the_organization() {
        let ann = founder();
        let mut branding = OrgBranding::platform_default(*ann.organization_id());
        let logo = Setting::Set(HttpsUrl::new("https://acme.com/logo.png").unwrap());
        let green = Setting::Set(HexColor::new("#00AA00").unwrap());

        by(&ann, |c| {
            branding.change_logo(logo, c)?;
            branding.change_primary_color(green, c)?;
            branding.change_sender_name(Setting::Set(label("Acme Admin")), c)
        })
        .unwrap();

        assert!(branding.logo_url().is_some());
        assert_eq!(
            branding.sender_name().map(Label::as_str),
            Some("Acme Admin")
        );
        assert_eq!(raised_complete_names(&mut branding).len(), 3);
    }

    /// Sam's member role cannot set Acme's logo; the refusal leaves the
    /// platform default in place.
    #[test]
    fn a_member_does_not_change_the_branding() {
        let ann = founder();
        let sam = joined_as(&ann, OrgRole::Member);
        let mut branding = OrgBranding::platform_default(*ann.organization_id());
        let logo = Setting::Set(HttpsUrl::new("https://sam.example.com/l.png").unwrap());

        let refused = by(&sam, |c| branding.change_logo(logo, c));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert!(branding.logo_url().is_none());
    }

    /// Ann branded Acme and now wants the platform's look back. Every part
    /// returns to the platform's at once, and the reset is on record.
    #[test]
    fn an_owner_resets_the_branding_to_the_platforms() {
        let ann = founder();
        let mut branding = OrgBranding::platform_default(*ann.organization_id());
        let logo = Setting::Set(HttpsUrl::new("https://acme.com/logo.png").unwrap());
        by(&ann, |c| branding.change_logo(logo, c)).unwrap();
        raised_complete_names(&mut branding);

        by(&ann, |c| branding.reset(c)).unwrap();

        assert!(branding.logo_url().is_none());
        assert!(branding.sender_name().is_none());
        assert_eq!(
            raised_complete_names(&mut branding),
            ["organization.branding_reset"]
        );
    }

    /// Sam's member role cannot reset Acme's branding, and its chosen logo
    /// remains set.
    #[test]
    fn a_member_does_not_reset_the_branding() {
        let ann = founder();
        let sam = joined_as(&ann, OrgRole::Member);
        let mut branding = OrgBranding::platform_default(*ann.organization_id());
        let logo = Setting::Set(HttpsUrl::new("https://acme.com/logo.png").unwrap());
        by(&ann, |c| branding.change_logo(logo, c)).unwrap();

        let refused = by(&sam, |c| branding.reset(c));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert!(branding.logo_url().is_some());
    }

    /// Ownership in another organization does not permit changing Acme's
    /// mail sender name.
    #[test]
    fn another_organization_does_not_brand_this_one() {
        let ann = founder();
        let mallory = founder();
        let mut branding = OrgBranding::platform_default(*ann.organization_id());

        let refused = by(&mallory, |c| {
            branding.change_sender_name(Setting::Set(label("IT Support")), c)
        });

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// A stored branding says it changed a day before it was made. It is
    /// refused as corrupt.
    #[test]
    fn a_stored_branding_changed_before_it_was_made_is_refused() {
        let now = crate::shared::clock::now();
        let row = OrgBrandingRow {
            organization_id: OrganizationId::new(),
            logo_url: Setting::Unset,
            primary_color: Setting::Unset,
            sender_name: Setting::Unset,
            created_at: now,
            updated_at: now.saturating_sub(time::Duration::days(1)),
        };

        assert!(crate::shared::model::row_check::refused_as_corrupt(
            &OrgBranding::reconstitute(row)
        ));
    }
}
