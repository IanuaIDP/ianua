//! Events about how the organization's own pages and mail look.

use time::OffsetDateTime;

use crate::shared::events::data::EventData;
use crate::shared::events::event::organization_event;
use crate::types::OrganizationId;

/// Which part of the organization's branding changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OrgBrandingPart {
    /// The logo shown on the dashboard and in its mail.
    Logo,
    /// The color of buttons and links.
    PrimaryColor,
    /// The name its mail is sent under.
    SenderName,
}

impl OrgBrandingPart {
    /// The stable name the record carries.
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Logo => "logo",
            Self::PrimaryColor => "primary_color",
            Self::SenderName => "sender_name",
        }
    }
}

/// The organization's branding changed.
///
/// The record names the part, not what it now says. A logo pointing
/// somewhere it should not is found in the stored branding, at the time
/// this says it changed.
#[derive(Debug)]
pub(crate) struct OrgBrandingUpdated {
    /// The organization whose branding changed.
    pub(crate) organization_id: OrganizationId,
    /// The part that changed.
    pub(crate) part: OrgBrandingPart,
    /// When it changed.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgBrandingUpdated => crate::types::event_type::OrganizationEvent::BrandingUpdated,
    fn payload(&self) -> EventData {
        EventData::new().field("part", self.part.as_str())
    }
}

/// The organization's branding went back to the platform's, every part at
/// once.
#[derive(Debug)]
pub(crate) struct OrgBrandingReset {
    /// The organization whose branding was reset.
    pub(crate) organization_id: OrganizationId,
    /// When it was reset.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgBrandingReset => crate::types::event_type::OrganizationEvent::BrandingReset,
    fn payload(&self) -> EventData {
        EventData::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::event::DomainEventCore;

    /// A change of the logo is recorded as the logo, so a reviewer knows
    /// which part to look at.
    #[test]
    fn a_branding_change_names_its_part() {
        let event = OrgBrandingUpdated {
            organization_id: OrganizationId::new(),
            part: OrgBrandingPart::Logo,
            occurred_at: OffsetDateTime::UNIX_EPOCH,
        };

        assert_eq!(event.payload().get("part"), Some("logo"));
    }
}
