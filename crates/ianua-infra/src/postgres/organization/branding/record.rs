//! An organization's branding as its row holds it: read back into the
//! aggregate, and written out from it.

use ianua_domain::domains::organization::branding::{OrgBranding, OrgBrandingRow};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{HexColor, HttpsUrl, Label, OrganizationId, Setting};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;

const BRANDING: Stored = Stored("organization branding");

/// A branding as it is read. The store's checked queries fill it.
pub(super) struct BrandingRecord {
    pub(super) organization_id: Uuid,
    pub(super) logo_url: Option<String>,
    pub(super) primary_color: Option<String>,
    pub(super) sender_name: Option<String>,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl BrandingRecord {
    /// The branding the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a part no longer passes
    /// its rules, or the row says it changed before it was made.
    pub(super) fn into_branding(self) -> Result<OrgBranding, DomainError> {
        let logo_url = self
            .logo_url
            .map(|url| BRANDING.value("logo", HttpsUrl::new(url)))
            .transpose()?;
        let primary_color = self
            .primary_color
            .map(|color| BRANDING.value("primary color", HexColor::new(color)))
            .transpose()?;
        let sender_name = self
            .sender_name
            .map(|name| BRANDING.value("sender name", Label::new("sender_name", name)))
            .transpose()?;
        OrgBranding::reconstitute(OrgBrandingRow {
            organization_id: OrganizationId::from_uuid(self.organization_id),
            logo_url: Setting::from_stored(logo_url),
            primary_color: Setting::from_stored(primary_color),
            sender_name: Setting::from_stored(sender_name),
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// A branding's columns, as they are written.
pub(super) struct BrandingColumns<'a> {
    pub(super) organization_id: &'a Uuid,
    pub(super) logo_url: Option<&'a str>,
    pub(super) primary_color: Option<&'a str>,
    pub(super) sender_name: Option<&'a str>,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> BrandingColumns<'a> {
    /// The columns `branding` is written to.
    pub(super) fn of(branding: &'a OrgBranding) -> Self {
        Self {
            organization_id: branding.organization_id().as_uuid(),
            logo_url: branding.logo_url().map(HttpsUrl::as_str),
            primary_color: branding.primary_color().map(HexColor::as_str),
            sender_name: branding.sender_name().map(Label::as_str),
            created_at: branding.created_at(),
            updated_at: branding.updated_at(),
        }
    }
}
