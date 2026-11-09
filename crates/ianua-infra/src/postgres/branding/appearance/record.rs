//! A tenant's branding as its row holds it: read back into the aggregate,
//! and written out from it.

use ianua_domain::domains::branding::config::{CustomCss, TenantBranding, TenantBrandingRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, HexColor, HttpsUrl, Label, RawCss, SanitizedCss, Setting};

use crate::postgres::foundation::stored::Stored;

const BRANDING: Stored = Stored("tenant branding");

/// A branding as it is read. The store's checked queries fill it.
pub(super) struct BrandingRecord {
    pub(super) logo_url: Option<String>,
    pub(super) primary_color: Option<String>,
    pub(super) background_color: Option<String>,
    pub(super) css_source: Option<String>,
    pub(super) css_rendered: Option<String>,
    pub(super) email_from_name: Option<String>,
    pub(super) email_from_address: Option<String>,
}

impl BrandingRecord {
    /// The branding the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a part no longer passes
    /// its rules, or only half of the custom CSS is stored.
    pub(super) fn into_branding(self) -> Result<TenantBranding<ResolvedTenant>, DomainError> {
        let logo_url = self
            .logo_url
            .map(|url| BRANDING.value("logo", HttpsUrl::new(url)))
            .transpose()?;
        TenantBranding::reconstitute(TenantBrandingRow {
            logo_url: Setting::from_stored(logo_url),
            primary_color: color("primary color", self.primary_color)?,
            background_color: color("background color", self.background_color)?,
            custom_css: Setting::from_stored(css_from(self.css_source, self.css_rendered)?),
            email_from_name: Setting::from_stored(
                self.email_from_name
                    .map(|name| BRANDING.value("sender name", Label::new("email_from_name", name)))
                    .transpose()?,
            ),
            email_from_address: Setting::from_stored(
                self.email_from_address
                    .map(|address| BRANDING.value("sender address", Email::new(address)))
                    .transpose()?,
            ),
        })
    }
}

/// A stored color, read back through its rules.
fn color(what: &'static str, stored: Option<String>) -> Result<Setting<HexColor>, DomainError> {
    stored
        .map(|color| BRANDING.value(what, HexColor::new(color)))
        .transpose()
        .map(Setting::from_stored)
}

/// The custom CSS a branding keeps, from its two columns.
fn css_from(
    source: Option<String>,
    rendered: Option<String>,
) -> Result<Option<CustomCss>, DomainError> {
    match (source, rendered) {
        (None, None) => Ok(None),
        (Some(source), Some(rendered)) => Ok(Some(CustomCss::new(
            BRANDING.value("CSS", RawCss::new(source))?,
            BRANDING.value("rendered CSS", SanitizedCss::new(rendered))?,
        ))),
        (Some(_), None) | (None, Some(_)) => Err(DomainError::corrupt_row(
            BRANDING.0,
            "custom CSS without its source or its rendered rules",
        )),
    }
}

/// A branding's columns, as they are written.
pub(super) struct BrandingColumns<'a> {
    pub(super) logo_url: Option<&'a str>,
    pub(super) primary_color: Option<&'a str>,
    pub(super) background_color: Option<&'a str>,
    pub(super) css_source: Option<&'a str>,
    pub(super) css_rendered: Option<&'a str>,
    pub(super) email_from_name: Option<&'a str>,
    pub(super) email_from_address: Option<&'a str>,
}

impl<'a> BrandingColumns<'a> {
    /// The columns `branding` is written to.
    pub(super) fn of(branding: &'a TenantBranding<ResolvedTenant>) -> Self {
        Self {
            logo_url: branding.logo_url().map(HttpsUrl::as_str),
            primary_color: branding.primary_color().map(HexColor::as_str),
            background_color: branding.background_color().map(HexColor::as_str),
            css_source: branding.custom_css_source().map(RawCss::as_str),
            css_rendered: branding.custom_css().map(SanitizedCss::as_str),
            email_from_name: branding.email_from_name().map(Label::as_str),
            email_from_address: branding.email_from_address().map(Email::as_str),
        }
    }
}
