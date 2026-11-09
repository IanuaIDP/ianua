//! Branding bodies: a tenant's look on its sign-in pages and its logo. Its
//! own versions of the platform's emails are in `templates`, the provider
//! its mail goes out through in `mail`.

pub mod mail;
pub mod templates;

use ianua_app::use_cases::branding::UpdateRequest;
use ianua_domain::domains::branding::config::TenantBranding;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{Email, HexColor, HttpsUrl, Label, RawCss};
use serde::{Deserialize, Serialize};
use utoipa::openapi::RefOr;
use utoipa::openapi::schema::{KnownFormat, ObjectBuilder, Schema, SchemaFormat, Type};

use crate::error::ApiError;
use crate::patch::patch_field;

/// The parts of a tenant's branding to change. Each field is
/// three-valued: absent leaves it unchanged, `null` returns it to the
/// platform's, a value replaces it.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UpdateBrandingBody {
    /// HTTPS URL of the logo on the sign-in page.
    #[serde(default, deserialize_with = "crate::patch::nullable::deserialize")]
    pub logo_url: Option<Option<String>>,
    /// Primary color, `#RGB` or `#RRGGBB`.
    #[serde(default, deserialize_with = "crate::patch::nullable::deserialize")]
    pub primary_color: Option<Option<String>>,
    /// Background color, `#RGB` or `#RRGGBB`.
    #[serde(default, deserialize_with = "crate::patch::nullable::deserialize")]
    pub background_color: Option<Option<String>>,
    /// CSS for the sign-in page, sanitized before it is ever rendered.
    #[serde(default, deserialize_with = "crate::patch::nullable::deserialize")]
    pub custom_css: Option<Option<String>>,
    /// The "From" name of the tenant's emails.
    #[serde(default, deserialize_with = "crate::patch::nullable::deserialize")]
    pub email_from_name: Option<Option<String>>,
    /// The "From" address of the tenant's emails.
    #[serde(default, deserialize_with = "crate::patch::nullable::deserialize")]
    pub email_from_address: Option<Option<String>>,
}

impl TryFrom<UpdateBrandingBody> for UpdateRequest {
    type Error = ApiError;

    fn try_from(body: UpdateBrandingBody) -> Result<Self, Self::Error> {
        Ok(Self {
            logo_url: patch_field(body.logo_url, |url| HttpsUrl::new(url))?,
            primary_color: patch_field(body.primary_color, |color| HexColor::new(color))?,
            background_color: patch_field(body.background_color, |color| HexColor::new(color))?,
            custom_css: patch_field(body.custom_css, |css| RawCss::new(css))?,
            email_from_name: patch_field(body.email_from_name, |name| {
                Label::new("email_from_name", name)
            })?,
            email_from_address: patch_field(body.email_from_address, |address| {
                Email::new(address)
            })?,
        })
    }
}

/// A tenant's branding. A part the tenant never set is `null`: the
/// platform's applies.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct BrandingResponse {
    /// HTTPS URL of the logo on the sign-in page.
    pub logo_url: Option<String>,
    /// The tenant's sign-in accent, as a hex color, or `null` for the default.
    pub primary_color: Option<String>,
    /// The tenant's sign-in backdrop, as a hex color, or `null` for the default.
    pub background_color: Option<String>,
    /// The CSS as the tenant wrote it, for them to edit. The sign-in page
    /// renders a sanitized form of it.
    pub custom_css: Option<String>,
    /// The "From" name of the tenant's emails.
    pub email_from_name: Option<String>,
    /// The "From" address of the tenant's emails.
    pub email_from_address: Option<String>,
}

impl From<&TenantBranding<ResolvedTenant>> for BrandingResponse {
    fn from(branding: &TenantBranding<ResolvedTenant>) -> Self {
        Self {
            logo_url: branding.logo_url().map(|url| url.as_str().to_owned()),
            primary_color: branding
                .primary_color()
                .map(|color| color.as_str().to_owned()),
            background_color: branding
                .background_color()
                .map(|color| color.as_str().to_owned()),
            custom_css: branding
                .custom_css_source()
                .map(|css| css.as_str().to_owned()),
            email_from_name: branding
                .email_from_name()
                .map(|name| name.as_str().to_owned()),
            email_from_address: branding
                .email_from_address()
                .map(|address| address.as_str().to_owned()),
        }
    }
}

/// The form a logo is uploaded in: one file in the `logo` field.
pub(crate) struct LogoUploadForm;

impl utoipa::ToSchema for LogoUploadForm {}

impl utoipa::PartialSchema for LogoUploadForm {
    /// Describes the file field parsed by the multipart extractor.
    fn schema() -> RefOr<Schema> {
        ObjectBuilder::new()
            .description(Some("The form a logo is uploaded in: one file in the `logo` field."))
            .property(
                "logo",
                ObjectBuilder::new()
                    .schema_type(Type::String)
                    .format(Some(SchemaFormat::KnownFormat(KnownFormat::Binary)))
                    .description(Some(
                        "The image: a PNG or a JPEG of at most 512 KiB, each side between 16\nand 4096 pixels.",
                    )),
            )
            .required("logo")
            .into()
    }
}

/// Where an uploaded logo is served.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct LogoUploadedResponse {
    /// The logo's HTTPS address, now the tenant's `logo_url`.
    pub logo_url: String,
}

impl From<HttpsUrl> for LogoUploadedResponse {
    fn from(served_at: HttpsUrl) -> Self {
        Self {
            logo_url: served_at.as_str().to_owned(),
        }
    }
}
