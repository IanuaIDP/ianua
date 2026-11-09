//! Organization branding bodies: how the organization's own dashboard and
//! mail look.

use ianua_app::use_cases::organization::branding::ChangeOrgRequest;
use ianua_domain::domains::organization::branding::OrgBranding;
use ianua_domain::types::{HexColor, HttpsUrl, Label};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::patch::patch_field;

/// The organization's branding. A part it never set is `null`: the
/// platform's applies.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OrgBrandingResponse {
    /// HTTPS URL of the logo.
    pub logo_url: Option<String>,
    /// The color of buttons and links.
    pub primary_color: Option<String>,
    /// The name the organization's mail goes out under.
    pub sender_name: Option<String>,
}

impl From<OrgBranding> for OrgBrandingResponse {
    fn from(branding: OrgBranding) -> Self {
        Self {
            logo_url: branding.logo_url().map(|url| url.as_str().to_owned()),
            primary_color: branding
                .primary_color()
                .map(|color| color.as_str().to_owned()),
            sender_name: branding.sender_name().map(|name| name.as_str().to_owned()),
        }
    }
}

/// The parts of the organization's branding to change. Each field is
/// three-valued: absent leaves it unchanged, `null` returns it to the
/// platform's, a value replaces it.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UpdateOrgBrandingBody {
    /// HTTPS URL of the logo.
    #[serde(default, deserialize_with = "crate::patch::nullable::deserialize")]
    pub logo_url: Option<Option<String>>,
    /// Primary color, `#RGB` or `#RRGGBB`.
    #[serde(default, deserialize_with = "crate::patch::nullable::deserialize")]
    pub primary_color: Option<Option<String>>,
    /// The name the organization's mail goes out under.
    #[serde(default, deserialize_with = "crate::patch::nullable::deserialize")]
    pub sender_name: Option<Option<String>>,
}

impl TryFrom<UpdateOrgBrandingBody> for ChangeOrgRequest {
    type Error = ApiError;

    fn try_from(body: UpdateOrgBrandingBody) -> Result<Self, Self::Error> {
        Ok(Self {
            logo_url: patch_field(body.logo_url, |url| HttpsUrl::new(url))?,
            primary_color: patch_field(body.primary_color, |color| HexColor::new(color))?,
            sender_name: patch_field(body.sender_name, |name| Label::new("sender_name", name))?,
        })
    }
}
