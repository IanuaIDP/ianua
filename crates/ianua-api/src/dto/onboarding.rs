//! Onboarding bodies: whether signups are taken, asking for an
//! organization, founding it from the link, and a member founding another.

use ianua_app::use_cases::onboarding::founding::Founded;
use ianua_app::use_cases::onboarding::{AnotherOrganizationRequest, SignupRequest};
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{DisplayName, Email, Locale, OrganizationId, TenantId, Timezone};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// Signup request body. Holds a password, so it has no `Debug`.
///
/// The subscription plan is not a field here: signup is unauthenticated
/// and takes no payment, so the tier is the server's to decide. A
/// `primary_domain` sent by older clients is ignored: a tenant proves a
/// domain after it exists.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct SignupBody {
    /// The organization name from which its URL slug is derived.
    pub company_name: String,
    /// Tenant name (e.g. "Production", "Main").
    pub tenant_name: String,
    /// Admin email address.
    pub admin_email: String,
    /// Admin user's full name, shown in the dashboard.
    pub admin_display_name: String,
    /// The initial credential chosen for the founding administrator's account.
    #[schema(format = Password)]
    pub admin_password: String,
}

impl SignupBody {
    /// The signup this body asks for, its values checked against `limits`.
    ///
    /// # Errors
    ///
    /// `422` for an invalid address or display name.
    pub(crate) fn request(self, limits: &DomainLimits) -> Result<SignupRequest, ApiError> {
        let admin_email = Email::new(&self.admin_email).map_err(ApiError::validation)?;
        let admin_display_name = DisplayName::new(&self.admin_display_name, &limits.display_name)
            .map_err(ApiError::validation)?;
        Ok(SignupRequest {
            company_name: self.company_name,
            tenant_name: self.tenant_name,
            admin_email,
            admin_display_name,
            admin_password: self.admin_password,
            timezone: None,
            locale: None,
        })
    }
}

/// Whether this deployment takes signups.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SignupOpenResponse {
    /// `false` on a self-hosted installation, which has only the
    /// organization it created for itself.
    pub open: bool,
}

/// The organization and first tenant created by signup, with their provisioning status.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SignupResponse {
    /// The newly founded organization that owns the first tenant.
    #[schema(value_type = String, format = Uuid)]
    pub organization_id: OrganizationId,
    /// Organization slug.
    pub org_slug: String,
    /// Tenant ID.
    ///
    /// Names the setup now running for this tenant: pass it as
    /// `reference_id` to the progress stream to follow the setup.
    #[schema(value_type = String, format = Uuid)]
    pub tenant_id: TenantId,
    /// The first tenant's name as used in request URLs.
    pub tenant_slug: String,
    /// The founding administrator's account within the new organization.
    pub admin_user_id: String,
    /// Status (always `"provisioning"` on creation).
    pub status: String,
}

impl From<&Founded> for SignupResponse {
    fn from(founded: &Founded) -> Self {
        Self {
            organization_id: founded.organization_id,
            org_slug: founded.org_slug.clone(),
            tenant_id: founded.tenant_id,
            tenant_slug: founded.tenant_slug.clone(),
            admin_user_id: founded.admin_user_id.to_string(),
            status: "provisioning".to_owned(),
        }
    }
}

/// The answer to a sign-up: always the same, whether or not the address has
/// an account.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SignupAcceptedResponse {
    /// Always `"check_inbox"`: a link, or a notice, went to the address.
    pub status: &'static str,
}

impl SignupAcceptedResponse {
    /// The one answer a sign-up gets.
    #[must_use]
    pub(crate) fn check_inbox() -> Self {
        Self {
            status: "check_inbox",
        }
    }
}

/// A member founding another organization of their own. Holds a password,
/// so it has no `Debug`.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct AnotherOrganizationBody {
    /// Company name, which the organization's slug is made from.
    pub company_name: String,
    /// Name of its first tenant (e.g. "Production"), which the tenant's
    /// slug is made from.
    pub tenant_name: String,
    /// The password of the member's account in the new organization. An
    /// address holds one account per organization, each with its own
    /// password.
    #[schema(format = Password)]
    pub password: String,
    /// The tenant's timezone, such as `Europe/Berlin`. UTC when left out.
    #[serde(default)]
    pub timezone: Option<String>,
    /// The tenant's locale, such as `de-DE`. `en-US` when left out.
    #[serde(default)]
    pub locale: Option<String>,
}

impl TryFrom<AnotherOrganizationBody> for AnotherOrganizationRequest {
    type Error = ApiError;

    fn try_from(body: AnotherOrganizationBody) -> Result<Self, Self::Error> {
        Ok(Self {
            company_name: body.company_name,
            tenant_name: body.tenant_name,
            password: Secret::new(body.password),
            timezone: body
                .timezone
                .map(Timezone::new)
                .transpose()
                .map_err(ApiError::validation)?,
            locale: body
                .locale
                .map(Locale::new)
                .transpose()
                .map_err(ApiError::validation)?,
        })
    }
}

/// The link a founder followed, to found the organization they asked for.
/// Holds the link's token, so it has no `Debug`.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ConfirmSignupBody {
    /// The token from the link.
    pub token: String,
}

impl From<ConfirmSignupBody> for Secret {
    fn from(body: ConfirmSignupBody) -> Self {
        Secret::new(body.token)
    }
}
