//! Organization member bodies: a member, the member listing, what a member
//! may reach, and the changes an owner or the member makes to an account.

use ianua_app::listing::{PageRequest, SortOrder};
use ianua_app::ports::identity::InvitationState;
use ianua_app::ports::organization::{OrgUserFilter, OrgUserSortField};
use ianua_app::use_cases::organization::members::{
    ChangeOrgUserDisplayNameRequest, ChangeOrgUserEmailRequest, ChangeOrgUserPasswordRequest,
    ChangeOrgUserRoleRequest, CreateOrgUserRequest, ListOrgUsersRequest, OrgMe, OrgUserAccess,
    ResetOrgUserPasswordRequest, ResetPasswordResult, SetOrgUserTenantAccessRequest, TenantAccess,
    UnlinkIdentityRequest, UpdateOrgUserPreferencesRequest, UpdateOrgUserStatusRequest,
};
use ianua_domain::domains::organization::members::membership::OrgRole;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::domains::organization::members::org_user_status::OrgUserStatus;
use ianua_domain::message;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    DisplayName, Email, Label, Locale, OrgUserId, Preference, TenantId, TenantSlug, Timezone,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;

/// An organization member.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OrgUserResponse {
    /// User ID.
    pub id: Uuid,
    /// Email address.
    pub email: String,
    /// The name shown for this person in organization membership lists.
    pub display_name: String,
    /// Current status: `Invited`, `PendingVerification`, `Active`, `Locked`
    /// or `Deactivated`.
    pub status: String,
    /// Authority in the organization: `Owner`, `Admin`, `Member`, `Billing`
    /// or `Viewer`.
    #[schema(schema_with = crate::dto::schemas::org_role)]
    pub role: OrgRole,
    /// Whether the user's email address has been verified.
    pub email_verified: bool,
    /// Preferred locale, or `null` when inheriting the organization default.
    pub locale: Option<String>,
    /// Preferred timezone, or `null` when inheriting the organization default.
    pub timezone: Option<String>,
    /// Invitation state for users who have not yet joined: `"Pending"` or
    /// `"Expired"`, or `null`. The member listing does not carry it yet, so
    /// filter by `PendingInvitation` / `InvitationExpired` to tell them apart.
    pub invitation_status: Option<String>,
    /// When created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    /// When the user accepted their invitation and joined, if yet.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub joined_at: Option<time::OffsetDateTime>,
}

impl From<OrgUser> for OrgUserResponse {
    fn from(u: OrgUser) -> Self {
        Self {
            id: *u.id().as_uuid(),
            email: u.email().as_str().to_owned(),
            display_name: u.display_name().as_str().to_owned(),
            status: u.status().to_string(),
            role: u.role(),
            email_verified: u.email_verified(),
            locale: u.locale().value().map(|l| l.as_str().to_owned()),
            timezone: u.timezone().value().map(|t| t.as_str().to_owned()),
            invitation_status: None,
            created_at: u.created_at(),
            joined_at: u.joined_at(),
        }
    }
}

/// The caller's own account and what it reaches.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OrgMeResponse {
    /// The signed-in member's profile, flattened into this response.
    #[serde(flatten)]
    pub account: OrgUserResponse,
    /// The tenants they reach, with their permissions in each.
    pub access: OrgUserAccessResponse,
}

impl From<OrgMe> for OrgMeResponse {
    fn from(me: OrgMe) -> Self {
        Self {
            account: OrgUserResponse::from(me.member),
            access: OrgUserAccessResponse::from(me.access),
        }
    }
}

/// What a member-listing status filter can select.
///
/// Wider than the account status because "invitation expired" is not one:
/// an invited member stays `Invited` whether or not their link still works.
#[derive(Debug, Clone, Copy, Deserialize, utoipa::ToSchema)]
pub(crate) enum OrgMemberStatusFilter {
    /// Invited, whether or not the invitation is still valid.
    Invited,
    /// Created and not yet confirmed.
    #[serde(
        alias = "pending_verification",
        alias = "pendingVerification",
        alias = "Pending Verification",
        alias = "Unverified",
        alias = "unverified"
    )]
    PendingVerification,
    /// Fully operational.
    Active,
    /// Locked out.
    Locked,
    /// The account has been taken out of service and cannot sign in.
    Deactivated,
    /// Invited, invitation still valid.
    #[serde(
        alias = "Pending",
        alias = "pending",
        alias = "pending_invitation",
        alias = "Pending Invitation",
        alias = "InvitationPending",
        alias = "Invitation Pending"
    )]
    PendingInvitation,
    /// Invited, invitation past its expiry.
    #[serde(
        alias = "Expired",
        alias = "expired",
        alias = "invitation_expired",
        alias = "Invitation Expired",
        alias = "ExpiredInvitation",
        alias = "Expired Invitation"
    )]
    InvitationExpired,
}

impl OrgMemberStatusFilter {
    /// The account status this selects, and the invitation state to narrow
    /// to.
    fn split(self) -> (OrgUserStatus, Option<InvitationState>) {
        match self {
            Self::Invited => (OrgUserStatus::Invited, None),
            Self::PendingVerification => (OrgUserStatus::PendingVerification, None),
            Self::Active => (OrgUserStatus::Active, None),
            Self::Locked => (OrgUserStatus::Locked, None),
            Self::Deactivated => (OrgUserStatus::Deactivated, None),
            Self::PendingInvitation => (OrgUserStatus::Invited, Some(InvitationState::Pending)),
            Self::InvitationExpired => (OrgUserStatus::Invited, Some(InvitationState::Expired)),
        }
    }
}

/// Query parameters for filtering the member listing.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct OrgUserFilterParams {
    /// Filter by account status, or by the state of an open invitation
    /// (`PendingInvitation` / `InvitationExpired`). Omit to return everyone.
    pub status: Option<OrgMemberStatusFilter>,
    /// Case-insensitive substring match on email address.
    pub email: Option<String>,
}

impl OrgUserFilterParams {
    /// The listing asked for: these members, in `sort` order, the page
    /// `pagination` names.
    #[must_use]
    pub(crate) fn listing(
        self,
        sort: SortOrder<OrgUserSortField>,
        pagination: PageRequest,
    ) -> ListOrgUsersRequest {
        let selected = self.status.map(OrgMemberStatusFilter::split);
        ListOrgUsersRequest {
            filter: OrgUserFilter {
                status: selected.map(|(status, _)| status),
                email_contains: self.email,
                ids: None,
            },
            invitation: selected.and_then(|(_, state)| state),
            sort,
            page: pagination,
        }
    }
}

/// A member an owner adds straight away, with a password they chose.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateOrgUserBody {
    /// Email address.
    pub email: String,
    /// The name shown for the new person in organization membership lists.
    pub display_name: String,
    /// The member's password, checked against the organization's password
    /// rules.
    pub password: String,
    /// Authority in the organization. Omit for `Member`, which grants no
    /// org-level authority on its own; `Owner` governs the organization.
    #[serde(default = "created_by_default")]
    #[schema(schema_with = crate::dto::schemas::org_role)]
    pub role: OrgRole,
}

/// The role a member added without one named gets: `Member`, as for an
/// invitation. `OrgRole`'s own default is the narrowest role, `Viewer`,
/// which is not what the body documents.
fn created_by_default() -> OrgRole {
    OrgRole::Member
}

impl CreateOrgUserBody {
    /// The member asked for, each value checked against `limits`.
    ///
    /// # Errors
    ///
    /// `422` when the address or display name is invalid.
    pub(crate) fn into_request(
        self,
        limits: &DomainLimits,
    ) -> Result<CreateOrgUserRequest, ApiError> {
        Ok(CreateOrgUserRequest {
            email: Email::new(&self.email).map_err(ApiError::validation)?,
            display_name: DisplayName::new(&self.display_name, &limits.display_name)
                .map_err(ApiError::validation)?,
            password: self.password,
            role: self.role,
        })
    }
}

/// The member just added.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CreateOrgUserResponse {
    /// The new user's ID.
    pub id: Uuid,
}

impl From<OrgUserId> for CreateOrgUserResponse {
    fn from(id: OrgUserId) -> Self {
        Self { id: *id.as_uuid() }
    }
}

/// The status a member moves to.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UpdateOrgUserStatusBody {
    /// The new status: `Active`, `Locked` or `Deactivated`.
    pub status: String,
}

impl UpdateOrgUserStatusBody {
    /// The move of `member` asked for.
    ///
    /// # Errors
    ///
    /// `422` for a status a member cannot be moved to by hand.
    pub(crate) fn for_member(
        self,
        member: OrgUserId,
    ) -> Result<UpdateOrgUserStatusRequest, ApiError> {
        let status = match self.status.as_str() {
            "Active" => OrgUserStatus::Active,
            "Locked" => OrgUserStatus::Locked,
            "Deactivated" => OrgUserStatus::Deactivated,
            other => {
                return Err(ApiError::validation(message!(
                    "api-invalid-status",
                    format!("invalid status: {other}")
                )));
            }
        };
        Ok(UpdateOrgUserStatusRequest { member, status })
    }
}

/// The organization role a member moves to.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ChangeOrgUserRoleBody {
    /// The role to grant: `Owner`, `Admin`, `Member`, `Billing` or `Viewer`.
    #[schema(schema_with = crate::dto::schemas::org_role)]
    pub role: OrgRole,
}

impl ChangeOrgUserRoleBody {
    /// The change of `member`'s role asked for.
    #[must_use]
    pub(crate) fn for_member(self, member: OrgUserId) -> ChangeOrgUserRoleRequest {
        ChangeOrgUserRoleRequest {
            member,
            role: self.role,
        }
    }
}

/// The address an owner moves another member to.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ChangeOrgUserEmailBody {
    /// The new address. It counts as unverified until the member follows
    /// the link mailed there.
    pub email: String,
}

impl ChangeOrgUserEmailBody {
    /// The change of `member`'s address asked for.
    ///
    /// # Errors
    ///
    /// `422` when the address is invalid.
    pub(crate) fn for_member(
        self,
        member: OrgUserId,
    ) -> Result<ChangeOrgUserEmailRequest, ApiError> {
        Ok(ChangeOrgUserEmailRequest {
            member,
            email: Email::new(&self.email).map_err(ApiError::validation)?,
        })
    }
}

/// The caller's own profile fields to change. Each is applied when present
/// and left unchanged when omitted or `null`.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UpdateOrgUserProfileBody {
    /// New display name.
    pub display_name: Option<String>,
    /// New preferred locale (BCP 47 tag, e.g. `en-US`). Overrides the
    /// organization default.
    pub locale: Option<String>,
    /// New preferred timezone (IANA id, e.g. `Europe/Berlin`). Overrides the
    /// organization default.
    pub timezone: Option<String>,
}

/// The changes a profile update makes: a new name, new preferences, or
/// both.
pub(crate) struct ProfileChange {
    /// The rename, when a display name was given.
    pub display_name: Option<ChangeOrgUserDisplayNameRequest>,
    /// The new language or timezone, when either was given.
    pub preferences: Option<UpdateOrgUserPreferencesRequest>,
}

impl UpdateOrgUserProfileBody {
    /// The changes to `member`'s profile asked for, each value checked
    /// against `limits`.
    ///
    /// # Errors
    ///
    /// `422` for an invalid display name, locale or timezone.
    pub(crate) fn for_member(
        self,
        member: OrgUserId,
        limits: &DomainLimits,
    ) -> Result<ProfileChange, ApiError> {
        let display_name = self
            .display_name
            .map(|name| DisplayName::new(name, &limits.display_name))
            .transpose()
            .map_err(ApiError::validation)?
            .map(|display_name| ChangeOrgUserDisplayNameRequest {
                member,
                display_name,
            });
        Ok(ProfileChange {
            display_name,
            preferences: profile_preferences(member, self.locale, self.timezone)?,
        })
    }
}

/// Parses supplied preferences in locale-then-timezone order, leaving omitted values unchanged.
fn profile_preferences(
    member: OrgUserId,
    locale: Option<String>,
    timezone: Option<String>,
) -> Result<Option<UpdateOrgUserPreferencesRequest>, ApiError> {
    let locale = locale
        .map(Locale::new)
        .transpose()
        .map_err(ApiError::validation)?
        .map(Preference::Own);
    let timezone = timezone
        .map(Timezone::new)
        .transpose()
        .map_err(ApiError::validation)?
        .map(Preference::Own);
    Ok(
        (locale.is_some() || timezone.is_some()).then_some(UpdateOrgUserPreferencesRequest {
            member,
            locale,
            timezone,
        }),
    )
}

/// The caller's own password change.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ChangePasswordBody {
    /// The current password.
    #[schema(format = Password)]
    pub old_password: String,
    /// The replacement credential to validate against the organization's password rules.
    #[schema(format = Password)]
    pub new_password: String,
}

impl From<ChangePasswordBody> for ChangeOrgUserPasswordRequest {
    fn from(body: ChangePasswordBody) -> Self {
        Self {
            current: Secret::new(body.old_password),
            new: Secret::new(body.new_password),
        }
    }
}

/// An owner setting another member's password.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ResetOrgUserPasswordBody {
    /// New password. If omitted, one is drawn to the organization's rules.
    pub password: Option<String>,
}

impl ResetOrgUserPasswordBody {
    /// The reset of `member`'s password asked for.
    #[must_use]
    pub(crate) fn for_member(self, member: OrgUserId) -> ResetOrgUserPasswordRequest {
        ResetOrgUserPasswordRequest {
            member,
            new_password: self.password,
        }
    }
}

/// The password a member now has, shown once to the owner.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ResetOrgUserPasswordResponse {
    /// The generated credential the owner must pass to the member.
    pub new_password: String,
}

impl From<ResetPasswordResult> for ResetOrgUserPasswordResponse {
    fn from(result: ResetPasswordResult) -> Self {
        Self {
            new_password: result.new_password.expose().to_owned(),
        }
    }
}

/// The roles a member holds in one tenant.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct SetOrgUserTenantAccessBody {
    /// Names of the tenant's roles the member should hold, replacing
    /// whatever they held before. An empty list withdraws access to the
    /// tenant.
    pub roles: Vec<String>,
}

impl SetOrgUserTenantAccessBody {
    /// The access of `member` in `tenant_slug` asked for.
    ///
    /// # Errors
    ///
    /// `422` when a role name is not a valid name.
    pub(crate) fn for_member(
        self,
        member: OrgUserId,
        tenant_slug: TenantSlug,
    ) -> Result<SetOrgUserTenantAccessRequest, ApiError> {
        let role_names = self
            .roles
            .into_iter()
            .map(|name| Label::new("roles", name))
            .collect::<Result<Vec<_>, _>>()
            .map_err(ApiError::validation)?;
        Ok(SetOrgUserTenantAccessRequest {
            member,
            tenant_slug,
            role_names,
        })
    }
}

/// What a member may reach across their organization.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OrgUserAccessResponse {
    /// The member's role in the organization.
    #[schema(schema_with = crate::dto::schemas::org_role)]
    pub role: OrgRole,
    /// Tenants the member can reach. For an `Owner` this is every tenant in
    /// the organization; for a `Member`, only the granted ones.
    pub tenants: Vec<TenantAccessResponse>,
}

/// One tenant a member can reach, and what they may do inside it.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct TenantAccessResponse {
    /// The tenant's unique ID.
    pub tenant_id: Uuid,
    /// The tenant's URL slug.
    pub slug: String,
    /// The tenant's display name.
    pub display_name: String,
    /// Names of the tenant roles the member holds here. Empty for an
    /// `Owner`, whose access comes from the org role.
    pub roles: Vec<String>,
    /// Every permission the member holds here, as `idp:<domain>:<action>`.
    pub permissions: Vec<String>,
}

/// A role a member can be given in one tenant.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct GrantableRoleResponse {
    /// The role's name, as `roles` in the request that sets a member's
    /// access names it.
    pub name: String,
}

impl From<Label> for GrantableRoleResponse {
    fn from(name: Label) -> Self {
        Self {
            name: name.to_string(),
        }
    }
}

impl From<OrgUserAccess> for OrgUserAccessResponse {
    fn from(access: OrgUserAccess) -> Self {
        Self {
            role: access.org_role,
            tenants: access
                .tenants
                .into_iter()
                .map(TenantAccessResponse::from)
                .collect(),
        }
    }
}

impl From<TenantAccess> for TenantAccessResponse {
    fn from(access: TenantAccess) -> Self {
        Self {
            tenant_id: *access.tenant_id.as_uuid(),
            slug: access.slug.as_str().to_owned(),
            display_name: access.display_name,
            roles: access.role_names,
            permissions: access.permissions.iter().map(ToString::to_string).collect(),
        }
    }
}

/// The account that leaves a group of linked accounts.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UnlinkIdentityBody {
    /// The address the group shares.
    pub email: String,
    /// The tenant whose account leaves the group.
    pub tenant_id: Uuid,
}

impl TryFrom<UnlinkIdentityBody> for UnlinkIdentityRequest {
    type Error = ApiError;

    fn try_from(body: UnlinkIdentityBody) -> Result<Self, Self::Error> {
        Ok(Self {
            email: Email::new(&body.email).map_err(ApiError::validation)?,
            tenant_id: TenantId::from_uuid(body.tenant_id),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Omitting a new member's role defaults it to Member.
    #[test]
    fn a_member_added_without_a_role_is_a_member() {
        let body: CreateOrgUserBody = serde_json::from_value(serde_json::json!({
            "email": "bob@example.com",
            "display_name": "Bob",
            "password": "Correct horse battery 1234",
        }))
        .unwrap();

        assert_eq!(body.role, OrgRole::Member);
    }
}
