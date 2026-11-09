//! Invitation and address-confirmation bodies: inviting a member, the
//! links an invitee or a new member follows, and what such a link is worth.

use ianua_app::email::{LinkScope, VerificationResent, VerificationTokenStatus};
use ianua_app::use_cases::organization::invitations::{
    AcceptOrgRequest, FollowedInvitation, InviteOrgUserRequest, OrgInvited, RenewOrgRequest,
    ResendOrgVerificationRequest,
};
use ianua_domain::domains::organization::members::membership::OrgRole;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::types::{
    DisplayName, Email, OrgUserId, OrganizationId, PasswordLinkStatus, Text, TokenStatus,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::dto::identity::invitations::handed_over_link;
use crate::error::ApiError;

/// Someone to invite into the organization.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct InviteOrgUserBody {
    /// Email address.
    pub email: String,
    /// The name shown for the invited person in organization membership lists.
    pub display_name: String,
    /// Authority in the organization. Omit for `Member`, which grants no
    /// org-level authority on its own; only an owner invites an owner.
    #[serde(default = "invited_by_default")]
    #[schema(schema_with = crate::dto::schemas::org_role)]
    pub role: OrgRole,
    /// A personal message for the invitation mail.
    #[serde(default)]
    pub message: Option<String>,
}

/// The role an invitation naming none gives: a member, as the contract
/// says. The domain's own default is the narrower viewer, so it is not
/// leaned on here.
fn invited_by_default() -> OrgRole {
    OrgRole::Member
}

impl InviteOrgUserBody {
    /// The invitation asked for, its link landing on `links`, each value
    /// checked against `limits`.
    ///
    /// # Errors
    ///
    /// `422` when the address, display name or message is invalid.
    pub(crate) fn into_request(
        self,
        links: LinkScope,
        limits: &DomainLimits,
    ) -> Result<InviteOrgUserRequest, ApiError> {
        Ok(InviteOrgUserRequest {
            email: Email::new(&self.email).map_err(ApiError::validation)?,
            display_name: DisplayName::new(&self.display_name, &limits.display_name)
                .map_err(ApiError::validation)?,
            role: self.role,
            message: self
                .message
                .map(|message| Text::new("message", message))
                .transpose()
                .map_err(ApiError::validation)?,
            scope: links,
        })
    }
}

/// The member just invited, and the accept link when nothing was mailed.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct InvitedOrgUserResponse {
    /// The member's ID.
    pub id: Uuid,
    /// The single-use accept link, present only on a deployment with no
    /// mail server, where nothing was mailed: pass it on to the invitee
    /// yourself. Whoever holds it joins as the invited member.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept_link: Option<String>,
}

impl From<OrgInvited> for InvitedOrgUserResponse {
    fn from(invited: OrgInvited) -> Self {
        Self {
            id: *invited.org_user_id.as_uuid(),
            accept_link: handed_over_link(&invited.delivery),
        }
    }
}

/// The member an invitation, an accepted invitation or a confirmed address
/// concerns.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OrgUserIdResponse {
    /// The member's ID.
    pub id: Uuid,
}

impl From<OrgUserId> for OrgUserIdResponse {
    fn from(id: OrgUserId) -> Self {
        Self { id: *id.as_uuid() }
    }
}

/// Accepting an invitation: the token from its link and the password the
/// invitee chooses.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct AcceptOrgInvitationBody {
    /// The token from the invitation email.
    pub token: String,
    /// The password the invitee chooses for their account.
    #[schema(format = Password)]
    pub password: String,
}

impl AcceptOrgInvitationBody {
    /// The acceptance of an invitation of `organization_id`.
    #[must_use]
    pub(crate) fn for_organization(self, organization_id: OrganizationId) -> AcceptOrgRequest {
        AcceptOrgRequest {
            organization_id,
            raw_token: self.token,
            password: self.password,
        }
    }
}

/// A member named by address, for the flows that run before they can sign
/// in.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OrgEmailBody {
    /// The member's email address.
    pub email: String,
}

impl OrgEmailBody {
    /// The address named.
    ///
    /// # Errors
    ///
    /// `422` when it is not an address.
    pub(crate) fn email(&self) -> Result<Email, ApiError> {
        Email::new(&self.email).map_err(ApiError::validation)
    }

    /// Another verification link for this address in `organization_id`,
    /// landing on `links`.
    ///
    /// # Errors
    ///
    /// `422` when it is not an address.
    pub(crate) fn resend_in(
        &self,
        organization_id: OrganizationId,
        links: LinkScope,
    ) -> Result<ResendOrgVerificationRequest, ApiError> {
        Ok(ResendOrgVerificationRequest {
            organization_id,
            email: self.email()?,
            scope: links,
        })
    }
}

/// The token from an emailed link.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OrgTokenBody {
    /// The single-use token from the email.
    pub token: String,
}

impl OrgTokenBody {
    /// The invitation link of `organization_id` this token was followed
    /// from.
    #[must_use]
    pub(crate) fn invitation_of(self, organization_id: OrganizationId) -> FollowedInvitation {
        FollowedInvitation {
            organization_id,
            raw_token: self.token,
        }
    }

    /// The renewal of the invitation link of `organization_id` this token
    /// was followed from, the new link landing on `scope`.
    #[must_use]
    pub(crate) fn renewal_of(
        self,
        organization_id: OrganizationId,
        scope: LinkScope,
    ) -> RenewOrgRequest {
        RenewOrgRequest {
            organization_id,
            raw_token: self.token,
            scope,
        }
    }
}

/// What a link that sets a password is worth, and the rules the new
/// password must meet.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PasswordLinkStatusResponse {
    /// `Valid`, `Expired`, `AlreadyUsed`, or `Invalid`.
    pub status: TokenStatusDto,
    /// The policy the new password must meet. Present only when `status`
    /// is `Valid`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub password_policy: Option<ianua_domain::types::PasswordPolicy>,
}

impl From<PasswordLinkStatus> for PasswordLinkStatusResponse {
    fn from(answer: PasswordLinkStatus) -> Self {
        Self {
            status: answer.token_status().into(),
            password_policy: answer.password_policy().cloned(),
        }
    }
}

/// The wire spelling of an emailed token's state.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) enum TokenStatusDto {
    /// Unspent and in date: offer the action.
    Valid,
    /// Out of date or superseded; offer to send another link.
    Expired,
    /// Already spent, so the action has happened.
    AlreadyUsed,
    /// No such token: mistyped, truncated by a mail client, or never ours.
    Invalid,
}

impl From<TokenStatus> for TokenStatusDto {
    fn from(status: TokenStatus) -> Self {
        match status {
            TokenStatus::Valid => Self::Valid,
            TokenStatus::Expired => Self::Expired,
            TokenStatus::AlreadyUsed => Self::AlreadyUsed,
            TokenStatus::Invalid => Self::Invalid,
        }
    }
}

/// What a verification link is worth, without spending it.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct VerificationTokenStatusResponse {
    /// `Valid`, `Expired`, or `Verified`.
    pub status: VerificationTokenStatusDto,
}

/// The wire spelling of a verification token's state.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) enum VerificationTokenStatusDto {
    /// Following the link will confirm the address.
    Valid,
    /// Out of date or superseded; ask for another link.
    Expired,
    /// The address is already confirmed; nothing to do.
    Verified,
}

impl From<VerificationTokenStatus> for VerificationTokenStatusResponse {
    fn from(status: VerificationTokenStatus) -> Self {
        let status = match status {
            VerificationTokenStatus::Valid => VerificationTokenStatusDto::Valid,
            VerificationTokenStatus::Expired => VerificationTokenStatusDto::Expired,
            VerificationTokenStatus::Verified => VerificationTokenStatusDto::Verified,
        };
        Self { status }
    }
}

/// Confirmation that another verification email is on its way.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct VerificationResentResponse {
    /// Seconds before another may be requested. Count this down rather than
    /// assuming a value: it is the wait the server enforces, and a request
    /// made sooner comes back `429`.
    pub retry_after_seconds: u64,
}

impl From<VerificationResent> for VerificationResentResponse {
    fn from(resent: VerificationResent) -> Self {
        Self {
            retry_after_seconds: resent.retry_after_seconds,
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::email::InvitationDelivery;
    use ianua_domain::shared::security::secret::Secret;

    use super::*;

    /// Ann invites Bob without naming a role. The contract promises he
    /// joins as a member, not as a viewer who reaches no tenant.
    #[test]
    fn an_invitation_naming_no_role_invites_a_member() {
        let body: InviteOrgUserBody =
            serde_json::from_str(r#"{"email":"bob@acme.test","display_name":"Bob"}"#)
                .expect("a body without a role reads");

        assert_eq!(body.role, OrgRole::Member);
    }

    /// A role that is named is the one invited.
    #[test]
    fn an_invitation_naming_a_role_invites_that_role() {
        let body: InviteOrgUserBody = serde_json::from_str(
            r#"{"email":"bob@acme.test","display_name":"Bob","role":"Viewer"}"#,
        )
        .expect("a body with a role reads");

        assert_eq!(body.role, OrgRole::Viewer);
    }

    /// The JSON a member's invitation whose link went out by `delivery`
    /// answers.
    fn invited(delivery: InvitationDelivery) -> serde_json::Value {
        let response = InvitedOrgUserResponse::from(OrgInvited {
            org_user_id: OrgUserId::new(),
            delivery,
        });
        serde_json::to_value(response).unwrap()
    }

    /// A mailed invitation answers with the member's id alone.
    #[test]
    fn a_mailed_invitation_carries_no_link() {
        let body = invited(InvitationDelivery::Mailed);

        assert!(body.get("accept_link").is_none());
        assert!(body.get("id").is_some());
    }

    /// An invitation on a deployment with no mail server hands the inviter
    /// its accept link.
    #[test]
    fn a_handed_over_invitation_carries_its_link() {
        let link = "https://app.test/accept-invite?org=acme&token=t";

        let body = invited(InvitationDelivery::HandOver {
            link: Secret::new(link),
        });

        assert_eq!(body["accept_link"], link);
    }
}
