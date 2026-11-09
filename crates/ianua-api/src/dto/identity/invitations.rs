//! Invitation bodies: inviting someone, and their accepting.

use ianua_app::email::{InvitationDelivery, LinkScope};
use ianua_app::use_cases::identity::invitations::{AcceptRequest, InviteUserRequest, Invited};
use ianua_domain::shared::config::DisplayNameLimits;
use ianua_domain::types::{DisplayName, Email, RoleId, Text};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;

/// Invites someone into the tenant.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct InviteUserBody {
    /// The address to invite.
    pub email: String,
    /// The name the invited account gets.
    pub display_name: String,
    /// The role accepting gives.
    pub role_id: String,
    /// A personal message for the invitation email. Blank counts as none.
    pub message: Option<String>,
}

impl InviteUserBody {
    /// The invitation asked for, under `limits`, its link landing on
    /// `scope`.
    ///
    /// # Errors
    ///
    /// [`ApiError::validation`] for an address, name, role id or message
    /// that is not a valid one.
    pub(crate) fn request(
        self,
        limits: &DisplayNameLimits,
        scope: LinkScope,
    ) -> Result<InviteUserRequest, ApiError> {
        let role = Uuid::parse_str(&self.role_id).map_err(ApiError::rejected)?;
        let message = self
            .message
            .filter(|message| !message.trim().is_empty())
            .map(|message| Text::new("message", message))
            .transpose()
            .map_err(ApiError::validation)?;
        Ok(InviteUserRequest {
            email: Email::new(self.email).map_err(ApiError::validation)?,
            display_name: DisplayName::new(self.display_name, limits)
                .map_err(ApiError::validation)?,
            role_id: RoleId::from_uuid(role),
            message,
            scope,
        })
    }
}

/// The invited user, and the accept link when nothing was mailed.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct InviteUserResponse {
    /// The invited user's id.
    pub id: Uuid,
    /// The single-use accept link, present only on a deployment with no
    /// mail server, where nothing was mailed: pass it on to the invitee
    /// yourself. Whoever holds it joins as the invited account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept_link: Option<String>,
}

impl From<Invited> for InviteUserResponse {
    fn from(invited: Invited) -> Self {
        Self {
            id: *invited.user_id.as_uuid(),
            accept_link: handed_over_link(&invited.delivery),
        }
    }
}

/// The accept link of an invitation sent again on a deployment with no
/// mail server, where nothing was mailed: pass it on to the invitee
/// yourself. Whoever holds it joins as the invited account.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct InvitationLinkResponse {
    /// The single-use accept link.
    pub accept_link: String,
}

impl InvitationLinkResponse {
    /// The link `delivery` hands over, or none for one that was mailed.
    #[must_use]
    pub(crate) fn handed_over(delivery: &InvitationDelivery) -> Option<Self> {
        handed_over_link(delivery).map(|accept_link| Self { accept_link })
    }
}

/// The accept link `delivery` hands over, as the response carries it.
pub(crate) fn handed_over_link(delivery: &InvitationDelivery) -> Option<String> {
    delivery.handed_over().map(|link| link.expose().to_owned())
}

/// Accepts an invitation from its emailed link.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct AcceptInvitationBody {
    /// The single-use token from the invitation email.
    pub token: String,
    /// The password the invitee chooses. Required when the tenant signs
    /// users in with a password; ignored, and never stored, when it does
    /// not.
    pub password: Option<String>,
}

impl From<AcceptInvitationBody> for AcceptRequest {
    fn from(body: AcceptInvitationBody) -> Self {
        Self {
            raw_token: body.token,
            password: body.password,
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::UserId;

    use super::*;

    const LINK: &str = "https://app.test/accept-invite?token=t";

    /// The JSON an invitation whose link went out by `delivery` answers.
    fn invited(delivery: InvitationDelivery) -> serde_json::Value {
        let response = InviteUserResponse::from(Invited {
            user_id: UserId::new(),
            delivery,
        });
        serde_json::to_value(response).unwrap()
    }

    /// A mailed invitation answers with the id alone, as before.
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
        let body = invited(InvitationDelivery::HandOver {
            link: Secret::new(LINK),
        });

        assert_eq!(body["accept_link"], LINK);
    }

    /// Sending again hands over a link only when nothing was mailed.
    #[test]
    fn a_resend_hands_over_a_link_only_when_nothing_was_mailed() {
        let handed = InvitationDelivery::HandOver {
            link: Secret::new(LINK),
        };

        assert!(InvitationLinkResponse::handed_over(&InvitationDelivery::Mailed).is_none());
        assert_eq!(
            InvitationLinkResponse::handed_over(&handed).map(|response| response.accept_link),
            Some(LINK.to_owned())
        );
    }
}
