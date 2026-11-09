//! A person's own account: their preferences, a move to another mailbox,
//! their consent, exports and erasure, the accounts of theirs they link
//! across tenants, and their link to an identity provider.

use serde::{Deserialize, Serialize};

/// The own-account response shared by members and tenant users.
#[derive(Debug, Deserialize)]
pub struct Account {
    /// The unchanged account identity across edits.
    pub id: String,
    /// The current sign-in address.
    pub email: String,
    /// The name shown to colleagues.
    pub display_name: String,
    /// Whether the mailbox has actually been proved.
    pub email_verified: bool,
    /// The account's current standing.
    pub status: String,
    /// An explicit language preference, or inherited default.
    pub locale: Option<String>,
    /// An explicit timezone preference, or inherited default.
    pub timezone: Option<String>,
}

/// An own-profile update; omitted fields retain the existing value.
#[derive(Default, Serialize)]
pub struct Preferences {
    /// A member's new name; tenant preferences do not change names.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// A new BCP 47 language tag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    /// A new IANA timezone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
}

/// A new address and re-entered proof. Holds secrets, so no Debug.
#[derive(Serialize)]
pub struct EmailChange {
    /// The proposed address, not current until confirmed.
    pub new_email: String,
    /// The holder's current password.
    pub password: String,
    /// A fresh code when the holder has a factor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

/// One grant or withdrawal on explicitly versioned consent terms.
#[derive(Debug, Serialize, Deserialize)]
pub struct Consent {
    /// The purpose the person decides on.
    pub consent_type: String,
    /// Which terms the decision applies to.
    pub version: String,
    /// Whether consent is given or withdrawn.
    pub granted: bool,
}

/// A newly requested export or erasure, named for subsequent operations.
#[derive(Debug, Deserialize)]
pub struct Requested {
    /// The request's opaque id.
    pub id: String,
}

/// An export as its holder sees its asynchronous progress.
#[derive(Debug, Deserialize)]
pub struct Export {
    /// The request's id.
    pub id: String,
    /// `access` or `portability`.
    pub scope: String,
    /// `requested`, `ready` or `expired`.
    pub status: String,
    /// `holder` or `staff`.
    pub asked_by: String,
}

/// A short-lived single-use file link. Holds a bearer secret, so no Debug.
#[derive(Deserialize)]
pub struct Download {
    /// The signed URL returned only to the person the export describes.
    pub url: String,
}

/// `POST …/users/{id}/exports`: which export is asked for.
#[derive(Debug, Clone, Serialize)]
pub struct ExportRequest {
    /// `access` or `portability`.
    pub scope: String,
}

/// `POST …/users/{id}/erasure`, on either plane: why the account is to go.
#[derive(Debug, Clone, Serialize)]
pub struct ErasureRequest {
    /// The reason given.
    pub reason: String,
}

/// `POST …/auth/tenant/switch`: the tenant whose linked account the
/// session moves into. The account is not named: it is the caller's own,
/// followed across the link.
#[derive(Debug, Clone, Serialize)]
pub struct LinkedSwitch {
    /// The tenant's id.
    pub target_tenant_id: String,
}

/// The session a switch opened in the linked account. Holds its token,
/// so it has no `Debug`.
#[derive(Clone, Deserialize)]
pub struct LinkedSession {
    /// The linked account signed in to.
    pub user_id: String,
    /// The new session's id.
    pub session_id: String,
    /// Its token, as `Authorization: Bearer`.
    pub refresh_token: String,
    /// Whether it owes more before it is let in, as a sign-in to the
    /// linked account would.
    pub mfa_required: bool,
}

/// `DELETE …/identities`: the account leaving its group of linked
/// accounts.
#[derive(Debug, Clone, Serialize)]
pub struct Unlink {
    /// The address the group shares.
    pub email: String,
    /// The tenant whose account leaves.
    pub tenant_id: String,
}

/// `GET …/federation/links`: the caller's links to identity providers,
/// oldest first.
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderLinks {
    /// Each link.
    pub links: Vec<ProviderLink>,
}

/// One link of an account to a provider.
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderLink {
    /// The connection the provider is reached through.
    pub connection_id: String,
    /// The id the provider knows the person by.
    pub subject: String,
}

/// `POST …/federation/connections/{id}/link/reconfirm`: the holder proved
/// again. Holds a password, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct ReconfirmLink {
    /// What the holder typed again just now.
    pub proof: LinkProof,
}

/// What a person gives to confirm their provider link again, the way they
/// sign in. Holds a password, so it has no `Debug`.
#[derive(Clone, Serialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum LinkProof {
    /// Their password, with a code from their second factor when they
    /// have one.
    Password {
        /// The password as typed.
        password: String,
        /// The code their authenticator shows, if they have one.
        #[serde(skip_serializing_if = "Option::is_none")]
        code: Option<String>,
    },
}
