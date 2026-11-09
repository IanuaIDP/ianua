//! A tenant's users, as its administrators manage them: who they are,
//! inviting and accepting, their status, and their sessions.

use serde::{Deserialize, Serialize};

/// One user of a tenant, from `GET …/users` and `GET …/users/{id}`.
#[derive(Debug, Clone, Deserialize)]
pub struct User {
    /// Handle used to manage this tenant account and its sessions.
    pub id: String,
    /// Their address.
    pub email: String,
    /// Human-readable label shown in the tenant's user list.
    pub display_name: String,
    /// `Invited`, `PendingVerification`, `Active`, `Locked`, `Deactivated`
    /// or `Closing`.
    pub status: String,
    /// Whether their address was proved.
    pub email_verified: bool,
    /// The roles they hold directly, in a listing.
    #[serde(default)]
    pub roles: Vec<RoleName>,
    /// `Pending` or `Expired` while an invitation is open.
    #[serde(default)]
    pub invitation_status: Option<String>,
    /// The person's details and the directory's records about them.
    #[serde(default)]
    pub profile: Option<UserProfile>,
}

/// What `GET …/users/{id}` holds about a person beyond their name and
/// address; every field is empty until something sets it.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct UserProfile {
    /// The personal name recorded separately from the surname.
    #[serde(default)]
    pub given_name: Option<String>,
    /// The surname recorded separately from the personal name.
    #[serde(default)]
    pub family_name: Option<String>,
    /// The name they go by.
    #[serde(default)]
    pub preferred_username: Option<String>,
    /// Their phone number, their word only.
    #[serde(default)]
    pub phone_number: Option<String>,
    /// What another directory calls the account.
    #[serde(default)]
    pub external_id: Option<String>,
    /// The organizational unit recorded by the company directory.
    #[serde(default)]
    pub department: Option<String>,
    /// The id of the user they report to.
    #[serde(default)]
    pub manager_id: Option<String>,
    /// The staff identifier the company directory assigned.
    #[serde(default)]
    pub employee_number: Option<String>,
}

/// `PUT …/users/{id}/details`: a person's own details, the whole set; a
/// field left out is cleared.
#[derive(Debug, Clone, Default, Serialize)]
pub struct UserDetails {
    /// The personal name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    /// The surname.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    /// The name they go by.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    /// A phone number in international form.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
}

/// `PUT …/users/{id}/records`: the company's records about a user, the
/// whole set; a field left out is cleared.
#[derive(Debug, Clone, Default, Serialize)]
pub struct UserRecords {
    /// What another directory calls the account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// The organizational unit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
    /// The id of the user they report to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manager_id: Option<String>,
    /// The staff identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub employee_number: Option<String>,
}

/// `POST …/users/import`: accounts brought over from another system.
/// Holds hashes, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct ImportUsers {
    /// The accounts, each address once.
    pub users: Vec<ImportedAccount>,
}

/// One account to bring over. Holds a hash, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct ImportedAccount {
    /// The account's address, unproved until its mailed link is followed.
    pub email: String,
    /// The name it shows.
    pub display_name: String,
    /// The password hash the other system kept, in its usual encoded form.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,
}

/// The answer to `POST …/users/import`: the import, to follow by its id.
#[derive(Debug, Clone, Deserialize)]
pub struct ImportStarted {
    /// The import's id.
    pub import_id: String,
}

/// `GET …/users/imports/{id}`: how far an import got.
#[derive(Debug, Clone, Deserialize)]
pub struct ImportProgress {
    /// `pending`, `running`, `finished` or `failed`.
    pub status: String,
    /// Every record sent.
    pub total: u32,
    /// The accounts opened so far.
    pub imported: u32,
    /// The records set aside so far.
    pub failed: u32,
    /// The records not worked through yet.
    pub remaining: u32,
    /// The records set aside, in the order they came.
    pub errors: Vec<ImportSetAside>,
}

/// One record an import set aside: it names no address and no hash.
#[derive(Debug, Clone, Deserialize)]
pub struct ImportSetAside {
    /// Where the record stood in the request, counted from one.
    pub line: u32,
    /// `address_taken`, `own_manager` or `user_limit_reached`.
    pub reason: String,
}

/// A role as a user's record names it.
#[derive(Debug, Clone, Deserialize)]
pub struct RoleName {
    /// The role's id.
    pub id: String,
    /// Label of a role directly assigned to the listed user.
    pub name: String,
}

/// `POST …/users/invite`: an invitation into the tenant with one role.
#[derive(Debug, Clone, Serialize)]
pub struct InviteUser {
    /// The address the invitation goes to.
    pub email: String,
    /// Human-readable label assigned to the invited tenant user.
    pub display_name: String,
    /// The role they join with.
    pub role_id: String,
}

/// The invitation made. Holds the link when no mail goes out, so it has
/// no `Debug`.
#[derive(Clone, Deserialize)]
pub struct UserInvited {
    /// The invited user's id.
    pub id: String,
    /// The link to accept with, only when the deployment sends no mail.
    #[serde(default)]
    pub accept_link: Option<String>,
}

/// `POST …/users/accept-invitation`: the mailed token and the password
/// chosen. Holds both, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct AcceptInvitation {
    /// The token from the mailed link.
    pub token: String,
    /// The password chosen.
    pub password: String,
}

/// The user an accepted invitation made active; no session is opened.
#[derive(Debug, Clone, Deserialize)]
pub struct UserJoined {
    /// Handle of the account activated by accepting the invitation.
    pub id: String,
}

/// `POST …/users/invitation-status`. Holds the token, so it has no
/// `Debug`.
#[derive(Clone, Serialize)]
pub struct LinkToken {
    /// The token from the link.
    pub token: String,
}

/// What a mailed link is worth.
#[derive(Debug, Clone, Deserialize)]
pub struct LinkStatus {
    /// `Valid`, `Expired`, `AlreadyUsed` or `Invalid`.
    pub status: String,
    /// The password rules a usable link offers its form under, when it
    /// carries them.
    #[serde(default)]
    pub password_policy: Option<serde_json::Value>,
}

/// `PATCH …/users/{id}`: what changes on a user's record.
#[derive(Debug, Clone, Default, Serialize)]
pub struct UserChange {
    /// Their new name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// `POST …/users/{id}/status`.
#[derive(Debug, Clone, Serialize)]
pub struct ChangeUserStatus {
    /// `Active`, `Locked` or `Deactivated`.
    pub status: String,
}

/// One session of a tenant user, from `GET …/me/sessions` and
/// `GET …/users/{id}/sessions`.
#[derive(Debug, Clone, Deserialize)]
pub struct Session {
    /// Handle used to suspend, resume or revoke this sign-in.
    pub id: String,
    /// `active` or `suspended`.
    pub status: String,
    /// How it signed in: `password`, `magic_link`, `passkey`, `saml` or
    /// `oidc`.
    pub auth_method: String,
    /// Whether its second factor was given.
    pub mfa_satisfied: bool,
    /// Whether it is the session asking.
    pub current: bool,
}

/// `POST …/users/{id}/reset-factors`: what was cleared for someone who
/// lost their device.
#[derive(Debug, Clone, Deserialize)]
pub struct FactorsCleared {
    /// Second factors turned off, in force or still being set up.
    pub enrollments_turned_off: usize,
    /// Passkeys the person can no longer sign in with.
    pub passkeys_removed: usize,
}
