//! An organization's members, as its members read and manage them: who
//! they are, their role, the tenants they reach, invitations, sessions,
//! how they sign in, the organization's own identity provider, and its
//! API keys.

use serde::{Deserialize, Serialize};

use super::sign_in::MemberProof;

/// The company profile and lifecycle returned to its own members.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Organization {
    /// Its durable identifier.
    pub id: String,
    /// Its address, retained when its display names change.
    pub slug: String,
    /// Its registered name.
    pub name: String,
    /// Its contact mailbox, which does not prove any member's address.
    pub contact_email: String,
    /// Its name shown to members.
    pub display_name: String,
    /// `Active`, `Suspended` or `Closed`.
    pub status: String,
    /// The number of tenants still belonging to it.
    pub tenant_count: usize,
}

/// A partial company profile update; omitted fields retain their values.
#[derive(Debug, Clone, Default, Serialize)]
pub struct OrganizationChange {
    /// A replacement registered name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// A replacement contact mailbox.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_email: Option<String>,
    /// A replacement display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// How an organization's members sign in, from `GET …/auth-config`, and
/// sent back whole with `PUT`. The fields a scenario changes are named;
/// every other one is kept as it came, so a replace changes only what was
/// meant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgSignInSettings {
    /// The ways in: `Password`, `MagicLink`, `Passkey`, `Saml`, `Oidc`.
    pub enabled_methods: Vec<String>,
    /// Every other setting, as the API answered it.
    #[serde(flatten)]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

/// `PUT …/auth-config`: the whole settings and the caller's password
/// typed again. Holds the password, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct ReplaceOrgSignInSettings {
    /// The settings, whole.
    #[serde(flatten)]
    pub settings: OrgSignInSettings,
    /// The caller, proved again.
    pub proof: MemberProof,
}

/// A member's authority in their organization, as the API spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrgRole {
    /// Reads the organization and its billing; reaches no tenant.
    Viewer,
    /// Manages billing; reaches no tenant.
    Billing,
    /// Reads the organization; reaches the tenants granted to them.
    Member,
    /// Manages everything but closing and billing; reaches every tenant.
    Admin,
    /// Governs the organization.
    Owner,
}

/// One member of an organization, from `GET …/users`.
#[derive(Debug, Clone, Deserialize)]
pub struct Member {
    /// Handle used to manage this member's status, role and tenant grants.
    pub id: String,
    /// Their address.
    pub email: String,
    /// Human-readable label shown to colleagues in the member list.
    pub display_name: String,
    /// Their account's status, such as `Active`.
    pub status: String,
    /// Whether their address was proved.
    pub email_verified: bool,
    /// Organization authority included when the endpoint reports membership.
    #[serde(default)]
    pub role: Option<OrgRole>,
}

/// `POST …/users`: an invitation to join the organization.
#[derive(Debug, Clone, Serialize)]
pub struct InviteMember {
    /// The address the invitation goes to.
    pub email: String,
    /// Human-readable label assigned to the invited member.
    pub display_name: String,
    /// The role they join with.
    pub role: OrgRole,
}

/// The invitation made. Holds the link when no mail goes out, so it has
/// no `Debug`.
#[derive(Clone, Deserialize)]
pub struct MemberInvited {
    /// The invited member's id.
    pub id: String,
    /// The link to accept with, only when the deployment sends no mail.
    #[serde(default)]
    pub accept_link: Option<String>,
}

/// `POST …/users/accept-invitation`: the mailed token and the new
/// password. Holds both, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct AcceptMemberInvitation {
    /// The token from the mailed link.
    pub token: String,
    /// The password they choose.
    pub password: String,
}

/// The member an accepted invitation made active.
#[derive(Debug, Clone, Deserialize)]
pub struct MemberJoined {
    /// Handle of the account activated by accepting the invitation.
    pub id: String,
}

/// An administrator provisions a member with a chosen password. No `Debug`
/// because the password must remain private in failed scenario diagnostics.
#[derive(Clone, Serialize)]
pub struct CreateMember {
    /// The new member's mailbox.
    pub email: String,
    /// The name shown to colleagues.
    pub display_name: String,
    /// A password checked against the organization's current policy.
    pub password: String,
    /// The authority offered, defaulting to `Member` when omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<OrgRole>,
}

/// A role offered when giving a member access to a tenant.
#[derive(Debug, Clone, Deserialize)]
pub struct GrantableRole {
    /// The name [`TenantRoles`] gives it by.
    pub name: String,
}

/// `PUT …/users/{id}/tenants/{tenant}`: the tenant roles a member holds
/// there, by name, replacing what they held.
#[derive(Debug, Clone, Serialize)]
pub struct TenantRoles {
    /// The roles' names, such as `Admin`; none withdraws the tenant.
    pub roles: Vec<String>,
}

/// `PATCH …/users/{id}/role`.
#[derive(Debug, Clone, Serialize)]
pub struct ChangeRole {
    /// The new role.
    pub role: OrgRole,
}

/// `PATCH …/users/{id}/status`.
#[derive(Debug, Clone, Serialize)]
pub struct ChangeMemberStatus {
    /// `Active`, `Locked` or `Deactivated`.
    pub status: String,
}

/// `PATCH …/users/{id}/email`: the new address an administrator moves a
/// member to.
#[derive(Debug, Clone, Serialize)]
pub struct ChangeMemberEmail {
    /// The new address, unverified until the link mailed there is followed.
    pub email: String,
}

/// `POST …/users/send-verification`: whose mailbox another proof is asked
/// for.
#[derive(Debug, Clone, Serialize)]
pub struct MemberAddress {
    /// The address on the account.
    pub email: String,
}

/// `POST …/users/invitation-resend`: when another may be asked for.
#[derive(Debug, Clone, Deserialize)]
pub struct InvitationRenewed {
    /// Seconds before the next replacement may be requested.
    pub retry_after_seconds: u64,
}

/// A signed-in member replacing their password after proving the current one.
/// Both values are secrets, so this request has no `Debug`.
#[derive(Clone, Serialize)]
pub struct ChangeMemberPassword {
    /// The password currently protecting the member.
    pub old_password: String,
    /// The replacement, subject to the organization's current rules.
    pub new_password: String,
}

/// An administrator choosing a member's replacement password, or asking
/// the platform to generate one. Contains a secret and has no `Debug`.
#[derive(Clone, Serialize)]
pub struct ResetMemberPassword {
    /// The chosen password, absent to generate one.
    pub password: Option<String>,
}

/// The replacement shown once after an administrative reset. No `Debug`
/// because an assertion must not expose the generated password.
#[derive(Clone, Deserialize)]
pub struct MemberPasswordReset {
    /// The password now protecting the member.
    pub new_password: String,
}

/// What a member reaches: their role and the tenants it opens.
#[derive(Debug, Clone, Deserialize)]
pub struct Reach {
    /// Organization authority governing which tenants the member can reach.
    pub role: OrgRole,
    /// The tenants they reach.
    pub tenants: Vec<ReachedTenant>,
}

/// A tenant a member reaches, and what they hold there.
#[derive(Debug, Clone, Deserialize)]
pub struct ReachedTenant {
    /// The tenant's id.
    pub tenant_id: String,
    /// URL segment used to address this tenant in API requests.
    pub slug: String,
    /// The tenant roles they hold there; none for an owner or admin, who
    /// reach it whole.
    pub roles: Vec<String>,
    /// What those roles let them do, such as `idp:users:view`.
    pub permissions: Vec<String>,
}

/// One live session of the organization, from `GET …/sessions/active`.
#[derive(Debug, Clone, Deserialize)]
pub struct ActiveSession {
    /// Handle used to revoke this member's active sign-in.
    pub session_id: String,
    /// When it began.
    pub created_at: String,
}

/// `POST …/api-keys`: an organization key and what it may do.
#[derive(Debug, Clone, Serialize)]
pub struct NewOrgApiKey {
    /// The name it is listed under.
    pub name: String,
    /// What it may do, such as `org:members:view`.
    pub scopes: Vec<String>,
}

/// `POST …/api-keys` with an end: an organization key that stops working
/// when `expires_at` comes.
#[derive(Debug, Clone, Serialize)]
pub struct NewEndingOrgApiKey {
    /// The name it is listed under.
    pub name: String,
    /// What it may do, such as `org:members:view`.
    pub scopes: Vec<String>,
    /// When it stops working, in RFC 3339.
    pub expires_at: String,
}

/// The key made, shown this once. Holds it, so it has no `Debug`.
#[derive(Clone, Deserialize)]
pub struct OrgApiKeyMade {
    /// The key's id.
    pub id: String,
    /// The key, sent as `Authorization: Bearer`.
    pub raw_key: String,
    /// The part of it that names it in lists.
    pub key_prefix: String,
}

/// One organization key, from `GET …/api-keys`.
#[derive(Debug, Clone, Deserialize)]
pub struct OrgApiKey {
    /// Handle used to revoke this organization credential.
    pub id: String,
    /// Label distinguishing the credential in the organization's list.
    pub name: String,
    /// The part of it that names it.
    pub key_prefix: String,
    /// Whether it was revoked.
    pub revoked: bool,
}

/// `POST …/identity-provider`: the organization's own identity provider,
/// which signs its members in to the dashboard. Holds an OIDC client
/// secret, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct AddIdentityProvider {
    /// The name members see on the sign-in page.
    pub name: String,
    /// How it is reached.
    pub config: IdentityProviderConfig,
}

/// How an identity provider is reached, as `{"Saml": {...}}` or
/// `{"Oidc": {...}}`. Holds an OIDC client secret, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub enum IdentityProviderConfig {
    /// SAML 2.0, each setting given by hand.
    Saml {
        /// The provider's entity id.
        entity_id: String,
        /// Where sign-in requests go.
        sso_url: String,
        /// The certificate its answers are signed with, PEM.
        certificate: String,
        /// The `NameID` format it names people by.
        name_id_format: String,
    },
    /// OpenID Connect.
    Oidc {
        /// The issuer, whose discovery document names its endpoints.
        issuer: String,
        /// The client id the platform is registered under.
        client_id: String,
        /// The client secret as the provider issued it; the field keeps
        /// the name the dashboard sends.
        encrypted_client_secret: String,
        /// The scopes asked for.
        scopes: Vec<String>,
    },
}

impl IdentityProviderConfig {
    /// The sign-in method the organization enables for it: `Saml` or
    /// `Oidc`.
    #[must_use]
    pub fn method(&self) -> &'static str {
        match self {
            Self::Saml { .. } => "Saml",
            Self::Oidc { .. } => "Oidc",
        }
    }
}

/// `PATCH …/identity-provider`: a change to the provider, with the
/// caller's proof. A field left out keeps its value. Holds the password,
/// so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct ChangeIdentityProvider {
    /// Whether the addresses it reports are taken as proven:
    /// `Unverified` or `Authoritative`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_trust: Option<String>,
    /// The caller, proved again.
    pub proof: MemberProof,
}

/// `PUT …/subscription`: the plan the organization moves to.
#[derive(Debug, Clone, Serialize)]
pub struct PlanChoice {
    /// `Free`, `Starter` or `Business`.
    pub plan: String,
}

/// `PUT …/identity-provider/status`: switches the provider on or off.
/// Holds the password, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct SwitchIdentityProvider {
    /// `Active` or `Disabled`.
    pub status: String,
    /// The caller, proved again.
    pub proof: MemberProof,
}

/// The organization's identity provider, as the API answers it, without
/// its configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct IdentityProvider {
    /// Handle identifying the provider configured for member sign-in.
    pub id: String,
    /// `Saml` or `Oidc`.
    pub protocol: String,
    /// `Active` or `Disabled`.
    pub status: String,
    /// `Unverified` or `Authoritative`.
    pub email_trust: String,
}
