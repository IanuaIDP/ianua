//! A tenant's directory link over SCIM 2.0: switching the endpoint on, the
//! token a directory calls it with, what it does with the users it makes,
//! and the users as the directory sends and reads them.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The bearer token a directory calls the SCIM endpoint with, from
/// `POST …/federation/scim` and `POST …/federation/scim/rotate-token`.
/// Holds the token, so it has no `Debug`.
#[derive(Clone, Deserialize)]
pub struct DirectoryToken {
    /// The token, shown this once; `null` when the endpoint was switched
    /// on again and keeps the token it had.
    pub bearer_token: Option<String>,
}

/// Whether the tenant's SCIM endpoint is set up, from
/// `GET …/federation/scim`, with everything else it answered, so a
/// scenario can search the whole answer for a token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryStatus {
    /// Whether it was ever set up.
    pub configured: bool,
    /// Every other field, as the API answered it.
    #[serde(flatten)]
    pub rest: serde_json::Map<String, Value>,
}

/// `PUT …/federation/scim/settings`: what the endpoint does with the
/// users the directory makes and removes.
#[derive(Debug, Clone, Serialize)]
pub struct DirectorySettings {
    /// The role every user the directory makes starts with; `null` for
    /// none beyond the tenant's defaults.
    pub default_role_id: Option<String>,
    /// Whether users the directory makes are active at once.
    pub auto_activate: bool,
    /// Whether a user the directory removes is deactivated and kept.
    pub deactivate_on_remove: bool,
}

/// `POST /scim/v2/…/Users`: a user as the directory sends one.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryUser {
    /// Their address, which SCIM calls the user name.
    pub user_name: String,
    /// Human-readable label supplied by the external directory.
    pub display_name: String,
    /// Whether they may sign in.
    pub active: bool,
    /// The directory's own id for them.
    pub external_id: String,
}

/// A user as the endpoint answers the directory.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryResource {
    /// The tenant's id for them.
    pub id: String,
    /// Their address.
    #[serde(default)]
    pub user_name: String,
    /// Human-readable label returned for this tenant account.
    #[serde(default)]
    pub display_name: String,
    /// Whether they may sign in.
    #[serde(default)]
    pub active: bool,
    /// The directory's own id for them, when it set one.
    #[serde(default)]
    pub external_id: Option<String>,
    /// Their name's parts, as the endpoint keeps them.
    #[serde(default)]
    pub name: Option<DirectoryName>,
    /// Their addresses: the sign-in address, as a list of one.
    #[serde(default)]
    pub emails: Vec<DirectoryEmail>,
    /// The schemas the record names: the core one, and the enterprise
    /// extension when it carries any of its fields.
    #[serde(default)]
    pub schemas: Vec<String>,
    /// Their department, employee number and manager, when any is kept.
    #[serde(
        default,
        rename = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
    )]
    pub enterprise: Option<DirectoryEnterprise>,
    /// What the record is and its version.
    #[serde(default)]
    pub meta: Option<DirectoryMeta>,
}

/// `POST /scim/v2/…/Users` or `PUT /scim/v2/…/Users/{id}`: a person's
/// whole record as a directory such as Okta or Entra ID sends it, with
/// the parts it leaves out left unset.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryRecord {
    /// Their address, which SCIM calls the user name.
    pub user_name: String,
    /// The name shown to people.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Their name's parts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<DirectoryName>,
    /// Their addresses; the primary one counts when `userName` is not one.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub emails: Vec<DirectoryEmail>,
    /// Whether they may sign in; left out means yes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    /// The directory's own id for them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// Their department, employee number and manager.
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
    )]
    pub enterprise: Option<DirectoryEnterprise>,
}

/// A person's name parts, as a directory sends them and the endpoint
/// answers them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryName {
    /// The whole name, which the endpoint answers as the display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    /// The given name the directory keeps, apart from the display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    /// The family name the directory keeps, apart from the display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
}

/// One address of a person's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryEmail {
    /// The address.
    pub value: String,
    /// Whether it is their main one.
    #[serde(default)]
    pub primary: bool,
    /// What kind it is, such as `work`.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// The enterprise extension's fields the endpoint keeps.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryEnterprise {
    /// The department the outside directory files them under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
    /// The number the outside directory knows them by.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub employee_number: Option<String>,
    /// Their manager, a user of the tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manager: Option<ManagerReference>,
}

/// A manager, by the tenant's id for them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagerReference {
    /// The manager's user id.
    pub value: String,
}

/// What a record is, and the version a directory sends back in
/// `If-None-Match` to learn whether it changed.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryMeta {
    /// `User` or `Group`.
    pub resource_type: String,
    /// The record's version, also sent as its `ETag`.
    pub version: String,
}

/// `GET /scim/v2/…/Users` or `…/Groups`: what a listing asks for. Each
/// part left out is not sent.
#[derive(Debug, Clone, Default)]
pub struct DirectorySearch {
    /// A SCIM filter, such as `displayName sw "Pat"`.
    pub filter: Option<String>,
    /// The 1-based index of the first result.
    pub start_index: Option<u64>,
    /// The most results on the page.
    pub count: Option<u64>,
    /// The attribute the results are ordered by.
    pub sort_by: Option<String>,
    /// `ascending` or `descending`.
    pub sort_order: Option<String>,
}

impl DirectorySearch {
    /// The query string pairs it sends, in SCIM's names.
    #[must_use]
    pub fn pairs(&self) -> Vec<(&'static str, String)> {
        let numbers = [("startIndex", self.start_index), ("count", self.count)];
        let texts = [
            ("filter", &self.filter),
            ("sortBy", &self.sort_by),
            ("sortOrder", &self.sort_order),
        ];
        texts
            .into_iter()
            .filter_map(|(name, value)| value.clone().map(|value| (name, value)))
            .chain(
                numbers
                    .into_iter()
                    .filter_map(|(name, value)| value.map(|value| (name, value.to_string()))),
            )
            .collect()
    }
}

/// `POST /scim/v2/…/Groups`: a group as the directory sends one.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryGroup {
    /// Its name, unique in the tenant.
    pub display_name: String,
    /// Who is in it, by the tenant's ids for them.
    pub members: Vec<DirectoryMember>,
}

/// One member of a group, by the tenant's id for them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryMember {
    /// The tenant's id for the member.
    pub value: String,
}

/// A group as the endpoint answers the directory.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryGroupResource {
    /// The tenant's id for it.
    pub id: String,
    /// What the outside directory calls the group.
    #[serde(default)]
    pub display_name: String,
    /// Who is in it, by the tenant's ids for them.
    #[serde(default)]
    pub members: Vec<DirectoryMember>,
    /// What the record is and its version.
    #[serde(default)]
    pub meta: Option<DirectoryMeta>,
}

/// `GET /scim/v2/…/Groups`: one page of the groups the directory keeps.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryGroupListing {
    /// How many groups match in all.
    pub total_results: u64,
    /// The groups on this page.
    #[serde(rename = "Resources", default)]
    pub resources: Vec<DirectoryGroupResource>,
}

/// `PATCH /scim/v2/…/Users/{id}`: the operations SCIM applies in order.
#[derive(Debug, Clone, Serialize)]
pub struct DirectoryPatch {
    /// Attribute changes applied in the order supplied by the directory.
    #[serde(rename = "Operations")]
    pub operations: Vec<DirectoryOperation>,
}

impl DirectoryPatch {
    /// The patch a directory sends when it deactivates a user: `active`
    /// replaced with `false`.
    #[must_use]
    pub fn deactivation() -> Self {
        Self::one("replace", "active", Value::Bool(false))
    }

    /// The patch a directory sends when it lets a user back in: `active`
    /// replaced with `true`.
    #[must_use]
    pub fn reactivation() -> Self {
        Self::one("replace", "active", Value::Bool(true))
    }

    /// The patch of the single operation `op` on `path` with `value`.
    #[must_use]
    pub fn one(op: &str, path: &str, value: Value) -> Self {
        Self {
            operations: vec![DirectoryOperation {
                op: op.to_owned(),
                path: path.to_owned(),
                value,
            }],
        }
    }

    /// The patch of the operations `operations`, in order, as one request.
    #[must_use]
    pub fn of(operations: Vec<DirectoryOperation>) -> Self {
        Self { operations }
    }
}

impl DirectoryOperation {
    /// The operation `op` on `path` with `value`.
    #[must_use]
    pub fn at(op: &str, path: &str, value: Value) -> Self {
        Self {
            op: op.to_owned(),
            path: path.to_owned(),
            value,
        }
    }

    /// The operation `op` with no path, whose `value` is an object of
    /// attribute names and their new values, as Okta sends it.
    #[must_use]
    pub fn pathless(op: &str, value: Value) -> Self {
        Self::at(op, "", value)
    }
}

/// One SCIM patch operation.
#[derive(Debug, Clone, Serialize)]
pub struct DirectoryOperation {
    /// `add`, `replace` or `remove`.
    pub op: String,
    /// The attribute it applies to; empty for a pathless operation, which
    /// sends none.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub path: String,
    /// The value it sets.
    pub value: Value,
}

/// `POST …/auth/ldap-service-accounts`: an account an application binds
/// to the LDAP directory as.
#[derive(Debug, Clone, Serialize)]
pub struct NewServiceAccount {
    /// Its name, the `cn` it binds under.
    pub name: String,
    /// What it may reach.
    pub scope: ServiceAccountScope,
}

/// What a service account may reach.
#[derive(Debug, Clone, Serialize)]
pub struct ServiceAccountScope {
    /// `ReadOnly`, the only access a service account has.
    pub access: String,
    /// The DNs it may search under.
    pub base_dns: Vec<String>,
}

/// The service account just made, with its secret shown this once. Holds
/// the secret, so it has no `Debug`.
#[derive(Clone, Deserialize)]
pub struct ServiceAccountMade {
    /// Handle used to rotate or revoke the LDAP binding credential.
    pub id: String,
    /// The secret it binds with.
    pub secret: String,
}

/// A service account as an administrator reads it, from
/// `GET …/auth/ldap-service-accounts/{id}`: never its secret, only what it
/// may reach and whether it binds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAccount {
    /// The id Tess rotates, switches off or deletes it by.
    pub id: String,
    /// The `cn` it binds under.
    pub name: String,
    /// `ReadOnly`, the only access a service account has.
    pub access: String,
    /// The DNs it may search under.
    pub base_dns: Vec<String>,
    /// Whether it binds now, such as `Active` or `Disabled`.
    pub status: String,
    /// Every other field, as the API answered it, so a scenario can
    /// search the whole answer for a secret.
    #[serde(flatten)]
    pub rest: serde_json::Map<String, Value>,
}

/// `GET …/auth/ldap-service-accounts`: the tenant's service accounts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAccounts {
    /// Each account, by name.
    pub service_accounts: Vec<ServiceAccount>,
}

/// `POST …/auth/ldap-service-accounts/{id}/rotate-secret`: the account's
/// new secret, shown this once. Holds the secret, so it has no `Debug`.
#[derive(Clone, Deserialize)]
pub struct ServiceAccountSecret {
    /// The secret it binds with from now on.
    pub secret: String,
}

/// `POST …/auth/ldap-certificates`: a person asks the tenant to sign the
/// request their device made, proving who they are again. Holds their
/// password, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct CertificateAsked {
    /// The device's signing request, PEM.
    pub csr_pem: String,
    /// What the person calls the device.
    pub device_label: String,
    /// Their password typed again.
    pub proof: crate::wire::tenants::PasswordAgain,
}

/// The certificate the tenant signed, shown this once.
#[derive(Debug, Clone, Deserialize)]
pub struct CertificateIssued {
    /// Handle used to revoke the issued device credential.
    pub certificate_id: String,
    /// Signed device identity presented when binding over TLS.
    pub certificate_pem: String,
}

/// `GET /scim/v2/…/Users`: one page of the tenant's users.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryListing {
    /// How many users match in all.
    pub total_results: u64,
    /// The 1-based index of the page's first user, as the endpoint echoes
    /// it.
    #[serde(default)]
    pub start_index: u64,
    /// How many users are on this page.
    #[serde(default)]
    pub items_per_page: u64,
    /// The users on this page.
    #[serde(rename = "Resources", default)]
    pub resources: Vec<DirectoryResource>,
}

/// `GET /scim/v2/…/ServiceProviderConfig`: what the endpoint supports, as
/// a provider's setup reads it before it sends anything.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisioningAbilities {
    /// The schemas the document follows.
    pub schemas: Vec<String>,
    /// Whether changes may be sent as a patch.
    pub patch: Ability,
    /// Whether several operations may be sent in one request.
    pub bulk: Ability,
    /// Whether users and groups may be found by a filter.
    pub filter: Ability,
    /// Whether a password may be set through the protocol.
    pub change_password: Ability,
    /// How the provider proves who it is.
    pub authentication_schemes: Vec<ProvisioningScheme>,
    /// The platform's own limits, such as the most members one group
    /// write names.
    #[serde(rename = "urn:ianua:params:scim:schemas:extension:limits:2.0:ServiceProviderConfig")]
    pub limits: ProvisioningLimits,
}

/// Whether one part of the protocol is offered.
#[derive(Debug, Clone, Deserialize)]
pub struct Ability {
    /// Whether it is.
    pub supported: bool,
}

/// One way a provider may prove who it is.
#[derive(Debug, Clone, Deserialize)]
pub struct ProvisioningScheme {
    /// Such as `oauthbearertoken`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Whether it is the one to use.
    #[serde(default)]
    pub primary: bool,
}

/// The platform's own limits on what one write may carry.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisioningLimits {
    /// The most members one group write names across its operations.
    pub max_members_per_operation: u32,
}

/// `GET /scim/v2/…/ResourceTypes` or `…/Schemas`: every entry on one
/// page.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryListing<T> {
    /// How many entries there are.
    pub total_results: u64,
    /// The entries.
    #[serde(rename = "Resources")]
    pub resources: Vec<T>,
}

/// One kind of record the endpoint provisions, and where it lives.
#[derive(Debug, Clone, Deserialize)]
pub struct ProvisionedKind {
    /// `User` or `Group`.
    pub name: String,
    /// The path under the endpoint's base, such as `/Users`.
    pub endpoint: String,
    /// The schema its records follow.
    pub schema: String,
}

/// The attributes one schema reads and returns.
#[derive(Debug, Clone, Deserialize)]
pub struct ProvisionedSchema {
    /// The schema's URN, such as
    /// `urn:ietf:params:scim:schemas:core:2.0:User`.
    pub id: String,
    /// Its short name, such as `User`.
    pub name: String,
    /// Each attribute the directory exposes, by its LDAP name.
    pub attributes: Vec<ProvisionedAttribute>,
}

/// One attribute of a schema.
#[derive(Debug, Clone, Deserialize)]
pub struct ProvisionedAttribute {
    /// Such as `userName`.
    pub name: String,
    /// Whether a provider must send it.
    pub required: bool,
}
