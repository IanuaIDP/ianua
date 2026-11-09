//! SCIM 2.0 wire types (RFC 7643, RFC 7644), and what they say in the app's
//! terms.
//!
//! Only the attributes this platform keeps are read or written: the core
//! user's `userName`, `displayName`, `name`, `emails`, `active` and
//! `externalId`, and the enterprise extension's `department`, `manager` and
//! `employeeNumber`. Anything else a provider sends, such as phone numbers
//! or addresses, is accepted and ignored, which is what providers expect of
//! a service that does not store them.

use ianua_app::ports::federation::ScimPage;
use ianua_app::use_cases::scim::groups::fields::{ScimGroup, ScimGroupChange, ScimGroupFields};
use ianua_app::use_cases::scim::users::fields::{
    self, AccountSwitch, ScimUserChange, ScimUserFields,
};
use ianua_domain::domains::identity::account::profile_values::{
    Department, EmployeeNumber, ExternalId, FamilyName, GivenName,
};
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::identity::account::user_profile::DirectoryRecords;
use ianua_domain::domains::identity::account::user_status::UserStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::types::{DisplayName, Email, Label, Setting, UserId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::error::scim::ScimApiError;
use crate::response::scim::ScimVersioned;

/// The SCIM core user schema.
pub(crate) const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
/// The SCIM enterprise user extension.
pub const ENTERPRISE_SCHEMA: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
/// The enterprise extension's URN lower-cased, as attribute paths are read.
pub(crate) const ENTERPRISE_PATH: &str =
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:user";
/// The core user schema's URN lower-cased with its separator, the prefix of
/// a fully qualified core attribute path.
const CORE_PATH: &str = "urn:ietf:params:scim:schemas:core:2.0:user:";
/// The SCIM core group schema.
pub(crate) const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
/// The list response message schema.
pub(crate) const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
/// The error message schema.
pub const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";

/// A user as a provider sends it on create or replace.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScimUserBody {
    /// The sign-in name; must be an email address here.
    pub user_name: String,
    /// The name shown to people.
    #[serde(default)]
    pub display_name: Option<String>,
    /// The person's name parts.
    #[serde(default)]
    pub name: Option<ScimName>,
    /// The person's addresses; the primary one is used when `userName` is
    /// not an address.
    #[serde(default)]
    pub emails: Vec<ScimEmail>,
    /// Whether the account may sign in. Absent means yes. Entra ID sends
    /// `"True"` and `"False"`, which are read too.
    #[serde(default)]
    #[schema(value_type = Option<bool>)]
    pub active: Option<ScimBool>,
    /// The directory's own id for the person, which Okta and Entra match
    /// on.
    #[serde(default)]
    pub external_id: Option<String>,
    /// The enterprise extension: department, manager and employee number.
    #[serde(
        default,
        rename = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
    )]
    pub enterprise: Option<ScimEnterpriseUser>,
}

impl ScimUserBody {
    /// The record this body sends, with names held to `limits`. A field
    /// left out is left unset, as a whole record replaces the old one.
    ///
    /// # Errors
    ///
    /// `invalidValue` if neither `userName` nor an email is an address, the
    /// name is not a valid display name, a profile field breaks its rules,
    /// or the manager is not a user id.
    pub(crate) fn fields(self, limits: &DomainLimits) -> Result<ScimUserFields, ScimApiError> {
        let email = Email::new(&self.user_name)
            .ok()
            .or_else(|| primary_email(&self.emails))
            .ok_or_else(|| ScimApiError::invalid_value("userName must be an email address"))?;
        let name = self.name.unwrap_or_default();
        let shown = self
            .display_name
            .or_else(|| name.formatted_name())
            .unwrap_or_else(|| email.as_str().to_owned());
        Ok(ScimUserFields {
            user_name: email,
            display_name: display_name(&shown, limits)?,
            name: name.parts()?,
            records: directory_records(self.external_id, self.enterprise.unwrap_or_default())?,
            active: self.active.map_or(AccountSwitch::On, AccountSwitch::from),
        })
    }
}

/// What a directory keeps about a person: `externalId` and the enterprise
/// fields.
fn directory_records(
    external_id: Option<String>,
    enterprise: ScimEnterpriseUser,
) -> Result<DirectoryRecords, ScimApiError> {
    Ok(DirectoryRecords {
        external_id: text_setting(external_id, ExternalId::new)?,
        department: text_setting(enterprise.department, Department::new)?,
        manager: manager_setting(enterprise.manager)?,
        employee_number: text_setting(enterprise.employee_number, EmployeeNumber::new)?,
    })
}

/// A person's name parts.
#[derive(Deserialize, Serialize, Default, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimName {
    /// The full name as displayed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    /// First name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    /// Last name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
}

impl ScimName {
    /// The name to show: `formatted`, or the given and family names joined.
    fn formatted_name(&self) -> Option<String> {
        if let Some(formatted) = self.formatted.as_ref().filter(|f| !f.trim().is_empty()) {
            return Some(formatted.clone());
        }
        let parts: Vec<&str> = [&self.given_name, &self.family_name]
            .into_iter()
            .flatten()
            .map(String::as_str)
            .collect();
        (!parts.is_empty()).then(|| parts.join(" "))
    }

    /// The given and family names, each unset when left out or blank.
    fn parts(&self) -> Result<fields::ScimName, ScimApiError> {
        Ok(fields::ScimName {
            given_name: text_setting(self.given_name.clone(), GivenName::new)?,
            family_name: text_setting(self.family_name.clone(), FamilyName::new)?,
        })
    }

    /// The changes replacing a person's `name` asks for: both parts, and
    /// the display name when the name gives one.
    fn changes(&self, limits: &DomainLimits) -> Result<Vec<ScimUserChange>, ScimApiError> {
        let parts = self.parts()?;
        let mut changes = vec![
            ScimUserChange::GivenName(parts.given_name),
            ScimUserChange::FamilyName(parts.family_name),
        ];
        if let Some(shown) = self.formatted_name() {
            changes.push(ScimUserChange::DisplayName(display_name(&shown, limits)?));
        }
        Ok(changes)
    }
}

/// The enterprise user extension's fields this service keeps.
#[derive(Deserialize, Serialize, Default, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScimEnterpriseUser {
    /// The person's department.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
    /// The person's employee number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub employee_number: Option<String>,
    /// The person's manager, by their user id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub manager: Option<ScimManagerRef>,
}

impl ScimEnterpriseUser {
    /// The extension for `records`, or `None` when it holds nothing.
    fn of(records: &DirectoryRecords) -> Option<Self> {
        let extension = Self {
            department: records.department.value().map(|d| d.as_str().to_owned()),
            employee_number: records
                .employee_number
                .value()
                .map(|n| n.as_str().to_owned()),
            manager: records.manager.value().map(|id| ScimManagerRef::Ref {
                value: id.to_string(),
            }),
        };
        let empty = extension.department.is_none()
            && extension.employee_number.is_none()
            && extension.manager.is_none();
        (!empty).then_some(extension)
    }
}

/// A manager as providers send one: `{"value": "<id>"}`, or the id alone.
#[derive(Deserialize, Serialize)]
#[serde(untagged)]
pub(crate) enum ScimManagerRef {
    /// `{"value": "<id>"}`, any other members ignored.
    Ref {
        /// The manager's user id.
        value: String,
    },
    /// The id as a bare string.
    Id(String),
}

impl ScimManagerRef {
    /// The id it names.
    fn id(&self) -> &str {
        match self {
            Self::Ref { value } | Self::Id(value) => value,
        }
    }
}

/// The manager `manager` names, unset when it names none.
fn manager_setting(manager: Option<ScimManagerRef>) -> Result<Setting<UserId>, ScimApiError> {
    let Some(manager) = manager.filter(|m| !m.id().trim().is_empty()) else {
        return Ok(Setting::Unset);
    };
    user_id(manager.id()).map(Setting::Set)
}

/// `text` made into a value by `make`, unset when absent or blank.
fn text_setting<T, E: std::fmt::Display>(
    text: Option<String>,
    make: impl FnOnce(String) -> Result<T, E>,
) -> Result<Setting<T>, ScimApiError> {
    let Some(text) = text.filter(|t| !t.trim().is_empty()) else {
        return Ok(Setting::Unset);
    };
    make(text)
        .map(Setting::Set)
        .map_err(ScimApiError::invalid_value)
}

/// A patch value made into a value by `make`, unset when `null` or blank.
fn value_setting<T, E: std::fmt::Display>(
    value: Value,
    make: impl FnOnce(String) -> Result<T, E>,
) -> Result<Setting<T>, ScimApiError> {
    match value {
        Value::Null => Ok(Setting::Unset),
        other => text_setting(Some(parse::<String>(other)?), make),
    }
}

/// One email address.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct ScimEmail {
    /// The address.
    pub value: String,
    /// Whether it is the person's main address.
    #[serde(default)]
    pub primary: bool,
    /// What kind of address it is.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// A boolean as providers send it: Entra ID sends `"True"` and `"False"`.
#[derive(Deserialize, Clone, Copy)]
#[serde(untagged)]
pub(crate) enum ScimBool {
    /// A JSON boolean.
    Bool(bool),
    /// A boolean spelled as a string, in any case.
    Text(BoolText),
}

/// `"true"` or `"false"`, in any case.
#[derive(Clone, Copy)]
pub(crate) struct BoolText(bool);

impl<'de> Deserialize<'de> for BoolText {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        match text.to_ascii_lowercase().as_str() {
            "true" => Ok(Self(true)),
            "false" => Ok(Self(false)),
            other => Err(serde::de::Error::custom(format!("not a boolean: {other}"))),
        }
    }
}

impl From<ScimBool> for AccountSwitch {
    fn from(value: ScimBool) -> Self {
        match value {
            ScimBool::Bool(true) | ScimBool::Text(BoolText(true)) => Self::On,
            ScimBool::Bool(false) | ScimBool::Text(BoolText(false)) => Self::Off,
        }
    }
}

/// A group as a provider sends it on create or replace.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScimGroupBody {
    /// The group's name.
    pub display_name: String,
    /// The user references to assign to the group; omission supplies an empty list.
    #[serde(default)]
    pub members: Vec<ScimMemberRef>,
}

impl ScimGroupBody {
    /// The record this body sends.
    ///
    /// # Errors
    ///
    /// `invalidValue` if the name is empty or a member id is not a user id.
    pub(crate) fn fields(self) -> Result<ScimGroupFields, ScimApiError> {
        Ok(ScimGroupFields {
            name: group_name(&self.display_name)?,
            members: member_ids(&self.members)?,
        })
    }
}

/// A reference to a member, by id.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct ScimMemberRef {
    /// The member's id.
    pub value: String,
    /// A label for the member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

/// A patch request.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ScimPatchBody {
    /// The operations, applied in order.
    #[serde(rename = "Operations")]
    pub operations: Vec<ScimPatchOperation>,
}

/// An ordered SCIM mutation naming an action, an optional attribute and its value.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ScimPatchOperation {
    /// `add`, `replace` or `remove`, in any case.
    pub op: String,
    /// The attribute it targets; absent when `value` names the attributes.
    #[serde(default)]
    pub path: Option<String>,
    /// The new value.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub value: Option<Value>,
}

impl ScimPatchBody {
    /// The changes a user patch asks for, with names held to `limits`.
    ///
    /// Understands both the `path` form (`{"op":"replace","path":"active",
    /// "value":false}`) and the pathless form (`{"op":"replace","value":
    /// {"active":false}}`), core attributes by short or fully qualified
    /// path, and the enterprise extension's. `remove` clears `externalId`,
    /// the name's parts and the enterprise fields; removing anything else
    /// is ignored, as are attributes this service does not keep.
    ///
    /// # Errors
    ///
    /// `invalidValue` if a value has the wrong type or is not valid.
    pub(crate) fn user_changes(
        self,
        limits: &DomainLimits,
    ) -> Result<Vec<ScimUserChange>, ScimApiError> {
        let mut changes = Vec::new();
        for operation in self.operations {
            changes.extend(operation.user_changes(limits)?);
        }
        Ok(changes)
    }

    /// The changes a group patch asks for: renaming it, and adding,
    /// removing or replacing members, including Entra ID's
    /// `members[value eq "id"]` form of removal.
    ///
    /// # Errors
    ///
    /// `invalidValue` if a value has the wrong type or a member id is not a
    /// user id; `invalidFilter` for a member path this service does not
    /// read.
    pub(crate) fn group_changes(self) -> Result<Vec<ScimGroupChange>, ScimApiError> {
        let mut changes = Vec::new();
        for operation in self.operations {
            let op = operation.op.to_ascii_lowercase();
            let path = operation.path.map(|p| p.to_ascii_lowercase());
            changes.extend(group_change(&op, path.as_deref(), operation.value)?);
        }
        Ok(changes)
    }
}

impl ScimPatchOperation {
    /// The user changes this one operation asks for.
    fn user_changes(self, limits: &DomainLimits) -> Result<Vec<ScimUserChange>, ScimApiError> {
        if self.op.eq_ignore_ascii_case("remove") {
            return match self.path {
                Some(path) if clearable(&path) => user_change(&path, Value::Null, limits),
                _ => Ok(Vec::new()),
            };
        }
        match (self.path, self.value) {
            (Some(path), Some(value)) => user_change(&path, value, limits),
            (None, Some(value)) => user_changes_from_object(value, limits),
            (_, None) => Ok(Vec::new()),
        }
    }
}

/// Whether removing the attribute at `path` clears it: the profile fields
/// do, the sign-in address, display name and switch cannot be removed.
fn clearable(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    let field = path
        .strip_prefix(ENTERPRISE_PATH)
        .map_or(path.as_str(), |rest| rest.trim_start_matches(':'));
    let field = field.strip_prefix(CORE_PATH).unwrap_or(field);
    matches!(
        field,
        "externalid"
            | "name.givenname"
            | "name.familyname"
            | "department"
            | "employeenumber"
            | "manager"
            | "manager.value"
    )
}

/// The user changes in a patch with no path, where the value is an object
/// of attribute names and new values.
fn user_changes_from_object(
    value: Value,
    limits: &DomainLimits,
) -> Result<Vec<ScimUserChange>, ScimApiError> {
    let Value::Object(fields) = value else {
        return Err(ScimApiError::invalid_value(
            "a patch without a path needs an object value",
        ));
    };
    let mut changes = Vec::new();
    for (path, value) in fields {
        changes.extend(user_change(&path, value, limits)?);
    }
    Ok(changes)
}

/// The changes one attribute asks for, none for an attribute this service
/// does not keep.
fn user_change(
    path: &str,
    value: Value,
    limits: &DomainLimits,
) -> Result<Vec<ScimUserChange>, ScimApiError> {
    let path = path.to_ascii_lowercase();
    if let Some(rest) = path.strip_prefix(ENTERPRISE_PATH) {
        return enterprise_change(rest, value);
    }
    core_change(path.strip_prefix(CORE_PATH).unwrap_or(&path), value, limits)
}

/// The change one core user attribute asks for.
fn core_change(
    path: &str,
    value: Value,
    limits: &DomainLimits,
) -> Result<Vec<ScimUserChange>, ScimApiError> {
    let change = match path {
        "active" => ScimUserChange::Active(parse::<ScimBool>(value)?.into()),
        "displayname" | "name.formatted" => {
            ScimUserChange::DisplayName(display_name(&parse::<String>(value)?, limits)?)
        }
        "username" => ScimUserChange::UserName(
            Email::new(parse::<String>(value)?).map_err(ScimApiError::invalid_value)?,
        ),
        "externalid" => ScimUserChange::ExternalId(value_setting(value, ExternalId::new)?),
        "name.givenname" => ScimUserChange::GivenName(value_setting(value, GivenName::new)?),
        "name.familyname" => ScimUserChange::FamilyName(value_setting(value, FamilyName::new)?),
        "name" => return parse::<ScimName>(value)?.changes(limits),
        p if p.starts_with("emails") => return Ok(email_change(p, value)?.into_iter().collect()),
        _ => return Ok(Vec::new()),
    };
    Ok(vec![change])
}

/// The change an enterprise extension path asks for; `rest` is what
/// follows the extension's URN: nothing for the whole extension as an
/// object, or `:field`.
fn enterprise_change(rest: &str, value: Value) -> Result<Vec<ScimUserChange>, ScimApiError> {
    let change = match rest.trim_start_matches(':') {
        "" => return enterprise_object(value),
        "department" => ScimUserChange::Department(value_setting(value, Department::new)?),
        "employeenumber" => {
            ScimUserChange::EmployeeNumber(value_setting(value, EmployeeNumber::new)?)
        }
        "manager" | "manager.value" => ScimUserChange::Manager(manager_value(value)?),
        _ => return Ok(Vec::new()),
    };
    Ok(vec![change])
}

/// The changes the whole enterprise extension, sent as an object, asks for.
fn enterprise_object(value: Value) -> Result<Vec<ScimUserChange>, ScimApiError> {
    let fields = match value {
        Value::Null => return Ok(Vec::new()),
        Value::Object(fields) => fields,
        _ => {
            return Err(ScimApiError::invalid_value(
                "the enterprise extension is an object",
            ));
        }
    };
    let mut changes = Vec::new();
    for (field, value) in fields {
        changes.extend(enterprise_change(&field.to_ascii_lowercase(), value)?);
    }
    Ok(changes)
}

/// The manager a patch value names: `null`, an id, or `{"value": "<id>"}`.
fn manager_value(value: Value) -> Result<Setting<UserId>, ScimApiError> {
    match value {
        Value::Null => Ok(Setting::Unset),
        other => manager_setting(Some(parse::<ScimManagerRef>(other)?)),
    }
}

/// The new sign-in address an `emails` path sets, either directly or as
/// the primary one of a list.
fn email_change(path: &str, value: Value) -> Result<Option<ScimUserChange>, ScimApiError> {
    if path.ends_with(".value") {
        return Email::new(parse::<String>(value)?)
            .map(|email| Some(ScimUserChange::UserName(email)))
            .map_err(ScimApiError::invalid_value);
    }
    let emails: Vec<ScimEmail> = parse(value)?;
    Ok(primary_email(&emails).map(ScimUserChange::UserName))
}

/// The address marked primary, or the first one when none is, if it is a
/// valid address.
fn primary_email(emails: &[ScimEmail]) -> Option<Email> {
    emails
        .iter()
        .find(|e| e.primary)
        .or_else(|| emails.first())
        .and_then(|e| Email::new(&e.value).ok())
}

/// A display name a provider sent, checked against the tenant's limits.
fn display_name(name: &str, limits: &DomainLimits) -> Result<DisplayName, ScimApiError> {
    DisplayName::new(name, &limits.display_name).map_err(ScimApiError::invalid_value)
}

/// The changes one group operation asks for, read from its operation and
/// path.
fn group_change(
    op: &str,
    path: Option<&str>,
    value: Option<Value>,
) -> Result<Vec<ScimGroupChange>, ScimApiError> {
    match (op, path) {
        ("remove", Some(p)) if p.starts_with("members[") => {
            Ok(vec![ScimGroupChange::RemoveMembers(vec![member_in_path(
                p,
            )?])])
        }
        (_, Some("members")) => {
            let refs: Vec<ScimMemberRef> = parse(value.unwrap_or(Value::Array(Vec::new())))?;
            Ok(vec![members_change(op, member_ids(&refs)?)])
        }
        (_, Some("displayname")) => {
            let name: String = parse(value.unwrap_or_default())?;
            Ok(vec![ScimGroupChange::Rename(group_name(&name)?)])
        }
        (_, None) => group_changes_from_object(op, value),
        _ => Ok(Vec::new()),
    }
}

/// The group changes in an operation with no path, where the value is an
/// object of attribute names and new values.
fn group_changes_from_object(
    op: &str,
    value: Option<Value>,
) -> Result<Vec<ScimGroupChange>, ScimApiError> {
    let Some(Value::Object(fields)) = value else {
        return Ok(Vec::new());
    };
    let mut changes = Vec::new();
    for (path, value) in fields {
        let path = path.to_ascii_lowercase();
        changes.extend(group_change(op, Some(&path), Some(value))?);
    }
    Ok(changes)
}

/// Adds, removes or replaces the members, as the operation says; any
/// other operation replaces them.
fn members_change(op: &str, members: Vec<UserId>) -> ScimGroupChange {
    match op {
        "add" => ScimGroupChange::AddMembers(members),
        "remove" => ScimGroupChange::RemoveMembers(members),
        _ => ScimGroupChange::ReplaceMembers(members),
    }
}

/// The id in `members[value eq "id"]`.
fn member_in_path(path: &str) -> Result<UserId, ScimApiError> {
    let inner = path
        .strip_prefix("members[")
        .and_then(|p| p.strip_suffix(']'))
        .ok_or_else(|| ScimApiError::invalid_filter(format!("unsupported path: {path}")))?;
    let filter = EqFilter::parse(inner)?;
    user_id(&filter.value)
}

/// A group name a provider sent.
///
/// # Errors
///
/// `invalidValue` if it is not a valid label.
pub fn group_name(name: &str) -> Result<Label, ScimApiError> {
    Label::new("displayName", name).map_err(ScimApiError::invalid_value)
}

/// The user ids of the members a provider sent.
fn member_ids(members: &[ScimMemberRef]) -> Result<Vec<UserId>, ScimApiError> {
    members
        .iter()
        .map(|member| user_id(&member.value))
        .collect()
}

/// The user id a provider sent, refused as an invalid value when it is
/// not one.
fn user_id(raw: &str) -> Result<UserId, ScimApiError> {
    Uuid::parse_str(raw.trim())
        .map(UserId::from_uuid)
        .map_err(|_| ScimApiError::invalid_value(format!("not a user id: {raw}")))
}

/// A value read as `T`, refused as an invalid value when it has the wrong
/// shape.
fn parse<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, ScimApiError> {
    serde_json::from_value(value).map_err(ScimApiError::invalid_value)
}

/// `attribute eq "value"`, the form a member path names its member in.
pub(crate) struct EqFilter {
    /// The value it must equal.
    pub value: String,
}

impl EqFilter {
    /// Reads the quoted value after a case-insensitive equality operator.
    ///
    /// # Errors
    ///
    /// `invalidFilter` for any other form.
    pub(crate) fn parse(filter: &str) -> Result<Self, ScimApiError> {
        let unsupported = || ScimApiError::invalid_filter(format!("unsupported filter: {filter}"));
        let mut parts = filter.trim().splitn(3, char::is_whitespace);
        let (Some(_attribute), Some(op), Some(rest)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(unsupported());
        };
        if !op.eq_ignore_ascii_case("eq") {
            return Err(unsupported());
        }
        let value = rest
            .trim()
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .ok_or_else(unsupported)?;
        Ok(Self {
            value: value.replace("\\\"", "\""),
        })
    }
}

/// A user as this platform returns it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScimUserResource {
    schemas: Vec<&'static str>,
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_id: Option<String>,
    user_name: String,
    display_name: String,
    name: ScimName,
    emails: [ScimEmail; 1],
    active: bool,
    #[serde(
        rename = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
        skip_serializing_if = "Option::is_none"
    )]
    enterprise: Option<ScimEnterpriseUser>,
    meta: ScimMeta,
}

impl From<&User<ResolvedTenant>> for ScimUserResource {
    fn from(user: &User<ResolvedTenant>) -> Self {
        let email = user.email().as_str().to_owned();
        let records = &user.profile().records;
        let enterprise = ScimEnterpriseUser::of(records);
        Self {
            schemas: user_schemas(enterprise.is_some()),
            id: user.id().to_string(),
            external_id: records.external_id.value().map(|id| id.as_str().to_owned()),
            user_name: email.clone(),
            display_name: user.display_name().as_str().to_owned(),
            name: name_of(user),
            emails: [ScimEmail {
                value: email,
                primary: true,
                kind: Some("work".to_owned()),
            }],
            active: user.status() == UserStatus::Active,
            enterprise,
            meta: ScimMeta::new("User", user.created_at(), user.updated_at()),
        }
        .versioned()
    }
}

impl ScimUserResource {
    /// This resource with its version worked out from what it says.
    fn versioned(mut self) -> Self {
        self.meta.version = version_of(&self);
        self
    }
}

impl ScimVersioned for ScimUserResource {
    fn version(&self) -> &str {
        &self.meta.version
    }
}

/// The schemas a user resource names: the core one, and the enterprise
/// extension when it carries any of its fields.
fn user_schemas(with_enterprise: bool) -> Vec<&'static str> {
    let mut schemas = vec![USER_SCHEMA];
    if with_enterprise {
        schemas.push(ENTERPRISE_SCHEMA);
    }
    schemas
}

/// `user`'s name: the display name as formatted, and the parts they have.
fn name_of(user: &User<ResolvedTenant>) -> ScimName {
    let details = &user.profile().details;
    ScimName {
        formatted: Some(user.display_name().as_str().to_owned()),
        given_name: details.given_name.value().map(|n| n.as_str().to_owned()),
        family_name: details.family_name.value().map(|n| n.as_str().to_owned()),
    }
}

/// A group as this platform returns it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScimGroupResource {
    schemas: [&'static str; 1],
    id: String,
    display_name: String,
    members: Vec<ScimMemberRef>,
    meta: ScimMeta,
}

impl From<&ScimGroup> for ScimGroupResource {
    fn from(scim: &ScimGroup) -> Self {
        let mut resource = Self {
            schemas: [GROUP_SCHEMA],
            id: scim.group.id().to_string(),
            display_name: scim.group.name().as_str().to_owned(),
            members: scim
                .members
                .iter()
                .map(|member| ScimMemberRef {
                    value: member.to_string(),
                    display: None,
                })
                .collect(),
            meta: ScimMeta::new("Group", scim.group.created_at(), scim.group.updated_at()),
        };
        resource.meta.version = version_of(&resource);
        resource
    }
}

impl ScimVersioned for ScimGroupResource {
    fn version(&self) -> &str {
        &self.meta.version
    }
}

/// What a resource is, when it changed, and its version.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScimMeta {
    resource_type: &'static str,
    created: String,
    last_modified: String,
    version: String,
}

impl ScimMeta {
    /// The meta block for a resource of this type, created and last
    /// changed at these times, its version not yet worked out.
    fn new(resource_type: &'static str, created: OffsetDateTime, modified: OffsetDateTime) -> Self {
        Self {
            resource_type,
            created: rfc3339(created),
            last_modified: rfc3339(modified),
            version: String::new(),
        }
    }
}

/// The weak entity tag of `resource`: a hash of everything it says, so any
/// change to it, a member added or a field cleared, gives a new one.
fn version_of(resource: &impl Serialize) -> String {
    let written = serde_json::to_vec(resource).unwrap_or_default();
    format!("W/\"{:016x}\"", fnv1a(&written))
}

/// The 64-bit FNV-1a hash of `bytes`, stable across builds and machines.
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// The time as an RFC 3339 string, or empty if it cannot be written.
fn rfc3339(at: OffsetDateTime) -> String {
    at.format(&Rfc3339).unwrap_or_default()
}

/// One page of a listing.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScimListResponse<T: Serialize> {
    schemas: [&'static str; 1],
    total_results: u64,
    start_index: u64,
    items_per_page: usize,
    #[serde(rename = "Resources")]
    resources: Vec<T>,
}

impl<T: Serialize> ScimListResponse<T> {
    /// `page` as `mapper` writes each item, starting at the 1-based
    /// `start_index`; empty when the listing's filter `matches` nobody.
    #[must_use]
    pub(crate) fn of<'p, S>(
        page: &'p ScimPage<S>,
        matches: FilterMatch,
        start_index: u64,
        mapper: impl FnMut(&'p S) -> T,
    ) -> Self {
        let (resources, total_results) = match matches {
            FilterMatch::Readable => (page.items.iter().map(mapper).collect(), page.total),
            FilterMatch::Nobody => (Vec::new(), 0),
        };
        Self {
            schemas: [LIST_SCHEMA],
            total_results,
            start_index,
            items_per_page: resources.len(),
            resources,
        }
    }
}

/// Whether a listing's filter can match anyone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilterMatch {
    /// The filter is one the use case reads.
    Readable,
    /// The filter names only attributes this service does not keep: the
    /// answer is empty.
    Nobody,
}

/// An error as SCIM clients expect it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScimErrorBody {
    /// Always [`ERROR_SCHEMA`].
    pub schemas: [&'static str; 1],
    /// The HTTP status, as a string.
    pub status: String,
    /// The SCIM error type, for the statuses that have one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scim_type: Option<&'static str>,
    /// What went wrong.
    pub detail: String,
}

impl ScimErrorBody {
    /// The answer to `/Me`, which this service does not offer: a directory
    /// signs in as the tenant's endpoint, not as a person, so there is no
    /// "me" to name (RFC 7644 section 3.11).
    #[must_use]
    pub(crate) fn me_unsupported() -> Self {
        Self {
            schemas: [ERROR_SCHEMA],
            status: "501".to_owned(),
            scim_type: None,
            detail:
                "/Me is not supported: the SCIM token names the tenant's directory, not a person"
                    .to_owned(),
        }
    }
}

/// The documents a provider reads to learn what this service supports
/// (RFC 7643 sections 5 and 6). The same for every tenant: they describe
/// the code and the deployment's limits, not the tenant.
pub mod discovery {
    use serde_json::{Value, json};

    use crate::dto::scim::{ENTERPRISE_SCHEMA, GROUP_SCHEMA, LIST_SCHEMA, USER_SCHEMA};

    /// The most resources one page holds.
    const MAX_RESULTS: u64 = 100;

    /// This service's own extension of the configuration. RFC 7643 has no
    /// field for how many members one group write may carry, so the limit
    /// is published here rather than left for a provider to discover.
    const LIMITS_SCHEMA: &str =
        "urn:ianua:params:scim:schemas:extension:limits:2.0:ServiceProviderConfig";

    /// What this service supports, for a provider setting up a connection:
    /// one group write, by `POST`, `PUT` or `PATCH`, names at most
    /// `members_per_write` members across all its operations.
    #[must_use]
    pub fn service_provider_config(members_per_write: u32) -> Value {
        json!({
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig",
                LIMITS_SCHEMA
            ],
            "patch": { "supported": true },
            "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
            "filter": { "supported": true, "maxResults": MAX_RESULTS },
            LIMITS_SCHEMA: { "maxMembersPerOperation": members_per_write },
            "changePassword": { "supported": false },
            "sort": { "supported": true },
            "etag": { "supported": true },
            "authenticationSchemes": [{
                "type": "oauthbearertoken",
                "name": "Bearer token",
                "description": "The tenant's SCIM token, sent as `Authorization: Bearer <token>`.",
                "primary": true
            }]
        })
    }

    /// The resource types this service provisions.
    #[must_use]
    pub fn resource_types() -> Value {
        let user = json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "schema": USER_SCHEMA,
            "schemaExtensions": [{ "schema": ENTERPRISE_SCHEMA, "required": false }]
        });
        let group = json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "Group",
            "name": "Group",
            "endpoint": "/Groups",
            "schema": GROUP_SCHEMA
        });
        listing(&[user, group])
    }

    /// The attributes this service reads and returns.
    #[must_use]
    pub fn schemas() -> Value {
        let user = json!({
            "id": USER_SCHEMA,
            "name": "User",
            "attributes": [
                attribute("userName", "string", Presence::Required, "The email address the account signs in with."),
                attribute("displayName", "string", Presence::Optional, "The name shown to people."),
                attribute("active", "boolean", Presence::Optional, "Whether the account may sign in."),
                attribute("emails", "complex", Presence::Optional, "The sign-in address, as a list of one."),
                attribute("name", "complex", Presence::Optional, "The given and family names; the display name when none is given."),
                attribute("externalId", "string", Presence::Optional, "The directory's own id for the person.")
            ]
        });
        let enterprise = json!({
            "id": ENTERPRISE_SCHEMA,
            "name": "EnterpriseUser",
            "attributes": [
                attribute("department", "string", Presence::Optional, "The person's department."),
                attribute("employeeNumber", "string", Presence::Optional, "The person's employee number."),
                attribute("manager", "complex", Presence::Optional, "The person's manager, by user id.")
            ]
        });
        let group = json!({
            "id": GROUP_SCHEMA,
            "name": "Group",
            "attributes": [
                attribute("displayName", "string", Presence::Required, "The group's name, unique in the tenant."),
                attribute("members", "complex", Presence::Optional, "The users in the group, by id.")
            ]
        });
        listing(&[user, enterprise, group])
    }

    /// Whether an attribute must be sent.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Presence {
        /// It must.
        Required,
        /// It may be left out.
        Optional,
    }

    /// The schema entry for one attribute; complex ones other than `name`
    /// and `manager` hold many values, and required ones are unique.
    fn attribute(name: &str, kind: &str, presence: Presence, description: &str) -> Value {
        let required = presence == Presence::Required;
        json!({
            "name": name,
            "type": kind,
            "multiValued": kind == "complex" && !matches!(name, "name" | "manager"),
            "required": required,
            "description": description,
            "mutability": "readWrite",
            "returned": "default",
            "uniqueness": if required { "server" } else { "none" }
        })
    }

    /// The resources as a single page holding all of them.
    fn listing(resources: &[Value]) -> Value {
        json!({
            "schemas": [LIST_SCHEMA],
            "totalResults": resources.len(),
            "itemsPerPage": resources.len(),
            "startIndex": 1,
            "Resources": resources
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A patch body read from JSON a provider would send.
    fn patch(json: Value) -> ScimPatchBody {
        serde_json::from_value(json).unwrap()
    }

    /// The default limits.
    fn limits() -> DomainLimits {
        DomainLimits::default()
    }

    /// A member path with a mixed-case equality operator retains its quoted value.
    #[test]
    fn an_eq_filter_is_read_case_insensitively() {
        let filter = EqFilter::parse(r#"value Eq "ada@acme.com""#).ok().unwrap();

        assert_eq!(filter.value, "ada@acme.com");
    }

    /// A member path with another operator, or a value without quotes, is
    /// refused.
    #[test]
    fn any_other_operator_is_an_invalid_filter() {
        assert!(EqFilter::parse(r#"value co "ada""#).is_err());
        assert!(EqFilter::parse("value eq ada").is_err());
    }

    /// Okta switches Ada off by sending `{active: false}` with no path; the
    /// account is switched off.
    #[test]
    fn okta_switches_a_user_off_with_a_pathless_patch() {
        let changes = patch(serde_json::json!({
            "Operations": [{ "op": "replace", "value": { "active": false } }]
        }))
        .user_changes(&limits())
        .ok()
        .unwrap();

        assert!(matches!(
            changes.as_slice(),
            [ScimUserChange::Active(AccountSwitch::Off)]
        ));
    }

    /// Entra ID switches Ada off with `"False"` as a string and `Replace`
    /// capitalised; the account is switched off.
    #[test]
    fn entra_switches_a_user_off_with_a_string_boolean() {
        let changes = patch(serde_json::json!({
            "Operations": [{ "op": "Replace", "path": "active", "value": "False" }]
        }))
        .user_changes(&limits())
        .ok()
        .unwrap();

        assert!(matches!(
            changes.as_slice(),
            [ScimUserChange::Active(AccountSwitch::Off)]
        ));
    }

    /// A provider sets the work email's value; that becomes the new sign-in
    /// address.
    #[test]
    fn a_work_email_path_changes_the_sign_in_address() {
        let changes = patch(serde_json::json!({
            "Operations": [{
                "op": "replace",
                "path": "emails[type eq \"work\"].value",
                "value": "new@acme.com"
            }]
        }))
        .user_changes(&limits())
        .ok()
        .unwrap();

        assert!(
            matches!(changes.as_slice(), [ScimUserChange::UserName(e)] if e.as_str() == "new@acme.com")
        );
    }

    /// A provider sets a job title, which this service does not keep; the
    /// patch asks for no change.
    #[test]
    fn attributes_this_service_does_not_keep_are_ignored() {
        let changes = patch(serde_json::json!({
            "Operations": [{ "op": "replace", "path": "title", "value": "Engineer" }]
        }))
        .user_changes(&limits())
        .ok()
        .unwrap();

        assert!(changes.is_empty());
    }

    /// Entra ID sets Ada's `externalId` and her department through the
    /// enterprise extension's full path; both are changed.
    #[test]
    fn entra_sets_the_external_id_and_an_enterprise_field() {
        let changes = patch(serde_json::json!({
            "Operations": [
                { "op": "replace", "path": "externalId", "value": "e-42" },
                {
                    "op": "Add",
                    "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
                    "value": "Research"
                }
            ]
        }))
        .user_changes(&limits())
        .ok()
        .unwrap();

        assert!(matches!(
            changes.as_slice(),
            [
                ScimUserChange::ExternalId(Setting::Set(id)),
                ScimUserChange::Department(Setting::Set(department)),
            ] if id.as_str() == "e-42" && department.as_str() == "Research"
        ));
    }

    /// Okta sends the whole enterprise extension in a pathless patch, the
    /// manager as `{"value": id}`; each field is changed.
    #[test]
    fn a_pathless_enterprise_object_changes_each_field() {
        let manager = Uuid::now_v7();
        let changes = patch(serde_json::json!({
            "Operations": [{ "op": "replace", "value": {
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                    "employeeNumber": "701",
                    "manager": { "value": manager.to_string() }
                }
            } }]
        }))
        .user_changes(&limits())
        .ok()
        .unwrap();

        assert_eq!(changes.len(), 2);
        assert!(changes.iter().any(|change| matches!(
            change,
            ScimUserChange::Manager(Setting::Set(id)) if *id == UserId::from_uuid(manager)
        )));
    }

    /// Removing the given name clears it; removing the sign-in address is
    /// ignored.
    #[test]
    fn remove_clears_profile_fields_only() {
        let changes = patch(serde_json::json!({
            "Operations": [
                { "op": "remove", "path": "name.givenName" },
                { "op": "remove", "path": "userName" }
            ]
        }))
        .user_changes(&limits())
        .ok()
        .unwrap();

        assert!(matches!(
            changes.as_slice(),
            [ScimUserChange::GivenName(Setting::Unset)]
        ));
    }

    /// A manager that is not a user id is refused.
    #[test]
    fn a_manager_that_is_not_a_user_id_is_an_invalid_value() {
        let result = patch(serde_json::json!({
            "Operations": [{
                "op": "replace",
                "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager",
                "value": "boss"
            }]
        }))
        .user_changes(&limits());

        assert!(result.is_err());
    }

    /// Entra ID removes a member by naming them in the path; that member is
    /// removed.
    #[test]
    fn entra_removes_a_member_by_filter_path() {
        let id = Uuid::now_v7();
        let changes = patch(serde_json::json!({
            "Operations": [{ "op": "Remove", "path": format!("members[value eq \"{id}\"]") }]
        }))
        .group_changes()
        .ok()
        .unwrap();

        assert!(matches!(
            changes.as_slice(),
            [ScimGroupChange::RemoveMembers(m)] if m == &[UserId::from_uuid(id)]
        ));
    }

    /// A provider adds a member by listing their id as the value; that
    /// member is added.
    #[test]
    fn members_are_added_by_value() {
        let id = Uuid::now_v7();
        let changes = patch(serde_json::json!({
            "Operations": [{ "op": "add", "path": "members", "value": [{ "value": id.to_string() }] }]
        }))
        .group_changes()
        .ok()
        .unwrap();

        assert!(matches!(
            changes.as_slice(),
            [ScimGroupChange::AddMembers(m)] if m == &[UserId::from_uuid(id)]
        ));
    }

    /// A member that is not a user id is refused.
    #[test]
    fn a_member_that_is_not_a_user_id_is_an_invalid_value() {
        let result = patch(serde_json::json!({
            "Operations": [{ "op": "add", "path": "members", "value": [{ "value": "nobody" }] }]
        }))
        .group_changes();

        assert!(result.is_err());
    }

    /// A provider sends Ada with the user name `ada`; she signs in with her
    /// primary email instead, her name is built from its parts and kept in
    /// them, and she starts switched on.
    #[test]
    fn a_user_name_that_is_not_an_address_falls_back_to_the_primary_email() {
        let body: ScimUserBody = serde_json::from_value(serde_json::json!({
            "userName": "ada",
            "emails": [{ "value": "ada@acme.com", "primary": true }],
            "name": { "givenName": "Ada", "familyName": "Lovelace" }
        }))
        .unwrap();

        let fields = body.fields(&limits()).ok().unwrap();

        assert_eq!(fields.user_name.as_str(), "ada@acme.com");
        assert_eq!(fields.display_name.as_str(), "Ada Lovelace");
        assert_eq!(fields.active, AccountSwitch::On);
        assert_eq!(
            fields.name.given_name.value().map(GivenName::as_str),
            Some("Ada")
        );
    }

    /// Okta creates Ada with her `externalId` and the enterprise extension;
    /// the record keeps each of them.
    #[test]
    fn a_created_user_keeps_the_directory_records() {
        let manager = Uuid::now_v7();
        let body: ScimUserBody = serde_json::from_value(serde_json::json!({
            "userName": "ada@acme.com",
            "externalId": "00u1",
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                "department": "Research",
                "employeeNumber": "701",
                "manager": { "value": manager.to_string(), "displayName": "Grace" }
            }
        }))
        .unwrap();

        let records = body.fields(&limits()).ok().unwrap().records;

        assert_eq!(
            records.external_id.value().map(ExternalId::as_str),
            Some("00u1")
        );
        assert_eq!(
            records.department.value().map(Department::as_str),
            Some("Research")
        );
        assert_eq!(records.manager.value(), Some(&UserId::from_uuid(manager)));
        assert_eq!(
            records.employee_number.value().map(EmployeeNumber::as_str),
            Some("701")
        );
    }

    /// Two resources that say different things have different versions,
    /// and the same one says the same version every time.
    #[test]
    fn a_version_follows_what_the_resource_says() {
        let first = fnv1a(b"{\"displayName\":\"Ada\"}");
        let again = fnv1a(b"{\"displayName\":\"Ada\"}");
        let other = fnv1a(b"{\"displayName\":\"Grace\"}");

        assert_eq!(first, again);
        assert_ne!(first, other);
    }
}
