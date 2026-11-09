//! User bodies: registering, importing, listing and changing a tenant's
//! users, their profile, an admin's reset of their password or factors, and
//! a person's own sign-up and preferences.

use std::collections::{BTreeMap, HashMap};

use ianua_app::email::{EmailVerification, LinkScope};
use ianua_app::error::AppError;
use ianua_app::listing::{Page, PageRequest};
use ianua_app::ports::identity::{InvitationState, StoredAttribute, TimeSpan};
use ianua_app::use_cases::identity::attributes::GetUsersMetadataRequest;
use ianua_app::use_cases::identity::email::{ChangeRequest, SendVerificationRequest};
use ianua_app::use_cases::identity::imports::StartRequest;
use ianua_app::use_cases::identity::users::{
    AttributeCondition, FactorsCleared, ListOrder, ListRequest, ListedUser, New, Preferences,
    RegisterResult, RenameRequest, ResetPasswordRequest, ResetPasswordResult, SignUp,
    SignUpRequest, UpdateDetailsRequest, UpdateRecordsRequest, UpdateStatusRequest, UserCriteria,
};
use ianua_app::use_cases::identity::whose::Whose;
use ianua_domain::domains::authorization::role::Role;
use ianua_domain::domains::identity::account::import::password_hash::ImportedPasswordHash;
use ianua_domain::domains::identity::account::import::run::UserImport;
use ianua_domain::domains::identity::account::import::{
    AccountImport, ImportBatch, ImportRecord, ImportedPassword,
};
use ianua_domain::domains::identity::account::profile_values::{
    Department, EmployeeNumber, ExternalId, FamilyName, GivenName, PhoneNumber, PreferredUsername,
};
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::identity::account::user_profile::{
    DirectoryRecords, PersonalDetails, UserProfile,
};
use ianua_domain::domains::identity::account::user_status::UserStatus;
use ianua_domain::domains::identity::attribute::{AttributeClearance, MetadataSchema};
use ianua_domain::domains::organization::billing::plan::PlanLimits;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::config::DisplayNameLimits;
use ianua_domain::types::{
    DisplayName, Email, GroupId, HttpsUrl, Locale, PasswordPolicy, RoleId, Setting, Timezone,
    UserId, UserImportId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::dto::authentication::password::PasswordBreachResponse;
use crate::dto::identity::attributes::listed_values;
use crate::error::ApiError;
use crate::extractors::time::parse_rfc3339;
use crate::response::PageResponse;

/// Registers a user in the tenant.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RegisterUserBody {
    /// The address the account signs in with.
    pub email: String,
    /// The name shown to other people in the tenant.
    pub display_name: String,
    /// The password. Omit it and one is generated, returned once.
    pub password: Option<String>,
    /// Let the account in at once rather than waiting for its holder to
    /// confirm the address. Off when omitted.
    pub auto_verify: Option<bool>,
    /// Roles to grant the new user at creation.
    ///
    /// Granted alongside the tenant's default roles, so naming a role that
    /// is already a default is agreement with it rather than a conflict.
    #[serde(default)]
    pub role_ids: Vec<String>,
    /// A single role to grant at creation.
    ///
    /// Superseded by `role_ids`, which takes any number. Still accepted, and
    /// merged with it, so a caller sending either or both gets what it asked
    /// for.
    #[serde(default)]
    pub role_id: Option<String>,
}

impl RegisterUserBody {
    /// The user to register, under `limits`, whose confirmation link lands
    /// on `scope`.
    ///
    /// # Errors
    ///
    /// [`ApiError::validation`] for an address, name or role id that is not
    /// a valid one.
    pub(crate) fn new_user(
        self,
        limits: &DisplayNameLimits,
        scope: LinkScope,
    ) -> Result<New, ApiError> {
        let roles = self.requested_roles()?;
        Ok(New {
            email: Email::new(self.email).map_err(ApiError::validation)?,
            display_name: DisplayName::new(self.display_name, limits)
                .map_err(ApiError::validation)?,
            password: self.password,
            verification: EmailVerification::from_auto_verify(self.auto_verify),
            roles,
            scope,
        })
    }

    /// Every role asked for, from either field. A role named twice is
    /// granted once.
    fn requested_roles(&self) -> Result<Vec<RoleId>, ApiError> {
        self.role_ids
            .iter()
            .chain(self.role_id.iter())
            .map(|raw| {
                Uuid::parse_str(raw)
                    .map(RoleId::from_uuid)
                    .map_err(ApiError::rejected)
            })
            .collect()
    }
}

/// A registered or activated user.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RegisterUserResponse {
    /// The user's id.
    pub id: Uuid,
    /// The generated password, only when none was given. Shown this once.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated_password: Option<String>,
    /// What the breach lookup said about the password set, when one was.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_breach: Option<PasswordBreachResponse>,
}

impl From<RegisterResult> for RegisterUserResponse {
    fn from(result: RegisterResult) -> Self {
        Self {
            id: *result.id.as_uuid(),
            generated_password: result
                .generated_password
                .map(|password| password.expose().to_owned()),
            password_breach: Some(result.breach.into()),
        }
    }
}

impl From<UserId> for RegisterUserResponse {
    fn from(id: UserId) -> Self {
        Self {
            id: *id.as_uuid(),
            generated_password: None,
            password_breach: None,
        }
    }
}

/// Changes to a user's profile. Each field is applied when present.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UpdateUserBody {
    /// A new display name.
    pub display_name: Option<String>,
    /// A new address. It starts a pending change: the account keeps its
    /// address until the link mailed to the new one is followed.
    pub email: Option<String>,
    /// `true` mails the current address a link that confirms it. Nobody
    /// vouches for an address: only following the link marks it verified.
    pub email_verified: Option<bool>,
}

/// What one profile update asks of the app, each part only when the body
/// asked for it.
pub(crate) struct UserEdits {
    /// The rename asked for.
    pub rename: Option<RenameRequest>,
    /// The address change asked for.
    pub change_email: Option<ChangeRequest>,
    /// The confirmation link asked for.
    pub verification: Option<SendVerificationRequest>,
}

impl UpdateUserBody {
    /// The edits the body asks of `user`, under `limits`, with any link
    /// landing on `scope`.
    ///
    /// # Errors
    ///
    /// [`ApiError::validation`] for a name or address that is not a valid
    /// one.
    pub(crate) fn edits(
        self,
        user: UserId,
        limits: &DisplayNameLimits,
        scope: LinkScope,
    ) -> Result<UserEdits, ApiError> {
        let rename = self
            .display_name
            .map(|name| DisplayName::new(name, limits))
            .transpose()
            .map_err(ApiError::validation)?
            .map(|new_name| RenameRequest {
                user_id: user,
                new_name,
            });
        let new_email = self
            .email
            .map(Email::new)
            .transpose()
            .map_err(ApiError::validation)?;
        let verification = (self.email_verified == Some(true)).then(|| SendVerificationRequest {
            user_id: user,
            scope: scope.clone(),
        });
        Ok(UserEdits {
            rename,
            change_email: new_email.map(|new_email| ChangeRequest {
                user_id: user,
                new_email,
                scope,
            }),
            verification,
        })
    }
}

/// Moves a user to another status.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UpdateStatusBody {
    /// `Active`, `Locked` or `Deactivated`.
    #[schema(schema_with = crate::dto::schemas::user_status)]
    pub status: UserStatus,
}

impl UpdateStatusBody {
    /// The move asked for `user`.
    #[must_use]
    pub(crate) fn request(self, user: UserId) -> UpdateStatusRequest {
        UpdateStatusRequest {
            user_id: user,
            target: self.status,
        }
    }
}

/// An admin resetting a user's password.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ResetPasswordBody {
    /// The new password. Omit it and a password is generated.
    pub password: Option<String>,
}

impl ResetPasswordBody {
    /// The reset asked for `user`.
    #[must_use]
    pub(crate) fn request(self, user: UserId) -> ResetPasswordRequest {
        ResetPasswordRequest {
            user_id: user,
            new_password: self.password,
        }
    }
}

/// The password a reset set.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ResetPasswordResponse {
    /// The new password, returned once for the admin to relay.
    pub new_password: String,
    /// What the breach lookup said about it.
    pub password_breach: PasswordBreachResponse,
}

impl From<ResetPasswordResult> for ResetPasswordResponse {
    fn from(result: ResetPasswordResult) -> Self {
        Self {
            new_password: result.new_password.expose().to_owned(),
            password_breach: result.breach.into(),
        }
    }
}

/// What clearing a user's second factor and passkeys took away.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct FactorsClearedResponse {
    /// Second factors turned off, in force or still being set up.
    pub enrollments_turned_off: usize,
    /// The number of registered credentials the person can no longer sign in with.
    pub passkeys_removed: usize,
}

impl From<FactorsCleared> for FactorsClearedResponse {
    fn from(cleared: FactorsCleared) -> Self {
        Self {
            enrollments_turned_off: cleared.enrollments_turned_off,
            passkeys_removed: cleared.passkeys_removed,
        }
    }
}

/// A person's own details, as they or someone who may edit their profile
/// write them. The whole set is replaced: a field left out or `null` is
/// cleared.
#[derive(Deserialize, Default, utoipa::ToSchema)]
pub(crate) struct UpdateDetailsBody {
    /// Their given name, such as `Ann`.
    #[serde(default)]
    pub given_name: Option<String>,
    /// Their family name, such as `Lovelace`.
    #[serde(default)]
    pub family_name: Option<String>,
    /// The one-word name they go by, such as `ann.l`. Not unique.
    #[serde(default)]
    pub preferred_username: Option<String>,
    /// An `https` address of their picture.
    #[serde(default)]
    pub picture: Option<String>,
    /// Their phone number in international form, such as `+4930123456`.
    /// Their word only: nothing sends codes to it.
    #[serde(default)]
    pub phone_number: Option<String>,
}

impl UpdateDetailsBody {
    /// The details as the domain holds them.
    ///
    /// # Errors
    ///
    /// [`ApiError::validation`] for a value its rules refuse.
    pub(crate) fn details(self) -> Result<PersonalDetails, ApiError> {
        Ok(PersonalDetails {
            given_name: setting(self.given_name, GivenName::new)?,
            family_name: setting(self.family_name, FamilyName::new)?,
            preferred_username: setting(self.preferred_username, PreferredUsername::new)?,
            picture: setting(self.picture, HttpsUrl::new)?,
            phone_number: setting(self.phone_number, PhoneNumber::new)?,
        })
    }

    /// The change asked for on `whose` details.
    ///
    /// # Errors
    ///
    /// [`ApiError::validation`] for a value its rules refuse.
    pub(crate) fn request(self, whose: Whose) -> Result<UpdateDetailsRequest, ApiError> {
        Ok(UpdateDetailsRequest {
            whose,
            details: self.details()?,
        })
    }
}

/// What the company's directory records about a user. The whole set is
/// replaced: a field left out or `null` is cleared.
#[derive(Deserialize, Default, utoipa::ToSchema)]
pub(crate) struct UpdateRecordsBody {
    /// What another directory calls the account.
    #[serde(default)]
    pub external_id: Option<String>,
    /// The organizational unit recorded by the company directory.
    #[serde(default)]
    pub department: Option<String>,
    /// The user they report to, a user of the same tenant.
    #[serde(default)]
    pub manager_id: Option<Uuid>,
    /// The staff identifier assigned by the company directory.
    #[serde(default)]
    pub employee_number: Option<String>,
}

impl UpdateRecordsBody {
    /// The records as the domain holds them.
    ///
    /// # Errors
    ///
    /// [`ApiError::validation`] for a value its rules refuse.
    pub(crate) fn records(self) -> Result<DirectoryRecords, ApiError> {
        Ok(DirectoryRecords {
            external_id: setting(self.external_id, ExternalId::new)?,
            department: setting(self.department, Department::new)?,
            manager: Setting::from_stored(self.manager_id.map(UserId::from_uuid)),
            employee_number: setting(self.employee_number, EmployeeNumber::new)?,
        })
    }

    /// The change asked for on `user`'s records.
    ///
    /// # Errors
    ///
    /// [`ApiError::validation`] for a value its rules refuse.
    pub(crate) fn request(self, user: UserId) -> Result<UpdateRecordsRequest, ApiError> {
        Ok(UpdateRecordsRequest {
            user_id: user,
            records: self.records()?,
        })
    }
}

/// `raw` checked by `parse` and held as a setting: unset when absent.
fn setting<T, E: Into<ianua_domain::shared::errors::DomainError>>(
    raw: Option<String>,
    parse: impl FnOnce(String) -> Result<T, E>,
) -> Result<Setting<T>, ApiError> {
    raw.map(parse)
        .transpose()
        .map(Setting::from_stored)
        .map_err(ApiError::validation)
}

/// Accounts brought over from another system's export.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ImportUsersBody {
    /// The accounts, at most ten thousand, each address and external id
    /// once. A batch with a record that does not check out is refused
    /// whole, before anything is kept.
    pub users: Vec<ImportUserBody>,
}

/// One account to bring over.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ImportUserBody {
    /// The account's address. It starts unverified, and a link to confirm
    /// it is mailed.
    pub email: String,
    /// The name it shows.
    pub display_name: String,
    /// The person's own details.
    #[serde(default)]
    pub details: UpdateDetailsBody,
    /// What the company's directory records about them.
    #[serde(default)]
    pub records: UpdateRecordsBody,
    /// The password hash the other system kept: Argon2id, bcrypt, scrypt
    /// or PBKDF2-SHA256 in its usual encoded form. Omit it and the person
    /// sets a password through a reset link.
    #[serde(default)]
    pub password_hash: Option<String>,
}

impl ImportUserBody {
    /// The record as the domain reads it, names held to `limits`.
    fn record(self, limits: &DisplayNameLimits) -> Result<ImportRecord, ApiError> {
        let password = match self.password_hash {
            None => ImportedPassword::NotCarried,
            Some(hash) => ImportedPassword::Hash(
                ImportedPasswordHash::parse(&hash).map_err(ApiError::validation)?,
            ),
        };
        Ok(ImportRecord {
            account: AccountImport {
                email: Email::new(self.email).map_err(ApiError::validation)?,
                display_name: DisplayName::new(self.display_name, limits)
                    .map_err(ApiError::validation)?,
                details: self.details.details()?,
                records: self.records.records()?,
            },
            password,
        })
    }
}

impl ImportUsersBody {
    /// The import asked for, names held to `limits`, confirmation links
    /// landing on `scope`.
    ///
    /// # Errors
    ///
    /// - [`ApiError::validation`] for a record with a value its rules
    ///   refuse, or a hash in no format the platform reads.
    /// - `422` for no records, too many, or two naming the same address or
    ///   external id.
    pub(crate) fn request(
        self,
        limits: &DisplayNameLimits,
        scope: LinkScope,
    ) -> Result<StartRequest, ApiError> {
        let records = self
            .users
            .into_iter()
            .map(|user| user.record(limits))
            .collect::<Result<Vec<_>, _>>()?;
        let batch = ImportBatch::new(records).map_err(|e| ApiError(AppError::from_domain(e)))?;
        Ok(StartRequest { batch, scope })
    }
}

/// The import kept, to follow by its id.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ImportStartedResponse {
    /// The import's id. `GET .../users/imports/{id}` says how far it got.
    pub import_id: Uuid,
}

impl From<UserImportId> for ImportStartedResponse {
    fn from(id: UserImportId) -> Self {
        Self {
            import_id: *id.as_uuid(),
        }
    }
}

/// Where an import stands, what it opened, and which records it set aside.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ImportResponse {
    /// The import's id.
    pub id: Uuid,
    /// `pending` until the worker takes it up, `running` while it opens
    /// accounts, `finished` once every record is worked through, `failed`
    /// when the worker gave up on it; the accounts it opened stay.
    pub status: &'static str,
    /// Every record sent.
    pub total: u32,
    /// The accounts opened so far.
    pub imported: u32,
    /// The records set aside so far.
    pub failed: u32,
    /// The records not worked through yet.
    pub remaining: u32,
    /// The records set aside, in the order they came.
    pub errors: Vec<ImportErrorResponse>,
    /// When it was sent.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it finished or was given up on.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub ended_at: Option<OffsetDateTime>,
}

/// One record an import set aside. It names no address and no hash.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ImportErrorResponse {
    /// Where the record stood in the request's `users`, counted from one.
    pub line: u32,
    /// `address_taken` when another account had the address by the time
    /// the record was reached, `own_manager` when the record names the
    /// account as its own manager, `user_limit_reached` when the plan had
    /// no room for another user by the time the record was reached.
    pub reason: &'static str,
}

impl From<&UserImport<ResolvedTenant>> for ImportResponse {
    fn from(import: &UserImport<ResolvedTenant>) -> Self {
        let counts = import.counts();
        Self {
            id: *import.id().as_uuid(),
            status: import.status().as_str(),
            total: counts.total,
            imported: counts.imported,
            failed: counts.failed,
            remaining: counts.remaining,
            errors: import
                .refused()
                .iter()
                .map(|failed| ImportErrorResponse {
                    line: failed.line().get(),
                    reason: failed.reason().as_str(),
                })
                .collect(),
            created_at: import.created_at(),
            ended_at: import.state().ended_at(),
        }
    }
}

/// The signed-in person's own preferences.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UpdateCurrentUserBody {
    /// New preferred locale (BCP 47 tag, such as `en-US`). Overrides the
    /// tenant default. Omit to leave unchanged.
    pub locale: Option<String>,
    /// New preferred timezone (IANA id, such as `Europe/Berlin`). Overrides
    /// the tenant default. Omit to leave unchanged.
    pub timezone: Option<String>,
}

impl TryFrom<UpdateCurrentUserBody> for Preferences {
    type Error = ApiError;

    /// The preferences the body sets.
    ///
    /// # Errors
    ///
    /// [`ApiError::validation`] for a locale or timezone that is not known.
    fn try_from(body: UpdateCurrentUserBody) -> Result<Self, ApiError> {
        Ok(Self {
            locale: body
                .locale
                .map(Locale::new)
                .transpose()
                .map_err(ApiError::validation)?,
            timezone: body
                .timezone
                .map(Timezone::new)
                .transpose()
                .map_err(ApiError::validation)?,
        })
    }
}

/// The values the members listing accepts for `status`.
///
/// The account statuses, plus the two states an open invitation can be in.
/// Those two are not account statuses (an invitee is `Invited` either way),
/// but the members list shows them as one column, so one parameter selects
/// any of them.
#[derive(Debug, Clone, Copy, Deserialize, utoipa::ToSchema)]
pub(crate) enum MemberStatusFilter {
    /// Invited, whatever the state of the invitation.
    #[serde(alias = "invited")]
    Invited,
    /// Able to sign in.
    #[serde(alias = "active")]
    Active,
    /// Locked out until unlocked.
    #[serde(alias = "locked")]
    Locked,
    /// Switched off.
    #[serde(alias = "deactivated")]
    Deactivated,
    /// Created without auto-verification and not yet confirmed.
    #[serde(
        alias = "pending_verification",
        alias = "pendingVerification",
        alias = "Unverified",
        alias = "unverified"
    )]
    PendingVerification,
    /// Invited, invitation still valid.
    #[serde(
        alias = "Pending",
        alias = "pending",
        alias = "invitation_pending",
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
        alias = "InvitationExpired",
        alias = "Invitation Expired",
        alias = "ExpiredInvitation",
        alias = "Expired Invitation"
    )]
    InvitationExpired,
}

impl MemberStatusFilter {
    /// The account status this selects, and the invitation state it
    /// narrows to.
    fn split(self) -> (UserStatus, Option<InvitationState>) {
        match self {
            Self::Invited => (UserStatus::Invited, None),
            Self::Active => (UserStatus::Active, None),
            Self::Locked => (UserStatus::Locked, None),
            Self::Deactivated => (UserStatus::Deactivated, None),
            Self::PendingVerification => (UserStatus::PendingVerification, None),
            Self::PendingInvitation => (UserStatus::Invited, Some(InvitationState::Pending)),
            Self::InvitationExpired => (UserStatus::Invited, Some(InvitationState::Expired)),
        }
    }
}

/// Query parameters narrowing a user listing.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct UserFilterParams {
    /// Filter by account status, or by the state of an open invitation
    /// (`PendingInvitation` or `InvitationExpired`). Omit to return
    /// everyone.
    pub status: Option<MemberStatusFilter>,
    /// Case-insensitive substring match on email address.
    pub email: Option<String>,
    /// Case-insensitive substring match on display name.
    pub name: Option<String>,
    /// Only users holding this role directly.
    pub role_id: Option<Uuid>,
    /// Only members of this group.
    pub group_id: Option<Uuid>,
    /// Only users who last signed in at or after this time (RFC 3339).
    pub last_login_from: Option<String>,
    /// Only users who last signed in before this time (RFC 3339).
    pub last_login_until: Option<String>,
    /// Only users created at or after this time (RFC 3339).
    pub created_from: Option<String>,
    /// Only users created before this time (RFC 3339).
    pub created_until: Option<String>,
}

impl UserFilterParams {
    /// The listing asked for: these users, narrowed by `attributes`, in
    /// `order`, the page `pagination` names.
    ///
    /// # Errors
    ///
    /// [`ApiError::validation`] for a time that is not RFC 3339.
    pub(crate) fn listing(
        self,
        attributes: Vec<AttributeCondition>,
        order: ListOrder,
        pagination: PageRequest,
    ) -> Result<ListRequest, ApiError> {
        let selected = self.status.map(MemberStatusFilter::split);
        Ok(ListRequest {
            criteria: UserCriteria {
                status: selected.map(|(status, _)| status),
                email_contains: self.email,
                name_contains: self.name,
                role: self.role_id.map(RoleId::from_uuid),
                group: self.group_id.map(GroupId::from_uuid),
                last_login: span(
                    self.last_login_from.as_deref(),
                    self.last_login_until.as_deref(),
                )?,
                created: span(self.created_from.as_deref(), self.created_until.as_deref())?,
                attributes,
            },
            invitation: selected.and_then(|(_, invitation)| invitation),
            order,
            page: pagination,
        })
    }
}

/// The span between `from` and `until`, each open when absent.
fn span(from: Option<&str>, until: Option<&str>) -> Result<TimeSpan, ApiError> {
    Ok(TimeSpan {
        from: from.map(parse_rfc3339).transpose()?,
        until: until.map(parse_rfc3339).transpose()?,
    })
}

/// The custom values a listing page carries: the listed attributes of
/// `schema`, for each user on `page`. The app leaves out what the caller
/// may not see.
#[must_use]
pub(crate) fn listed_values_of(
    page: &Page<ListedUser>,
    schema: &MetadataSchema<ResolvedTenant>,
) -> GetUsersMetadataRequest {
    GetUsersMetadataRequest {
        user_ids: page.items.iter().map(|listed| *listed.user.id()).collect(),
        keys: schema
            .listed(AttributeClearance::Sensitive)
            .map(|declared| (declared.namespace(), declared.key().clone()))
            .collect(),
    }
}

/// A tenant account's sign-in identity, status and profile settings.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct UserResponse {
    /// The user's id.
    pub id: Uuid,
    /// The address they sign in with.
    pub email: String,
    /// The name shown to other people.
    pub display_name: String,
    /// `Invited`, `PendingVerification`, `Active`, `Locked`, `Deactivated`
    /// or `Closing`.
    #[schema(schema_with = crate::dto::schemas::user_status)]
    pub status: UserStatus,
    /// Whether the address has been confirmed.
    pub email_verified: bool,
    /// Preferred locale, or `null` when inheriting the tenant default.
    pub locale: Option<String>,
    /// Preferred timezone, or `null` when inheriting the tenant default.
    pub timezone: Option<String>,
    /// The roles assigned to the user directly.
    pub roles: Vec<UserRoleInfo>,
    /// Invitation state for users who have not yet joined: `"Pending"` or
    /// `"Expired"`. `null` for joined members and users with no open
    /// invitation.
    pub invitation_status: Option<String>,
    /// The role an invited person gets when they accept. `null` for
    /// everyone else: a joined member's roles are in `roles`, and an
    /// invitation only grants its role on acceptance.
    pub invited_role: Option<UserRoleInfo>,
    /// The tenant's own custom fields for this person, keyed by
    /// `<namespace>.<key>`.
    ///
    /// Carries only the fields declared as shown in a listing, and only
    /// those the caller is cleared to read. Absent when there are none.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    #[schema(value_type = Object)]
    pub attributes: BTreeMap<String, Value>,
    /// When the account was made.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    /// When its holder last signed in.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_login_at: Option<OffsetDateTime>,
    /// When its holder joined: accepted an invitation or confirmed their
    /// address.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub joined_at: Option<OffsetDateTime>,
    /// The person's own details and the directory's records about them.
    pub profile: ProfileResponse,
}

/// A person's details and what the company's directory records about
/// them. Each is `null` when unset.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ProfileResponse {
    /// The personal name recorded separately from the surname.
    pub given_name: Option<String>,
    /// The surname recorded separately from the personal name.
    pub family_name: Option<String>,
    /// The name they go by.
    pub preferred_username: Option<String>,
    /// The address of their picture.
    pub picture: Option<String>,
    /// Their phone number, in international form. Not proved to reach them.
    pub phone_number: Option<String>,
    /// What another directory calls the account.
    pub external_id: Option<String>,
    /// The organizational unit recorded by the company directory.
    pub department: Option<String>,
    /// The user they report to.
    pub manager_id: Option<Uuid>,
    /// The staff identifier assigned by the company directory.
    pub employee_number: Option<String>,
}

impl From<&UserProfile> for ProfileResponse {
    fn from(profile: &UserProfile) -> Self {
        let (details, records) = (&profile.details, &profile.records);
        let text = |value: Option<&str>| value.map(str::to_owned);
        Self {
            given_name: text(details.given_name.value().map(GivenName::as_str)),
            family_name: text(details.family_name.value().map(FamilyName::as_str)),
            preferred_username: text(
                details
                    .preferred_username
                    .value()
                    .map(PreferredUsername::as_str),
            ),
            picture: text(details.picture.value().map(HttpsUrl::as_str)),
            phone_number: text(details.phone_number.value().map(PhoneNumber::as_str)),
            external_id: text(records.external_id.value().map(ExternalId::as_str)),
            department: text(records.department.value().map(Department::as_str)),
            manager_id: records.manager.value().map(|id| *id.as_uuid()),
            employee_number: text(records.employee_number.value().map(EmployeeNumber::as_str)),
        }
    }
}

/// A role embedded in a user.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct UserRoleInfo {
    /// The role's id.
    pub id: Uuid,
    /// The role's name.
    pub name: String,
}

impl From<&Role<ResolvedTenant>> for UserRoleInfo {
    fn from(role: &Role<ResolvedTenant>) -> Self {
        Self {
            id: *role.id().as_uuid(),
            name: role.name().as_str().to_owned(),
        }
    }
}

impl From<User<ResolvedTenant>> for UserResponse {
    fn from(user: User<ResolvedTenant>) -> Self {
        Self {
            id: *user.id().as_uuid(),
            email: user.email().as_str().to_owned(),
            display_name: user.display_name().as_str().to_owned(),
            status: user.status(),
            email_verified: user.email_verified(),
            locale: user.locale().value().map(|l| l.as_str().to_owned()),
            timezone: user.timezone().value().map(|t| t.as_str().to_owned()),
            roles: Vec::new(),
            invitation_status: None,
            invited_role: None,
            attributes: BTreeMap::new(),
            created_at: user.created_at(),
            updated_at: user.updated_at(),
            last_login_at: user.last_login_at(),
            joined_at: user.joined_at(),
            profile: ProfileResponse::from(user.profile()),
        }
    }
}

impl UserResponse {
    /// The users on `page`, each with their custom `values`.
    #[must_use]
    pub(crate) fn page(
        page: Page<ListedUser>,
        mut values: HashMap<UserId, Vec<StoredAttribute>>,
    ) -> PageResponse<Self> {
        PageResponse::from_page(page, |listed| {
            let stored = values.remove(listed.user.id()).unwrap_or_default();
            Self::listed(listed, stored)
        })
    }

    /// A listing row: the user, their roles, their listed custom values,
    /// and for someone invited, whether the invitation still works and
    /// which role accepting grants.
    fn listed(listed: ListedUser, stored: Vec<StoredAttribute>) -> Self {
        let ListedUser {
            user,
            roles,
            invitation,
        } = listed;
        let mut row = Self::from(user);
        row.roles = roles.iter().map(UserRoleInfo::from).collect();
        row.attributes = listed_values(stored);
        let Some(invitation) = invitation else {
            return row;
        };
        row.invitation_status = Some(invitation_label(invitation.state).to_owned());
        row.invited_role = invitation.role.as_ref().map(UserRoleInfo::from);
        row
    }
}

/// How a listing names an open invitation's state.
fn invitation_label(state: InvitationState) -> &'static str {
    match state {
        InvitationState::Pending => "Pending",
        InvitationState::Expired => "Expired",
    }
}

/// A person signing themselves up to a tenant that allows it.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct SignUpBody {
    /// The address the account signs in with; the verification link goes
    /// here.
    pub email: String,
    /// The name shown to other people in the tenant.
    pub display_name: String,
    /// The password, held to the tenant's password rules.
    pub password: String,
}

impl SignUpBody {
    /// The sign-up asked for, under `limits`, counted against `plan`, its
    /// confirmation link landing on `scope`.
    ///
    /// # Errors
    ///
    /// [`ApiError::validation`] for an address or name that is not a valid
    /// one.
    pub(crate) fn request(
        self,
        limits: &DisplayNameLimits,
        plan: PlanLimits,
        scope: LinkScope,
    ) -> Result<SignUpRequest, ApiError> {
        Ok(SignUpRequest {
            person: SignUp {
                email: Email::new(self.email).map_err(ApiError::validation)?,
                display_name: DisplayName::new(self.display_name, limits)
                    .map_err(ApiError::validation)?,
                password: self.password,
            },
            limits: plan,
            scope,
        })
    }
}

/// Whether a tenant takes sign-ups, and what a password needs.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SignUpRulesResponse {
    /// Whether people may sign themselves up.
    pub open: bool,
    /// The rules a password must meet; absent when sign-up is closed.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub password_policy: Option<PasswordPolicy>,
}

impl From<Option<PasswordPolicy>> for SignUpRulesResponse {
    fn from(password_policy: Option<PasswordPolicy>) -> Self {
        Self {
            open: password_policy.is_some(),
            password_policy,
        }
    }
}
