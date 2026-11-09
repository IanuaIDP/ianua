//! A user as its row holds it: read back into the aggregate, and written
//! out from it.

use ianua_domain::domains::identity::account::address::AddressStanding;
use ianua_domain::domains::identity::account::profile_values::{
    Department, EmployeeNumber, ExternalId, FamilyName, GivenName, PhoneNumber, PreferredUsername,
};
use ianua_domain::domains::identity::account::user::{User, UserRow};
use ianua_domain::domains::identity::account::user_profile::{
    DirectoryRecords, PersonalDetails, UserProfile,
};
use ianua_domain::domains::identity::account::vouching::Vouching;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::validation::ValidationError;
use ianua_domain::types::{
    CredentialChange, DisplayName, Email, HttpsUrl, Joining, Locale, Preference, Setting, Timezone,
    UserId,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const USER: Stored = Stored("user");

/// A user as it is read. The store's checked queries fill it.
pub(crate) struct UserRecord {
    pub(crate) id: Uuid,
    pub(crate) email: String,
    pub(crate) display_name: String,
    pub(crate) status: String,
    pub(crate) email_verified: bool,
    pub(crate) locale: Option<String>,
    pub(crate) timezone: Option<String>,
    pub(crate) given_name: Option<String>,
    pub(crate) family_name: Option<String>,
    pub(crate) preferred_username: Option<String>,
    pub(crate) picture: Option<String>,
    pub(crate) phone_number: Option<String>,
    pub(crate) external_id: Option<String>,
    pub(crate) department: Option<String>,
    pub(crate) manager_id: Option<Uuid>,
    pub(crate) employee_number: Option<String>,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) updated_at: OffsetDateTime,
    pub(crate) last_login_at: Option<OffsetDateTime>,
    pub(crate) joined_at: Option<OffsetDateTime>,
    pub(crate) credentials_changed_at: Option<OffsetDateTime>,
    pub(crate) route_vouches: bool,
}

impl UserRecord {
    /// The user the record holds, rebuilt through the domain's checks, its
    /// name checked against `limits`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the user
    /// keeps.
    pub(crate) fn into_user(
        mut self,
        limits: &DomainLimits,
    ) -> Result<User<ResolvedTenant>, DomainError> {
        let profile = self.take_profile()?;
        let email_standing = if self.email_verified {
            AddressStanding::Verified
        } else {
            AddressStanding::Unverified
        };
        User::reconstitute(UserRow {
            id: UserId::from_uuid(self.id),
            email: USER.value("email", Email::new(self.email))?,
            display_name: USER.value(
                "display name",
                DisplayName::new(self.display_name, &limits.display_name),
            )?,
            status: USER.choice(&self.status)?,
            email_standing,
            locale: preference("locale", self.locale, Locale::new)?,
            timezone: preference("timezone", self.timezone, Timezone::new)?,
            profile,
            created_at: self.created_at,
            updated_at: self.updated_at,
            last_login_at: self.last_login_at,
            joining: Joining::from_stored(self.joined_at),
            credentials_changed_at: CredentialChange::from_stored(self.credentials_changed_at),
            vouching: RouteVouches(self.route_vouches).into(),
        })
    }

    /// Moves the profile columns into validated personal and directory details.
    fn take_profile(&mut self) -> Result<UserProfile, DomainError> {
        Ok(UserProfile {
            details: self.take_details()?,
            records: self.take_directory()?,
        })
    }

    /// Validates and moves the optional personal profile columns in storage order.
    fn take_details(&mut self) -> Result<PersonalDetails, DomainError> {
        Ok(PersonalDetails {
            given_name: setting("given name", self.given_name.take(), GivenName::new)?,
            family_name: setting("family name", self.family_name.take(), FamilyName::new)?,
            preferred_username: setting(
                "preferred username",
                self.preferred_username.take(),
                PreferredUsername::new,
            )?,
            picture: setting("picture", self.picture.take(), HttpsUrl::new)?,
            phone_number: setting("phone number", self.phone_number.take(), PhoneNumber::new)?,
        })
    }

    /// Validates and moves the directory fields after the personal fields were accepted.
    fn take_directory(&mut self) -> Result<DirectoryRecords, DomainError> {
        Ok(DirectoryRecords {
            external_id: setting("external id", self.external_id.take(), ExternalId::new)?,
            department: setting("department", self.department.take(), Department::new)?,
            manager: Setting::from_stored(self.manager_id.map(UserId::from_uuid)),
            employee_number: setting(
                "employee number",
                self.employee_number.take(),
                EmployeeNumber::new,
            )?,
        })
    }
}

/// A user's columns, as they are written.
pub(super) struct UserColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) email: &'a str,
    pub(super) display_name: &'a str,
    pub(super) status: &'static str,
    pub(super) email_verified: bool,
    pub(super) locale: Option<&'a str>,
    pub(super) timezone: Option<&'a str>,
    pub(super) given_name: Option<&'a str>,
    pub(super) family_name: Option<&'a str>,
    pub(super) preferred_username: Option<&'a str>,
    pub(super) picture: Option<&'a str>,
    pub(super) phone_number: Option<&'a str>,
    pub(super) external_id: Option<&'a str>,
    pub(super) department: Option<&'a str>,
    pub(super) manager_id: Option<Uuid>,
    pub(super) employee_number: Option<&'a str>,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
    pub(super) last_login_at: Option<OffsetDateTime>,
    pub(super) joined_at: Option<OffsetDateTime>,
    pub(super) credentials_changed_at: Option<OffsetDateTime>,
    pub(super) route_vouches: bool,
}

impl<'a> UserColumns<'a> {
    /// The columns `user` is written to.
    pub(super) fn of(user: &'a User<ResolvedTenant>) -> Self {
        let details = &user.profile().details;
        let records = &user.profile().records;
        Self {
            id: user.id().as_uuid(),
            email: user.email().as_str(),
            display_name: user.display_name().as_str(),
            status: user.status().word(),
            email_verified: user.email_verified(),
            locale: user.locale().value().map(Locale::as_str),
            timezone: user.timezone().value().map(Timezone::as_str),
            given_name: details.given_name.value().map(GivenName::as_str),
            family_name: details.family_name.value().map(FamilyName::as_str),
            preferred_username: details
                .preferred_username
                .value()
                .map(PreferredUsername::as_str),
            picture: details.picture.value().map(HttpsUrl::as_str),
            phone_number: details.phone_number.value().map(PhoneNumber::as_str),
            external_id: records.external_id.value().map(ExternalId::as_str),
            department: records.department.value().map(Department::as_str),
            manager_id: records.manager.value().map(|manager| *manager.as_uuid()),
            employee_number: records.employee_number.value().map(EmployeeNumber::as_str),
            created_at: user.created_at(),
            updated_at: user.updated_at(),
            last_login_at: user.last_login_at(),
            joined_at: user.joined_at(),
            credentials_changed_at: user.credentials_changed_at().changed_at(),
            route_vouches: user.vouching() == Vouching::Fresh,
        }
    }
}

/// The `route_vouches` column of users and members: whether a trusted
/// route vouches for the account's next sign-in.
pub(crate) struct RouteVouches(pub(crate) bool);

impl From<RouteVouches> for Vouching {
    fn from(RouteVouches(vouches): RouteVouches) -> Self {
        if vouches {
            return Self::Fresh;
        }
        Self::Absent
    }
}

/// The value a stored column holds, read back through `read`, or unset
/// when the column is empty.
fn setting<T>(
    what: &'static str,
    stored: Option<String>,
    read: impl Fn(String) -> Result<T, ValidationError>,
) -> Result<Setting<T>, DomainError> {
    stored
        .map(|text| USER.value(what, read(text)))
        .transpose()
        .map(Setting::from_stored)
}

/// Restores a validated preference while retaining the absence of an override.
fn preference<T>(
    what: &'static str,
    stored: Option<String>,
    read: impl Fn(String) -> Result<T, ValidationError>,
) -> Result<Preference<T>, DomainError> {
    stored
        .map(|text| USER.value(what, read(text)))
        .transpose()
        .map(Preference::from_stored)
}
