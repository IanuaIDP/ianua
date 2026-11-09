//! What a directory says about a user: the whole record, or one change to
//! it.

use ianua_domain::domains::identity::account::profile_values::{
    Department, EmployeeNumber, ExternalId, FamilyName, GivenName,
};
use ianua_domain::domains::identity::account::user_profile::DirectoryRecords;
use ianua_domain::types::{DisplayName, Email, Setting, UserId};

/// Everything a directory says about a user when it sends the whole record.
pub struct ScimUserFields {
    /// The address the account signs in with (SCIM `userName`).
    pub user_name: Email,
    /// The name shown to other people.
    pub display_name: DisplayName,
    /// The parts of the person's name (SCIM `name`).
    pub name: ScimName,
    /// What the directory keeps about the person: its `externalId`, and the
    /// enterprise `department`, `manager` and `employeeNumber`.
    pub records: DirectoryRecords,
    /// Whether the directory wants the account able to sign in.
    pub active: AccountSwitch,
}

/// The parts of a person's name a directory sends (SCIM `name`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScimName {
    /// `name.givenName`.
    pub given_name: Setting<GivenName>,
    /// `name.familyName`.
    pub family_name: Setting<FamilyName>,
}

/// Whether a directory wants an account on or off (SCIM `active`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountSwitch {
    /// The account may sign in.
    On,
    /// The account may not sign in.
    Off,
}

/// One change a directory asks for.
pub enum ScimUserChange {
    /// A new sign-in address.
    UserName(Email),
    /// A new display name.
    DisplayName(DisplayName),
    /// Switch the account on or off.
    Active(AccountSwitch),
    /// A new given name, or none.
    GivenName(Setting<GivenName>),
    /// A new family name, or none.
    FamilyName(Setting<FamilyName>),
    /// A new `externalId`, or none.
    ExternalId(Setting<ExternalId>),
    /// A new department, or none.
    Department(Setting<Department>),
    /// A new manager, by their account in the tenant, or none.
    Manager(Setting<UserId>),
    /// A new employee number, or none.
    EmployeeNumber(Setting<EmployeeNumber>),
}
