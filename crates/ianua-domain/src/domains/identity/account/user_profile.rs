//! What an account records about its holder beyond the name it shows.
//!
//! Two parts, changed by different people. The holder's personal details,
//! their name's parts, the name they go by, a picture and a phone number,
//! are theirs to change, as the display name is. What a company's directory
//! records about them, its id for the account, their department, manager
//! and employee number, is the company's: an administrator or the
//! directory changes it, never the person alone.

use crate::domains::identity::account::profile_values::{
    Department, EmployeeNumber, ExternalId, FamilyName, GivenName, PhoneNumber, PreferredUsername,
};
use crate::types::{HttpsUrl, Setting, UserId};

/// The details a person keeps about themselves. Each is unset until
/// someone sets it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PersonalDetails {
    /// The person's first names, when supplied, without inferring them from a display label.
    pub given_name: Setting<GivenName>,
    /// The person's surname, when supplied, without inferring it from a display label.
    pub family_name: Setting<FamilyName>,
    /// The short name they go by.
    pub preferred_username: Setting<PreferredUsername>,
    /// Where a picture of them is.
    pub picture: Setting<HttpsUrl>,
    /// A phone number they gave. Nobody proved it reaches them.
    pub phone_number: Setting<PhoneNumber>,
}

/// What a company's directory records about a person. Each is unset until
/// someone sets it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DirectoryRecords {
    /// What the provisioning directory calls the account.
    pub external_id: Setting<ExternalId>,
    /// The department they work in.
    pub department: Setting<Department>,
    /// Their manager's account in the same tenant.
    pub manager: Setting<UserId>,
    /// The number the company knows them by.
    pub employee_number: Setting<EmployeeNumber>,
}

/// Everything an account records about its holder beyond its name: their
/// own details and the directory's records. A new account has neither.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UserProfile {
    /// What the person keeps about themselves.
    pub details: PersonalDetails,
    /// What the company's directory keeps about them.
    pub records: DirectoryRecords,
}

/// One field of a profile, named as the audit trail names it.
///
/// A record of a change names which fields changed and never what they
/// say: a phone number written into a permanent audit line would outlive
/// the person's erasure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChangedProfileField {
    /// [`PersonalDetails::given_name`].
    GivenName,
    /// [`PersonalDetails::family_name`].
    FamilyName,
    /// [`PersonalDetails::preferred_username`].
    PreferredUsername,
    /// [`PersonalDetails::picture`].
    Picture,
    /// [`PersonalDetails::phone_number`].
    PhoneNumber,
    /// [`DirectoryRecords::external_id`].
    ExternalId,
    /// [`DirectoryRecords::department`].
    Department,
    /// [`DirectoryRecords::manager`].
    Manager,
    /// [`DirectoryRecords::employee_number`].
    EmployeeNumber,
}

impl ChangedProfileField {
    /// The field's name, stable across releases.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GivenName => "given_name",
            Self::FamilyName => "family_name",
            Self::PreferredUsername => "preferred_username",
            Self::Picture => "picture",
            Self::PhoneNumber => "phone_number",
            Self::ExternalId => "external_id",
            Self::Department => "department",
            Self::Manager => "manager",
            Self::EmployeeNumber => "employee_number",
        }
    }
}

impl PersonalDetails {
    /// The fields that differ between these details and `after`, in the
    /// order they are declared.
    #[must_use]
    pub fn fields_changed_to(&self, after: &Self) -> Vec<ChangedProfileField> {
        [
            (
                ChangedProfileField::GivenName,
                self.given_name != after.given_name,
            ),
            (
                ChangedProfileField::FamilyName,
                self.family_name != after.family_name,
            ),
            (
                ChangedProfileField::PreferredUsername,
                self.preferred_username != after.preferred_username,
            ),
            (ChangedProfileField::Picture, self.picture != after.picture),
            (
                ChangedProfileField::PhoneNumber,
                self.phone_number != after.phone_number,
            ),
        ]
        .into_iter()
        .filter_map(|(field, changed)| changed.then_some(field))
        .collect()
    }
}

impl DirectoryRecords {
    /// The fields that differ between these records and `after`, in the
    /// order they are declared.
    #[must_use]
    pub fn fields_changed_to(&self, after: &Self) -> Vec<ChangedProfileField> {
        [
            (
                ChangedProfileField::ExternalId,
                self.external_id != after.external_id,
            ),
            (
                ChangedProfileField::Department,
                self.department != after.department,
            ),
            (ChangedProfileField::Manager, self.manager != after.manager),
            (
                ChangedProfileField::EmployeeNumber,
                self.employee_number != after.employee_number,
            ),
        ]
        .into_iter()
        .filter_map(|(field, changed)| changed.then_some(field))
        .collect()
    }

    /// Whether these records name `account` as its own manager.
    #[must_use]
    pub fn names_as_own_manager(&self, account: &UserId) -> bool {
        self.manager.value() == Some(account)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ann adds her given name and phone number and leaves the rest. Only
    /// those two fields read as changed, in the order they are declared.
    #[test]
    fn only_the_fields_that_differ_read_as_changed() {
        let before = PersonalDetails::default();
        let after = PersonalDetails {
            phone_number: Setting::Set(PhoneNumber::new("+4930123456").unwrap()),
            given_name: Setting::Set(GivenName::new("Ann").unwrap()),
            ..PersonalDetails::default()
        };

        let changed = before.fields_changed_to(&after);

        assert_eq!(
            changed,
            vec![
                ChangedProfileField::GivenName,
                ChangedProfileField::PhoneNumber
            ]
        );
    }

    /// Ann's manager is Bob. Clearing it reads as a change to `manager`, and
    /// nothing else.
    #[test]
    fn clearing_a_record_reads_as_its_change() {
        let before = DirectoryRecords {
            manager: Setting::Set(UserId::new()),
            ..DirectoryRecords::default()
        };

        let changed = before.fields_changed_to(&DirectoryRecords::default());

        assert_eq!(changed, vec![ChangedProfileField::Manager]);
    }

    /// Records naming Ann as Ann's manager name her as her own manager.
    /// Records naming Bob do not.
    #[test]
    fn records_naming_the_account_itself_as_manager_are_seen() {
        let ann = UserId::new();
        let bob = UserId::new();
        let managed_by = |manager| DirectoryRecords {
            manager: Setting::Set(manager),
            ..DirectoryRecords::default()
        };

        assert!(managed_by(ann).names_as_own_manager(&ann));
        assert!(!managed_by(bob).names_as_own_manager(&ann));
    }

    /// Every field has its own audit name, so no two changes read the same.
    #[test]
    fn every_field_has_its_own_name() {
        let fields = [
            ChangedProfileField::GivenName,
            ChangedProfileField::FamilyName,
            ChangedProfileField::PreferredUsername,
            ChangedProfileField::Picture,
            ChangedProfileField::PhoneNumber,
            ChangedProfileField::ExternalId,
            ChangedProfileField::Department,
            ChangedProfileField::Manager,
            ChangedProfileField::EmployeeNumber,
        ];

        let names = fields.map(ChangedProfileField::as_str);

        assert_eq!(
            crate::shared::validation::distinct::first_repeat(names),
            None
        );
    }
}
