//! What an account shows of its holder: the name, the locale, the
//! timezone and the personal details, which the holder or someone who may
//! edit their profile changes, and the directory's records, which only
//! someone who may act on the account changes.

use crate::domains::identity::account::control::{
    AccountAction, AccountControlCheck, ProfileEditor,
};
use crate::domains::identity::account::user::User;
use crate::domains::identity::account::user_profile::{
    ChangedProfileField, DirectoryRecords, PersonalDetails,
};
use crate::domains::identity::events::account::{UserPreferencesUpdated, UserRenamed};
use crate::domains::identity::events::profile::UserProfileUpdated;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{DisplayName, Locale, Preference, Timezone};

impl<T: TenantScope> User<T> {
    /// Replaces the holder's personal details with `details`: their name's
    /// parts, the name they go by, their picture and their phone number. As
    /// with [`rename`](Self::rename), only the holder or someone who may
    /// edit their profile makes the change. Raises
    /// `identity.user_profile_updated` naming the fields that changed, and
    /// nothing when none did.
    ///
    /// The phone number is the holder's word. Nothing here proves it
    /// reaches them, so no sign-in or recovery step may trust it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not edit this profile.
    pub fn update_details(
        &mut self,
        details: PersonalDetails,
        by: &impl ProfileEditor<T>,
    ) -> Result<(), DomainError> {
        by.ensure_may_edit(&self.id)?;
        let fields = self.profile.details.fields_changed_to(&details);
        self.profile.details = details;
        self.profile_changed(fields);
        Ok(())
    }

    /// Replaces what the company's directory records about the holder with
    /// `records`: its id for the account, their department, manager and
    /// employee number, as `control` allows. Raises
    /// `identity.user_profile_updated` naming the fields that changed, and
    /// nothing when none did.
    ///
    /// These are the company's records, not the person's word: a manager
    /// decides who approves for whom. Sam may edit only his own profile.
    /// Without this check, he names himself his own manager and approves
    /// his own requests, or writes another's employee number onto his
    /// account.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `control` refuses it: it was made
    ///   for another account, the person acting lacks the right, or the
    ///   account holds more than them.
    /// - [`DomainError::Validation`] when `records` name the account as its
    ///   own manager.
    pub fn update_records(
        &mut self,
        records: DirectoryRecords,
        control: &impl AccountControlCheck,
    ) -> Result<(), DomainError> {
        control.ensure_allowed(&self.id, AccountAction::EditRecords)?;
        if records.names_as_own_manager(&self.id) {
            return Err(DomainError::invalid(message!(
                "identity-a-person-is-never-their-own",
                "a person is never their own manager"
            )));
        }
        let fields = self.profile.records.fields_changed_to(&records);
        self.profile.records = records;
        self.profile_changed(fields);
        Ok(())
    }

    /// Records a change to `fields` of the profile, when there was one.
    fn profile_changed(&mut self, fields: Vec<ChangedProfileField>) {
        if fields.is_empty() {
            return;
        }
        self.touch();
        self.raised.raise(UserProfileUpdated {
            user_id: self.id,
            fields,
            occurred_at: self.updated_at,
        });
    }

    /// Updates the display name, by the person it belongs to or by someone
    /// `by` shows may edit their profile. Raises `identity.user_renamed`
    /// with both names.
    ///
    /// Sam may only view users. Without this check, he renames Ann to
    /// "Former employee" and her colleagues stop trusting her messages.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not edit this profile:
    ///   someone else is signed in, or the person acting lacks the right to
    ///   update users or holds less than the account.
    pub fn rename(
        &mut self,
        display_name: DisplayName,
        by: &impl ProfileEditor<T>,
    ) -> Result<(), DomainError> {
        by.ensure_may_edit(&self.id)?;
        let old_name = std::mem::replace(&mut self.display_name, display_name);
        self.touch();
        self.raised.raise(UserRenamed {
            old_name,
            new_name: self.display_name.clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Sets the locale and the timezone given, each their own choice or back
    /// to the tenant's, and leaves one not given as it is. As with
    /// [`rename`](Self::rename), only the holder or someone who may edit
    /// their profile sets them. Raises `identity.user_preferences_updated`
    /// with both settings as they stand afterwards, even when neither was
    /// given.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not edit this profile.
    pub fn change_preferences(
        &mut self,
        locale: Option<Preference<Locale>>,
        timezone: Option<Preference<Timezone>>,
        by: &impl ProfileEditor<T>,
    ) -> Result<(), DomainError> {
        by.ensure_may_edit(&self.id)?;
        if let Some(locale) = locale {
            self.change_locale(locale, by)?;
        }
        if let Some(timezone) = timezone {
            self.change_timezone(timezone, by)?;
        }
        self.raised.raise(UserPreferencesUpdated {
            locale: self.locale.clone(),
            timezone: self.timezone.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Sets the locale: their own choice, or back to the tenant's.
    pub(super) fn change_locale(
        &mut self,
        locale: Preference<Locale>,
        by: &impl ProfileEditor<T>,
    ) -> Result<(), DomainError> {
        by.ensure_may_edit(&self.id)?;
        self.locale = locale;
        self.touch();
        Ok(())
    }

    /// Sets the timezone: their own choice, or back to the tenant's.
    pub(super) fn change_timezone(
        &mut self,
        timezone: Preference<Timezone>,
        by: &impl ProfileEditor<T>,
    ) -> Result<(), DomainError> {
        by.ensure_may_edit(&self.id)?;
        self.timezone = timezone;
        self.touch();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::granter::{AccountControl, Handout};
    use crate::domains::authorization::permission::{SystemPermission, UserAction};
    use crate::domains::authorization::stewardship::Stewardship;
    use crate::domains::identity::account::profile_values::{Department, GivenName, PhoneNumber};
    use crate::domains::identity::account::user::UserRow;
    use crate::domains::identity::account::user::tests::{control_over, signed_in_as};
    use crate::domains::identity::account::user_profile::UserProfile;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::builders::user;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{Setting, UserId};

    /// Ann's account, with what opening it raised taken away.
    fn ann() -> User<ResolvedTenant> {
        let mut account = user(UserId::new(), "ann@example.com");
        raised(&mut account);
        account
    }

    /// Someone who may only view users, acting on `account`.
    fn viewer_on(account: &User<ResolvedTenant>) -> AccountControl<'static> {
        AccountControl::assumed(
            anyone_holding(&[SystemPermission::Users(UserAction::View)]),
            *account.id(),
            Stewardship::OthersAdminister,
            Handout::NOTHING,
        )
    }

    fn with_phone() -> PersonalDetails {
        PersonalDetails {
            given_name: Setting::Set(GivenName::new("Ann").unwrap()),
            phone_number: Setting::Set(PhoneNumber::new("+4930123456").unwrap()),
            ..PersonalDetails::default()
        }
    }

    /// Ann adds her given name and phone number from her own sign-in. Her
    /// profile holds them, and the record names the two fields, not what
    /// they say.
    #[test]
    fn the_holder_fills_in_their_details() {
        let mut account = ann();
        let holder = signed_in_as::<ResolvedTenant>(*account.id());

        account.update_details(with_phone(), &holder).unwrap();

        assert_eq!(account.profile().details, with_phone());
        let events = raised(&mut account);
        assert_eq!(events.len(), 1);
        let payload = events[0].payload();
        assert_eq!(payload.get("fields"), Some("given_name,phone_number"));
        assert!(!format!("{:?}", payload.value("fields")).contains("+4930123456"));
    }

    /// User-view authority cannot replace Ann's personal details, which
    /// remain at their defaults after the refusal.
    #[test]
    fn someone_who_may_only_view_users_cannot_edit_details() {
        let mut account = ann();

        let refused = account.update_details(with_phone(), &viewer_on(&account));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(account.profile().details, PersonalDetails::default());
    }

    /// Signing in as another person grants no right to edit Ann's details.
    #[test]
    fn another_signed_in_person_cannot_edit_details() {
        let mut account = ann();
        let mallory = signed_in_as::<ResolvedTenant>(UserId::new());

        let refused = account.update_details(with_phone(), &mallory);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Saving the details Ann already has records nothing.
    #[test]
    fn saving_unchanged_details_records_nothing() {
        let mut account = ann();
        let holder = signed_in_as::<ResolvedTenant>(*account.id());

        account
            .update_details(PersonalDetails::default(), &holder)
            .unwrap();

        assert!(raised_names(&mut account).is_empty());
    }

    /// An admin puts Ann in Finance under Bob. Her records hold both, and
    /// the record names the department and the manager.
    #[test]
    fn an_admin_keeps_the_directory_records() {
        let mut account = ann();
        let bob = UserId::new();
        let records = DirectoryRecords {
            department: Setting::Set(Department::new("Finance").unwrap()),
            manager: Setting::Set(bob),
            ..DirectoryRecords::default()
        };

        account
            .update_records(records.clone(), &control_over(&account))
            .unwrap();

        assert_eq!(account.profile().records, records);
        let events = raised(&mut account);
        assert_eq!(
            events[0].payload().get("fields"),
            Some("department,manager")
        );
    }

    /// User-view authority cannot assign Ann a manager, and her directory
    /// records remain unchanged.
    #[test]
    fn someone_who_may_only_view_users_cannot_change_the_records() {
        let mut account = ann();
        let records = DirectoryRecords {
            manager: Setting::Set(UserId::new()),
            ..DirectoryRecords::default()
        };

        let refused = account.update_records(records, &viewer_on(&account));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert_eq!(account.profile().records, DirectoryRecords::default());
    }

    /// Assigning Ann as her own manager is rejected even with account
    /// administration authority.
    #[test]
    fn nobody_is_their_own_manager() {
        let mut account = ann();
        let records = DirectoryRecords {
            manager: Setting::Set(*account.id()),
            ..DirectoryRecords::default()
        };

        let refused = account.update_records(records, &control_over(&account));

        assert!(matches!(refused, Err(DomainError::Validation(_))));
    }

    /// A stored row naming its account as its own manager is refused as
    /// corrupt.
    #[test]
    fn a_stored_account_managing_itself_is_refused() {
        let account = ann();
        let id = *account.id();
        let row = UserRow {
            id,
            email: account.email().clone(),
            display_name: account.display_name().clone(),
            status: account.status(),
            email_standing: account.address().standing(),
            locale: Preference::Inherited,
            timezone: Preference::Inherited,
            profile: UserProfile {
                records: DirectoryRecords {
                    manager: Setting::Set(id),
                    ..DirectoryRecords::default()
                },
                ..UserProfile::default()
            },
            created_at: account.created_at(),
            updated_at: account.updated_at(),
            last_login_at: None,
            joining: crate::types::Joining::NotYet,
            credentials_changed_at: account.credentials_changed_at(),
            vouching: account.vouching(),
        };

        assert!(refused_as_corrupt(&User::<ResolvedTenant>::reconstitute(
            row
        )));
    }

    /// The record of a change holds the account it was made to.
    #[test]
    fn a_profile_change_names_the_account() {
        let mut account = ann();
        let holder = signed_in_as::<ResolvedTenant>(*account.id());

        account.update_details(with_phone(), &holder).unwrap();

        let events = raised(&mut account);
        let Some(FieldValue::Reference(reference)) = events[0].payload().value("user").cloned()
        else {
            panic!("the record names no account");
        };
        assert_eq!(reference.id(), account.id().to_string());
    }
}
