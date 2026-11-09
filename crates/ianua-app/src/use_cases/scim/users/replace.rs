//! Replace SCIM user: the directory sends a user's whole record, and every
//! field of it is applied as a change.

use std::sync::Arc;

use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::UserId;

use crate::auditor::RequestAuditor;
use crate::context::ScimCaller;
use crate::error::AppError;
use crate::use_case::Command;
use crate::use_cases::scim::users::fields::{ScimUserChange, ScimUserFields};
use crate::use_cases::scim::users::{UpdateScimRequest, UpdateScimUseCase};

/// The whole record a directory sends for one user.
pub struct ReplaceScimRequest {
    /// The user being replaced.
    pub user_id: UserId,
    /// Their new record.
    pub fields: ScimUserFields,
}

/// The ports [`ReplaceScimUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ReplaceScimPorts {
    /// Applies the record's fields as changes, with every check a change
    /// has.
    pub update: Arc<UpdateScimUseCase>,
}

/// Replaces a tenant user's record for its directory.
pub struct ReplaceScimUseCase {
    ports: ReplaceScimPorts,
}

impl ReplaceScimUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ReplaceScimPorts) -> Self {
        Self { ports }
    }
}

impl Command for ReplaceScimUseCase {
    type Caller = ScimCaller;
    type Input = ReplaceScimRequest;
    type Output = Result<User<ResolvedTenant>, AppError>;

    /// Makes the user's address, display name, name parts, the directory's
    /// records and switch the ones in `request.fields`. A part the record
    /// leaves out is cleared.
    ///
    /// # Errors
    ///
    /// As [`UpdateScimUseCase`].
    async fn execute(
        &self,
        caller: &ScimCaller,
        auditor: &RequestAuditor,
        request: ReplaceScimRequest,
    ) -> Result<User<ResolvedTenant>, AppError> {
        let ReplaceScimRequest { user_id, fields } = request;
        let request = UpdateScimRequest {
            user_id,
            changes: every_field(fields),
        };
        self.ports.update.execute(caller, auditor, request).await
    }
}

/// Every field of `fields` as a change, so a field the record leaves out is
/// cleared.
fn every_field(fields: ScimUserFields) -> Vec<ScimUserChange> {
    let ScimUserFields {
        user_name,
        display_name,
        name,
        records,
        active,
    } = fields;
    vec![
        ScimUserChange::UserName(user_name),
        ScimUserChange::DisplayName(display_name),
        ScimUserChange::GivenName(name.given_name),
        ScimUserChange::FamilyName(name.family_name),
        ScimUserChange::ExternalId(records.external_id),
        ScimUserChange::Department(records.department),
        ScimUserChange::Manager(records.manager),
        ScimUserChange::EmployeeNumber(records.employee_number),
        ScimUserChange::Active(active),
    ]
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::account::profile_values::{
        ExternalId, FamilyName, GivenName,
    };
    use ianua_domain::domains::identity::account::user_profile::DirectoryRecords;
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::shared::config::DisplayNameLimits;
    use ianua_domain::types::{DisplayName, Email, Setting};

    use super::*;
    use crate::acting::ScimAuthorities;
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::scim::{SignInRefusal, refused_sign_in, scim_caller, signed_in};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};
    use crate::use_cases::scim::users::UpdateScimPorts;
    use crate::use_cases::scim::users::fields::{AccountSwitch, ScimName};

    fn use_case(
        scim_authorities: Arc<dyn ScimAuthorities>,
        users: &Arc<FakeUserStore>,
    ) -> ReplaceScimUseCase {
        ReplaceScimUseCase::new(ReplaceScimPorts {
            update: Arc::new(UpdateScimUseCase::new(UpdateScimPorts {
                scim_authorities,
                user_store: users.clone(),
                ..UpdateScimPorts::fakes()
            })),
        })
    }

    fn grace_switched_off(user_id: UserId) -> ReplaceScimRequest {
        ReplaceScimRequest {
            user_id,
            fields: ScimUserFields {
                user_name: Email::new("grace@acme.com").unwrap(),
                display_name: DisplayName::new("Grace Hopper", &DisplayNameLimits::default())
                    .unwrap(),
                name: ScimName {
                    given_name: Setting::Set(GivenName::new("Grace").unwrap()),
                    family_name: Setting::Set(FamilyName::new("Hopper").unwrap()),
                },
                records: DirectoryRecords {
                    external_id: Setting::Set(ExternalId::new("00u-grace").unwrap()),
                    ..DirectoryRecords::default()
                },
                active: AccountSwitch::Off,
            },
        }
    }

    fn replace(
        use_case: &ReplaceScimUseCase,
        caller: &ScimCaller,
        request: ReplaceScimRequest,
    ) -> Result<User<ResolvedTenant>, AppError> {
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        block_on(use_case.execute(caller, &auditor, request))
    }

    /// Okta sends the whole record of an account: a new address, a new name,
    /// switched off. Every field is applied.
    #[test]
    fn replacing_a_record_applies_every_field() {
        let id = UserId::new();
        let users = Arc::new(FakeUserStore::with_user(id, "ada@acme.com"));

        let replaced = replace(
            &use_case(signed_in(), &users),
            &scim_caller(),
            grace_switched_off(id),
        )
        .unwrap();

        assert_eq!(replaced.email().as_str(), "grace@acme.com");
        assert_eq!(replaced.display_name().as_str(), "Grace Hopper");
        assert_eq!(replaced.status(), UserStatus::Locked);
        let profile = replaced.profile();
        assert_eq!(
            profile.details.family_name.value().unwrap().as_str(),
            "Hopper"
        );
        assert_eq!(
            profile.records.external_id.value().unwrap().as_str(),
            "00u-grace"
        );
    }

    /// Missing, incorrect or rotated tokens and disabled SCIM prevent record
    /// replacement, leaving Ada's stored address unchanged.
    #[test]
    fn a_directory_that_is_not_signed_in_is_refused() {
        for refusal in SignInRefusal::ALL {
            let id = UserId::new();
            let users = Arc::new(FakeUserStore::with_user(id, "ada@acme.com"));
            let (scim_authorities, caller) = refused_sign_in(refusal);

            let result = replace(
                &use_case(scim_authorities, &users),
                &caller,
                grace_switched_off(id),
            );

            assert!(
                matches!(result, Err(AppError::Unauthenticated)),
                "{refusal:?}"
            );
            assert_eq!(users.get_email(&id).unwrap().as_str(), "ada@acme.com");
        }
    }
}
