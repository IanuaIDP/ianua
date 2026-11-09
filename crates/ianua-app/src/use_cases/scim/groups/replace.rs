//! Replace SCIM group: the directory sends a group's whole record, its
//! name and every member, and it is applied as changes.

use std::sync::Arc;

use ianua_domain::types::GroupId;

use crate::auditor::RequestAuditor;
use crate::context::ScimCaller;
use crate::error::AppError;
use crate::use_case::Command;
use crate::use_cases::scim::groups::fields::{ScimGroup, ScimGroupChange, ScimGroupFields};
use crate::use_cases::scim::groups::{UpdateScimRequest, UpdateScimUseCase};

/// The whole record a directory sends for one group.
pub struct ReplaceScimRequest {
    /// The group being replaced.
    pub group_id: GroupId,
    /// Its new name and members.
    pub fields: ScimGroupFields,
}

/// The ports [`ReplaceScimUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ReplaceScimPorts {
    /// Applies the record as changes, with every check a change has.
    pub update: Arc<UpdateScimUseCase>,
}

/// Replaces the name and members of a group a tenant's directory keeps.
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
    type Output = Result<ScimGroup, AppError>;

    /// Renames the group and makes `request.fields.members` its whole
    /// membership.
    ///
    /// # Errors
    ///
    /// As [`UpdateScimUseCase`].
    async fn execute(
        &self,
        caller: &ScimCaller,
        auditor: &RequestAuditor,
        request: ReplaceScimRequest,
    ) -> Result<ScimGroup, AppError> {
        let ReplaceScimRequest { group_id, fields } = request;
        let changes = vec![
            ScimGroupChange::Rename(fields.name),
            ScimGroupChange::ReplaceMembers(fields.members),
        ];
        let request = UpdateScimRequest { group_id, changes };
        self.ports.update.execute(caller, auditor, request).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::group::GroupOrigin;
    use ianua_domain::types::{Label, PrincipalRef, UserId};

    use super::*;
    use crate::acting::ScimAuthorities;
    use crate::ports::authorization::GroupMembershipStore;
    use crate::test_support::authorization::{
        FakeGroupMembershipStore, FakeGroupStore, stored_membership,
    };
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::scim::{
        SignInRefusal, kept_group, refused_sign_in, scim_caller, signed_in,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::scim::groups::{MemberCap, UpdateScimPorts};

    struct Acme {
        engineering: GroupId,
        grace: UserId,
        groups: Arc<FakeGroupStore>,
        memberships: Arc<FakeGroupMembershipStore>,
        users: Arc<FakeUserStore>,
    }

    fn acme() -> Acme {
        let tenant = test_ctx().tenant_id();
        let engineering = kept_group("Engineering", GroupOrigin::Directory);
        let id = *engineering.id();
        let (ada, grace) = (UserId::new(), UserId::new());
        let users = FakeUserStore::with_user(ada, "ada@acme.com");
        users.add_active_user(grace, "grace@acme.com");
        Acme {
            engineering: id,
            grace,
            groups: Arc::new(FakeGroupStore::holding(tenant, [engineering])),
            memberships: Arc::new(FakeGroupMembershipStore::holding(
                tenant,
                [stored_membership(PrincipalRef::User(ada), id)],
            )),
            users: Arc::new(users),
        }
    }

    impl Acme {
        fn replace(
            &self,
            scim_authorities: Arc<dyn ScimAuthorities>,
            caller: &ScimCaller,
        ) -> Result<ScimGroup, AppError> {
            let ports = UpdateScimPorts {
                scim_authorities,
                group_store: self.groups.clone(),
                membership_store: self.memberships.clone(),
                user_store: self.users.clone(),
                ..UpdateScimPorts::fakes()
            };
            let update = UpdateScimUseCase::new(ports, MemberCap::default());
            let use_case = ReplaceScimUseCase::new(ReplaceScimPorts {
                update: Arc::new(update),
            });
            let request = ReplaceScimRequest {
                group_id: self.engineering,
                fields: ScimGroupFields {
                    name: Label::new("displayName", "Platform").unwrap(),
                    members: vec![self.grace],
                },
            };
            let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
            block_on(use_case.execute(caller, &auditor, request))
        }

        fn members(&self) -> usize {
            block_on(
                self.memberships
                    .find_by_group(&test_ctx().tenant(), &self.engineering),
            )
            .unwrap()
            .len()
        }
    }

    /// Okta sends Engineering's whole record: now Platform, with Grace
    /// alone. The group is renamed and Ada leaves.
    #[test]
    fn replacing_a_record_renames_and_resets_membership() {
        let acme = acme();

        let replaced = acme.replace(signed_in(), &scim_caller()).unwrap();

        assert_eq!(replaced.group.name().as_str(), "Platform");
        assert_eq!(replaced.members, [acme.grace]);
    }

    /// Replacing a group with a missing, invalid or rotated token, or with
    /// SCIM disabled, returns an unauthenticated error and leaves its member
    /// count unchanged.
    #[test]
    fn a_directory_that_is_not_signed_in_is_refused() {
        for refusal in SignInRefusal::ALL {
            let acme = acme();
            let (scim_authorities, caller) = refused_sign_in(refusal);

            let result = acme.replace(scim_authorities, &caller);

            assert!(
                matches!(result, Err(AppError::Unauthenticated)),
                "{refusal:?}"
            );
            assert_eq!(acme.members(), 1);
        }
    }
}
