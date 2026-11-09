//! Searching the directory: the users and groups a bound person may read.
//!
//! Reading the directory takes the right to view users, held now. An LDAP
//! connection stays open long after its bind, so every search works out
//! again what the person holds, as a write does: a certificate revoked, an
//! account shut or a right taken away since the bind stops the next
//! search. A person only ever reads the tenant they bound in: a search
//! aimed anywhere else is refused, whatever they hold.
//!
//! Every search is recorded, a refused one too. LDAP search is a path fewer
//! people watch than the API, and guessing a password with a bind, then
//! exporting the whole directory with a search, is a classic attack.

use std::sync::Arc;

use ianua_domain::domains::authentication::operations::directory_attempt::DirectorySearchAttempt;
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{GroupId, UserId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::use_case::Command;
use crate::use_cases::directory::listing::{EntryPorts, ensure_aimed_at_bind};
use crate::use_cases::directory::principal::{DirectoryBase, DirectoryPrincipal};

/// The most entries of each kind a search returns, as common LDAP servers
/// limit it. A larger directory needs paged search, which is not offered
/// yet.
pub(crate) const MAX_DIRECTORY_ENTRIES: u32 = 1000;

/// A user as the directory shows them.
pub struct DirectoryUser {
    /// The user's id.
    pub id: UserId,
    /// The user's address, the entry's `uid` and `mail`.
    pub email: String,
    /// The user's display name, the entry's `cn`.
    pub display_name: String,
}

/// A group as the directory shows it.
pub struct DirectoryGroup {
    /// The group's id.
    pub id: GroupId,
    /// The group's name, the entry's `cn`.
    pub name: String,
    /// The users directly in the group.
    pub members: Vec<UserId>,
}

/// What a search returns.
pub struct DirectoryListing {
    /// The tenant's users.
    pub users: Vec<DirectoryUser>,
    /// The tenant's groups, with their members.
    pub groups: Vec<DirectoryGroup>,
}

/// The ports [`SearchUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SearchPorts {
    /// Reads the tenant's users and groups.
    pub entries: EntryPorts,
    /// What the bound person holds in their tenant now, worked out again
    /// for every search.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads the directory for a bound person.
pub struct SearchUseCase {
    ports: SearchPorts,
}

impl SearchUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: SearchPorts) -> Self {
        Self { ports }
    }

    /// What `principal` holds now, once they may search the part of the
    /// directory `base` names.
    async fn reader(
        &self,
        principal: &DirectoryPrincipal,
        base: &DirectoryBase,
    ) -> Result<TenantAuthority, AppError> {
        ensure_aimed_at_bind(principal.base(), base)?;
        let authority = self
            .ports
            .tenant_authorities
            .authority(principal.caller())
            .await?;
        authority
            .ensure_holds(SystemPermission::Users(UserAction::View))
            .map_err(AppError::from_domain)?;
        Ok(authority)
    }

    /// What `principal` holds, when they may read the directory at `base`.
    /// A refusal is raised on `trail` and recorded through `auditor` as done
    /// by the person who bound.
    async fn recorded_reader(
        &self,
        principal: &DirectoryPrincipal,
        base: &DirectoryBase,
        trail: &mut DirectorySearchAttempt<ResolvedTenant>,
        auditor: &RequestAuditor,
    ) -> Result<TenantAuthority, AppError> {
        let refused = match self.reader(principal, base).await {
            Ok(authority) => return Ok(authority),
            Err(refused @ (AppError::Forbidden(_) | AppError::Unauthenticated)) => refused,
            Err(failed) => return Err(failed),
        };
        trail.record_denial();
        auditor
            .dispatch_by(
                &principal.authority().actor(),
                trail.take_events(principal.tenant()),
            )
            .await
            .or_internal()?;
        Err(refused)
    }
}

impl Command for SearchUseCase {
    type Caller = DirectoryPrincipal;
    type Input = DirectoryBase;
    type Output = Result<DirectoryListing, AppError>;

    /// The users and groups of the tenant `principal` bound in, for a search
    /// aimed at `base`.
    ///
    /// A search records `authentication.directory_search_performed` with
    /// how many entries it returned, never the entries; a refused one
    /// records `authentication.directory_search_denied`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the certificate the person bound
    ///   over was revoked or ran out since, their account was shut, or its
    ///   password was reset or changed since the bind.
    /// - `AppError::Forbidden` when `base` is not the part of the directory
    ///   the person bound to, or they may not view users now.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        principal: &DirectoryPrincipal,
        auditor: &RequestAuditor,
        base: DirectoryBase,
    ) -> Result<DirectoryListing, AppError> {
        let mut trail =
            DirectorySearchAttempt::new(*principal.user_id(), principal.user_label().clone());
        let authority = self
            .recorded_reader(principal, &base, &mut trail, auditor)
            .await?;
        let tenant = principal.tenant();
        let listing = self.ports.entries.listing(tenant).await?;
        trail.record_search(listing.users.len(), listing.groups.len());
        auditor
            .dispatch_by(&authority.actor(), trail.take_events(tenant))
            .await
            .or_internal()
            .map(|()| listing)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::group::GroupPlace;
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::types::{AgentId, Human, HumanAccount, PersonKey, PrincipalRef, TenantSlug};

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::authorization::{
        FakeGroupMembershipStore, FakeGroupStore, stored_group, stored_membership,
    };
    use crate::test_support::directory::{BindRefusal, BoundDirectory};
    use crate::test_support::identity::{FakeUserStore, stored_user};
    use crate::test_support::tenant::cfg;
    use crate::test_support::{
        FakeEventDispatcher, block_on, test_auditor, test_ctx, test_ctx_with,
    };

    const ANN: &str = "ann@acme.test";

    fn slug(value: &str) -> TenantSlug {
        TenantSlug::new(value, &cfg().slug).unwrap()
    }

    fn acme() -> DirectoryBase {
        DirectoryBase {
            organization: slug("acme-corp"),
            tenant: slug("acme"),
        }
    }

    /// Ann, bound in the test tenant under `acme-corp/acme`, holding `held`.
    fn ann_holding(held: &[SystemPermission]) -> DirectoryPrincipal {
        let account = stored_user(UserId::new(), ANN, UserStatus::Active);
        let who = Human::new(
            HumanAccount::User(*account.id()),
            PersonKey::new(ANN).unwrap(),
        );
        let authority = TenantAuthority::assumed(who, test_ctx().tenant_id(), held, &[]);
        let caller = test_ctx_with(
            test_ctx().organization_id(),
            test_ctx().tenant_id(),
            *account.id(),
        );
        DirectoryPrincipal::bound(authority, caller, acme(), &account)
    }

    fn reader() -> DirectoryPrincipal {
        ann_holding(&[SystemPermission::Users(UserAction::View)])
    }

    struct Fixture {
        users: FakeUserStore,
        groups: FakeGroupStore,
        memberships: FakeGroupMembershipStore,
        holds_now: FakeTenantAuthorities,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn empty() -> Self {
            Self {
                users: FakeUserStore::empty(),
                groups: FakeGroupStore::empty(),
                memberships: FakeGroupMembershipStore::empty(),
                holds_now: FakeTenantAuthorities::holding(&[SystemPermission::Users(
                    UserAction::View,
                )]),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn search(
            self,
            principal: &DirectoryPrincipal,
            base: DirectoryBase,
        ) -> (Result<DirectoryListing, AppError>, Vec<String>) {
            let use_case = SearchUseCase::new(SearchPorts {
                entries: EntryPorts {
                    users: Arc::new(self.users),
                    groups: Arc::new(self.groups),
                    memberships: Arc::new(self.memberships),
                },
                tenant_authorities: Arc::new(self.holds_now),
            });
            let result =
                block_on(use_case.execute(principal, &test_auditor(self.audit.clone()), base));
            let recorded = self.audit.records.lock().unwrap().clone();
            (result, recorded)
        }
    }

    /// Ann may view users and searches her directory. She reads its users
    /// and its groups with their members, and the search is recorded with
    /// its counts.
    #[test]
    fn a_reader_lists_the_users_and_groups_with_their_members() {
        let ada = UserId::new();
        let engineering = stored_group("Engineering", GroupPlace::TopLevel, vec![]);
        let membership = stored_membership(PrincipalRef::User(ada), *engineering.id());
        let tenant = test_ctx().tenant_id();
        let fixture = Fixture {
            users: FakeUserStore::with_user(ada, "ada@acme.test"),
            groups: FakeGroupStore::holding(tenant, [engineering]),
            memberships: FakeGroupMembershipStore::holding(tenant, [membership]),
            ..Fixture::empty()
        };
        let audit = fixture.audit.clone();

        let (result, recorded) = fixture.search(&reader(), acme());

        let listing = result.unwrap();
        assert_eq!(listing.users.len(), 1);
        assert_eq!(listing.users[0].email, "ada@acme.test");
        assert_eq!(listing.groups[0].name, "Engineering");
        assert_eq!(listing.groups[0].members, vec![ada]);
        assert_eq!(recorded, ["authentication.directory_search_performed"]);
        let payload = audit.payload_of("authentication.directory_search_performed");
        assert_eq!(payload.get("users_returned"), Some("1"));
    }

    /// Binding successfully grants no user-viewing right; a search without
    /// that right is forbidden and records a denial.
    #[test]
    fn a_search_without_the_right_to_view_users_is_refused_and_recorded() {
        let fixture = Fixture {
            holds_now: FakeTenantAuthorities::holding(&[]),
            ..Fixture::empty()
        };

        let (result, recorded) = fixture.search(&ann_holding(&[]), acme());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(recorded, ["authentication.directory_search_denied"]);
    }

    /// Searches over `directory`'s stores, working out what the bound
    /// person holds as production does.
    fn searching(directory: &BoundDirectory) -> SearchUseCase {
        SearchUseCase::new(SearchPorts {
            entries: EntryPorts {
                users: directory.users.clone(),
                groups: directory.sources.groups.clone(),
                memberships: directory.sources.memberships.clone(),
            },
            tenant_authorities: directory.authorities(),
        })
    }

    /// Ann, an admin, binds to the directory and searches it. What she
    /// holds is worked out again, and she reads herself in it.
    #[test]
    fn a_bound_admin_searches_with_what_she_holds_now() {
        let directory = BoundDirectory::holding(SystemPermission::all());
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));

        let listing =
            block_on(searching(&directory).execute(&directory.bind(), &auditor, acme())).unwrap();

        assert_eq!(listing.users.len(), 1);
        assert_eq!(listing.users[0].id, directory.ann);
    }

    /// An invalidated bind or missing viewing right blocks the next search
    /// on an open connection and records a denial.
    #[test]
    fn a_bind_that_no_longer_counts_or_lacks_the_right_searches_nothing() {
        for refusal in BindRefusal::ALL {
            let (directory, principal) = refusal.bound(SystemPermission::all());
            let audit = Arc::new(FakeEventDispatcher::new());
            let auditor = test_auditor(audit.clone());

            let result = block_on(searching(&directory).execute(&principal, &auditor, acme()));

            assert!(refusal.refused(&result), "{refusal:?}");
            assert_eq!(
                audit.records.lock().unwrap().as_slice(),
                ["authentication.directory_search_denied"],
                "{refusal:?}"
            );
        }
    }

    /// Even an administrator cannot search another tenant through an Acme
    /// bind; the attempt is forbidden and recorded as denied.
    #[test]
    fn a_search_aimed_at_another_tenant_is_refused() {
        let elsewhere = DirectoryBase {
            tenant: slug("elsewhere"),
            ..acme()
        };

        let (result, recorded) =
            Fixture::empty().search(&ann_holding(SystemPermission::all()), elsewhere);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(recorded, ["authentication.directory_search_denied"]);
    }

    /// A matching tenant name in another organization does not extend
    /// Ann's bind scope; searching it is forbidden.
    #[test]
    fn a_search_aimed_at_another_organization_is_refused() {
        let elsewhere = DirectoryBase {
            organization: slug("other-corp"),
            ..acme()
        };

        let (result, _) = Fixture::empty().search(&reader(), elsewhere);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Ann's group holds an agent beside Ada. The agent has no directory
    /// entry, so only Ada is listed as a member.
    #[test]
    fn only_users_are_listed_as_group_members() {
        let ada = UserId::new();
        let ops = stored_group("Ops", GroupPlace::TopLevel, vec![]);
        let tenant = test_ctx().tenant_id();
        let memberships = [
            stored_membership(PrincipalRef::User(ada), *ops.id()),
            stored_membership(PrincipalRef::Agent(AgentId::new()), *ops.id()),
        ];
        let fixture = Fixture {
            groups: FakeGroupStore::holding(tenant, [ops]),
            memberships: FakeGroupMembershipStore::holding(tenant, memberships),
            ..Fixture::empty()
        };

        let (result, _) = fixture.search(&reader(), acme());

        assert_eq!(result.unwrap().groups[0].members, vec![ada]);
    }
}
