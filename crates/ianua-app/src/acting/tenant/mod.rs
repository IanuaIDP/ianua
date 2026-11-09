//! What a caller may do inside a tenant, worked out from the stored records
//! for the credential they came with.

mod account;
mod api_key;
mod directory_bind;
mod impersonation;
mod member;
mod run;
mod session;
mod support_impersonation;

use std::sync::Arc;

pub use account::{AccountHolder, SignedInAccount};
use async_trait::async_trait;
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::domains::organization::members::tenant_grant::OrgTenantGrant;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::types::{OrgUserId, SessionId, TenantId, UserId};
use time::OffsetDateTime;

use crate::acting::TenantAuthorities;
use crate::acting::tenant::impersonation::OperatorParties;
use crate::acting::tenant::support_impersonation::SupportParties;
use crate::context::{CallerContext, CallerIdentity, Credential};
use crate::error::AppError;
use crate::ports::authorization::{AccessRecordStore, HeldRecords, Holder};
use crate::ports::directory::LdapCertificateStore;
use crate::ports::identity::{SupportImpersonationStore, UserStore};
use crate::ports::oauth::ApiKeyStore;
use crate::ports::operator::{ImpersonationGrantStore, OperatorKeyStore, OperatorStore};
use crate::ports::organization::{
    OrgSessionStore, OrgTenantGrantStore, OrgUserStore, OrganizationStore,
};
use crate::ports::shared::SessionStore;
use crate::ports::tenant::TenantStore;
use crate::ports::workflows::WorkflowExecutionStore;
use crate::tenancy::ScopedTenant;

/// The stores [`TenantActing`] reads a caller's records from.
#[derive(ianua_macros::Fakes)]
pub struct TenantActingPorts {
    /// Who holds what in the tenant.
    pub access: Arc<dyn AccessRecordStore>,
    /// Tenants, for their session timeouts and their posture.
    pub tenants: Arc<dyn TenantStore>,
    /// A tenant caller's own records: their account, sessions, keys and directory certificates.
    pub tenant: TenantCredentialPorts,
    /// An organization member's records: the organization, the member, their sessions and tenant grants.
    pub members: MemberPorts,
    /// Operators and the impersonations that let them or an admin act as someone.
    pub operators: OperatorPorts,
    /// Workflow runs, read afresh each time a company step acts as a run's
    /// person.
    pub executions: Arc<dyn WorkflowExecutionStore>,
}

/// A tenant caller's own records: their account, sessions, keys and directory certificates.
#[derive(ianua_macros::Fakes)]
pub struct TenantCredentialPorts {
    /// The tenant's users.
    pub users: Arc<dyn UserStore>,
    /// The tenant's sessions.
    pub sessions: Arc<dyn SessionStore>,
    /// The tenant's API keys.
    pub api_keys: Arc<dyn ApiKeyStore>,
    /// The tenant's LDAP client certificates, which a directory bind is
    /// checked against again on every request.
    pub certificates: Arc<dyn LdapCertificateStore>,
}

/// An organization member's records: the organization, the member, their sessions and tenant grants.
#[derive(ianua_macros::Fakes)]
pub struct MemberPorts {
    /// Organizations, for their standing.
    pub organizations: Arc<dyn OrganizationStore>,
    /// Organization members.
    pub org_users: Arc<dyn OrgUserStore>,
    /// Organization members' sessions.
    pub org_sessions: Arc<dyn OrgSessionStore>,
    /// Organization members' tenant grants.
    pub org_grants: Arc<dyn OrgTenantGrantStore>,
}

/// Operators and the impersonations that let them or an admin act as someone.
#[derive(ianua_macros::Fakes)]
pub struct OperatorPorts {
    /// Platform operators.
    pub operators: Arc<dyn OperatorStore>,
    /// Operators' own keys.
    pub operator_keys: Arc<dyn OperatorKeyStore>,
    /// Impersonation grants.
    pub impersonations: Arc<dyn ImpersonationGrantStore>,
    /// Tenant admins' support impersonations.
    pub support_impersonations: Arc<dyn SupportImpersonationStore>,
}

/// Works out what a caller holds in the tenant they act in, from the stored
/// records for the credential they came with.
///
/// Nothing the request says decides it. A session counts only while the
/// domain's session check admits it, a key only for what its maker holds
/// now, a directory bind only while the certificate it was made over is in
/// force, and an operator only through an impersonation grant the tenant
/// allows.
pub struct TenantActing {
    ports: TenantActingPorts,
}

impl TenantActing {
    /// A resolver reading from `ports`.
    #[must_use]
    pub fn new(ports: TenantActingPorts) -> Self {
        Self { ports }
    }

    /// What the credential the caller came with holds, by what it is.
    async fn by_credential(&self, at: &Resolving<'_>) -> Result<TenantAuthority, AppError> {
        match (at.caller.identity(), at.caller.credential()) {
            (CallerIdentity::TenantUser(user), Credential::TenantSession(session)) => {
                self.of_session(at, user, session).await
            }
            (
                CallerIdentity::TenantUser(_) | CallerIdentity::OrgUser(_),
                Credential::TenantApiKey(key),
            ) => self.of_key(at, key).await,
            (CallerIdentity::TenantUser(user), Credential::DirectoryBind(bound)) => {
                self.of_directory_bind(at, user, bound).await
            }
            (CallerIdentity::OrgUser(member), Credential::OrgSession(session)) => {
                self.of_member_session(at, member, session).await
            }
            (CallerIdentity::Operator(operator), Credential::Impersonation { .. }) => {
                let parties = OperatorParties::of(operator, at.caller.credential())?;
                self.of_impersonation(at, parties).await
            }
            (identity, Credential::WorkflowRun(execution)) => {
                self.through_run(at, identity, execution).await
            }
            (CallerIdentity::TenantUser(admin), Credential::SupportImpersonation { .. }) => {
                let parties = SupportParties::of(admin, at.caller.credential())?;
                self.of_support_impersonation(at, parties).await
            }
            (_, credential) => Err(credential_refusal(credential)),
        }
    }

    async fn user(
        &self,
        tenant: &ScopedTenant,
        id: &UserId,
    ) -> Result<User<ResolvedTenant>, AppError> {
        self.ports
            .tenant
            .users
            .find_by_id(tenant, id)
            .await
            .map_err(AppError::from_domain)?
            .ok_or(AppError::Unauthenticated)
    }

    async fn tenant_record(&self, tenant: &TenantId) -> Result<Tenant, AppError> {
        self.ports
            .tenants
            .find_by_id(tenant)
            .await
            .map_err(AppError::from_domain)?
            .ok_or(AppError::Unauthenticated)
    }

    /// Who holds the account the caller came with, whatever the tenant's
    /// standing.
    async fn account_holder(&self, caller: &CallerContext) -> Result<AccountHolder, AppError> {
        let now = clock::now();
        match (caller.identity(), caller.credential()) {
            (CallerIdentity::TenantUser(user), Credential::TenantSession(session)) => self
                .checked_session(caller, user, session, now)
                .await
                .map(|person| AccountHolder::Session(Box::new(person))),
            (CallerIdentity::TenantUser(user), Credential::DirectoryBind(bound)) => self
                .bound_account(caller, user, bound, now)
                .await
                .map(|account| AccountHolder::Directory(Box::new(account))),
            _ => Err(AppError::Unauthenticated),
        }
    }

    /// Refuses unless `tenant` is open: nothing is done in the name of a
    /// suspended, archived or deleted tenant.
    async fn ensure_open(&self, tenant: &TenantId) -> Result<(), AppError> {
        if !self.tenant_record(tenant).await?.status().is_open() {
            return Err(AppError::TenantUnavailable(message!(
                "api-this-workspace-is-not-available",
                "this workspace is not available"
            )));
        }
        Ok(())
    }

    async fn member(&self, id: &OrgUserId) -> Result<OrgUser, AppError> {
        self.ports
            .members
            .org_users
            .find_by_id(id)
            .await
            .map_err(AppError::from_domain)?
            .ok_or(AppError::Unauthenticated)
    }

    async fn organization(&self, caller: &CallerContext) -> Result<Organization, AppError> {
        self.ports
            .members
            .organizations
            .find_by_id(&caller.organization_id())
            .await
            .map_err(AppError::from_domain)?
            .ok_or(AppError::Unauthenticated)
    }

    async fn grants(
        &self,
        member: &OrgUserId,
        caller: &CallerContext,
    ) -> Result<Vec<OrgTenantGrant>, AppError> {
        self.ports
            .members
            .org_grants
            .list_by_user_in_tenant(member, &caller.tenant_id())
            .await
            .map_err(AppError::from_domain)
    }

    /// The records that decide what `holder` holds in the caller's tenant,
    /// and no one else's.
    async fn held_by(
        &self,
        caller: &CallerContext,
        holder: Holder<'_>,
    ) -> Result<HeldRecords, AppError> {
        self.ports
            .access
            .load_held_by(&caller.tenant(), holder)
            .await
            .map_err(AppError::from_domain)
    }
}

#[async_trait]
impl TenantAuthorities for TenantActing {
    async fn authority(&self, caller: &CallerContext) -> Result<TenantAuthority, AppError> {
        let at = Resolving {
            caller,
            now: clock::now(),
        };
        let authority = self.by_credential(&at).await?;
        self.ensure_open(&caller.tenant_id()).await?;
        Ok(authority)
    }

    async fn signed_in(&self, caller: &CallerContext) -> Result<SignedInAccount, AppError> {
        let (CallerIdentity::TenantUser(user), Credential::TenantSession(session)) =
            (caller.identity(), caller.credential())
        else {
            return Err(AppError::Unauthenticated);
        };
        let person = self
            .checked_session(caller, user, session, clock::now())
            .await?;
        self.ensure_open(&caller.tenant_id()).await?;
        Ok(person)
    }

    async fn holder(&self, caller: &CallerContext) -> Result<AccountHolder, AppError> {
        let holder = self.account_holder(caller).await?;
        self.ensure_open(&caller.tenant_id()).await?;
        Ok(holder)
    }

    async fn signed_in_on(
        &self,
        tenant: &ScopedTenant,
        session_id: &SessionId,
    ) -> Result<SignedInAccount, AppError> {
        let person = self
            .session_holder(tenant, session_id, clock::now())
            .await?;
        self.ensure_open(tenant).await?;
        Ok(person)
    }
}

/// Why a credential that does not act inside a tenant is turned away.
pub(crate) fn credential_refusal(credential: &Credential) -> AppError {
    match credential {
        Credential::OrgApiKey(_) => AppError::Forbidden(message!(
            "app-an-organization-key-acts-on-the",
            "an organization key acts on the organization, never inside a tenant"
        )),
        Credential::OperatorKey(_) => AppError::Forbidden(message!(
            "app-an-operator-acts-inside-a-tenant",
            "an operator acts inside a tenant only through an impersonation grant"
        )),
        _ => AppError::Unauthenticated,
    }
}

/// One resolution: the caller, and the moment it is worked out for.
struct Resolving<'a> {
    caller: &'a CallerContext,
    now: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::group::GroupPlace;
    use ianua_domain::domains::authorization::permission::{
        RoleAction, RoutingAction, SystemPermission, UserAction,
    };
    use ianua_domain::domains::oauth::clients::api_key::ApiKey;
    use ianua_domain::domains::operator::status::OperatorStatus;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::organization::members::tenant_grant::OrgTenantGrantRow;
    use ianua_domain::domains::tenant::status::TenantStatus;
    use ianua_domain::types::{
        ActedBy, ActorRef, ApiKeyId, Expiry, GroupId, ImpersonationGrantId, KeyPrefix, OrgApiKeyId,
        PrincipalRef, RoleId, SessionId, TenantId,
    };
    use time::Duration;

    use super::*;
    use crate::ports::authorization::AccessRecords;
    use crate::test_support::authentication::FakeSessionStore;
    use crate::test_support::authorization::{
        FakeAccessRecordStore, stored_assignment, stored_group, stored_membership, stored_role,
    };
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::oauth::{
        FakeApiKeyStore, api_key_row, signed_in_session, stored_api_key,
    };
    use crate::test_support::operator::{
        FakeOperatorKeyStore, FakeOperatorStore, operator_without_grant, stored_operator,
        stored_operator_key, test_operator_id,
    };
    use crate::test_support::organization::{
        FakeOrgTenantGrantStore, OrgShape, RecordingOrgSessionStore, org_session_of,
        org_session_on_organization, org_shaped, org_store_with, org_user_store_with,
        password_only, test_org_user,
    };
    use crate::test_support::tenant::{
        FakeTenantStore, tenant_store_in_status, test_tenant_for_ctx,
    };
    use crate::test_support::{block_on, test_ctx, test_ctx_with, test_session_id};

    fn acting_over(ann: UserId, sessions: FakeSessionStore) -> TenantActing {
        TenantActing::new(TenantActingPorts {
            tenants: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
            tenant: TenantCredentialPorts {
                users: Arc::new(FakeUserStore::with_user(ann, "ann@acme.test")),
                sessions: Arc::new(sessions),
                ..TenantCredentialPorts::fakes()
            },
            ..TenantActingPorts::fakes()
        })
    }

    fn caller(ann: UserId) -> CallerContext {
        test_ctx_with(test_ctx().organization_id(), test_ctx().tenant_id(), ann)
    }

    /// Ann comes with her session. She is signed in, and the answer carries
    /// that session, so a use case working on it need not load it again.
    #[test]
    fn a_signed_in_person_comes_with_their_session() {
        let ann = UserId::new();
        let sessions = FakeSessionStore::with_session(signed_in_session(test_session_id(), ann));

        let person = block_on(acting_over(ann, sessions).signed_in(&caller(ann))).unwrap();

        assert_eq!(person.account.id(), &ann);
        assert_eq!(person.session.id(), &test_session_id());
    }

    /// Ann's session still exists in a suspended tenant, but authority,
    /// signed-in account and holder resolution all return tenant unavailable.
    #[test]
    fn nothing_acts_in_a_suspended_tenant() {
        let ann = UserId::new();
        let sessions = FakeSessionStore::with_session(signed_in_session(test_session_id(), ann));
        let acting = TenantActing::new(TenantActingPorts {
            tenants: tenant_store_in_status(TenantStatus::Suspended),
            tenant: TenantCredentialPorts {
                users: Arc::new(FakeUserStore::with_user(ann, "ann@acme.test")),
                sessions: Arc::new(sessions),
                ..TenantCredentialPorts::fakes()
            },
            ..TenantActingPorts::fakes()
        });

        let authority = block_on(acting.authority(&caller(ann)));
        let signed_in = block_on(acting.signed_in(&caller(ann)));
        let holder = block_on(acting.holder(&caller(ann)));

        assert!(matches!(authority, Err(AppError::TenantUnavailable(_))));
        assert!(matches!(signed_in, Err(AppError::TenantUnavailable(_))));
        assert!(matches!(holder, Err(AppError::TenantUnavailable(_))));
    }

    /// Ann, signed in, with `access` as the tenant's records.
    fn acting_with(ann: UserId, access: Arc<FakeAccessRecordStore>) -> TenantActing {
        let sessions = FakeSessionStore::with_session(signed_in_session(test_session_id(), ann));
        TenantActing::new(TenantActingPorts {
            access,
            tenants: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
            tenant: TenantCredentialPorts {
                users: Arc::new(FakeUserStore::with_user(ann, "ann@acme.test")),
                sessions: Arc::new(sessions),
                ..TenantCredentialPorts::fakes()
            },
            ..TenantActingPorts::fakes()
        })
    }

    const VIEW_USERS: SystemPermission = SystemPermission::Users(UserAction::View);
    const VIEW_ROLES: SystemPermission = SystemPermission::Roles(RoleAction::View);
    const CREATE_ROLES: SystemPermission = SystemPermission::Roles(RoleAction::Create);

    /// Acme's records: Ann may view roles herself, and is in Engineers,
    /// under Staff, whose role lets its people view users. Bob manages
    /// roles, and Bob's second assignment names a role that is gone.
    fn acme_records(ann: UserId) -> AccessRecords {
        let viewer = stored_role("viewer", vec![VIEW_ROLES], Vec::new());
        let staff_role = stored_role("staff", vec![VIEW_USERS], Vec::new());
        let manager = stored_role(
            "manager",
            vec![SystemPermission::Roles(RoleAction::Manage)],
            Vec::new(),
        );
        let staff = stored_group("Staff", GroupPlace::TopLevel, vec![*staff_role.id()]);
        let engineers = stored_group("Engineers", GroupPlace::Under(*staff.id()), Vec::new());
        let bob = PrincipalRef::User(UserId::new());
        AccessRecords {
            assignments: vec![
                stored_assignment(PrincipalRef::User(ann), *viewer.id()),
                stored_assignment(bob, *manager.id()),
                stored_assignment(bob, RoleId::new()),
            ],
            memberships: vec![stored_membership(PrincipalRef::User(ann), *engineers.id())],
            roles: vec![viewer, staff_role, manager],
            groups: vec![staff, engineers],
            ..AccessRecords::default()
        }
    }

    /// Ann's request is worked out from her own records alone: the role
    /// given to her, and the role Staff carries, which reaches her through
    /// Engineers below it. Bob's right to manage roles is not hers, and the
    /// broken record Bob has does not stop her, since nobody else's records
    /// are read. The tenant's records are never read whole for it.
    #[test]
    fn authority_comes_from_the_callers_own_holdings() {
        let ann = UserId::new();
        let access = Arc::new(FakeAccessRecordStore::holding(
            test_ctx().tenant_id(),
            acme_records(ann),
        ));

        let authority =
            block_on(acting_with(ann, Arc::clone(&access)).authority(&caller(ann))).unwrap();

        assert!(authority.holds(VIEW_ROLES));
        assert!(authority.holds(VIEW_USERS));
        assert!(!authority.holds(CREATE_ROLES));
        assert_eq!(access.whole_reads(), 0);
    }

    /// A membership referencing a missing group makes Ann's authority
    /// lookup fail internally instead of yielding partial permissions.
    #[test]
    fn a_broken_record_of_the_caller_is_refused() {
        let ann = UserId::new();
        let mut records = acme_records(ann);
        records
            .memberships
            .push(stored_membership(PrincipalRef::User(ann), GroupId::new()));
        let access = Arc::new(FakeAccessRecordStore::holding(
            test_ctx().tenant_id(),
            records,
        ));

        let result = block_on(acting_with(ann, access).authority(&caller(ann)));

        assert!(matches!(result, Err(AppError::Internal(_))));
    }

    /// Roles stored for another tenant grant Ann neither role-view nor
    /// user-view permission in the tenant she is requesting.
    #[test]
    fn holdings_in_another_tenant_do_not_count() {
        let ann = UserId::new();
        let access = Arc::new(FakeAccessRecordStore::holding(
            TenantId::new(),
            acme_records(ann),
        ));

        let authority = block_on(acting_with(ann, access).authority(&caller(ann))).unwrap();

        assert!(!authority.holds(VIEW_ROLES));
        assert!(!authority.holds(VIEW_USERS));
    }

    /// A caller naming a session absent from storage is unauthenticated
    /// when resolving the signed-in account.
    #[test]
    fn a_session_that_no_longer_exists_is_signed_out() {
        let ann = UserId::new();

        let result = block_on(acting_over(ann, FakeSessionStore::empty()).signed_in(&caller(ann)));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// A caller of the test tenant who came as `identity` with `credential`.
    fn came_with(identity: CallerIdentity, credential: Credential) -> CallerContext {
        let tenant = test_ctx();
        CallerContext::new(
            identity,
            credential,
            tenant.organization_id(),
            tenant.tenant_id(),
            tenant.plan_limits().clone(),
        )
        .unwrap()
    }

    /// What `ports` say `caller` holds in the tenant.
    fn authority_of(
        ports: TenantActingPorts,
        caller: &CallerContext,
    ) -> Result<TenantAuthority, AppError> {
        block_on(TenantActing::new(ports).authority(caller))
    }

    /// An unknown tenant API key cannot resolve authority and returns
    /// unauthenticated.
    #[test]
    fn an_unknown_api_key_holds_nothing() {
        let mallory = came_with(
            CallerIdentity::TenantUser(UserId::new()),
            Credential::TenantApiKey(ApiKeyId::new()),
        );

        let result = authority_of(TenantActingPorts::fakes(), &mallory);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Bob's key ran out a minute ago and the sweep has not removed it yet.
    /// He is told what a wrong key is told, not that the key was good once.
    #[test]
    fn a_key_past_its_end_holds_nothing() {
        let bob = UserId::new();
        let mut row = api_key_row("deploys", ActorRef::User(bob));
        row.created_at = clock::now() - Duration::days(1);
        row.expires_at = Expiry::At(clock::now() - Duration::minutes(1));
        let key = ApiKey::reconstitute(row).unwrap();
        let mallory = came_with(
            CallerIdentity::TenantUser(bob),
            Credential::TenantApiKey(*key.id()),
        );
        let ports = TenantActingPorts {
            tenant: TenantCredentialPorts {
                api_keys: Arc::new(FakeApiKeyStore::holding(&test_ctx().tenant(), key)),
                ..TenantCredentialPorts::fakes()
            },
            ..TenantActingPorts::fakes()
        };

        let result = authority_of(ports, &mallory);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Bob's API key is stored but his account is missing. Authority
    /// resolution rejects the key as unauthenticated.
    #[test]
    fn a_key_whose_maker_is_gone_holds_nothing() {
        let bob = UserId::new();
        let key = stored_api_key("deploys", ActorRef::User(bob));
        let mallory = came_with(
            CallerIdentity::TenantUser(bob),
            Credential::TenantApiKey(*key.id()),
        );
        let ports = TenantActingPorts {
            tenant: TenantCredentialPorts {
                api_keys: Arc::new(FakeApiKeyStore::holding(&test_ctx().tenant(), key)),
                ..TenantCredentialPorts::fakes()
            },
            ..TenantActingPorts::fakes()
        };

        let result = authority_of(ports, &mallory);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Tess, an owner of the organization, made a key in this tenant that
    /// reads routes, and her directory sync comes with it. The key names
    /// her as a member, and acts with what she holds here, narrowed to its
    /// scope.
    #[test]
    fn a_key_an_organization_member_made_acts_in_the_tenant() {
        let tenant = test_ctx();
        let tess = test_org_user(tenant.organization_id(), "tess@acme.test", OrgRole::Owner);
        let key = stored_api_key("directory sync", ActorRef::OrgUser(*tess.id()));
        let caller = came_with(
            CallerIdentity::OrgUser(*tess.id()),
            Credential::TenantApiKey(*key.id()),
        );
        let ports = TenantActingPorts {
            tenants: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
            tenant: TenantCredentialPorts {
                api_keys: Arc::new(FakeApiKeyStore::holding(&tenant.tenant(), key)),
                ..TenantCredentialPorts::fakes()
            },
            members: MemberPorts {
                org_users: Arc::new(org_user_store_with([tess])),
                organizations: org_store_with([org_shaped(
                    tenant.organization_id(),
                    OrgShape::owning(&[tenant.tenant_id()]),
                )]),
                ..MemberPorts::fakes()
            },
            ..TenantActingPorts::fakes()
        };

        let authority = authority_of(ports, &caller).unwrap();

        assert!(authority.holds(SystemPermission::Routing(RoutingAction::View)));
        assert!(!authority.holds(VIEW_USERS));
    }

    /// An organization member with a missing session receives
    /// unauthenticated when requesting tenant authority.
    #[test]
    fn a_member_session_that_does_not_exist_holds_nothing() {
        let tenant = test_ctx();
        let mallory = test_org_user(
            tenant.organization_id(),
            "mallory@acme.test",
            OrgRole::Member,
        );
        let caller = came_with(
            CallerIdentity::OrgUser(*mallory.id()),
            Credential::OrgSession(SessionId::new()),
        );
        let ports = TenantActingPorts {
            members: MemberPorts {
                org_users: Arc::new(org_user_store_with([mallory])),
                organizations: org_store_with([org_shaped(
                    tenant.organization_id(),
                    OrgShape::owning(&[tenant.tenant_id()]),
                )]),
                ..MemberPorts::fakes()
            },
            ..TenantActingPorts::fakes()
        };

        let result = authority_of(ports, &caller);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An organization's owner cannot use a session opened in staging
    /// for another tenant, even when the organization owns both. The
    /// requested authority is forbidden.
    #[test]
    fn a_member_session_opened_in_another_tenant_holds_nothing() {
        let tenant = test_ctx();
        let mallory = test_org_user(
            tenant.organization_id(),
            "mallory@acme.test",
            OrgRole::Owner,
        );
        let staging = TenantId::new();
        let session = org_session_of(&mallory, staging, password_only());
        let caller = came_with(
            CallerIdentity::OrgUser(*mallory.id()),
            Credential::OrgSession(*session.id()),
        );
        let ports = TenantActingPorts {
            members: MemberPorts {
                org_users: Arc::new(org_user_store_with([mallory])),
                org_sessions: Arc::new(RecordingOrgSessionStore::holding([session])),
                organizations: org_store_with([org_shaped(
                    tenant.organization_id(),
                    OrgShape::owning(&[tenant.tenant_id(), staging]),
                )]),
                ..MemberPorts::fakes()
            },
            ..TenantActingPorts::fakes()
        };

        let result = authority_of(ports, &caller);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Sam has a tenant grant, but his session is scoped to the
    /// organization alone. Using it to obtain tenant authority is forbidden.
    #[test]
    fn a_member_session_on_the_organization_alone_holds_nothing() {
        let tenant = test_ctx();
        let sam = test_org_user(tenant.organization_id(), "sam@acme.test", OrgRole::Member);
        let session = org_session_on_organization(&sam);
        let caller = came_with(
            CallerIdentity::OrgUser(*sam.id()),
            Credential::OrgSession(*session.id()),
        );
        let grant = OrgTenantGrant::reconstitute(OrgTenantGrantRow {
            org_user_id: *sam.id(),
            tenant_id: tenant.tenant_id(),
            role_id: RoleId::new(),
            granted_by: ActedBy::Platform,
            granted_at: clock::now(),
        })
        .unwrap();
        let ports = TenantActingPorts {
            members: MemberPorts {
                org_users: Arc::new(org_user_store_with([sam])),
                org_sessions: Arc::new(RecordingOrgSessionStore::holding([session])),
                org_grants: Arc::new(FakeOrgTenantGrantStore::holding([grant])),
                organizations: org_store_with([org_shaped(
                    tenant.organization_id(),
                    OrgShape::owning(&[tenant.tenant_id()]),
                )]),
            },
            ..TenantActingPorts::fakes()
        };

        let result = authority_of(ports, &caller);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// The impersonation an operator of the test platform makes of Ann,
    /// through `grant`.
    fn impersonating(grant: ImpersonationGrantId) -> CallerContext {
        came_with(
            CallerIdentity::Operator(test_operator_id()),
            Credential::Impersonation {
                key: KeyPrefix::new("opk_support").unwrap(),
                grant,
                user: UserId::new(),
            },
        )
    }

    /// An active operator with a stored key still needs an impersonation
    /// grant. A missing grant makes tenant authority forbidden.
    #[test]
    fn an_impersonation_whose_grant_is_gone_holds_nothing() {
        let ports = TenantActingPorts {
            operators: OperatorPorts {
                operators: Arc::new(FakeOperatorStore::holding([stored_operator(
                    test_operator_id(),
                    "support@ianua.test",
                    OperatorStatus::Active,
                )])),
                operator_keys: Arc::new(FakeOperatorKeyStore::holding([stored_operator_key(
                    test_operator_id(),
                    "opk_support",
                )])),
                ..OperatorPorts::fakes()
            },
            ..TenantActingPorts::fakes()
        };

        let result = authority_of(ports, &impersonating(ImpersonationGrantId::new()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Impersonation by an operator absent from storage is unauthenticated.
    #[test]
    fn an_impersonation_by_an_unknown_operator_holds_nothing() {
        let result = authority_of(
            TenantActingPorts::fakes(),
            &impersonating(ImpersonationGrantId::new()),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An organization API key is forbidden from obtaining tenant authority.
    #[test]
    fn an_organization_key_holds_nothing_in_a_tenant() {
        let mallory = came_with(
            CallerIdentity::OrgUser(OrgUserId::new()),
            Credential::OrgApiKey(OrgApiKeyId::new()),
        );

        let result = authority_of(TenantActingPorts::fakes(), &mallory);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// An operator key without an impersonation grant is forbidden inside
    /// a tenant.
    #[test]
    fn an_operator_key_holds_nothing_in_a_tenant() {
        let result = authority_of(TenantActingPorts::fakes(), &operator_without_grant());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
