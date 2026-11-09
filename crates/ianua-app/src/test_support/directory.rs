//! The directory's neutral doubles: a bound person holds what the tenant's
//! records say, read from a store that holds none unless a test seeds it.
//! And a tenant whose directory a person really binds to, for the writes a
//! bound connection makes.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::password::PasswordHasher;
use ianua_domain::domains::authorization::group::{Group, GroupPlace};
use ianua_domain::domains::authorization::permission::SystemPermission;
use ianua_domain::domains::identity::account::user_status::UserStatus;
use ianua_domain::domains::tenant::status::TenantStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::test_support::fakes::FakeHasher;
use ianua_domain::types::{
    CertificateFingerprint, Email, Fact, GroupId, LdapCertificateId, PrincipalRef, TenantSlug,
    UserId,
};

use crate::acting::TenantAuthorities;
use crate::acting::directory::{DirectoryActing, DirectoryAuthorities};
use crate::acting::tenant::{TenantActing, TenantActingPorts, TenantCredentialPorts};
use crate::error::AppError;
use crate::ports::authorization::{GroupMembershipStore, GroupStore, RoleAssignmentStore};
use crate::ports::directory::LdapCertificateStore;
use crate::ports::identity::UserStore;
use crate::test_support::authentication::{
    AllowingThrottle, CertificateStanding, FakeLdapCertificateStore, REENTERED_PASSWORD,
    ldap_certificate, revoked_now,
};
use crate::test_support::authorization::{
    AccessSources, FakeAccessRecordStore, stored_assignment, stored_group, stored_membership,
    stored_role,
};
use crate::test_support::identity::{FakeUserStore, RecordingCredentialStore, stored_user};
use crate::test_support::organization::{org_store_with, test_org};
use crate::test_support::tenant::{cfg, tenant_store_in_status};
use crate::test_support::{Fake, FakeEventDispatcher, block_on, test_auditor, test_ctx};
use crate::use_case::Command;
use crate::use_cases::directory::principal::{DirectoryBase, DirectoryPrincipal};
use crate::use_cases::directory::{BindPorts, BindRequest, BindUseCase};

/// The address the bound person, Ann, signs in with.
pub const BOUND_ADDRESS: &str = "ann@acme.test";

/// Ann's password, the one a fresh proof accepts too.
pub const BOUND_PASSWORD: &str = REENTERED_PASSWORD;

impl Fake for Arc<dyn DirectoryAuthorities> {
    fn fake() -> Self {
        Arc::new(DirectoryActing::new(Arc::new(
            FakeAccessRecordStore::empty(),
        )))
    }
}

/// The test tenant, `acme` of `acme-corp`, where Ann's laptop holds a
/// certificate in force and Ann holds one role, granting what the test
/// says. Its stores are shared, so what a write saves shows in the records
/// the next request reads.
pub struct BoundDirectory {
    /// Ann's account.
    pub ann: UserId,
    /// The tenant's users.
    pub users: Arc<FakeUserStore>,
    /// The tenant's LDAP client certificates.
    pub certificates: Arc<FakeLdapCertificateStore>,
    /// The stores the tenant's access records are read from.
    pub sources: AccessSources,
    /// The tenant's access records, read from [`Self::sources`].
    pub access: Arc<FakeAccessRecordStore>,
    /// The tenant's password hashes.
    pub credentials: Arc<RecordingCredentialStore>,
    certificate: LdapCertificateId,
}

impl BoundDirectory {
    /// Ann holds a role granting `held`, and nothing else.
    ///
    /// # Panics
    ///
    /// Never: the fakes it seeds accept every write.
    #[must_use]
    pub fn holding(held: &[SystemPermission]) -> Self {
        let ann = UserId::new();
        let certificate = ldap_certificate(ann, laptop(), CertificateStanding::InForce);
        let sources = AccessSources::default();
        let role = stored_role("Directory admin", held.to_vec(), Vec::new());
        let given = stored_assignment(PrincipalRef::User(ann), *role.id());
        sources.roles.add(test_ctx().tenant_id(), [role]);
        block_on(sources.assignments.save(&test_ctx().tenant(), &given))
            .expect("the fake keeps every assignment");
        Self {
            ann,
            users: Arc::new(FakeUserStore::with_user(ann, BOUND_ADDRESS)),
            certificate: *certificate.id(),
            certificates: Arc::new(FakeLdapCertificateStore::holding(
                test_ctx().tenant_id(),
                [certificate],
            )),
            access: Arc::new(FakeAccessRecordStore::reading(sources.clone())),
            sources,
            credentials: Arc::new(RecordingCredentialStore::holding(
                ann,
                &FakeHasher
                    .hash(BOUND_PASSWORD)
                    .expect("the fake hasher hashes anything"),
            )),
        }
    }

    /// Ann binds from her laptop with her password.
    ///
    /// # Panics
    ///
    /// When the bind is refused, which it is not while her certificate is
    /// in force and her account active.
    #[must_use]
    pub fn bind(&self) -> DirectoryPrincipal {
        let use_case = BindUseCase::new(BindPorts {
            organizations: org_store_with([test_org(test_ctx().organization_id(), "acme-corp")]),
            tenants: tenant_store_in_status(TenantStatus::Active),
            throttle: Arc::new(AllowingThrottle),
            certificates: self.certificates.clone(),
            users: self.users.clone(),
            credentials: self.credentials.clone(),
            directory_authorities: Arc::new(DirectoryActing::new(self.access.clone())),
            ..BindPorts::fakes()
        });
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        block_on(use_case.execute(&(), &auditor, ann_binds()))
            .expect("Ann binds with her password over her certificate")
    }

    /// What every request of a bound connection holds, worked out from this
    /// tenant's records as production does.
    #[must_use]
    pub fn authorities(&self) -> Arc<dyn TenantAuthorities> {
        Arc::new(TenantActing::new(TenantActingPorts {
            access: self.access.clone(),
            tenants: tenant_store_in_status(TenantStatus::Active),
            tenant: TenantCredentialPorts {
                users: self.users.clone(),
                certificates: self.certificates.clone(),
                ..TenantCredentialPorts::fakes()
            },
            ..TenantActingPorts::fakes()
        }))
    }

    /// Ann's admin revokes the certificate on her laptop.
    ///
    /// # Panics
    ///
    /// Never: the certificate is held, and the fake keeps every save.
    pub fn revoke_certificate(&self) {
        let tenant = test_ctx().tenant();
        let held = block_on(self.certificates.find_by_id(&tenant, &self.certificate))
            .expect("the fake reads")
            .expect("Ann's certificate is held");
        block_on(self.certificates.save(&tenant, &revoked_now(&held)))
            .expect("the fake keeps every save");
    }

    /// Puts the dashboard group `name` into the tenant, at the top and
    /// carrying no role.
    ///
    /// # Panics
    ///
    /// Never: the fake keeps every save.
    #[must_use]
    pub fn add_group(&self, name: &str) -> GroupId {
        self.kept_group(&stored_group(name, GroupPlace::TopLevel, Vec::new()))
    }

    /// Puts the group "Admins" into the tenant, carrying a role that grants
    /// every built-in permission.
    ///
    /// # Panics
    ///
    /// Never: the fake keeps every save.
    #[must_use]
    pub fn add_admins(&self) -> GroupId {
        let owner = stored_role("Owner", SystemPermission::all().to_vec(), Vec::new());
        let admins = stored_group("Admins", GroupPlace::TopLevel, vec![*owner.id()]);
        self.sources.roles.add(test_ctx().tenant_id(), [owner]);
        self.kept_group(&admins)
    }

    /// Puts `member` into the group `group_id`.
    ///
    /// # Panics
    ///
    /// Never: the fake keeps every save.
    pub fn add_member(&self, group_id: GroupId, member: PrincipalRef) {
        let membership = stored_membership(member, group_id);
        block_on(
            self.sources
                .memberships
                .save(&test_ctx().tenant(), &membership),
        )
        .expect("the fake keeps every save");
    }

    /// Saves a group and returns the ID the directory will use for it.
    fn kept_group(&self, group: &Group<ResolvedTenant>) -> GroupId {
        let id = *group.id();
        block_on(self.sources.groups.save(&test_ctx().tenant(), group))
            .expect("the fake keeps every save");
        id
    }

    /// Ann's account is closed.
    ///
    /// # Panics
    ///
    /// Never: the fake keeps every save.
    pub fn close_account(&self) {
        let closed = stored_user(self.ann, BOUND_ADDRESS, UserStatus::Deactivated);
        block_on(self.users.save(&test_ctx().tenant(), &closed))
            .expect("the fake keeps every save");
    }

    /// Ann's admin resets her password, which changes how her account
    /// signs in.
    ///
    /// # Panics
    ///
    /// Never: Ann's account is held, and the fake keeps every save.
    pub fn reset_password(&self) {
        let tenant = test_ctx().tenant();
        let mut ann = block_on(self.users.find_by_id(&tenant, &self.ann))
            .expect("the fake reads")
            .expect("Ann's account is held");
        ann.record_credential_change();
        block_on(self.users.save(&tenant, &ann)).expect("the fake keeps every save");
    }
}

/// The ways a write over a bound connection is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindRefusal {
    /// The certificate Ann bound over was revoked after she bound.
    CertificateRevoked,
    /// Ann's account was closed after she bound.
    AccountClosed,
    /// Ann's password was reset after she bound.
    PasswordReset,
    /// Ann holds no right at all.
    WithoutTheRight,
}

impl BindRefusal {
    /// Every way a write over a bound connection is refused.
    pub const ALL: [Self; 4] = [
        Self::CertificateRevoked,
        Self::AccountClosed,
        Self::PasswordReset,
        Self::WithoutTheRight,
    ];

    /// Ann bound to a directory where she holds `held`, then turned away
    /// as this says.
    #[must_use]
    pub fn bound(self, held: &[SystemPermission]) -> (BoundDirectory, DirectoryPrincipal) {
        let directory = match self {
            Self::WithoutTheRight => BoundDirectory::holding(&[]),
            Self::CertificateRevoked | Self::AccountClosed | Self::PasswordReset => {
                BoundDirectory::holding(held)
            }
        };
        let principal = directory.bind();
        match self {
            Self::CertificateRevoked => directory.revoke_certificate(),
            Self::AccountClosed => directory.close_account(),
            Self::PasswordReset => directory.reset_password(),
            Self::WithoutTheRight => {}
        }
        (directory, principal)
    }

    /// Whether `result` is the refusal this calls for: signed out once the
    /// bind no longer counts, forbidden for a person without the right.
    #[must_use]
    pub fn refused<T>(self, result: &Result<T, AppError>) -> bool {
        match self {
            Self::CertificateRevoked | Self::AccountClosed | Self::PasswordReset => {
                matches!(result, Err(AppError::Unauthenticated))
            }
            Self::WithoutTheRight => matches!(result, Err(AppError::Forbidden(_))),
        }
    }
}

/// The fingerprint of the certificate Ann's laptop holds, the one a
/// connection from it presents.
#[must_use]
pub fn laptop() -> CertificateFingerprint {
    CertificateFingerprint::from_digest([7; 32])
}

fn ann_binds() -> BindRequest {
    let slug = |value: &str| TenantSlug::new(value, &cfg().slug).expect("a valid slug");
    BindRequest {
        base: DirectoryBase {
            organization: slug("acme-corp"),
            tenant: slug("acme"),
        },
        email: Email::new(BOUND_ADDRESS).expect("a valid address"),
        password: Secret::new(BOUND_PASSWORD),
        presented: Some(laptop()),
        ip_address: Fact::Unknown,
    }
}
