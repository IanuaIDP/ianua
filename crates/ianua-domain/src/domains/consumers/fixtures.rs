//! Records, consumers and controls the consumers context's tests share.

use crate::domains::authorization::authority::TenantAccess;
use crate::domains::authorization::group::{Group, GroupMembership};
use crate::domains::authorization::permission::{DataAccessAction, SystemPermission};
use crate::domains::authorization::role::{DefaultAssignment, NewRole, Role, RoleAssignment};
use crate::domains::authorization::stewardship::TenantGrants;
use crate::domains::consumers::authority::ConsumerAuthority;
use crate::domains::consumers::consumer::{Consumer, CreateConsumerParams};
use crate::domains::consumers::control::ConsumerControl;
use crate::domains::consumers::credential::ConsumerCredentialKind;
use crate::domains::consumers::quota::ConsumerQuota;
use crate::domains::consumers::sign_in::ConsumerSignIn;
use crate::domains::data_classification::level::DataClassLevel;
use crate::isolation::scope::ResolvedTenant;
use crate::test_support::authority::{anyone_holding, assumed_authority};
use crate::test_support::builders::label;
use crate::types::{
    ConsumerId, Expiry, Human, HumanAccount, Issuer, KeyPrefix, PersonKey, PrincipalRef, RoleId,
    TenantId, TokenHash, UserId,
};

/// Acme, the tenant the records and controls belong to.
pub(crate) fn acme() -> TenantId {
    TenantId::from_uuid(uuid::Uuid::from_u128(0xac))
}

/// Sam, acting in Acme with `system` and no custom permission.
pub(crate) fn sam_holding(system: &[SystemPermission]) -> ConsumerControl<'static> {
    let sam = Human::new(
        HumanAccount::User(UserId::from_uuid(uuid::Uuid::from_u128(0x5a))),
        PersonKey::new("sam@acme.test").unwrap(),
    );
    ConsumerControl::new(assumed_authority(&sam, acme(), system, &[]))
}

/// Acme's own token issuer.
pub(crate) fn acme_issuer() -> Issuer {
    Issuer::new("https://acme.ianua.test").unwrap()
}

/// An active consumer of Acme, "billing-sync", signing in with an API key.
pub(crate) fn billing_sync() -> Consumer<ResolvedTenant> {
    let params = CreateConsumerParams {
        name: label("billing-sync"),
        description: None,
        credential: ConsumerCredentialKind::ApiKey {
            prefix: KeyPrefix::new("sk_live_abc").unwrap(),
            key_hash: TokenHash::from_stored("hash123".to_owned()),
        },
        credential_expiry: Expiry::Never,
        quota: ConsumerQuota::Unlimited,
        clearance: DataClassLevel::Internal,
    };
    let admin = sam_holding(&[SystemPermission::ManageConsumers]);
    Consumer::create(params, &acme_issuer(), &admin).unwrap()
}

/// The proof that `consumer`, made by [`billing_sync`], signed in with its
/// API key.
pub(crate) fn key_sign_in(consumer: &Consumer<ResolvedTenant>) -> ConsumerSignIn {
    consumer
        .sign_in_with_key(&TokenHash::from_stored("hash123".to_owned()))
        .unwrap()
}

/// The authority of an active consumer, cleared for internal data, whose
/// one role grants `system`.
pub(crate) fn service_holding(system: &[SystemPermission]) -> ConsumerAuthority {
    service_cleared(system, DataClassLevel::Internal)
}

/// The authority of an active consumer cleared for `clearance`, whose one
/// role grants `system`.
pub(crate) fn service_cleared(
    system: &[SystemPermission],
    clearance: DataClassLevel,
) -> ConsumerAuthority {
    let mut consumer = billing_sync();
    consumer
        .change_clearance(
            clearance,
            &sam_holding(&[
                SystemPermission::ManageConsumers,
                SystemPermission::Data(DataAccessAction::Restricted),
            ]),
        )
        .unwrap();
    let records = ConsumerRecords::where_holding(PrincipalRef::Consumer(*consumer.id()), system);
    ConsumerAuthority::of(&consumer, &key_sign_in(&consumer), &records.access()).unwrap()
}

/// Acme's roles and who holds them, owned so a test can lend them out.
pub(crate) struct ConsumerRecords {
    roles: Vec<Role<ResolvedTenant>>,
    assignments: Vec<RoleAssignment<ResolvedTenant>>,
}

impl ConsumerRecords {
    /// Acme with no roles at all.
    pub(crate) fn empty() -> Self {
        Self {
            roles: Vec::new(),
            assignments: Vec::new(),
        }
    }

    /// Acme, where `consumer` holds one role granting `system`.
    pub(crate) fn consumer_holding(consumer: &ConsumerId, system: &[SystemPermission]) -> Self {
        Self::where_holding(PrincipalRef::Consumer(*consumer), system)
    }

    /// Acme, where `principal` holds one role granting `system`.
    pub(crate) fn where_holding(principal: PrincipalRef, system: &[SystemPermission]) -> Self {
        let role = role_granting(system);
        let assignment =
            RoleAssignment::create(principal, &role, anyone_holding(SystemPermission::all()))
                .unwrap();
        Self {
            roles: vec![role],
            assignments: vec![assignment],
        }
    }

    /// Acme, with one role granting `system` that no account of the tenant
    /// holds, for an organization grant to name.
    pub(crate) fn unassigned(system: &[SystemPermission]) -> Self {
        Self {
            roles: vec![role_granting(system)],
            assignments: Vec::new(),
        }
    }

    /// The id of Acme's first role.
    pub(crate) fn first_role(&self) -> RoleId {
        *self.roles[0].id()
    }

    /// The records, as a use case reads them for Acme.
    pub(crate) fn access(&self) -> TenantAccess<'_, ResolvedTenant> {
        TenantAccess {
            tenant: acme(),
            grants: TenantGrants {
                roles: &self.roles,
                assignments: &self.assignments,
                groups: &[] as &[Group<ResolvedTenant>],
                memberships: &[] as &[GroupMembership<ResolvedTenant>],
            },
            catalogue: &[],
            break_glass: &[],
        }
    }
}

/// A role of Acme granting `system`.
fn role_granting(system: &[SystemPermission]) -> Role<ResolvedTenant> {
    Role::provisioned(NewRole {
        id: RoleId::new(),
        name: label("integration"),
        system_permissions: system.to_vec(),
        custom_permissions: Vec::new(),
        assignment: DefaultAssignment::Manual,
    })
}
