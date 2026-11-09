//! Small value builders shared by tests, so test modules do not each keep
//! their own copy.

use crate::domains::agents::execution::run::{AgentRun, RunCheck};
use crate::domains::identity::account::address::AddressStanding;
use crate::domains::identity::account::user::User;
use crate::domains::identity::account::vouching::Vouching;
use crate::domains::organization::members::membership::OrgRole;
use crate::domains::organization::members::org_user::{OrgPassword, OrgUser, OrgUserRow};
use crate::domains::organization::members::org_user_status::OrgUserStatus;
use crate::domains::tenant::custom_domains::dns_zone::{RecordName, RecordValue, TxtValue};
use crate::isolation::scope::ResolvedTenant;
use crate::shared::config::DisplayNameLimits;
use crate::test_support::authority::user_adder;
use crate::types::{
    CredentialChange, DisplayName, DomainName, Email, Joining, Label, OrgUserId, OrganizationId,
    Preference, UserId,
};

/// A verified, active organization member with this `id` and `email`,
/// read back as storage keeps one.
///
/// # Panics
///
/// - If `email` is not a valid address. Tests pass literals that are.
#[must_use]
pub fn org_user(id: OrgUserId, email: &str) -> OrgUser {
    let now = crate::shared::clock::now();
    OrgUser::reconstitute(OrgUserRow {
        id,
        organization_id: OrganizationId::new(),
        email: Email::new(email).expect("a test passes a valid address"),
        display_name: DisplayName::new("Test Member", &DisplayNameLimits::default())
            .expect("a test passes a valid name"),
        password_hash: OrgPassword::NotSet,
        status: OrgUserStatus::Active,
        role: OrgRole::Member,
        email_standing: AddressStanding::Verified,
        locale: Preference::Inherited,
        timezone: Preference::Inherited,
        created_at: now,
        updated_at: now,
        joining: Joining::Joined { at: now },
        credentials_changed_at: CredentialChange::Never,
        vouching: Vouching::Absent,
    })
    .expect("an active, joined member is a consistent row")
}

/// A newly registered tenant user with this `id` and `email`.
///
/// # Panics
///
/// - If `email` is not a valid address. Tests pass literals that are.
#[must_use]
pub fn user(id: UserId, email: &str) -> User<ResolvedTenant> {
    User::register(
        id,
        Email::new(email).expect("a test passes a valid address"),
        DisplayName::new("Test User", &DisplayNameLimits::default())
            .expect("a test passes a valid name"),
        &user_adder(),
    )
    .expect("someone who may add users registers accounts")
}

/// A [`Label`] holding `value`.
///
/// # Panics
///
/// - If `value` is not a valid label. Tests pass literals that are.
#[must_use]
pub fn label(value: &str) -> Label {
    Label::new("name", value).expect("a test passes a valid label")
}

/// A [`DomainName`] holding `value`.
///
/// # Panics
///
/// - If `value` is not a valid domain name. Tests pass literals that are.
#[must_use]
pub fn domain_name(value: &str) -> DomainName {
    DomainName::new(value).expect("a test passes a valid domain name")
}

/// A [`RecordName`] holding `value`.
///
/// # Panics
///
/// - If `value` is not a valid record name. Tests pass literals that are.
#[must_use]
pub fn record_name(value: &str) -> RecordName {
    RecordName::new(value).expect("a test passes a valid record name")
}

/// A TXT [`RecordValue`] holding `value`.
///
/// # Panics
///
/// - If `value` is not a valid TXT value. Tests pass literals that are.
#[must_use]
pub fn txt_record(value: &str) -> RecordValue {
    RecordValue::Text(TxtValue::new(value).expect("a test passes a valid TXT value"))
}

/// `run`, its answers held to `check`, as a workflow's code step starting
/// the agent its sandbox version holds makes it.
#[must_use]
pub fn held_to(run: AgentRun<ResolvedTenant>, check: RunCheck) -> AgentRun<ResolvedTenant> {
    run.checked_by(check)
}
