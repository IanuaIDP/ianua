//! A fake for the SCIM user filters: the tenant's users held in memory and
//! picked as the adapter's query would pick them.

use std::cmp::Ordering;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::identity::account::profile_values::{
    Department, EmployeeNumber, ExternalId, FamilyName, GivenName,
};
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;

use crate::ports::TenantScoped;
use crate::ports::federation::{
    ScimPage, ScimQuery, ScimUserAttribute, ScimUserQueries, ScimUserSort, ScimWindow,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::identity::copy_user;

/// In-memory users, each kept under its tenant, found by SCIM filters.
#[derive(Default)]
pub struct FakeScimUserQueries {
    users: Mutex<Vec<(TenantId, User<ResolvedTenant>)>>,
}

impl TenantScoped for FakeScimUserQueries {}

impl FakeScimUserQueries {
    /// A store holding no user.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `users` in `tenant`.
    #[must_use]
    pub fn holding(
        tenant: &ScopedTenant,
        users: impl IntoIterator<Item = User<ResolvedTenant>>,
    ) -> Self {
        Self {
            users: Mutex::new(users.into_iter().map(|user| (**tenant, user)).collect()),
        }
    }
}

#[async_trait]
impl ScimUserQueries for FakeScimUserQueries {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        query: &ScimQuery<ScimUserAttribute>,
        sort: ScimUserSort,
        window: ScimWindow,
    ) -> Result<ScimPage<User<ResolvedTenant>>, DomainError> {
        let mut picked: Vec<User<ResolvedTenant>> = self
            .users
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, user)| tenant == &**tenant_id && picks(query, user))
            .map(|(_, user)| copy_user(user))
            .collect::<Result<_, _>>()?;
        if let ScimUserSort::By(attribute, direction) = sort {
            picked.sort_by(|a, b| direction.apply(compare(attribute, a, b)));
        }
        Ok(window.cut(picked))
    }
}

impl Fake for Arc<dyn ScimUserQueries> {
    fn fake() -> Self {
        Arc::new(FakeScimUserQueries::empty())
    }
}

/// Whether `query` picks `user`.
fn picks(query: &ScimQuery<ScimUserAttribute>, user: &User<ResolvedTenant>) -> bool {
    match query {
        ScimQuery::All => true,
        ScimQuery::Compare {
            attribute,
            operator,
            value,
        } => value_of(*attribute, user)
            .is_some_and(|stored| operator.holds(&stored, value, attribute.case())),
        ScimQuery::And(left, right) => picks(left, user) && picks(right, user),
        ScimQuery::Or(left, right) => picks(left, user) || picks(right, user),
    }
}

/// How `a` and `b` compare on `attribute`, ascending, a user with no value
/// last.
fn compare(
    attribute: ScimUserAttribute,
    a: &User<ResolvedTenant>,
    b: &User<ResolvedTenant>,
) -> Ordering {
    match (value_of(attribute, a), value_of(attribute, b)) {
        (Some(a), Some(b)) => a.cmp(&b),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

/// What `user` holds for `attribute`, if anything.
fn value_of(attribute: ScimUserAttribute, user: &User<ResolvedTenant>) -> Option<String> {
    let profile = user.profile();
    let text = |value: Option<&str>| value.map(str::to_owned);
    match attribute {
        ScimUserAttribute::UserName => Some(user.email().as_str().to_owned()),
        ScimUserAttribute::DisplayName => Some(user.display_name().as_str().to_owned()),
        ScimUserAttribute::ExternalId => {
            text(profile.records.external_id.value().map(ExternalId::as_str))
        }
        ScimUserAttribute::GivenName => {
            text(profile.details.given_name.value().map(GivenName::as_str))
        }
        ScimUserAttribute::FamilyName => {
            text(profile.details.family_name.value().map(FamilyName::as_str))
        }
        ScimUserAttribute::Department => {
            text(profile.records.department.value().map(Department::as_str))
        }
        ScimUserAttribute::EmployeeNumber => text(
            profile
                .records
                .employee_number
                .value()
                .map(EmployeeNumber::as_str),
        ),
    }
}
