//! A tenant's data classification: reading the rule set, and adding,
//! changing and removing its rules.

use super::{Request, TenantPath};
use crate::net::Call;
use crate::wire::classification::{
    Classification, ClassificationChange, ClassificationRule, NewClassificationRule,
};

/// `GET …/classification`.
#[must_use]
pub fn get(tenant: &TenantPath) -> Request<Classification> {
    Request::of(Call::get(tenant.at("/classification")))
}

/// `POST …/classification/rules`.
#[must_use]
pub fn add(tenant: &TenantPath, rule: &NewClassificationRule) -> Request<ClassificationRule> {
    Request::of(Call::post(tenant.at("/classification/rules")).json(rule))
}

/// `PUT …/classification/rules/{id}`.
#[must_use]
pub fn change(tenant: &TenantPath, rule_id: &str, change: &ClassificationChange) -> Request<()> {
    let path = tenant.at(&format!("/classification/rules/{rule_id}"));
    Request::of(Call::put(path).json(change))
}

/// `DELETE …/classification/rules/{id}`.
#[must_use]
pub fn remove(tenant: &TenantPath, rule_id: &str) -> Request<()> {
    Request::of(Call::delete(
        tenant.at(&format!("/classification/rules/{rule_id}")),
    ))
}
