//! The rules beside roles that a clone's roles and policies part carries:
//! the resource types custom permissions name, the separation of duty
//! between roles, the clearance permissions give for classified data, and
//! the longest access a person may ask for.
//!
//! Resource types are matched by key and separation rules by name, so a
//! copy made again lands where the first did and keeps the target's ids.
//! Clearance and the request limit are one set per tenant, written whole.
//! A separation rule names roles by id, so each is put in the target's
//! terms; one naming a role the source no longer has keeps the id, which
//! matches no one in the target either.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_app::ports::authorization::{
    AccessRequestPolicyStore as _, ClearanceRuleStore as _, ResourceTypeStore as _,
    SeparationRuleStore as _,
};
use ianua_domain::domains::authorization::clearance::{ClearanceRules, ClearanceRulesRow};
use ianua_domain::domains::authorization::request_policy::{
    AccessRequestPolicy, AccessRequestPolicyRow,
};
use ianua_domain::domains::authorization::resource_type::{ResourceType, ResourceTypeRow};
use ianua_domain::domains::authorization::separation::{SeparationRule, SeparationRuleRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ResourceTypeId, RoleId, SeparationRuleId};
use time::OffsetDateTime;

use crate::postgres::authorization::{
    PgAccessRequestPolicyStore, PgClearanceRuleStore, PgResourceTypeStore, PgSeparationRuleStore,
};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::tenant::copies::Pair;

/// Copies the rules beside a tenant's roles.
pub(crate) struct RuleCopy {
    resource_types: PgResourceTypeStore,
    separation: PgSeparationRuleStore,
    clearance: PgClearanceRuleStore,
    requests: PgAccessRequestPolicyStore,
}

impl RuleCopy {
    /// A copy reading and writing the tenants of `databases`.
    pub(crate) fn new(databases: &Arc<Databases>) -> Self {
        Self {
            resource_types: PgResourceTypeStore::new(Arc::clone(databases)),
            separation: PgSeparationRuleStore::new(Arc::clone(databases)),
            clearance: PgClearanceRuleStore::new(Arc::clone(databases)),
            requests: PgAccessRequestPolicyStore::new(Arc::clone(databases)),
        }
    }

    /// Writes the source's resource types over the target's, matched by
    /// key, before the roles that name their permissions are copied.
    pub(crate) async fn copy_resource_types(
        &self,
        pair: &Pair,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let source = self.resource_types.list_every(&pair.source).await?;
        let target = self.resource_types.list_every(&pair.target).await?;
        let held: HashMap<&str, &ResourceType<ResolvedTenant>> = target
            .iter()
            .map(|kind| (kind.key().as_str(), kind))
            .collect();
        for kind in &source {
            let copy = resource_type_for_target(kind, held.get(kind.key().as_str()).copied(), now)?;
            self.resource_types.save(&pair.target, &copy).await?;
        }
        Ok(())
    }

    /// Writes the source's separation rules, clearance and request limit
    /// over the target's, with roles named as `roles` renamed them.
    pub(crate) async fn copy_after_roles(
        &self,
        pair: &Pair,
        roles: &HashMap<RoleId, RoleId>,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        self.copy_separation(pair, roles).await?;
        self.copy_clearance(pair, now).await?;
        self.copy_request_limit(pair, now).await
    }

    /// Writes the source's separation rules over the target's, matched by
    /// name.
    async fn copy_separation(
        &self,
        pair: &Pair,
        roles: &HashMap<RoleId, RoleId>,
    ) -> Result<(), DomainError> {
        let source = self.separation.list(&pair.source).await?;
        let target = self.separation.list(&pair.target).await?;
        let held: HashMap<&str, &SeparationRule<ResolvedTenant>> = target
            .iter()
            .map(|rule| (rule.name().as_str(), rule))
            .collect();
        for rule in &source {
            let kept = held.get(rule.name().as_str()).copied();
            let copy = separation_for_target(rule, kept, roles)?;
            self.separation.save(&pair.target, &copy).await?;
        }
        Ok(())
    }

    /// Writes the source's clearance rules as the target's, when the source
    /// has any.
    async fn copy_clearance(&self, pair: &Pair, now: OffsetDateTime) -> Result<(), DomainError> {
        let Some(source) = self.clearance.load(&pair.source).await? else {
            return Ok(());
        };
        let rules = source
            .rules()
            .iter()
            .map(|rule| (rule.permission().clone(), rule.up_to()))
            .collect();
        let copy = ClearanceRules::reconstitute(ClearanceRulesRow {
            rules,
            updated_at: now,
        })?;
        self.clearance.save(&pair.target, &copy).await
    }

    /// Writes the source's limit on requested access as the target's, when
    /// the source set one.
    async fn copy_request_limit(
        &self,
        pair: &Pair,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let Some(source) = self.requests.find(&pair.source).await? else {
            return Ok(());
        };
        let copy = AccessRequestPolicy::reconstitute(AccessRequestPolicyRow {
            longest: source.limits().longest(),
            updated_at: now,
        })?;
        self.requests.save(&pair.target, &copy).await
    }
}

/// `kind` as the target keeps it, under the id of `kept` when the target
/// has a resource type of its key.
fn resource_type_for_target(
    kind: &ResourceType<ResolvedTenant>,
    kept: Option<&ResourceType<ResolvedTenant>>,
    now: OffsetDateTime,
) -> Result<ResourceType<ResolvedTenant>, DomainError> {
    ResourceType::reconstitute(ResourceTypeRow {
        id: kept.map_or_else(ResourceTypeId::new, |held| *held.id()),
        key: kind.key().clone(),
        display_name: kind.display_name().clone(),
        description: kind.description().cloned(),
        actions: kind.actions().to_vec(),
        created_at: kept.map_or(now, ResourceType::created_at),
        updated_at: now,
        data_class: kind.data_class(),
    })
}

/// `rule` as the target keeps it: its two roles in the target's terms,
/// under the id of `kept` when the target has a rule of its name.
fn separation_for_target(
    rule: &SeparationRule<ResolvedTenant>,
    kept: Option<&SeparationRule<ResolvedTenant>>,
    roles: &HashMap<RoleId, RoleId>,
) -> Result<SeparationRule<ResolvedTenant>, DomainError> {
    let (first, second) = rule.roles();
    let renamed = |role: &RoleId| roles.get(role).copied().unwrap_or(*role);
    SeparationRule::reconstitute(SeparationRuleRow {
        id: kept.map_or_else(SeparationRuleId::new, |held| *held.id()),
        name: rule.name().clone(),
        first: renamed(first),
        second: renamed(second),
        created_at: kept.map_or_else(|| rule.created_at(), SeparationRule::created_at),
    })
}
