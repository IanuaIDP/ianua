//! Data clearance from what a person holds.
//!
//! Everyone acting in a tenant sees its internal data, and the built-in
//! data rights clear them for confidential or restricted data. A tenant
//! whose own app has a `payroll:read` permission says, once, that holding
//! it clears its holder for confidential data. The gateway's redaction then
//! shows a payroll clerk the salary field it hides from everyone else.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authorization::authority::TenantAuthority;
use crate::domains::authorization::events::clearance::{
    ClearanceRuleAdded, ClearanceRuleChanged, ClearanceRuleRemoved,
};
use crate::domains::authorization::permission::{
    ClassificationAction, CustomPermission, SystemPermission,
};
use crate::domains::data_classification::level::DataClassLevel;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::distinct::first_repeat;
use crate::types::PermissionName;

/// The right that changes clearance rules: the right to change how data is
/// classified.
const CLASSIFIES: SystemPermission = SystemPermission::Classification(ClassificationAction::Update);

/// Holding `permission` clears its holder for data up to `up_to`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearanceRule {
    permission: CustomPermission,
    up_to: DataClassLevel,
}

impl ClearanceRule {
    /// Holding `permission` clears for data up to `up_to`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `up_to` is public or internal,
    ///   which everyone in the tenant sees already.
    pub fn new(permission: CustomPermission, up_to: DataClassLevel) -> Result<Self, DomainError> {
        ensure_above_internal(up_to)?;
        Ok(Self { permission, up_to })
    }

    /// The permission that clears.
    #[must_use]
    pub fn permission(&self) -> &CustomPermission {
        &self.permission
    }

    /// The most sensitive data it clears for.
    #[must_use]
    pub fn up_to(&self) -> DataClassLevel {
        self.up_to
    }
}

/// A tenant's clearance rules: which app permissions clear for which data.
///
/// Each permission has at most one rule. Nobody writes a rule clearing for
/// more than they are cleared for themselves: Sam, cleared for internal
/// data, cannot make `notes:read`, which he holds, clear for restricted.
#[derive(Debug)]
pub struct ClearanceRules<T: TenantScope> {
    rules: Vec<ClearanceRule>,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// A tenant's [`ClearanceRules`] as storage holds them, read back through
/// [`ClearanceRules::reconstitute`].
pub struct ClearanceRulesRow {
    /// Each permission that clears, and for what.
    pub rules: Vec<(CustomPermission, DataClassLevel)>,
    /// When the rules last changed.
    pub updated_at: OffsetDateTime,
}

impl<T: TenantScope> ClearanceRules<T> {
    /// A tenant's rules before anyone wrote one: no app permission clears
    /// for anything.
    #[must_use]
    pub fn none() -> Self {
        Self {
            rules: Vec::new(),
            updated_at: crate::shared::clock::now(),
            raised: Raised::default(),
            _scope: PhantomData,
        }
    }

    /// Rebuilds the rules from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when a rule clears for public or
    ///   internal data, or two rules name one permission.
    pub fn reconstitute(row: ClearanceRulesRow) -> Result<Self, DomainError> {
        RowCheck::of("clearance rules")
            .holds(
                row.rules
                    .iter()
                    .all(|(_, up_to)| ensure_above_internal(*up_to).is_ok()),
                "a rule clearing for what everyone sees",
            )
            .holds(
                first_repeat(row.rules.iter().map(|(permission, _)| permission)).is_none(),
                "two rules for one permission",
            )
            .finish()?;
        Ok(Self {
            rules: row
                .rules
                .into_iter()
                .map(|(permission, up_to)| ClearanceRule { permission, up_to })
                .collect(),
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// The declarations used to derive a caller's maximum readable data class.
    #[must_use]
    pub fn rules(&self) -> &[ClearanceRule] {
        &self.rules
    }

    /// When the rules last changed.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// Adds `rule`, for `by`. Raises `authorization.clearance_rule_added`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change how data is
    ///   classified, or is not cleared for `rule.up_to` themselves.
    /// - [`DomainError::Conflict`] when a rule already names the permission.
    pub fn add_rule(
        &mut self,
        rule: ClearanceRule,
        by: &TenantAuthority,
    ) -> Result<(), DomainError> {
        ensure_may_clear(by, rule.up_to)?;
        if self.position(&rule.permission).is_some() {
            return Err(DomainError::conflict(message!(
                "authorization-a-rule-already-clears-for-this",
                "a rule already clears for this permission; change it instead"
            )));
        }
        self.updated_at = crate::shared::clock::now();
        self.raised.raise(ClearanceRuleAdded {
            permission: rule.permission.clone(),
            up_to: rule.up_to,
            occurred_at: self.updated_at,
        });
        self.rules.push(rule);
        Ok(())
    }

    /// Changes what holding `permission` clears for to `up_to`, for `by`.
    /// Raises `authorization.clearance_rule_changed` with the level before
    /// and after.
    ///
    /// Lowering a clearance takes data away from its holders, so `by` must
    /// be cleared for both levels.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `up_to` is public or internal.
    /// - [`DomainError::Forbidden`] when `by` may not change how data is
    ///   classified, or is not cleared for the level before or after.
    /// - [`DomainError::NotFound`] when no rule names `permission`.
    pub fn change_rule(
        &mut self,
        permission: &CustomPermission,
        up_to: DataClassLevel,
        by: &TenantAuthority,
    ) -> Result<(), DomainError> {
        ensure_above_internal(up_to)?;
        let at = self.position(permission).ok_or(DomainError::NotFound)?;
        let rule = self.rules.get_mut(at).ok_or(DomainError::NotFound)?;
        ensure_may_clear(by, rule.up_to.max(up_to))?;
        let previous = std::mem::replace(&mut rule.up_to, up_to);
        self.updated_at = crate::shared::clock::now();
        self.raised.raise(ClearanceRuleChanged {
            permission: permission.clone(),
            previous,
            up_to,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Removes the rule naming `permission`, for `by`. Raises
    /// `authorization.clearance_rule_removed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change how data is
    ///   classified, or is not cleared for what the rule clears for.
    /// - [`DomainError::NotFound`] when no rule names `permission`.
    pub fn remove_rule(
        &mut self,
        permission: &CustomPermission,
        by: &TenantAuthority,
    ) -> Result<(), DomainError> {
        let at = self.position(permission).ok_or(DomainError::NotFound)?;
        let rule = self.rules.get(at).ok_or(DomainError::NotFound)?;
        ensure_may_clear(by, rule.up_to)?;
        self.rules.remove(at);
        self.updated_at = crate::shared::clock::now();
        self.raised.raise(ClearanceRuleRemoved {
            permission: permission.clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// The most sensitive data `authority` may see now: their built-in data
    /// rights, raised by any rule naming an app permission they hold.
    #[must_use]
    pub fn clearance_of(&self, authority: &TenantAuthority) -> DataClassLevel {
        self.rules
            .iter()
            .filter(|rule| authority.holds_custom(&rule.permission))
            .map(ClearanceRule::up_to)
            .fold(authority.data_clearance(), DataClassLevel::max)
    }

    /// The most sensitive data a caller carrying `held` may see, starting
    /// from `floor`: what the gateway works out from the permissions a
    /// signed assertion names.
    #[must_use]
    pub fn clearance_for(&self, floor: DataClassLevel, held: &[PermissionName]) -> DataClassLevel {
        self.rules
            .iter()
            .filter(|rule| rule.permission.held_in(held))
            .map(ClearanceRule::up_to)
            .fold(floor, DataClassLevel::max)
    }

    /// Where the rule naming `permission` stands.
    fn position(&self, permission: &CustomPermission) -> Option<usize> {
        self.rules
            .iter()
            .position(|rule| rule.permission == *permission)
    }
}

impl<T: TenantScope> Raises for ClearanceRules<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// Refuses a level everyone in the tenant sees already.
fn ensure_above_internal(up_to: DataClassLevel) -> Result<(), DomainError> {
    if up_to <= DataClassLevel::Internal {
        return Err(DomainError::invalid(message!(
            "authorization-a-clearance-rule-clears-for-confidential",
            "a clearance rule clears for confidential or restricted data"
        )));
    }
    Ok(())
}

/// Refuses `by` unless they may change classification and are cleared for
/// `level` themselves.
fn ensure_may_clear(by: &TenantAuthority, level: DataClassLevel) -> Result<(), DomainError> {
    by.ensure_holds(CLASSIFIES)?;
    if by.data_clearance() < level {
        return Err(DomainError::forbidden(message!(
            "authorization-clearing-for-data-needs-that-clearance",
            format!(
                "clearing for {} data needs that clearance yourself",
                level.as_str()
            )
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::fixtures::custom;
    use crate::domains::authorization::permission::DataAccessAction;
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::authority::assumed_authority;
    use crate::test_support::events::raised_names;
    use crate::types::{Human, HumanAccount, PersonKey, TenantId, UserId};

    const CONFIDENTIAL: SystemPermission = SystemPermission::Data(DataAccessAction::Confidential);
    const RESTRICTED: SystemPermission = SystemPermission::Data(DataAccessAction::Restricted);

    fn holding(system: &[SystemPermission], app: &[&str]) -> &'static TenantAuthority {
        let who = Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new("someone@acme.test").unwrap(),
        );
        let app: Vec<CustomPermission> = app.iter().map(|text| custom(text)).collect();
        assumed_authority(&who, TenantId::new(), system, &app)
    }

    /// Ann may classify data and is cleared for restricted data.
    fn ann() -> &'static TenantAuthority {
        holding(&[CLASSIFIES, RESTRICTED], &[])
    }

    fn payroll_confidential() -> ClearanceRule {
        ClearanceRule::new(custom("payroll:read"), DataClassLevel::Confidential).unwrap()
    }

    /// Ann makes `payroll:read` clear for confidential data. A clerk who
    /// holds it, through `payroll:*`, is cleared for confidential data; one
    /// without it sees internal data only.
    #[test]
    fn holding_a_named_permission_raises_clearance() {
        let mut rules = ClearanceRules::<ResolvedTenant>::none();
        rules.add_rule(payroll_confidential(), ann()).unwrap();

        let clerk = holding(&[], &["payroll:*"]);
        let other = holding(&[], &["notes:read"]);

        assert_eq!(rules.clearance_of(clerk), DataClassLevel::Confidential);
        assert_eq!(rules.clearance_of(other), DataClassLevel::Internal);
        assert_eq!(
            raised_names(&mut rules),
            ["authorization.clearance_rule_added"]
        );
    }

    /// A built-in right that clears for more is never lowered by a rule:
    /// Dan holds restricted access and `payroll:read`, and stays cleared
    /// for restricted data.
    #[test]
    fn a_rule_never_lowers_a_clearance() {
        let mut rules = ClearanceRules::<ResolvedTenant>::none();
        rules.add_rule(payroll_confidential(), ann()).unwrap();

        let dan = holding(&[RESTRICTED], &["payroll:read"]);

        assert_eq!(rules.clearance_of(dan), DataClassLevel::Restricted);
    }

    /// The gateway reads a caller's permissions from the assertion. One
    /// naming `payroll:read` is cleared for confidential data.
    #[test]
    fn clearance_is_read_from_permission_names() {
        let mut rules = ClearanceRules::<ResolvedTenant>::none();
        rules.add_rule(payroll_confidential(), ann()).unwrap();
        let named = [PermissionName::new("payroll:read").unwrap()];

        let cleared = rules.clearance_for(DataClassLevel::Internal, &named);

        assert_eq!(cleared, DataClassLevel::Confidential);
        assert_eq!(
            rules.clearance_for(DataClassLevel::Internal, &[]),
            DataClassLevel::Internal
        );
    }

    /// Confidential clearance cannot authorize adding or raising rules to
    /// restricted. Adding even a confidential rule also requires classification rights.
    #[test]
    fn nobody_clears_for_more_than_they_are_cleared_for() {
        let mut rules = ClearanceRules::<ResolvedTenant>::none();
        rules.add_rule(payroll_confidential(), ann()).unwrap();
        let sam = holding(&[CLASSIFIES, CONFIDENTIAL], &[]);
        let viewer = holding(&[CONFIDENTIAL], &[]);

        let added = rules.add_rule(
            ClearanceRule::new(custom("notes:read"), DataClassLevel::Restricted).unwrap(),
            sam,
        );
        let raised = rules.change_rule(&custom("payroll:read"), DataClassLevel::Restricted, sam);
        let unclassified = rules.add_rule(
            ClearanceRule::new(custom("notes:read"), DataClassLevel::Confidential).unwrap(),
            viewer,
        );

        for refused in [added, raised, unclassified] {
            assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        }
    }

    /// Ann raises the payroll rule to restricted and later removes it.
    /// Each change is recorded, and a second rule for one permission is
    /// refused.
    #[test]
    fn a_rule_is_changed_and_removed() {
        let mut rules = ClearanceRules::<ResolvedTenant>::none();
        rules.add_rule(payroll_confidential(), ann()).unwrap();
        raised_names(&mut rules);

        let twice = rules.add_rule(payroll_confidential(), ann());
        rules
            .change_rule(&custom("payroll:read"), DataClassLevel::Restricted, ann())
            .unwrap();
        assert_eq!(rules.rules()[0].up_to(), DataClassLevel::Restricted);
        rules.remove_rule(&custom("payroll:read"), ann()).unwrap();
        let gone = rules.remove_rule(&custom("payroll:read"), ann());

        assert!(matches!(twice, Err(DomainError::Conflict(_))));
        assert!(matches!(gone, Err(DomainError::NotFound)));
        assert_eq!(
            raised_names(&mut rules),
            [
                "authorization.clearance_rule_changed",
                "authorization.clearance_rule_removed",
            ]
        );
    }

    /// A rule clearing for internal or public data, which everyone sees, is
    /// refused when written and when read from storage.
    #[test]
    fn a_rule_clears_for_more_than_everyone_sees() {
        let stored = ClearanceRules::<ResolvedTenant>::reconstitute(ClearanceRulesRow {
            rules: vec![(custom("notes:read"), DataClassLevel::Internal)],
            updated_at: crate::shared::clock::now(),
        });

        assert!(ClearanceRule::new(custom("notes:read"), DataClassLevel::Internal).is_err());
        assert!(ClearanceRule::new(custom("notes:read"), DataClassLevel::Public).is_err());
        assert!(matches!(stored, Err(DomainError::Infrastructure(_))));
    }
}
