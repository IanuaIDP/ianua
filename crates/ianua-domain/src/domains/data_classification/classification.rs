//! How sensitive each field of an API response is.
//!
//! A tenant tags response fields with a classification level. The proxy's
//! Redact stage reads the tags and removes, masks or hashes sensitive
//! fields before the response reaches the caller.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::data_classification::control::ClassificationControlCheck;
use crate::domains::data_classification::events::{
    ClassificationRuleAdded, ClassificationRuleChanged, ClassificationRuleRemoved,
};
use crate::domains::data_classification::level::DataClassLevel;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::distinct::first_repeat;
use crate::types::{ClassificationRuleId, ClassificationRuleSetId, FieldPath};

/// Gives one field path a classification level and a way to redact it.
///
/// Field paths use dots, such as `user.ssn` or `billing.card_number`.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ClassificationRule {
    /// The rule's id.
    id: ClassificationRuleId,
    /// The field the rule covers.
    field_path: FieldPath,
    /// How sensitive the field is.
    level: DataClassLevel,
    /// How to redact the field when its level is at or above the proxy's
    /// threshold.
    redaction: RedactionStrategy,
}

impl ClassificationRule {
    /// A new rule with a fresh id.
    #[must_use]
    pub fn new(field_path: FieldPath, level: DataClassLevel, redaction: RedactionStrategy) -> Self {
        Self {
            id: ClassificationRuleId::new(),
            field_path,
            level,
            redaction,
        }
    }

    /// The rule's id.
    #[must_use]
    pub fn id(&self) -> &ClassificationRuleId {
        &self.id
    }

    /// The field path this rule applies to.
    #[must_use]
    pub fn field_path(&self) -> &FieldPath {
        &self.field_path
    }

    /// How sensitive the field is.
    #[must_use]
    pub fn level(&self) -> DataClassLevel {
        self.level
    }

    /// How to redact the field.
    #[must_use]
    pub fn redaction(&self) -> &RedactionStrategy {
        &self.redaction
    }
}

/// What a masked field reads as, wherever it is hidden.
pub const MASK: &str = "***";

/// How to redact a classified field.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RedactionStrategy {
    /// Remove the field from the response.
    Remove,
    /// Replace the value with a fixed mask, such as `"***"`.
    Mask,
    /// Replace the value with a keyed one-way digest, the same for one value
    /// within a tenant and apart between tenants. Keyed, so a short value
    /// such as a social security number cannot be found by digesting every
    /// one there is.
    Hash,
    /// Meant to encrypt the value. No keys back it, so the proxy masks the
    /// field instead, and a rule set refuses new rules that ask for it.
    Encrypt,
}

impl RedactionStrategy {
    /// The stable name an audit record carries.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Remove => "remove",
            Self::Mask => "mask",
            Self::Hash => "hash",
            Self::Encrypt => "encrypt",
        }
    }
}

/// A tenant's classification rules.
///
/// It says which fields in the tenant's API responses are sensitive and
/// how to redact them. Each field path has at most one rule.
#[derive(Debug)]
pub struct ClassificationRuleSet<T: TenantScope> {
    /// The rule set's id.
    id: ClassificationRuleSetId,
    /// The rules in the set.
    rules: Vec<ClassificationRule>,
    /// When the set was created.
    created_at: OffsetDateTime,
    /// When the set last changed.
    updated_at: OffsetDateTime,
    /// What adding and removing rules raised, until the save takes it.
    raised: Raised<T>,
    /// Which plane the set belongs to. See [`crate::isolation`].
    _scope: PhantomData<T>,
}

/// A rule set as stored, read back through
/// [`ClassificationRuleSet::reconstitute`].
pub struct ClassificationRuleSetRow {
    /// The rule set's id.
    pub id: ClassificationRuleSetId,
    /// The rules in the set.
    pub rules: Vec<ClassificationRule>,
    /// When the set was created.
    pub created_at: OffsetDateTime,
    /// When the set last changed.
    pub updated_at: OffsetDateTime,
}

impl<T: TenantScope> ClassificationRuleSet<T> {
    /// A new rule set with no rules, made by `by`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change classification
    ///   rules.
    pub fn empty(by: &impl ClassificationControlCheck) -> Result<Self, DomainError> {
        by.ensure_may_change_rules()?;
        let now = crate::shared::clock::now();
        Ok(Self {
            id: ClassificationRuleSetId::new(),
            rules: Vec::new(),
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Rebuilds a rule set from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row has two rules for one
    ///   field, or two rules under one id.
    /// - [`DomainError::Infrastructure`] when it changed before it was
    ///   created.
    pub fn reconstitute(row: ClassificationRuleSetRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            rules: row.rules,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule the set keeps.
    fn ensure_consistent(row: &ClassificationRuleSetRow) -> Result<(), DomainError> {
        RowCheck::of("classification rule set")
            .holds(
                first_repeat(row.rules.iter().map(|rule| rule.field_path().as_str())).is_none(),
                "two rules classifying one field",
            )
            .holds(
                first_repeat(row.rules.iter().map(ClassificationRule::id)).is_none(),
                "two rules under one id",
            )
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was created",
            )
            .finish()
    }

    /// The rule set's id.
    #[must_use]
    pub fn id(&self) -> &ClassificationRuleSetId {
        &self.id
    }

    /// All rules in the set.
    #[must_use]
    pub fn rules(&self) -> &[ClassificationRule] {
        &self.rules
    }

    /// When the set was created.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When the set last changed.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// Adds a rule to the set and gives back its id. Raises
    /// `proxy.classification_rule_added`.
    ///
    /// Each field path has one rule. [`Self::classify`] takes the first
    /// match, so a second rule on the same path would never apply. Ann
    /// tags `user.ssn` as public, then adds a restricted rule for it. The
    /// list would show the field as restricted while the proxy sends it in
    /// the clear.
    ///
    /// A new rule may not ask for [`RedactionStrategy::Encrypt`]. No keys
    /// back it, and the proxy masks the field instead. Storing the rule
    /// would show the field as encrypted in the rule list while it leaves
    /// as a mask. A stored rule asking for it is still read back.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change classification
    ///   rules.
    /// - [`DomainError::Validation`] when the rule asks for encryption.
    /// - [`DomainError::Conflict`] if a rule already covers this field path.
    ///   Remove that rule first.
    pub fn add_rule(
        &mut self,
        rule: ClassificationRule,
        by: &impl ClassificationControlCheck,
    ) -> Result<ClassificationRuleId, DomainError> {
        by.ensure_may_change_rules()?;
        if matches!(rule.redaction(), RedactionStrategy::Encrypt) {
            return Err(DomainError::invalid(message!(
                "data_classification-encrypt-is-not-available-yet-choose",
                "Encrypt is not available yet: choose Remove, Mask or Hash"
            )));
        }
        if self.classify(rule.field_path().as_str()).is_some() {
            return Err(DomainError::conflict(message!(
                "data_classification-a-rule-already-classifies-remove-it",
                format!(
                    "a rule already classifies '{}'; remove it before adding another",
                    rule.field_path().as_str()
                )
            )));
        }

        let id = *rule.id();
        self.updated_at = crate::shared::clock::now();
        self.raised.raise(ClassificationRuleAdded {
            rule_id: id,
            field_path: rule.field_path().clone(),
            level: rule.level(),
            redaction: rule.redaction().clone(),
            occurred_at: self.updated_at,
        });
        self.rules.push(rule);

        Ok(id)
    }

    /// Removes the rule with this id, and says whether there was one.
    /// Raises `proxy.classification_rule_removed` when there was.
    ///
    /// The field it classified then reaches callers unredacted.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change classification
    ///   rules.
    pub fn remove_rule(
        &mut self,
        rule_id: &ClassificationRuleId,
        by: &impl ClassificationControlCheck,
    ) -> Result<bool, DomainError> {
        by.ensure_may_change_rules()?;
        let Some(position) = self.rules.iter().position(|r| r.id() == rule_id) else {
            return Ok(false);
        };
        let removed = self.rules.remove(position);
        self.updated_at = crate::shared::clock::now();
        self.raised.raise(ClassificationRuleRemoved {
            rule_id: removed.id,
            field_path: removed.field_path,
            occurred_at: self.updated_at,
        });
        Ok(true)
    }

    /// Changes how sensitive the rule with this id says its field is, and
    /// how it is redacted, keeping its id and field. Raises
    /// `proxy.classification_rule_changed` with what changed.
    ///
    /// Removing the rule and adding another would leave a moment where the
    /// field goes out in the clear, and give the rule a new id.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change classification
    ///   rules.
    /// - [`DomainError::Validation`] when the change asks for encryption,
    ///   for the reason [`Self::add_rule`] gives.
    /// - [`DomainError::NotFound`] when no rule has this id.
    pub fn change_rule(
        &mut self,
        rule_id: &ClassificationRuleId,
        level: DataClassLevel,
        redaction: RedactionStrategy,
        by: &impl ClassificationControlCheck,
    ) -> Result<(), DomainError> {
        by.ensure_may_change_rules()?;
        if matches!(redaction, RedactionStrategy::Encrypt) {
            return Err(DomainError::invalid(message!(
                "data_classification-encrypt-is-not-available-yet-choose",
                "Encrypt is not available yet: choose Remove, Mask or Hash"
            )));
        }
        let rule = self
            .rules
            .iter_mut()
            .find(|r| r.id() == rule_id)
            .ok_or(DomainError::NotFound)?;
        let previous_level = std::mem::replace(&mut rule.level, level);
        let previous_redaction = std::mem::replace(&mut rule.redaction, redaction.clone());
        let field_path = rule.field_path.clone();
        self.updated_at = crate::shared::clock::now();
        self.raised.raise(ClassificationRuleChanged {
            rule_id: *rule_id,
            field_path,
            previous_level,
            level,
            previous_redaction,
            redaction,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// The rule for exactly this field path, if there is one.
    #[must_use]
    pub fn classify(&self, field_path: &str) -> Option<&ClassificationRule> {
        self.rules
            .iter()
            .find(|r| r.field_path().as_str() == field_path)
    }

    /// How the field at `field_path` is hidden when what is at `min` or
    /// above is hidden, or `None` when it stays: it has no rule, or one
    /// below `min`. The gateway and workflow steps both ask this, so a
    /// field is hidden alike wherever it passes.
    #[must_use]
    pub fn redaction_at(
        &self,
        field_path: &str,
        min: DataClassLevel,
    ) -> Option<&RedactionStrategy> {
        self.classify(field_path)
            .filter(|rule| rule.level() >= min)
            .map(ClassificationRule::redaction)
    }

    /// The distinct levels the rules define, highest first: what a request
    /// the set classifies is tagged with.
    #[must_use]
    pub fn levels(&self) -> Vec<DataClassLevel> {
        let mut levels: Vec<DataClassLevel> =
            self.rules.iter().map(ClassificationRule::level).collect();
        levels.sort_unstable_by(|a, b| b.cmp(a));
        levels.dedup();
        levels
    }

    /// The rules whose level is `min_level` or higher.
    #[must_use]
    pub fn rules_above(&self, min_level: DataClassLevel) -> Vec<&ClassificationRule> {
        self.rules
            .iter()
            .filter(|r| r.level() >= min_level)
            .collect()
    }
}

impl<T: TenantScope> Raises for ClassificationRuleSet<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::authority::TenantAuthority;
    use crate::domains::authorization::permission::{ClassificationAction, SystemPermission};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::FieldPath;

    fn fp(s: &str) -> FieldPath {
        FieldPath::new(s).unwrap()
    }

    fn editor() -> &'static TenantAuthority {
        anyone_holding(&[SystemPermission::Classification(
            ClassificationAction::Update,
        )])
    }

    fn viewer() -> &'static TenantAuthority {
        anyone_holding(&[SystemPermission::Classification(ClassificationAction::View)])
    }

    fn empty() -> ClassificationRuleSet<ResolvedTenant> {
        ClassificationRuleSet::empty(editor()).unwrap()
    }

    fn masked_ssn() -> ClassificationRule {
        ClassificationRule::new(
            fp("user.ssn"),
            DataClassLevel::Restricted,
            RedactionStrategy::Mask,
        )
    }

    /// A viewer cannot remove or add a rule or create a set. The existing
    /// set still has its single restricted SSN rule.
    #[test]
    fn a_viewer_may_not_change_the_rules() {
        let mut rs = empty();
        let ssn = rs.add_rule(masked_ssn(), editor()).unwrap();

        let public_email = ClassificationRule::new(
            fp("user.email"),
            DataClassLevel::Public,
            RedactionStrategy::Remove,
        );

        let removed = rs.remove_rule(&ssn, viewer());
        let added = rs.add_rule(public_email, viewer());
        let made = ClassificationRuleSet::<ResolvedTenant>::empty(viewer());

        assert!(matches!(removed, Err(DomainError::Forbidden(_))));
        assert!(matches!(added, Err(DomainError::Forbidden(_))));
        assert!(matches!(made, Err(DomainError::Forbidden(_))));
        assert_eq!(
            rs.classify("user.ssn").map(ClassificationRule::level),
            Some(DataClassLevel::Restricted)
        );
        assert_eq!(rs.rules().len(), 1);
    }

    /// A tenant tags `user.ssn` and `user.card` restricted and
    /// `user.email` confidential. The set defines two levels, highest
    /// first, each once; an empty set defines none.
    #[test]
    fn the_levels_are_distinct_and_highest_first() {
        let mut rs = empty();
        rs.add_rule(masked_ssn(), editor()).unwrap();
        for (path, level) in [
            ("user.email", DataClassLevel::Confidential),
            ("user.card", DataClassLevel::Restricted),
        ] {
            let rule = ClassificationRule::new(fp(path), level, RedactionStrategy::Mask);
            rs.add_rule(rule, editor()).unwrap();
        }

        assert_eq!(
            rs.levels(),
            [DataClassLevel::Restricted, DataClassLevel::Confidential]
        );
        assert!(empty().levels().is_empty());
    }

    /// A tenant that has tagged nothing starts with an empty rule set, so no
    /// field is redacted.
    #[test]
    fn empty_rule_set_has_no_rules() {
        let rs = empty();
        assert!(rs.rules().is_empty());
    }

    /// A tenant tags `user.ssn` as restricted with a mask. Looking up that
    /// path gives back the same level and strategy.
    #[test]
    fn add_and_classify() {
        let mut rs = empty();
        rs.add_rule(masked_ssn(), editor()).unwrap();

        let rule = rs.classify("user.ssn").unwrap();
        assert_eq!(rule.level(), DataClassLevel::Restricted);
        assert!(matches!(rule.redaction(), RedactionStrategy::Mask));
    }

    /// Adding a rule gives back that rule's own id, so the caller can remove
    /// it later.
    #[test]
    fn adding_returns_the_id_of_the_rule_it_created() {
        let mut rs = empty();
        let rule = masked_ssn();
        let expected = *rule.id();

        assert_eq!(rs.add_rule(rule, editor()).unwrap(), expected);
    }

    /// Adding a public rule for an already restricted field returns a
    /// conflict and leaves its single restricted rule in place.
    #[test]
    fn a_second_rule_on_the_same_field_is_refused() {
        let mut rs = empty();
        rs.add_rule(masked_ssn(), editor()).unwrap();

        let second = rs.add_rule(
            ClassificationRule::new(
                fp("user.ssn"),
                DataClassLevel::Public,
                RedactionStrategy::Remove,
            ),
            editor(),
        );

        assert!(
            matches!(second, Err(DomainError::Conflict(_))),
            "classify takes the first match, so a second rule would never fire"
        );
        assert_eq!(rs.rules().len(), 1);
        assert_eq!(
            rs.classify("user.ssn").unwrap().level(),
            DataClassLevel::Restricted,
            "the rule already in the set keeps deciding"
        );
    }

    /// A field no rule names, such as `unknown.field`, has no classification.
    #[test]
    fn classify_unknown_field_returns_none() {
        let rs = empty();
        assert!(rs.classify("unknown.field").is_none());
    }

    /// A tenant adds a hash rule for `user.email`, then removes it. The
    /// removal reports success and the set is empty again.
    #[test]
    fn a_removed_rule_no_longer_classifies() {
        let mut rs = empty();
        let rule = ClassificationRule::new(
            fp("user.email"),
            DataClassLevel::Confidential,
            RedactionStrategy::Hash,
        );
        let id = rs.add_rule(rule, editor()).unwrap();
        assert_eq!(rs.rules().len(), 1);

        assert!(rs.remove_rule(&id, editor()).unwrap());
        assert!(rs.rules().is_empty());
    }

    /// An encryption rule is rejected as invalid, leaving the rule set
    /// empty because the strategy has no backing keys.
    #[test]
    fn a_rule_asking_for_encryption_is_refused() {
        let mut rs = empty();
        let encrypted = ClassificationRule::new(
            fp("user.ssn"),
            DataClassLevel::Restricted,
            RedactionStrategy::Encrypt,
        );

        let added = rs.add_rule(encrypted, editor());

        assert!(matches!(added, Err(DomainError::Validation(_))));
        assert!(rs.rules().is_empty());
    }

    /// A set has a public, a confidential and a restricted rule. Asking for
    /// confidential and higher gives the two sensitive ones.
    #[test]
    fn rules_above_filters_by_level() {
        let mut rs = empty();
        let rules = [
            ClassificationRule::new(
                fp("user.name"),
                DataClassLevel::Public,
                RedactionStrategy::Remove,
            ),
            masked_ssn(),
            ClassificationRule::new(
                fp("user.email"),
                DataClassLevel::Confidential,
                RedactionStrategy::Hash,
            ),
        ];
        for rule in rules {
            rs.add_rule(rule, editor()).unwrap();
        }

        let restricted = rs.rules_above(DataClassLevel::Confidential);
        assert_eq!(restricted.len(), 2);
    }

    /// A set has rules for `user.email` and `user.phone`. Removing the phone
    /// rule keeps only the email rule. Removing an id that was never there
    /// reports that nothing was removed.
    #[test]
    fn removing_a_rule_takes_away_that_rule_and_reports_whether_it_found_one() {
        let mut rs = empty();
        let kept = rs
            .add_rule(
                ClassificationRule::new(
                    fp("user.email"),
                    DataClassLevel::Confidential,
                    RedactionStrategy::Mask,
                ),
                editor(),
            )
            .unwrap();
        let removed = rs
            .add_rule(
                ClassificationRule::new(
                    fp("user.phone"),
                    DataClassLevel::Confidential,
                    RedactionStrategy::Hash,
                ),
                editor(),
            )
            .unwrap();

        assert!(rs.remove_rule(&removed, editor()).unwrap());
        assert_eq!(rs.rules().len(), 1);
        assert_eq!(*rs.rules()[0].id(), kept);

        assert!(
            !rs.remove_rule(&ClassificationRuleId::new(), editor())
                .unwrap(),
            "a rule that was never there cannot be removed"
        );
        assert!(!rs.id().as_uuid().is_nil());
    }

    /// A stored set holds two rules for `user.email`. Only the first would
    /// ever apply, so the row is refused as corrupt.
    #[test]
    fn a_stored_rule_set_classifying_one_field_twice_is_refused() {
        let now = crate::shared::clock::now();
        let rule = || {
            ClassificationRule::new(
                fp("user.email"),
                DataClassLevel::Confidential,
                RedactionStrategy::Mask,
            )
        };

        let set = ClassificationRuleSet::<ResolvedTenant>::reconstitute(ClassificationRuleSetRow {
            id: ClassificationRuleSetId::new(),
            rules: vec![rule(), rule()],
            created_at: now,
            updated_at: now,
        });

        assert!(refused_as_corrupt(&set));
    }

    /// A stored set assigning one identifier to both SSN and email rules
    /// is rejected as corrupt.
    #[test]
    fn a_stored_rule_set_with_two_rules_under_one_id_is_refused() {
        let now = crate::shared::clock::now();
        let ssn = masked_ssn();
        let mut email = ClassificationRule::new(
            fp("user.email"),
            DataClassLevel::Confidential,
            RedactionStrategy::Mask,
        );
        email.id = *ssn.id();

        let set = ClassificationRuleSet::<ResolvedTenant>::reconstitute(ClassificationRuleSetRow {
            id: ClassificationRuleSetId::new(),
            rules: vec![ssn, email],
            created_at: now,
            updated_at: now,
        });

        assert!(refused_as_corrupt(&set));
    }

    /// Ann masks `user.ssn` and later removes the rule. Each is raised, in
    /// order, naming the rule and the field.
    #[test]
    fn adding_and_removing_a_rule_are_raised_in_order() {
        let mut rs = empty();

        let ssn = rs.add_rule(masked_ssn(), editor()).unwrap();
        rs.remove_rule(&ssn, editor()).unwrap();
        let events = raised(&mut rs);

        let names: Vec<String> = events.iter().map(|e| e.event_type().to_string()).collect();
        assert_eq!(
            names,
            [
                "proxy.classification_rule_added",
                "proxy.classification_rule_removed",
            ]
        );
        for event in &events {
            let payload = event.payload();
            assert_eq!(
                payload.value("rule_id").and_then(FieldValue::as_str),
                Some(ssn.to_string().as_str())
            );
            assert_eq!(
                payload.value("field_path").and_then(FieldValue::as_str),
                Some("user.ssn")
            );
        }
    }

    /// Ann removes a rule that is not in the set. Nothing was removed, so
    /// nothing is raised.
    #[test]
    fn removing_a_rule_that_is_not_there_raises_nothing() {
        let mut rs = empty();

        let removed = rs.remove_rule(&ClassificationRuleId::new(), editor());

        assert!(!removed.unwrap());
        assert!(raised_names(&mut rs).is_empty());
    }

    /// Removal by a viewer, a duplicate field rule and an encryption rule
    /// are all rejected without raising any event.
    #[test]
    fn a_refused_rule_change_raises_nothing() {
        let mut rs = empty();
        let ssn = rs.add_rule(masked_ssn(), editor()).unwrap();
        raised_names(&mut rs);
        let encrypted = ClassificationRule::new(
            fp("user.email"),
            DataClassLevel::Confidential,
            RedactionStrategy::Encrypt,
        );

        let removed = rs.remove_rule(&ssn, viewer());
        let repeated = rs.add_rule(masked_ssn(), editor());
        let encrypting = rs.add_rule(encrypted, editor());

        assert!(removed.is_err());
        assert!(repeated.is_err());
        assert!(encrypting.is_err());
        assert!(raised_names(&mut rs).is_empty());
    }

    /// A rule set read back from storage, or a new empty one, has raised
    /// nothing.
    #[test]
    fn a_rule_set_read_back_from_storage_has_raised_nothing() {
        let now = crate::shared::clock::now();
        let mut stored =
            ClassificationRuleSet::<ResolvedTenant>::reconstitute(ClassificationRuleSetRow {
                id: ClassificationRuleSetId::new(),
                rules: vec![masked_ssn()],
                created_at: now,
                updated_at: now,
            })
            .unwrap();
        let mut fresh = empty();

        assert!(raised_names(&mut stored).is_empty());
        assert!(raised_names(&mut fresh).is_empty());
    }

    /// Ann lowers `user.ssn` from restricted and masked to confidential and
    /// hashed. The rule keeps its id and field, and the record keeps both
    /// levels and both redactions.
    #[test]
    fn a_rule_is_changed_in_place() {
        let mut rs = empty();
        let ssn = rs.add_rule(masked_ssn(), editor()).unwrap();
        raised_names(&mut rs);

        rs.change_rule(
            &ssn,
            DataClassLevel::Confidential,
            RedactionStrategy::Hash,
            editor(),
        )
        .unwrap();

        let rule = rs.classify("user.ssn").unwrap();
        assert_eq!(rule.id(), &ssn);
        assert_eq!(rule.level(), DataClassLevel::Confidential);
        let events = raised(&mut rs);
        let payload = events[0].payload();
        let Some(FieldValue::Change(level)) = payload.value("level") else {
            panic!("the level is recorded as a change");
        };
        assert_eq!(
            (level.from(), level.to()),
            (Some("restricted"), Some("confidential"))
        );
    }

    /// Changes by a viewer, unsupported encryption and a missing rule are
    /// refused with distinct errors. The SSN rule remains restricted.
    #[test]
    fn a_rule_is_changed_only_by_an_editor_and_only_to_what_exists() {
        let mut rs = empty();
        let ssn = rs.add_rule(masked_ssn(), editor()).unwrap();

        let by_viewer = rs.change_rule(
            &ssn,
            DataClassLevel::Public,
            RedactionStrategy::Remove,
            viewer(),
        );
        let encrypting = rs.change_rule(
            &ssn,
            DataClassLevel::Restricted,
            RedactionStrategy::Encrypt,
            editor(),
        );
        let missing = rs.change_rule(
            &ClassificationRuleId::new(),
            DataClassLevel::Restricted,
            RedactionStrategy::Mask,
            editor(),
        );

        assert!(matches!(by_viewer, Err(DomainError::Forbidden(_))));
        assert!(matches!(encrypting, Err(DomainError::Validation(_))));
        assert!(matches!(missing, Err(DomainError::NotFound)));
        assert_eq!(
            rs.classify("user.ssn").unwrap().level(),
            DataClassLevel::Restricted
        );
    }
}
