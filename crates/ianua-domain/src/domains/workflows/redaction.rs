//! Hiding a workflow value's sensitive fields, by the tenant's
//! classification rules, as the gateway hides them in an app's answer.
//!
//! Pat's workflow reads an order with the customer's card number, and Acme
//! classifies `orders.card_number` as restricted. Before the order goes on
//! to a support ticket, a step hides what is confidential or above: the
//! card number is removed, masked or replaced by a keyed digest, as its
//! rule says, and the rest of the order goes on. A list's items are read
//! under the list's own path, so a rule for `items.ssn` covers each item.

use crate::domains::data_classification::classification::{
    ClassificationRuleSet, MASK, RedactionStrategy,
};
use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::workflows::data::{FieldName, FlowData, FlowValue};
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;

/// The keyed digest a hashed field is replaced with: the same for one
/// value within a tenant, so equal values still read equal, and no value
/// found again by digesting guesses.
pub trait FieldDigest {
    /// The digest of `value`, a field's value as JSON.
    fn digest(&self, value: &str) -> String;
}

/// What hiding a value's sensitive fields applies.
pub struct Hiding<'a, T: TenantScope> {
    /// The tenant's classification rules.
    pub rules: &'a ClassificationRuleSet<T>,
    /// The least sensitive level hidden: every field classified at it or
    /// above is.
    pub min: DataClassLevel,
    /// The digest a hashed field is replaced with.
    pub digest: &'a dyn FieldDigest,
}

/// A value with its sensitive fields hidden, and how many were.
#[derive(Debug, Clone, PartialEq)]
pub struct Hidden {
    /// The value, the classified fields hidden.
    pub data: FlowData,
    /// How many fields were hidden.
    pub count: usize,
}

/// `data` with every field `hiding` classifies hidden, found from the root
/// path `path`, which is empty for a whole value.
///
/// # Errors
///
/// Returns [`DomainError::Validation`] when the value hidden is no longer
/// workflow data, which it always is: hiding only removes or shortens.
pub fn hidden<T: TenantScope>(
    data: &FlowData,
    path: &str,
    hiding: &Hiding<'_, T>,
) -> Result<Hidden, DomainError> {
    match data.value() {
        FlowValue::Map(fields) => hidden_fields(fields, path, hiding),
        FlowValue::List(items) => {
            let mut count: usize = 0;
            let mut kept = Vec::with_capacity(items.len());
            for item in items {
                let one = hidden(item, path, hiding)?;
                count = count.saturating_add(one.count);
                kept.push(one.data);
            }
            Ok(Hidden {
                data: FlowData::list(kept)?,
                count,
            })
        }
        FlowValue::Null | FlowValue::Bool(_) | FlowValue::Number(_) | FlowValue::Text(_) => {
            Ok(Hidden {
                data: data.clone(),
                count: 0,
            })
        }
    }
}

/// The fields of one map with those `hiding` classifies hidden, and what
/// is classified inside the rest. A hidden field is not looked into.
fn hidden_fields<T: TenantScope>(
    fields: &[(FieldName, FlowData)],
    path: &str,
    hiding: &Hiding<'_, T>,
) -> Result<Hidden, DomainError> {
    let mut count: usize = 0;
    let mut kept = Vec::with_capacity(fields.len());
    for (name, value) in fields {
        let at = joined(path, name.as_str());
        let Some(strategy) = hiding.rules.redaction_at(&at, hiding.min) else {
            let inner = hidden(value, &at, hiding)?;
            count = count.saturating_add(inner.count);
            kept.push((name.clone(), inner.data));
            continue;
        };
        count = count.saturating_add(1);
        if let Some(shown) = hidden_as(strategy, value, hiding.digest)? {
            kept.push((name.clone(), shown));
        }
    }
    Ok(Hidden {
        data: FlowData::map(kept)?,
        count,
    })
}

/// What `value`, a field `strategy` hides, is shown as: `None` when it is
/// removed. A guardrail hides the fields it finds the same way.
///
/// # Errors
///
/// Returns [`DomainError::Validation`] when the mask or digest is no longer
/// workflow data, which it always is: both are short text.
pub(crate) fn hidden_as(
    strategy: &RedactionStrategy,
    value: &FlowData,
    digest: &dyn FieldDigest,
) -> Result<Option<FlowData>, DomainError> {
    match strategy {
        RedactionStrategy::Remove => Ok(None),
        RedactionStrategy::Mask | RedactionStrategy::Encrypt => FlowData::text(MASK).map(Some),
        RedactionStrategy::Hash => FlowData::text(digest.digest(&value.render())).map(Some),
    }
}

/// The dotted path of the field `name` inside `parent`.
pub(crate) fn joined(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        return name.to_owned();
    }
    format!("{parent}.{name}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::data_classification::classification::{
        ClassificationRule, ClassificationRuleSetRow,
    };
    use crate::isolation::scope::ResolvedTenant;
    use crate::types::{ClassificationRuleSetId, FieldPath};

    fn field(name: &str) -> FieldName {
        FieldName::new(name).unwrap()
    }

    fn text(value: &str) -> FlowData {
        FlowData::text(value).unwrap()
    }

    /// Acme's rules: card numbers restricted and removed, emails
    /// confidential and masked, item serials confidential and hashed, and
    /// notes internal and masked.
    fn acme_rules() -> ClassificationRuleSet<ResolvedTenant> {
        let now = crate::shared::clock::now();
        ClassificationRuleSet::reconstitute(ClassificationRuleSetRow {
            id: ClassificationRuleSetId::new(),
            rules: vec![
                rule(
                    "order.card",
                    DataClassLevel::Restricted,
                    RedactionStrategy::Remove,
                ),
                rule(
                    "order.email",
                    DataClassLevel::Confidential,
                    RedactionStrategy::Mask,
                ),
                rule(
                    "order.items.serial",
                    DataClassLevel::Confidential,
                    RedactionStrategy::Hash,
                ),
                rule(
                    "order.note",
                    DataClassLevel::Internal,
                    RedactionStrategy::Mask,
                ),
            ],
            created_at: now,
            updated_at: now,
        })
        .unwrap()
    }

    /// Builds one validated path rule for the tenant's classification fixture.
    fn rule(path: &str, level: DataClassLevel, redaction: RedactionStrategy) -> ClassificationRule {
        ClassificationRule::new(FieldPath::new(path).unwrap(), level, redaction)
    }

    /// An order with a card, an email, a note and two items with serials.
    fn order() -> FlowData {
        let item = |serial: &str| FlowData::map(vec![(field("serial"), text(serial))]).unwrap();
        FlowData::map(vec![(
            field("order"),
            FlowData::map(vec![
                (field("card"), text("4111 1111 1111 1111")),
                (field("email"), text("lee@acme.com")),
                (field("note"), text("leave at the door")),
                (
                    field("items"),
                    FlowData::list(vec![item("A1"), item("B2")]).unwrap(),
                ),
            ])
            .unwrap(),
        )])
        .unwrap()
    }

    /// A digest that spells out what it digested, so a test can see it.
    struct Spelled;

    impl FieldDigest for Spelled {
        fn digest(&self, value: &str) -> String {
            format!("digest-of-{value}")
        }
    }

    /// Hiding what is confidential or above removes the card, masks the
    /// email, digests each item's serial and keeps the internal note.
    #[test]
    fn what_is_classified_at_the_level_or_above_is_hidden_as_its_rule_says() {
        let rules = acme_rules();
        let hiding = Hiding {
            rules: &rules,
            min: DataClassLevel::Confidential,
            digest: &Spelled,
        };

        let result = hidden(&order(), "", &hiding).unwrap();

        let path = |p: &str| crate::domains::workflows::data::DataPath::parse(p).unwrap();
        assert_eq!(result.count, 4);
        assert_eq!(result.data.at(&path("order.card")), None);
        assert_eq!(result.data.at(&path("order.email")), Some(&text(MASK)));
        assert_eq!(
            result.data.at(&path("order.note")),
            Some(&text("leave at the door"))
        );
        assert!(result.data.render().contains("digest-of-\\\"A1\\\""));
    }
}
