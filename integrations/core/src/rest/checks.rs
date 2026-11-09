//! The rules every set of operations keeps, for each service's tests to
//! hold its operations to: a key used once, a spec and guide made for each,
//! every input explained, every picker filled by a read of the same set,
//! every path input placed by a segment and every segment reading a
//! declared input, no body input on a verb without a body, every input
//! asked only in the form optional, and something given back.

use std::collections::HashSet;

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::integration::{InputNeed, IntegrationKey};

use crate::rest::operation::{Operation, Place, Segment};

/// Every way `operations` break the rules, each named with its operation;
/// empty when they keep them all.
#[must_use]
pub fn misdescribed<'a>(
    integration: &IntegrationKey,
    operations: impl IntoIterator<Item = &'a Operation>,
) -> Vec<String> {
    let operations: Vec<&Operation> = operations.into_iter().collect();
    let mut seen = HashSet::new();
    let mut wrong = unread_pickers(integration, &operations);
    for operation in operations {
        if !seen.insert(operation.key) {
            wrong.push(format!("{}: the key is used twice", operation.key));
        }
        wrong.extend(explained(integration, operation));
        wrong.extend(placed(operation));
        wrong.extend(required_form_inputs(operation));
        if !operation.verb.sends_body() && sends_body(operation) {
            wrong.push(format!(
                "{}: body values on a verb that sends no body",
                operation.key
            ));
        }
        if operation.outputs.is_empty() {
            wrong.push(format!(
                "{}: it does not say what it gives back",
                operation.key
            ));
        }
    }
    wrong
}

/// Every operation whose form fills a picker from an operation of the set
/// that is not a read, or from none of them.
fn unread_pickers(integration: &IntegrationKey, operations: &[&Operation]) -> Vec<String> {
    let specs: Vec<_> = operations
        .iter()
        .filter_map(|operation| operation.spec(integration, DataClassLevel::Internal).ok())
        .collect();
    operations
        .iter()
        .filter_map(|operation| {
            let guide = operation.guide(None).ok()?;
            let refused = guide.ensure_pickers_read(&specs).err()?;
            Some(format!("{}: {refused}", operation.key))
        })
        .collect()
}

/// Why `operation`'s spec or guide cannot be made, or the guide does not
/// explain the spec.
fn explained(integration: &IntegrationKey, operation: &Operation) -> Option<String> {
    let made = operation
        .spec(integration, DataClassLevel::Internal)
        .and_then(|spec| Ok((spec, operation.guide(None)?)));
    let (spec, guide) = match made {
        Ok(made) => made,
        Err(error) => return Some(format!("{}: {error}", operation.key)),
    };
    guide
        .ensure_explains(&spec)
        .err()
        .map(|error| format!("{}: {error}", operation.key))
}

/// Why `operation`'s path inputs and segments do not match one to one.
fn placed(operation: &Operation) -> Option<String> {
    let mut declared: Vec<&str> = operation
        .fields
        .iter()
        .filter(|field| field.place == Place::Path)
        .map(|field| field.name)
        .collect();
    let mut read: Vec<&str> = operation
        .path
        .iter()
        .filter_map(|segment| match segment {
            Segment::Pair(name) | Segment::Input(name) | Segment::Slashed(name) => Some(*name),
            Segment::Prefixed { input, .. } | Segment::Suffixed { input, .. } => Some(*input),
            Segment::Fixed(_) => None,
        })
        .collect();
    declared.sort_unstable();
    read.sort_unstable();
    (declared != read).then(|| {
        format!(
            "{}: path inputs {declared:?} and the segments reading {read:?} differ",
            operation.key
        )
    })
}

/// Every input asked only in the form that is required: a step must run
/// with only what it sends, so a form-only input is always optional.
fn required_form_inputs(operation: &Operation) -> Vec<String> {
    operation
        .fields
        .iter()
        .filter(|field| field.place == Place::Form && field.need == InputNeed::Required)
        .map(|field| {
            format!(
                "{}: {} is asked only in the form, so it must be optional",
                operation.key, field.name
            )
        })
        .collect()
}

/// Whether `operation` puts anything in a body.
fn sends_body(operation: &Operation) -> bool {
    !operation.fixed.is_empty()
        || operation
            .fields
            .iter()
            .any(|field| field.place == Place::Body)
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::DeclaredAction;

    use super::*;
    use crate::rest::operation::{Field, Fixed, Kind, Shape, Verb};

    const GOOD: Operation = Operation {
        key: "get-item",
        title: "Get an item",
        description: "Reads one item.",
        effect: DeclaredAction::Undeclared,
        verb: Verb::Get,
        path: &[Segment::Fixed("items"), Segment::Input("item")],
        fields: &[Field::required(
            "item",
            Kind::Count,
            Place::Path,
            "The item.",
        )],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[("status", "The status.")],
    };

    fn key() -> IntegrationKey {
        IntegrationKey::new("sample").unwrap()
    }

    /// An operation keeping every rule has nothing said against it.
    #[test]
    fn a_well_described_operation_passes() {
        assert!(misdescribed(&key(), [&GOOD]).is_empty());
    }

    /// Operations with missing path inputs, extra segments, a body on a
    /// read, no outputs, or a required input asked only in the form.
    fn broken_operations() -> [Operation; 5] {
        let unplaced = Operation {
            key: "unplaced",
            path: &[Segment::Fixed("items")],
            ..GOOD
        };
        let unread = Operation {
            key: "unread",
            path: &[Segment::Input("item"), Segment::Input("ghost")],
            ..GOOD
        };
        let bodied = Operation {
            key: "bodied",
            fixed: &[("state", Fixed::Text("open"))],
            ..GOOD
        };
        let silent = Operation {
            key: "silent",
            outputs: &[],
            ..GOOD
        };
        const DEMANDED: &[Field] = &[
            Field::required("item", Kind::Count, Place::Path, "The item."),
            Field::required("shelf", Kind::Text, Place::Form, "Narrows the items."),
        ];
        let demanding = Operation {
            key: "demanding",
            fields: DEMANDED,
            ..GOOD
        };
        [unplaced, unread, bodied, silent, demanding]
    }

    /// Duplicate keys, mismatched path inputs, body values on reads,
    /// missing outputs and required form-only inputs each produce a
    /// diagnostic naming the broken rule.
    #[test]
    fn each_broken_rule_is_named() {
        let broken = broken_operations();
        let operations = [&GOOD, &GOOD].into_iter().chain(broken.iter());
        let wrong = misdescribed(&key(), operations).join("\n");

        for rule in [
            "used twice",
            "unplaced: path inputs",
            "unread: path inputs",
            "bodied: body values",
            "silent: it does not say",
            "demanding: shelf is asked only in the form",
        ] {
            assert!(wrong.contains(rule), "{rule} was not named in:\n{wrong}");
        }
    }
}
