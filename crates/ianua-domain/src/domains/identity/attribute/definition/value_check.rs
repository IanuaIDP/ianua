//! Checking a value against the attribute it is stored under.

use crate::domains::identity::attribute::definition::{
    AttributeDefinition, MAX_LENGTH_LIMIT, MAX_OPTIONS, MAX_VALUE_BYTES,
};
use crate::domains::identity::metadata_value::MetadataValue;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::model::restriction::Restriction;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;

/// Checks `value` against `def`, as [`AttributeDefinition::validate`]
/// describes.
pub(super) fn check<T: TenantScope>(
    def: &AttributeDefinition<T>,
    value: &MetadataValue,
) -> Result<(), DomainError> {
    reject_if_archived(def)?;
    check_list_size(def, value)?;
    check_total_size(def, value)?;

    if !def.value_type().accepts(value) {
        return Err(invalid(
            def,
            &format!("must be {}", def.value_type().describe()),
        ));
    }

    check_finite(def, value)?;
    def.kind()
        .check_format(value)
        .map_err(|e| invalid(def, &strip_prefix(&e)))?;

    check_length(def, value)?;
    check_list_repeats(def, value)?;
    check_range(def, value)?;
    check_against_options(def, value)
}

/// Refuses a list value with more than `MAX_OPTIONS` items, before any
/// item is read.
fn check_list_size<T: TenantScope>(
    def: &AttributeDefinition<T>,
    value: &MetadataValue,
) -> Result<(), DomainError> {
    let MetadataValue::StringArray(items) = value else {
        return Ok(());
    };
    validate_count("value", items.len(), 0..=MAX_OPTIONS)
        .map_err(|_| invalid(def, &format!("may hold at most {MAX_OPTIONS} items")))?;
    Ok(())
}

/// Refuses a value larger than `MAX_VALUE_BYTES` in all.
fn check_total_size<T: TenantScope>(
    def: &AttributeDefinition<T>,
    value: &MetadataValue,
) -> Result<(), DomainError> {
    let bytes = match value {
        MetadataValue::String(text) => text.len(),
        MetadataValue::StringArray(items) => items.iter().map(String::len).sum(),
        MetadataValue::Integer(_)
        | MetadataValue::Number(_)
        | MetadataValue::Bool(_)
        | MetadataValue::Null => 0,
    };
    if bytes > MAX_VALUE_BYTES {
        return Err(invalid(
            def,
            &format!("may hold at most {MAX_VALUE_BYTES} bytes"),
        ));
    }
    Ok(())
}

/// Refuses a number that is not finite.
///
/// Not a number compares false with every bound, so it would pass any
/// range. Infinity has no place in a salary or a percentage either.
fn check_finite<T: TenantScope>(
    def: &AttributeDefinition<T>,
    value: &MetadataValue,
) -> Result<(), DomainError> {
    let MetadataValue::Number(number) = value else {
        return Ok(());
    };
    if !number.is_finite() {
        return Err(invalid(def, "must be a finite number"));
    }
    Ok(())
}

/// Refuses any value for an archived attribute.
fn reject_if_archived<T: TenantScope>(def: &AttributeDefinition<T>) -> Result<(), DomainError> {
    if def.archived() {
        return Err(invalid(def, "is no longer in use"));
    }
    Ok(())
}

/// Refuses text longer than the declared maximum, counted in characters.
///
/// Counting characters, not bytes, means an accented name is as long as it
/// looks. An attribute that declares no limit is still held to
/// `MAX_LENGTH_LIMIT`. A value is stored and sent with every token, so
/// "no limit" cannot mean any size.
fn check_length<T: TenantScope>(
    def: &AttributeDefinition<T>,
    value: &MetadataValue,
) -> Result<(), DomainError> {
    let max = def
        .max_length()
        .limit()
        .copied()
        .unwrap_or(MAX_LENGTH_LIMIT);

    let max = usize::try_from(max).unwrap_or(usize::MAX);
    let too_long = |text: &str| text.chars().count() > max;

    let over = match value {
        MetadataValue::String(text) => too_long(text),
        MetadataValue::StringArray(items) => items.iter().any(|item| too_long(item)),
        MetadataValue::Integer(_)
        | MetadataValue::Number(_)
        | MetadataValue::Bool(_)
        | MetadataValue::Null => false,
    };

    if over {
        return Err(invalid(def, &format!("must be at most {max} characters")));
    }

    Ok(())
}

/// Refuses a list value naming one item twice, whatever the attribute's
/// kind.
fn check_list_repeats<T: TenantScope>(
    def: &AttributeDefinition<T>,
    value: &MetadataValue,
) -> Result<(), DomainError> {
    let MetadataValue::StringArray(items) = value else {
        return Ok(());
    };
    if first_repeat(items.iter().map(String::as_str)).is_some() {
        return Err(invalid(def, "may not list the same item twice"));
    }
    Ok(())
}

/// Refuses a number below the declared lowest or above the declared
/// highest.
fn check_range<T: TenantScope>(
    def: &AttributeDefinition<T>,
    value: &MetadataValue,
) -> Result<(), DomainError> {
    let Some(number) = value.as_f64() else {
        return Ok(());
    };

    if let Restriction::To(min) = def.minimum()
        && number < min
    {
        return Err(invalid(def, &format!("must be at least {min}")));
    }

    if let Restriction::To(max) = def.maximum()
        && number > max
    {
        return Err(invalid(def, &format!("must be at most {max}")));
    }

    Ok(())
}

/// Refuses a chosen value this attribute does not offer.
///
/// The refusal names the attribute, not the value. The value is whatever
/// the caller sent, up to kilobytes of it. Put in the error, it would end up
/// in every log that records the error.
fn check_against_options<T: TenantScope>(
    def: &AttributeDefinition<T>,
    value: &MetadataValue,
) -> Result<(), DomainError> {
    if def.options().is_empty() {
        return Ok(());
    }

    let offered = |candidate: &str| def.options().iter().any(|o| o.as_str() == candidate);

    let all_offered = match value {
        MetadataValue::String(text) => offered(text),
        MetadataValue::StringArray(items) => items.iter().all(|item| offered(item)),
        MetadataValue::Integer(_)
        | MetadataValue::Number(_)
        | MetadataValue::Bool(_)
        | MetadataValue::Null => true,
    };

    if !all_offered {
        return Err(invalid(def, "does not offer that value"));
    }
    Ok(())
}

/// A validation error naming this attribute.
fn invalid<T: TenantScope>(def: &AttributeDefinition<T>, what: &str) -> DomainError {
    DomainError::invalid(message!(
        "identity-message",
        format!("'{}' {what}", def.key().as_str())
    ))
}

/// Rewords a format error so the attribute's name can lead it.
fn strip_prefix(error: &DomainError) -> String {
    let message = error.to_string();
    let bare = message
        .strip_prefix("validation failed: ")
        .unwrap_or(&message);

    bare.strip_prefix("value ").unwrap_or(bare).to_owned()
}
