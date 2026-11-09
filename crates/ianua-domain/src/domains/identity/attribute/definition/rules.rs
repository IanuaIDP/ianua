//! The rules an attribute declaration keeps, whatever changes it.

use crate::domains::identity::attribute::control::AttributeControl;
use crate::domains::identity::attribute::definition::{
    AttributeVisibility, MAX_LENGTH_LIMIT, MAX_OPTIONS, Sorting,
};
use crate::domains::identity::attribute::kind::AttributeKind;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::model::restriction::Restriction;
use crate::shared::validation::numeric::{validate_count, validate_range};
use crate::types::Label;

/// Refuses a control the kind does not list.
pub(super) fn check_control(
    kind: AttributeKind,
    control: AttributeControl,
) -> Result<(), DomainError> {
    if kind.permits_control(control) {
        return Ok(());
    }

    Err(DomainError::invalid(message!(
        "identity-a-attribute-cannot-be-shown-as",
        format!(
            "a {kind:?} attribute cannot be shown as {}",
            control.as_str()
        )
    )))
}

/// Refuses options on a kind that takes typed values. For a choice kind it
/// refuses an empty list, more than `MAX_OPTIONS` options, or one offered
/// twice.
pub(super) fn check_options(kind: AttributeKind, options: &[Label]) -> Result<(), DomainError> {
    if !kind.requires_options() && options.is_empty() {
        return Ok(());
    }
    if !kind.requires_options() {
        return Err(DomainError::invalid(message!(
            "identity-a-attribute-takes-typed-values-not",
            format!("a {kind:?} attribute takes typed values, not a list of options")
        )));
    }

    validate_count("options", options.len(), 1..=MAX_OPTIONS)?;

    let mut seen: Vec<&str> = options.iter().map(Label::as_str).collect();
    let total = seen.len();
    seen.sort_unstable();
    seen.dedup();

    if seen.len() != total {
        return Err(DomainError::invalid(message!(
            "identity-the-same-option-is-offered-twice",
            "the same option is offered twice"
        )));
    }

    Ok(())
}

/// Refuses a length limit on a kind that allows none, or one outside 1 to
/// `MAX_LENGTH_LIMIT`.
pub(super) fn check_max_length(
    kind: AttributeKind,
    max_length: Restriction<u32>,
) -> Result<(), DomainError> {
    let Restriction::To(max) = max_length else {
        return Ok(());
    };

    if !kind.permits_length_limit() {
        return Err(DomainError::invalid(message!(
            "identity-a-attribute-has-no-text-to",
            format!("a {kind:?} attribute has no text to limit the length of")
        )));
    }

    validate_range("max_length", max, 1..=MAX_LENGTH_LIMIT)?;
    Ok(())
}

/// Refuses bounds on a kind that allows none, a bound that is not finite, or
/// a lowest value above the highest.
pub(super) fn check_bounds(
    kind: AttributeKind,
    minimum: Restriction<f64>,
    maximum: Restriction<f64>,
) -> Result<(), DomainError> {
    if !minimum.is_restricted() && !maximum.is_restricted() {
        return Ok(());
    }

    if !kind.permits_bounds() {
        return Err(DomainError::invalid(message!(
            "identity-a-attribute-has-no-range-to",
            format!("a {kind:?} attribute has no range to constrain")
        )));
    }

    for bound in [minimum, maximum].iter().filter_map(Restriction::limit) {
        if !bound.is_finite() {
            return Err(DomainError::invalid(message!(
                "identity-a-bound-must-be-a-finite",
                "a bound must be a finite number"
            )));
        }
    }

    if let (Restriction::To(min), Restriction::To(max)) = (minimum, maximum)
        && min > max
    {
        return Err(DomainError::invalid(message!(
            "identity-the-lowest-value-is-above-the",
            format!("the lowest value {min} is above the highest {max}")
        )));
    }

    Ok(())
}

/// Refuses sorting on a kind whose values cannot be sorted.
pub(super) fn check_sortable(
    kind: AttributeKind,
    visibility: AttributeVisibility,
) -> Result<(), DomainError> {
    if visibility.sortable == Sorting::Sortable && !kind.is_orderable() {
        return Err(DomainError::invalid(message!(
            "identity-a-attribute-holds-a-list-which",
            format!("a {kind:?} attribute holds a list, which has no order to sort by")
        )));
    }

    Ok(())
}
