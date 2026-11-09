//! Whether a change to a declared attribute would strand what people have
//! already stored under it, counted from the stored values.
//!
//! Widening is always fine. Narrowing is fine only while nothing already
//! sits outside the new declaration, and every refusal says how many people
//! it concerns, so an administrator can go and fix them.

use ianua_domain::domains::identity::attribute::AttributeDefinition;
use ianua_domain::domains::identity::attribute::definition::Requirement;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::model::restriction::Restriction;
use ianua_domain::types::Label;

use crate::error::{AppError, OrInternal};
use crate::ports::identity::{HeldValues, MetadataStore, UserFilter, UserStore};
use crate::tenancy::ScopedTenant;
use crate::use_cases::identity::attributes::Changes;

/// The stores the stored values and people are counted in.
pub(in crate::use_cases::identity) struct Holders<'a> {
    /// Counts who holds which values.
    pub(in crate::use_cases::identity) values: &'a dyn MetadataStore,
    /// Counts the tenant's users.
    pub(in crate::use_cases::identity) users: &'a dyn UserStore,
    /// The tenant counted in.
    pub(in crate::use_cases::identity) tenant: &'a ScopedTenant,
}

/// Refuses `changes` when they would leave stored values outside the new
/// declaration, or people without a value it now requires.
///
/// # Errors
///
/// - `AppError::Conflict` naming how many people the change would strand.
/// - `AppError::Internal` when the values cannot be counted.
pub(in crate::use_cases::identity) async fn ensure_nothing_stranded(
    holders: &Holders<'_>,
    definition: &AttributeDefinition<ResolvedTenant>,
    changes: &Changes,
) -> Result<(), AppError> {
    ensure_withdrawn_options_unheld(holders, definition, changes.options.as_deref()).await?;
    ensure_values_fit_max_length(holders, definition, changes).await?;
    ensure_values_above_minimum(holders, definition, changes.minimum).await?;
    ensure_values_below_maximum(holders, definition, changes.maximum).await?;
    ensure_everyone_holds_value(holders, definition, changes).await
}

/// Refuses withdrawing an option somebody has chosen.
async fn ensure_withdrawn_options_unheld(
    holders: &Holders<'_>,
    definition: &AttributeDefinition<ResolvedTenant>,
    proposed: Option<&[Label]>,
) -> Result<(), AppError> {
    let Some(proposed) = proposed else {
        return Ok(());
    };
    let withdrawn = definition.options_withdrawn_by(proposed);
    if withdrawn.is_empty() {
        return Ok(());
    }
    let stranded = count(holders, definition, HeldValues::OneOf(&withdrawn)).await?;
    if stranded == 0 {
        return Ok(());
    }
    let options = quoted(&withdrawn);
    Err(AppError::Conflict(message!(
        "identity-cannot-withdraw-options-still-in-use",
        format!(
            "Cannot withdraw options still in use: {options}. Number of people affected: {stranded}."
        )
    )))
}

/// Refuses shortening a limit past what people have already written.
async fn ensure_values_fit_max_length(
    holders: &Holders<'_>,
    definition: &AttributeDefinition<ResolvedTenant>,
    changes: &Changes,
) -> Result<(), AppError> {
    let Some(Some(proposed)) = changes.max_length.map(|limit| limit.limit().copied()) else {
        return Ok(());
    };
    let widens = definition
        .max_length()
        .limit()
        .is_some_and(|current| proposed >= *current);
    if widens {
        return Ok(());
    }
    let over = count(holders, definition, HeldValues::LongerThan(proposed)).await?;
    if over == 0 {
        return Ok(());
    }
    Err(AppError::Conflict(message!(
        "identity-cannot-shorten-the-character-limit-to",
        format!(
            "Cannot shorten the character limit to {proposed} while longer values are stored. Number of people affected: {over}."
        )
    )))
}

/// Refuses raising the lowest value past what people have already stored.
async fn ensure_values_above_minimum(
    holders: &Holders<'_>,
    definition: &AttributeDefinition<ResolvedTenant>,
    proposed: Option<Restriction<f64>>,
) -> Result<(), AppError> {
    let Some(Restriction::To(proposed)) = proposed else {
        return Ok(());
    };
    let widens = definition
        .minimum()
        .limit()
        .is_some_and(|current| proposed <= *current);
    if widens {
        return Ok(());
    }
    let under = count(holders, definition, HeldValues::Below(proposed)).await?;
    if under == 0 {
        return Ok(());
    }
    Err(AppError::Conflict(message!(
        "identity-cannot-set-the-minimum-to-while",
        format!(
            "Cannot set the minimum to {proposed} while lower values are stored. Number of people affected: {under}."
        )
    )))
}

/// Refuses lowering the highest value past what people have already
/// stored.
async fn ensure_values_below_maximum(
    holders: &Holders<'_>,
    definition: &AttributeDefinition<ResolvedTenant>,
    proposed: Option<Restriction<f64>>,
) -> Result<(), AppError> {
    let Some(Restriction::To(proposed)) = proposed else {
        return Ok(());
    };
    let widens = definition
        .maximum()
        .limit()
        .is_some_and(|current| proposed >= *current);
    if widens {
        return Ok(());
    }
    let over = count(holders, definition, HeldValues::Above(proposed)).await?;
    if over == 0 {
        return Ok(());
    }
    Err(AppError::Conflict(message!(
        "identity-cannot-set-the-maximum-to-while",
        format!(
            "Cannot set the maximum to {proposed} while higher values are stored. Number of people affected: {over}."
        )
    )))
}

/// Refuses requiring an attribute people have not filled in.
async fn ensure_everyone_holds_value(
    holders: &Holders<'_>,
    definition: &AttributeDefinition<ResolvedTenant>,
    changes: &Changes,
) -> Result<(), AppError> {
    let Some(visibility) = changes.visibility else {
        return Ok(());
    };
    if visibility.required != Requirement::Required || definition.required() {
        return Ok(());
    }
    let holding = count(holders, definition, HeldValues::Any).await?;
    let total = holders
        .users
        .count(holders.tenant, &UserFilter::all())
        .await
        .or_internal()?;
    if holding >= total {
        return Ok(());
    }
    let missing = total - holding;
    Err(AppError::Conflict(message!(
        "identity-cannot-make-this-attribute-required-while",
        format!(
            "Cannot make this attribute required while values are missing. Number of people affected: {missing}."
        )
    )))
}

/// How many users hold a value matching `held`.
async fn count(
    holders: &Holders<'_>,
    definition: &AttributeDefinition<ResolvedTenant>,
    held: HeldValues<'_>,
) -> Result<u64, AppError> {
    holders
        .values
        .count_holders(
            holders.tenant,
            definition.namespace(),
            definition.key(),
            held,
        )
        .await
        .or_internal()
}

/// The withdrawn options, quoted and joined, for a refusal message.
fn quoted(options: &[Label]) -> String {
    options
        .iter()
        .map(|option| format!("'{}'", option.as_str()))
        .collect::<Vec<_>>()
        .join(", ")
}
