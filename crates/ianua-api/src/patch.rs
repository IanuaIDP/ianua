//! Tri-state PATCH field parsing for the HTTP boundary.
//!
//! JSON merge-patch encodes an optional, clearable field as
//! `Option<Option<String>>`: absent (keep), `null` (clear), or a value (set).
//! [`patch_field`] folds that wire shape into a domain [`FieldUpdate`],
//! validating only the value case, so handlers stay clear of the
//! `Option<Option<_>>` juggling.

use ianua_app::input::FieldUpdate;
use ianua_domain::shared::errors::DomainError;

use crate::error::ApiError;

/// Parses a JSON merge-patch field into a [`FieldUpdate`].
///
/// Maps the three wire states: field absent, explicit `null`, or a value :
/// to `Keep`, `Clear`, and `Set`, validating only the value case through
/// `parse`.
///
/// # Errors
///
/// Returns [`ApiError`] as a validation error when the value case fails to
/// parse through `parse`.
pub(crate) fn patch_field<T, E: Into<DomainError>>(
    field: Option<Option<String>>,
    parse: impl Fn(&str) -> Result<T, E>,
) -> Result<FieldUpdate<T>, ApiError> {
    Ok(match field {
        None => FieldUpdate::Keep,
        Some(None) => FieldUpdate::Clear,
        Some(Some(raw)) => FieldUpdate::Set(parse(&raw).map_err(ApiError::validation)?),
    })
}

/// Preserves absent, null and a typed value as distinct PATCH operations.
#[must_use]
pub(crate) fn value_field<T>(field: Option<Option<T>>) -> FieldUpdate<T> {
    match field {
        None => FieldUpdate::Keep,
        Some(None) => FieldUpdate::Clear,
        Some(Some(value)) => FieldUpdate::Set(value),
    }
}

/// Serde helper for `Option<Option<T>>` request fields that distinguishes
/// absent (no change), explicit `null` (clear), and a value (set).
///
/// Serde's built-in `Option` handling swallows `null` before calling
/// `deserialize_with`, so a bare function cannot tell absent from null. This
/// module uses `#[serde(with)]` semantics and a custom `Visitor` to observe
/// all three cases. Pair with `#[serde(default, deserialize_with =
/// "crate::input::nullable::deserialize")]` on the field.
pub(crate) mod nullable {
    use std::fmt;
    use std::marker::PhantomData;

    use serde::de::{self, Deserializer, Visitor};

    /// Reads `null` as `Some(None)` and a value as `Some(Some(value))`, so
    /// an absent field, left to its default, is the only `None`.
    ///
    /// # Errors
    ///
    /// The deserializer's error when the value does not read as a `T`.
    pub(crate) fn deserialize<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
    where
        D: Deserializer<'de>,
        T: de::Deserialize<'de>,
    {
        struct NullableVisitor<T>(PhantomData<T>);

        impl<'de, T: de::Deserialize<'de>> Visitor<'de> for NullableVisitor<T> {
            type Value = Option<Option<T>>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("null or a value")
            }

            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(Some(None))
            }

            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(Some(None))
            }

            fn visit_some<D2: Deserializer<'de>>(self, d: D2) -> Result<Self::Value, D2::Error> {
                T::deserialize(d).map(|v| Some(Some(v)))
            }
        }

        deserializer.deserialize_option(NullableVisitor(PhantomData))
    }
}
