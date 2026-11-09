//! Partial-update field intents shared by PATCH use cases.
//!
//! [`FieldUpdate`] turns the three states a JSON merge-patch field can carry
//! (absent, explicit `null`, or a value) into an explicit instruction the
//! use case matches on, instead of threading the wire shape
//! `Option<Option<T>>` through the application layer.

use ianua_domain::types::Setting;

/// Intent for a single patchable field.
#[derive(Debug, Clone)]
pub enum FieldUpdate<T> {
    /// Leave the field unchanged.
    Keep,
    /// Clear the field (set it to `None`).
    Clear,
    /// Replace the field with a new value.
    Set(T),
}

impl<T> FieldUpdate<T> {
    /// `true` when the field should be left untouched.
    #[must_use]
    pub fn is_keep(&self) -> bool {
        matches!(self, Self::Keep)
    }

    /// Calls `setter` unless the intent is [`FieldUpdate::Keep`]:
    /// [`FieldUpdate::Clear`] calls `setter(None)`, [`FieldUpdate::Set`] calls
    /// `setter(Some(value))`.
    ///
    /// Use this for setters that take the whole option when `Keep` should skip
    /// the call entirely.
    pub fn apply(&self, setter: impl FnOnce(Option<&T>)) {
        match self {
            Self::Keep => {}
            Self::Clear => setter(None),
            Self::Set(value) => setter(Some(value)),
        }
    }

    /// Resolves this intent against `current` into the value to store:
    /// unchanged for [`FieldUpdate::Keep`], `None` for [`FieldUpdate::Clear`],
    /// and the new value for [`FieldUpdate::Set`].
    ///
    /// Use this when the destination is a setter that takes the whole option
    /// (`set_email_from(name, address)`) and several fields must be resolved
    /// against their current values before a single call.
    #[must_use]
    pub fn resolve(&self, current: &Option<T>) -> Option<T>
    where
        T: Clone,
    {
        match self {
            Self::Keep => current.clone(),
            Self::Clear => None,
            Self::Set(value) => Some(value.clone()),
        }
    }

    /// The domain setting this intent asks for: none for
    /// [`FieldUpdate::Keep`], which leaves the part alone, unset for
    /// [`FieldUpdate::Clear`], and the new value for [`FieldUpdate::Set`].
    #[must_use]
    pub fn setting(&self) -> Option<Setting<T>>
    where
        T: Clone,
    {
        match self {
            Self::Keep => None,
            Self::Clear => Some(Setting::Unset),
            Self::Set(value) => Some(Setting::Set(value.clone())),
        }
    }
}
