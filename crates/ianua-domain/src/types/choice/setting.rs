//! A configuration value that is off until someone sets it.

/// A configuration value that is off until someone sets it.
///
/// Examples are a header to send, a filter to apply and a schema to check
/// against. It is not an `Option`, so a reader names what "unset" does
/// instead of letting a missing value fall through `unwrap_or`. It is
/// stored and sent as the value itself, or `null` when unset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Setting<T> {
    /// Nobody set it. The feature it configures is off.
    #[default]
    Unset,
    /// An explicit value enabling or configuring the feature.
    Set(T),
}

impl<T> Setting<T> {
    /// The setting a stored value records. No value means unset.
    #[must_use]
    pub fn from_stored(value: Option<T>) -> Self {
        value.map_or(Self::Unset, Self::Set)
    }

    /// The value, when set. Storage and the wire keep it in this form.
    #[must_use]
    pub fn value(&self) -> Option<&T> {
        match self {
            Self::Unset => None,
            Self::Set(value) => Some(value),
        }
    }

    /// Whether nobody set it.
    #[must_use]
    pub fn is_unset(&self) -> bool {
        matches!(self, Self::Unset)
    }
}

#[cfg(feature = "serde")]
impl<T: serde::Serialize> serde::Serialize for Setting<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.value().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for Setting<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Option::<T>::deserialize(deserializer).map(Self::from_stored)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No stored value reads as unset, a stored 4 reads back as 4, and a
    /// fresh setting starts unset.
    #[test]
    fn unset_reads_back_as_unset() {
        assert_eq!(Setting::<u8>::from_stored(None), Setting::Unset);
        assert_eq!(Setting::from_stored(Some(4)).value(), Some(&4));
        assert!(Setting::<u8>::default().is_unset());
    }

    /// A set value of 3 is written to JSON as `3` and an unset one as
    /// `null`. Reading `null` back gives unset.
    #[cfg(feature = "serde")]
    #[test]
    fn it_is_written_as_the_value_or_null() {
        assert_eq!(serde_json::to_string(&Setting::Set(3)).unwrap(), "3");
        assert_eq!(
            serde_json::to_string(&Setting::<u8>::Unset).unwrap(),
            "null"
        );
        assert_eq!(
            serde_json::from_str::<Setting<u8>>("null").unwrap(),
            Setting::Unset
        );
    }
}
