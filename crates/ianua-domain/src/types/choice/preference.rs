//! Something's own value, or that it follows a default set elsewhere.

/// Something's own value, or that it follows a default set elsewhere.
///
/// Examples are a person's locale over the tenant's, a tenant's email
/// subject over the platform's, and an attribute's control over its kind's.
/// It is not an `Option`, so a reader names what "no choice" means instead
/// of reading a missing value as "none at all". It is stored and sent as
/// the value itself, or `null` when inherited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Preference<T> {
    /// No value of its own. The default applies.
    #[default]
    Inherited,
    /// Its own value.
    Own(T),
}

impl<T> Preference<T> {
    /// The preference a stored value records. No value means inherited.
    #[must_use]
    pub fn from_stored(value: Option<T>) -> Self {
        value.map_or(Self::Inherited, Self::Own)
    }

    /// Its own value, when it has one. Storage and the wire keep it in this
    /// form.
    #[must_use]
    pub fn value(&self) -> Option<&T> {
        match self {
            Self::Inherited => None,
            Self::Own(value) => Some(value),
        }
    }

    /// What applies: its own value, or `default` when it follows that.
    #[must_use]
    pub fn or_inherit<'a>(&'a self, default: &'a T) -> &'a T {
        match self {
            Self::Inherited => default,
            Self::Own(value) => value,
        }
    }
}

#[cfg(feature = "serde")]
impl<T: serde::Serialize> serde::Serialize for Preference<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.value().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for Preference<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Option::<T>::deserialize(deserializer).map(Self::from_stored)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With a default of 7, an inherited preference gives 7 and an own value
    /// of 3 gives 3. No stored value reads as inherited.
    #[test]
    fn an_inherited_preference_takes_the_default() {
        assert_eq!(*Preference::<u8>::Inherited.or_inherit(&7), 7);
        assert_eq!(*Preference::Own(3).or_inherit(&7), 3);
        assert_eq!(Preference::<u8>::from_stored(None), Preference::Inherited);
        assert_eq!(Preference::from_stored(Some(3)).value(), Some(&3));
    }

    /// An own value of 3 is written to JSON as `3`, and an inherited one as
    /// `null`.
    #[cfg(feature = "serde")]
    #[test]
    fn it_is_written_as_the_value_or_null() {
        assert_eq!(serde_json::to_string(&Preference::Own(3)).unwrap(), "3");
        assert_eq!(
            serde_json::to_string(&Preference::<u8>::Inherited).unwrap(),
            "null"
        );
    }
}
