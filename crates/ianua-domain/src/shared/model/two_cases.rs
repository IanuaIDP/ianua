//! Yes-or-no settings and facts as types that name both cases.

/// Declares a type with two named cases in place of a `bool`.
///
/// A call site reads `Readiness::Ready` instead of `true`. A check matches
/// on both cases, so `false` cannot mean whatever the writer had in mind.
/// The type is stored and sent as a plain `true`/`false`, with the first
/// case as `true`.
///
/// ```ignore
/// two_cases! {
///     /// Whether a resource is in place.
///     pub enum Readiness {
///         /// In place.
///         Ready => true,
///         /// Not yet.
///         Pending => false,
///     }
/// }
/// ```
macro_rules! two_cases {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $(#[$yes_meta:meta])*
            $yes:ident => true,
            $(#[$no_meta:meta])*
            $no:ident => false $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[cfg_attr(feature = "serde", serde(from = "bool", into = "bool"))]
        $vis enum $name {
            $(#[$yes_meta])*
            $yes,
            $(#[$no_meta])*
            $no,
        }

        impl From<bool> for $name {
            /// The case a stored or sent `true`/`false` stands for.
            fn from(flag: bool) -> Self {
                if flag {
                    return Self::$yes;
                }
                Self::$no
            }
        }

        impl From<$name> for bool {
            fn from(value: $name) -> Self {
                value == $name::$yes
            }
        }
    };
}

pub(crate) use two_cases;
