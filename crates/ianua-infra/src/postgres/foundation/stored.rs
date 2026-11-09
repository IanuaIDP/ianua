//! Reading stored values back into the domain.
//!
//! A choice, such as a plan or a status, is stored as a word. Each choice
//! has one table of its words, written with [`stored_words!`], which gives
//! both directions, so writing and reading can never disagree. A word the
//! table does not know, or a value that no longer passes its own rules,
//! refuses the row as corrupt: it is the store's fault, never the caller's.

use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::validation::ValidationError;

/// A domain choice stored as one word.
pub(crate) trait StoredWord: Sized + Copy {
    /// The refusal for a row holding a word this choice does not know.
    const UNKNOWN: &'static str;

    /// The word `self` is stored as.
    fn word(self) -> &'static str;

    /// The choice `word` stands for, if any.
    fn from_word(word: &str) -> Option<Self>;
}

/// The words a domain choice is stored as, one per case:
///
/// ```ignore
/// stored_words! {
///     OrganizationPlan as "plan" {
///         Free => "free",
///         Starter => "starter",
///     }
/// }
/// ```
macro_rules! stored_words {
    ($choice:ty as $what:literal { $($case:ident => $word:literal),+ $(,)? }) => {
        impl $crate::postgres::foundation::stored::StoredWord for $choice {
            const UNKNOWN: &'static str = concat!("an unknown ", $what);

            fn word(self) -> &'static str {
                match self {
                    $(Self::$case => $word,)+
                }
            }

            fn from_word(word: &str) -> Option<Self> {
                match word {
                    $($word => Some(Self::$case),)+
                    _ => None,
                }
            }
        }
    };
}

pub(crate) use stored_words;

/// What one stored row is, so a refusal names it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Stored(pub(crate) &'static str);

impl Stored {
    /// The choice `word` stands for.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the word is unknown.
    pub(crate) fn choice<T: StoredWord>(self, word: &str) -> Result<T, DomainError> {
        T::from_word(word).ok_or_else(|| DomainError::corrupt_row(self.0, T::UNKNOWN))
    }

    /// A value read back through its own rules.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure`, naming `what` and keeping the
    /// broken rule, when the value no longer passes them.
    pub(crate) fn value<T>(
        self,
        what: &'static str,
        read: Result<T, ValidationError>,
    ) -> Result<T, DomainError> {
        read.map_err(|rule| DomainError::corrupt_value(self.0, what, rule))
    }
}
