//! The recovery codes a person was shown once, when their second factor
//! was set up, kept as they would keep the printout: each code is crossed
//! out once used.

use std::fmt;

/// The recovery codes a setup showed, the used ones crossed out. `Debug`
/// shows how many are left, never a code.
#[derive(Clone)]
pub struct RecoveryCodes {
    codes: Vec<String>,
    used: usize,
}

impl fmt::Debug for RecoveryCodes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryCodes")
            .field("left", &self.left())
            .finish_non_exhaustive()
    }
}

impl RecoveryCodes {
    /// The codes as a setup showed them, in order.
    ///
    /// # Panics
    ///
    /// When there are none, which no setup shows.
    #[must_use]
    pub fn printed(codes: Vec<String>) -> Self {
        assert!(!codes.is_empty(), "the setup showed no recovery codes");
        Self { codes, used: 0 }
    }

    /// The next code not crossed out, crossing it out.
    ///
    /// # Panics
    ///
    /// When every code is used.
    pub fn take(&mut self) -> String {
        let Some(code) = self.codes.get(self.used) else {
            panic!(
                "every one of the {} recovery codes is used",
                self.codes.len()
            );
        };
        self.used += 1;
        code.clone()
    }

    /// A code already crossed out, as someone who kept a used one would
    /// type it again.
    ///
    /// # Panics
    ///
    /// When none is used yet.
    #[must_use]
    pub fn used_one(&self) -> String {
        let Some(last) = self.used.checked_sub(1) else {
            panic!("no recovery code is used yet");
        };
        self.codes[last].clone()
    }

    /// How many are not crossed out.
    #[must_use]
    pub fn left(&self) -> usize {
        self.codes.len() - self.used
    }

    /// Every code, used or not, to make sure none appears where it should
    /// not.
    #[must_use]
    pub fn all(&self) -> &[String] {
        &self.codes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn printout() -> RecoveryCodes {
        RecoveryCodes::printed(vec!["alpha one".to_owned(), "bravo two".to_owned()])
    }

    /// Codes are handed out in order, each once.
    #[test]
    fn codes_are_handed_out_in_order_each_once() {
        let mut codes = printout();

        assert_eq!(codes.take(), "alpha one");
        assert_eq!(codes.used_one(), "alpha one");
        assert_eq!(codes.take(), "bravo two");
        assert_eq!(codes.left(), 0);
    }

    /// Asking for a code when every one is used fails, naming how many
    /// there were.
    #[test]
    #[should_panic(expected = "every one of the 2 recovery codes is used")]
    fn a_used_up_printout_gives_no_more_codes() {
        let mut codes = printout();
        codes.take();
        codes.take();

        codes.take();
    }
}
