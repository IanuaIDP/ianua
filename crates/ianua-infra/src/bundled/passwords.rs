//! The common passwords a new password may not be, bundled with the build.
//!
//! The list is `passwords.txt` beside this file, one password a line, each
//! at least as long as the shortest password the platform takes, since a
//! shorter one is refused before the list is asked. It is read once into a
//! set when the adapter is made, so a check is one lookup in memory: no
//! call out, nothing that can hang. Both the list and the password asked
//! about are case-folded, as `CommonPassword::among` compares, and the
//! folded password is held as a `Secret`, wiped when the check ends.
//!
//! The source is `Passwords/Common-Credentials/xato-net-10-million-passwords-100000.txt`
//! from SecLists (<https://github.com/danielmiessler/SecLists>), commit
//! `145f1f45ba7bc5fd6b3966d3a79bf95654deb20e`, file SHA-256
//! `1472aafa2561df5e3293aee252aee3ca660c12b399a283cf808bb01b39be388b`.
//! SecLists is under the MIT License, Copyright (c) 2018 Daniel Miessler.
//! It holds the 100,000 most used passwords of Mark Burnett's ten million
//! password set, most used first.
//!
//! From those, every entry between 8 and 128 characters was kept, case-folded,
//! with later duplicates dropped and the order kept: 38,451 passwords, about
//! 350 KB in the binary. The top 100,000 is where guessing lists spend their
//! first tries; a million-line list would add megabytes to every build for
//! passwords an attacker rarely reaches before the rate limits do.

use std::collections::HashSet;

use ianua_app::ports::authentication::CommonPasswordList;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::password_policy::{CommonPassword, MAX_PASSWORD_LENGTH};

/// The list as it is bundled.
const LISTED: &str = include_str!("passwords.txt");

/// The common password list bundled with the build.
pub struct BundledCommonPasswordList {
    listed: HashSet<String>,
}

impl BundledCommonPasswordList {
    /// The bundled list, case-folded, read into memory once.
    #[must_use]
    pub fn new() -> Self {
        Self {
            listed: entries(LISTED).map(str::to_lowercase).collect(),
        }
    }
}

impl Default for BundledCommonPasswordList {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for BundledCommonPasswordList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BundledCommonPasswordList")
            .field("listed", &self.listed.len())
            .finish()
    }
}

impl CommonPasswordList for BundledCommonPasswordList {
    fn verdict(&self, password: &Secret) -> CommonPassword {
        let chosen = password.expose();
        if chosen.chars().count() > usize::from(MAX_PASSWORD_LENGTH) {
            return CommonPassword::NotListed;
        }
        let folded = Secret::new(chosen.to_lowercase());
        match self.listed.contains(folded.expose()) {
            true => CommonPassword::Listed,
            false => CommonPassword::NotListed,
        }
    }
}

/// The passwords of a list file: every line that holds one.
fn entries(list: &str) -> impl Iterator<Item = &str> {
    list.lines().map(str::trim).filter(|line| !line.is_empty())
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::password_policy::MIN_PASSWORD_LENGTH;

    use super::*;

    fn verdict(password: &str) -> CommonPassword {
        BundledCommonPasswordList::new().verdict(&Secret::new(password.to_owned()))
    }

    /// Common choices such as password123 and qwertyuiop are marked as listed.
    #[test]
    fn a_listed_password_is_listed() {
        assert_eq!(verdict("password123"), CommonPassword::Listed);
        assert_eq!(verdict("qwertyuiop"), CommonPassword::Listed);
    }

    /// Mixed-case and uppercase forms of common passwords are still listed.
    #[test]
    fn a_listed_password_is_listed_in_any_case() {
        assert_eq!(verdict("PassWord123"), CommonPassword::Listed);
        assert_eq!(verdict("ILOVEYOU"), CommonPassword::Listed);
    }

    /// A password no list holds is taken.
    #[test]
    fn an_unlisted_password_is_not_listed() {
        assert_eq!(
            verdict("violet-harbour-71-quilt"),
            CommonPassword::NotListed
        );
    }

    /// A password longer than the platform takes is never listed: the
    /// length rule refuses it, and the list never lowercases it.
    #[test]
    fn a_password_past_the_longest_taken_is_not_listed() {
        let long = "password".repeat(usize::from(MAX_PASSWORD_LENGTH));

        assert_eq!(verdict(&long), CommonPassword::NotListed);
    }

    /// The bundled list contains 30,000 to 60,000 entries and fits within 512 KiB.
    #[test]
    fn the_bundled_list_loads_at_its_expected_size() {
        let list = BundledCommonPasswordList::new();

        assert!(list.listed.len() >= 30_000);
        assert!(list.listed.len() <= 60_000);
        assert!(LISTED.len() <= 512 * 1024);
    }

    /// Representative passwords from deeper in the source list remain recognized.
    #[test]
    fn passwords_from_across_the_source_list_are_listed() {
        assert_eq!(verdict("football"), CommonPassword::Listed);
        assert_eq!(verdict("princess1"), CommonPassword::Listed);
        assert_eq!(verdict("chocolate1"), CommonPassword::Listed);
        assert_eq!(verdict("hockey123"), CommonPassword::Listed);
    }

    /// A long passphrase of unrelated words is taken.
    #[test]
    fn a_strong_passphrase_is_not_listed() {
        assert_eq!(
            verdict("Cobalt otter juggles 4 quiet lanterns"),
            CommonPassword::NotListed
        );
    }

    /// Every bundled entry is a password the length rule would let through,
    /// written in lower case once, so no line of the list is dead weight.
    #[test]
    fn every_bundled_entry_could_be_chosen() {
        let lines: Vec<&str> = entries(LISTED).collect();
        let distinct: HashSet<&str> = lines.iter().copied().collect();

        assert_eq!(lines.len(), distinct.len());
        assert!(lines.iter().all(|line| {
            line.chars().count() >= usize::from(MIN_PASSWORD_LENGTH)
                && line.chars().count() <= usize::from(MAX_PASSWORD_LENGTH)
                && *line == line.to_lowercase()
        }));
    }
}
