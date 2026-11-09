//! The people who shaped a workflow version's steps.

use crate::shared::errors::DomainError;
use crate::types::Human;

/// Everyone who drafted, edited or published a workflow version, or any
/// version it was copied from. Each person is listed once, through the
/// first account they used.
///
/// None of them may give an approval a high-risk step of it needs. Mallory
/// adds a payment to her own account and an approval before it. Without
/// this, she approves the payment herself as one of the two people.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authors(Vec<Human>);

impl Authors {
    /// The authors of a version only `by` worked on so far.
    #[must_use]
    pub(crate) fn first(by: &Human) -> Self {
        Self(vec![by.clone()])
    }

    /// Reads the authors storage holds.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the list is empty.
    /// - [`DomainError::Infrastructure`] when it names one person twice.
    pub fn from_stored(people: Vec<Human>) -> Result<Self, DomainError> {
        if people.is_empty() {
            return Err(DomainError::corrupt_row("workflow", "no authors"));
        }
        let repeats = people.iter().enumerate().any(|(index, person)| {
            people
                .iter()
                .take(index)
                .any(|earlier| earlier.is_same_person_as(person))
        });
        if repeats {
            return Err(DomainError::corrupt_row(
                "workflow",
                "an author listed twice",
            ));
        }
        Ok(Self(people))
    }

    /// Adds `by`, unless they are already listed through any account.
    pub(in crate::domains::workflows) fn add(&mut self, by: &Human) {
        if !self.includes(by) {
            self.0.push(by.clone());
        }
    }

    /// Whether `person` is one of them, through any of their accounts.
    #[must_use]
    pub fn includes(&self, person: &Human) -> bool {
        self.0.iter().any(|author| author.is_same_person_as(person))
    }

    /// Every author, in the order they first worked on it.
    #[must_use]
    pub fn as_slice(&self) -> &[Human] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{HumanAccount, OrgUserId, PersonKey, UserId};

    fn person(address: &str) -> Human {
        Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new(address).unwrap(),
        )
    }

    /// Ann edits a draft through her organization account after drafting it
    /// as a tenant user. She is listed once, so each author counts once.
    #[test]
    fn an_author_is_listed_once_through_any_account() {
        let ann = person("ann@corp.test");
        let ann_elsewhere = Human::new(
            HumanAccount::OrgUser(OrgUserId::new()),
            PersonKey::new("ann@corp.test").unwrap(),
        );
        let mut authors = Authors::first(&ann);

        authors.add(&ann_elsewhere);
        authors.add(&person("bob@corp.test"));

        assert_eq!(authors.as_slice().len(), 2);
        assert!(authors.includes(&ann_elsewhere));
    }

    /// A stored list with no author, or with Ann twice, is refused as
    /// corrupt. A version always has the person who drafted it.
    #[test]
    fn a_stored_list_empty_or_with_a_repeat_is_refused() {
        let ann = person("ann@corp.test");

        assert!(matches!(
            Authors::from_stored(Vec::new()),
            Err(DomainError::Infrastructure(_))
        ));
        assert!(matches!(
            Authors::from_stored(vec![ann.clone(), ann]),
            Err(DomainError::Infrastructure(_))
        ));
    }
}
