//! Which users and agents a signal stream hears about.
//!
//! The Shared Signals framework lets a stream start with every subject or
//! with none, and lets its receiver add and remove subjects after. A stream
//! that started with every subject keeps the ones removed from it; one that
//! started with none keeps the ones added to it.

use crate::domains::signals::signal::SignalSubject;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_count;

/// The most subjects one stream lists, added or removed.
const MOST_LISTED: usize = 10_000;

/// Which subjects a new stream starts with, as `default_subjects` in the
/// Shared Signals framework names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultSubjects {
    /// Every user and agent of the tenant.
    All,
    /// None, until subjects are added.
    None,
}

/// Which subjects a stream hears about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamSubjects {
    /// Every subject of the tenant except these, which were removed.
    AllExcept(Vec<SignalSubject>),
    /// Only these, which were added.
    Only(Vec<SignalSubject>),
}

/// Whether adding or removing a subject changed what a stream hears.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectChange {
    /// It did.
    Changed,
    /// The stream already heard, or already did not hear, about it.
    AlreadySo,
}

impl StreamSubjects {
    /// The subjects a new stream starts with.
    #[must_use]
    pub fn starting_with(default: DefaultSubjects) -> Self {
        match default {
            DefaultSubjects::All => Self::AllExcept(Vec::new()),
            DefaultSubjects::None => Self::Only(Vec::new()),
        }
    }

    /// Whether the stream hears about `subject`.
    #[must_use]
    pub fn covers(&self, subject: &SignalSubject) -> bool {
        match self {
            Self::AllExcept(removed) => !removed.contains(subject),
            Self::Only(added) => added.contains(subject),
        }
    }

    /// The subjects listed, removed or added as the case may be.
    #[must_use]
    pub fn listed(&self) -> &[SignalSubject] {
        match self {
            Self::AllExcept(listed) | Self::Only(listed) => listed,
        }
    }

    /// Whether the list stays within the most a stream keeps.
    pub(crate) fn within_bounds(&self) -> bool {
        self.listed().len() <= MOST_LISTED
    }

    /// Makes the stream hear about `subject`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the stream already lists the most
    ///   subjects it keeps.
    pub(crate) fn add(&mut self, subject: SignalSubject) -> Result<SubjectChange, DomainError> {
        if self.covers(&subject) {
            return Ok(SubjectChange::AlreadySo);
        }
        match self {
            Self::AllExcept(removed) => removed.retain(|listed| *listed != subject),
            Self::Only(added) => push_bounded(added, subject)?,
        }
        Ok(SubjectChange::Changed)
    }

    /// Makes the stream stop hearing about `subject`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the stream already lists the most
    ///   subjects it keeps.
    pub(crate) fn remove(&mut self, subject: SignalSubject) -> Result<SubjectChange, DomainError> {
        if !self.covers(&subject) {
            return Ok(SubjectChange::AlreadySo);
        }
        match self {
            Self::AllExcept(removed) => push_bounded(removed, subject)?,
            Self::Only(added) => added.retain(|listed| *listed != subject),
        }
        Ok(SubjectChange::Changed)
    }
}

/// Adds `subject` to `listed`, unless that passes the most a stream keeps.
///
/// # Errors
///
/// - [`DomainError::Validation`] when `listed` is already full.
fn push_bounded(
    listed: &mut Vec<SignalSubject>,
    subject: SignalSubject,
) -> Result<(), DomainError> {
    validate_count("subjects", listed.len().saturating_add(1), 0..=MOST_LISTED)?;
    listed.push(subject);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AgentId, UserId};

    /// Ann, a user of the tenant.
    fn ann() -> SignalSubject {
        SignalSubject::User(UserId::from_uuid(uuid::Uuid::from_u128(0xa)))
    }

    /// The tenant's billing agent.
    fn billing_agent() -> SignalSubject {
        SignalSubject::Agent(AgentId::from_uuid(uuid::Uuid::from_u128(0xb)))
    }

    /// A stream that starts with every subject hears about Ann and the
    /// billing agent. One that starts with none hears about neither.
    #[test]
    fn a_stream_starts_with_every_subject_or_none() {
        let all = StreamSubjects::starting_with(DefaultSubjects::All);
        let none = StreamSubjects::starting_with(DefaultSubjects::None);

        assert!(all.covers(&ann()) && all.covers(&billing_agent()));
        assert!(!none.covers(&ann()) && !none.covers(&billing_agent()));
    }

    /// A stream that starts with none has Ann added. It hears about her and
    /// still not about the billing agent. Removed again, she is no longer
    /// heard about.
    #[test]
    fn a_subject_added_and_removed_from_an_empty_stream() {
        let mut subjects = StreamSubjects::starting_with(DefaultSubjects::None);

        subjects.add(ann()).unwrap();
        let after_add = (subjects.covers(&ann()), subjects.covers(&billing_agent()));
        subjects.remove(ann()).unwrap();

        assert_eq!(after_add, (true, false));
        assert!(!subjects.covers(&ann()));
        assert!(subjects.listed().is_empty());
    }

    /// A stream that hears about everyone has the billing agent removed.
    /// It still hears about Ann, and about the agent once it is added back.
    #[test]
    fn a_subject_removed_from_a_stream_of_everyone_and_added_back() {
        let mut subjects = StreamSubjects::starting_with(DefaultSubjects::All);

        subjects.remove(billing_agent()).unwrap();
        let after_remove = (subjects.covers(&ann()), subjects.covers(&billing_agent()));
        subjects.add(billing_agent()).unwrap();

        assert_eq!(after_remove, (true, false));
        assert!(subjects.covers(&billing_agent()));
    }

    /// Ann is added twice. The second time changes nothing and lists her
    /// once.
    #[test]
    fn adding_a_subject_already_heard_changes_nothing() {
        let mut subjects = StreamSubjects::starting_with(DefaultSubjects::None);
        subjects.add(ann()).unwrap();

        let again = subjects.add(ann()).unwrap();

        assert_eq!(again, SubjectChange::AlreadySo);
        assert_eq!(subjects.listed(), &[ann()]);
    }

    /// Adding a subject to a list of ten thousand is refused, and the list
    /// remains within its bound.
    #[test]
    fn a_stream_lists_at_most_ten_thousand_subjects() {
        let full: Vec<SignalSubject> = (100_u128..)
            .take(MOST_LISTED)
            .map(|n| SignalSubject::User(UserId::from_uuid(uuid::Uuid::from_u128(n))))
            .collect();
        let mut subjects = StreamSubjects::Only(full);

        let result = subjects.add(ann());

        assert!(matches!(result, Err(DomainError::Validation(_))));
        assert!(subjects.within_bounds());
    }
}
