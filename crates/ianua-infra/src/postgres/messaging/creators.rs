//! Who made a topic or a schema, as three columns hold them: the kind of
//! account, its id, and for a person the person behind it.
//!
//! Topics and schemas keep their maker the same way, so the mapping is
//! written once, here, with the authorization context's words for a kind.

use ianua_domain::domains::messaging::control::CreatedBy;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ConsumerId, PrincipalRef};
use uuid::Uuid;

use crate::postgres::authorization::principals::{
    HumanColumns, PrincipalKind, human_from, kind_word,
};
use crate::postgres::foundation::stored::Stored;

/// A maker's columns, as they are written.
pub(super) struct CreatorColumns<'a> {
    pub(super) kind: &'static str,
    pub(super) id: Uuid,
    pub(super) person: Option<&'a str>,
}

impl<'a> CreatorColumns<'a> {
    /// The columns `created_by` is written to.
    pub(super) fn of(created_by: &'a CreatedBy) -> Self {
        match created_by {
            CreatedBy::Person(human) => {
                let columns = HumanColumns::of(human);
                Self {
                    kind: columns.kind,
                    id: columns.id,
                    person: Some(columns.person),
                }
            }
            CreatedBy::Consumer(consumer) => Self {
                kind: kind_word(&PrincipalRef::Consumer(*consumer)),
                id: *consumer.as_uuid(),
                person: None,
            },
        }
    }
}

/// The maker the three columns of a row of `entity` hold.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the kind is unknown or an
/// agent's, a person has no person behind the account, or a consumer has
/// one.
pub(super) fn creator_from(
    entity: Stored,
    kind: &str,
    id: Uuid,
    person: Option<String>,
) -> Result<CreatedBy, DomainError> {
    match (entity.choice::<PrincipalKind>(kind)?, person) {
        (PrincipalKind::Consumer, None) => Ok(CreatedBy::Consumer(ConsumerId::from_uuid(id))),
        (PrincipalKind::User | PrincipalKind::OrgUser, Some(person)) => {
            human_from(entity, kind, id, person).map(CreatedBy::Person)
        }
        (PrincipalKind::Agent, _)
        | (PrincipalKind::Consumer, Some(_))
        | (PrincipalKind::User | PrincipalKind::OrgUser, None) => Err(DomainError::corrupt_row(
            entity.0,
            "a maker that is neither a person nor a consumer",
        )),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::UserId;

    use super::*;
    use crate::test_support::rows::authorization::human;

    const NOTE: Stored = Stored("note");

    /// A person who made something reads back as that person, through the
    /// same account.
    #[test]
    fn a_person_reads_back_as_the_same_person() {
        let ann = CreatedBy::Person(human(UserId::new(), "ann@acme.example"));
        let columns = CreatorColumns::of(&ann);

        let read = creator_from(
            NOTE,
            columns.kind,
            columns.id,
            columns.person.map(str::to_owned),
        )
        .unwrap();

        assert_eq!(read, ann);
    }

    /// A consumer that made something reads back as that consumer, with no
    /// person.
    #[test]
    fn a_consumer_reads_back_as_the_same_consumer() {
        let billing = CreatedBy::Consumer(ConsumerId::new());
        let columns = CreatorColumns::of(&billing);

        let read = creator_from(NOTE, columns.kind, columns.id, None).unwrap();

        assert_eq!(columns.person, None);
        assert_eq!(read, billing);
    }

    /// An agent recorded as a topic or schema creator is rejected as
    /// corrupt storage.
    #[test]
    fn an_agent_as_maker_is_refused() {
        let read = creator_from(NOTE, "agent", Uuid::nil(), None);

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
