//! Who set something in motion, as three columns keep them: the kind of
//! party and its id, as every principal is kept, and for a human the
//! person behind the account. A run's starter and the requester of an
//! approval are kept this way.

use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Initiator, PrincipalRef};
use uuid::Uuid;

use crate::postgres::authorization::principals::{human_from, kind_word, principal_from};
use crate::postgres::foundation::stored::Stored;

/// An initiator's columns, as they are written.
pub(crate) struct InitiatorColumns<'a> {
    pub(crate) kind: &'static str,
    pub(crate) id: Uuid,
    pub(crate) person: Option<&'a str>,
}

impl<'a> InitiatorColumns<'a> {
    /// The columns `initiator` is written to: the person only for a human.
    pub(crate) fn of(initiator: &'a Initiator) -> Self {
        let principal = initiator.principal();
        Self {
            kind: kind_word(&principal),
            id: principal.id(),
            person: initiator.human().map(|human| human.person().as_str()),
        }
    }
}

/// The initiator three columns of a row of `entity` hold.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the kind is unknown, a human
/// has no person behind the account, a machine has one, or the person is
/// not an address.
pub(crate) fn initiator_from(
    entity: Stored,
    kind: &str,
    id: Uuid,
    person: Option<String>,
) -> Result<Initiator, DomainError> {
    let Some(person) = person else {
        return machine_from(entity, kind, id);
    };
    human_from(entity, kind, id, person).map(Initiator::Human)
}

/// The agent or consumer a kind and an id with no person hold.
fn machine_from(entity: Stored, kind: &str, id: Uuid) -> Result<Initiator, DomainError> {
    match principal_from(entity, kind, id)? {
        PrincipalRef::Agent(agent) => Ok(Initiator::Agent(agent)),
        PrincipalRef::Consumer(consumer) => Ok(Initiator::Consumer(consumer)),
        PrincipalRef::User(_) | PrincipalRef::OrgUser(_) => Err(DomainError::corrupt_row(
            entity.0,
            "a human with no person behind the account",
        )),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::{AgentId, Human, HumanAccount, PersonKey, UserId};

    use super::*;

    const ROW: Stored = Stored("agent run");

    fn read_back(initiator: &Initiator) -> Result<Initiator, DomainError> {
        let columns = InitiatorColumns::of(initiator);
        let person = columns.person.map(str::to_owned);
        initiator_from(ROW, columns.kind, columns.id, person)
    }

    /// A human starter and an agent starter each read back from their
    /// columns as they were written.
    #[test]
    fn an_initiator_reads_back_from_its_columns() {
        let ann = Initiator::Human(Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new("ann@acme.example").unwrap(),
        ));
        let bot = Initiator::Agent(AgentId::new());

        assert_eq!(read_back(&ann).unwrap(), ann);
        assert_eq!(read_back(&bot).unwrap(), bot);
    }

    /// A stored human initiator without a person is rejected as corrupt.
    #[test]
    fn a_human_without_a_person_is_refused() {
        let read = initiator_from(ROW, "user", Uuid::from_u128(7), None);

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
