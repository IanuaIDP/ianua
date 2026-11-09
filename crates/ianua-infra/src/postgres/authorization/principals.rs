//! How a principal and a human are kept in columns: a kind word beside an
//! id, and for a human the person behind the account too.
//!
//! Every authorization table writes a principal's kind with these words,
//! and other contexts' queries that filter by role or group read them, so
//! they are written once, here.

use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    AgentId, ConsumerId, Human, HumanAccount, OrgUserId, PersonKey, PrincipalRef, UserId,
};
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _, stored_words};

/// The kind of a principal, as its column holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrincipalKind {
    /// A tenant user.
    User,
    /// An organization member.
    OrgUser,
    /// An enrolled workload acting under delegated authority.
    Agent,
    /// A consumer outside the platform.
    Consumer,
}

stored_words! {
    PrincipalKind as "principal kind" {
        User => "user",
        OrgUser => "org_user",
        Agent => "agent",
        Consumer => "consumer",
    }
}

impl From<&PrincipalRef> for PrincipalKind {
    fn from(principal: &PrincipalRef) -> Self {
        match principal {
            PrincipalRef::User(_) => Self::User,
            PrincipalRef::OrgUser(_) => Self::OrgUser,
            PrincipalRef::Agent(_) => Self::Agent,
            PrincipalRef::Consumer(_) => Self::Consumer,
        }
    }
}

/// The word `principal`'s kind is stored as.
pub(crate) fn kind_word(principal: &PrincipalRef) -> &'static str {
    PrincipalKind::from(principal).word()
}

/// The principal a kind column and an id column of a row of `entity` hold.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the kind is unknown.
pub(crate) fn principal_from(
    entity: Stored,
    kind: &str,
    id: Uuid,
) -> Result<PrincipalRef, DomainError> {
    let principal = match entity.choice::<PrincipalKind>(kind)? {
        PrincipalKind::User => PrincipalRef::User(UserId::from_uuid(id)),
        PrincipalKind::OrgUser => PrincipalRef::OrgUser(OrgUserId::from_uuid(id)),
        PrincipalKind::Agent => PrincipalRef::Agent(AgentId::from_uuid(id)),
        PrincipalKind::Consumer => PrincipalRef::Consumer(ConsumerId::from_uuid(id)),
    };
    Ok(principal)
}

/// A human as their three columns hold them: the account's kind, the
/// account, and the person behind it.
pub(crate) struct HumanColumns<'a> {
    pub(crate) kind: &'static str,
    pub(crate) id: Uuid,
    pub(crate) person: &'a str,
}

impl<'a> HumanColumns<'a> {
    /// The columns `human` is written to.
    pub(crate) fn of(human: &'a Human) -> Self {
        let principal = human.principal();
        Self {
            kind: kind_word(&principal),
            id: principal.id(),
            person: human.person().as_str(),
        }
    }
}

/// The human three columns of a row of `entity` hold.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the kind is not one a human
/// signs in through, or the person is not an address.
pub(crate) fn human_from(
    entity: Stored,
    kind: &str,
    id: Uuid,
    person: String,
) -> Result<Human, DomainError> {
    let account = match principal_from(entity, kind, id)? {
        PrincipalRef::User(user) => HumanAccount::User(user),
        PrincipalRef::OrgUser(member) => HumanAccount::OrgUser(member),
        PrincipalRef::Agent(_) | PrincipalRef::Consumer(_) => {
            return Err(DomainError::corrupt_row(
                entity.0,
                "a human acting through no human's account",
            ));
        }
    };
    let person = entity.value("person", PersonKey::new(person))?;
    Ok(Human::new(account, person))
}

/// The human three nullable columns of a row of `entity` hold, or `None`
/// when all three are empty.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when only some are empty, or as
/// [`human_from`] does.
pub(crate) fn maybe_human_from(
    entity: Stored,
    kind: Option<String>,
    id: Option<Uuid>,
    person: Option<String>,
) -> Result<Option<Human>, DomainError> {
    match (kind, id, person) {
        (None, None, None) => Ok(None),
        (Some(kind), Some(id), Some(person)) => human_from(entity, &kind, id, person).map(Some),
        (_, _, _) => Err(DomainError::corrupt_row(entity.0, "half of a human")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROW: Stored = Stored("test row");

    /// Every kind of principal is stored as its word and reads back as the
    /// same principal.
    #[test]
    fn every_principal_reads_back_from_its_kind_and_id() {
        let principals = [
            PrincipalRef::User(UserId::new()),
            PrincipalRef::OrgUser(OrgUserId::new()),
            PrincipalRef::Agent(AgentId::new()),
            PrincipalRef::Consumer(ConsumerId::new()),
        ];

        for principal in principals {
            let read = principal_from(ROW, kind_word(&principal), principal.id()).unwrap();
            assert_eq!(read, principal);
        }
    }

    /// The words other contexts' queries filter by stay as they are.
    #[test]
    fn the_kind_words_are_the_ones_queries_name() {
        let words: Vec<&str> = [
            PrincipalKind::User,
            PrincipalKind::OrgUser,
            PrincipalKind::Agent,
            PrincipalKind::Consumer,
        ]
        .into_iter()
        .map(PrincipalKind::word)
        .collect();

        assert_eq!(words, ["user", "org_user", "agent", "consumer"]);
    }

    /// An agent account cannot be reconstructed as a human approver and
    /// is reported as corrupt storage.
    #[test]
    fn a_human_through_an_agent_is_refused() {
        let read = human_from(ROW, "agent", Uuid::nil(), "ann@acme.example".to_owned());

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// A human kind without its account and person columns is corrupt
    /// storage, rather than an absent human.
    #[test]
    fn half_a_human_is_refused() {
        let read = maybe_human_from(ROW, Some("user".to_owned()), None, None);

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
