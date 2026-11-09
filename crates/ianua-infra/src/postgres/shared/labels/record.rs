//! The names the audit trail reads back for the records it points at, each
//! made into the label it records through the label's own constructor, so
//! a stored name is made safe the way a recorded one is.

use ianua_domain::types::EventLabel;
use uuid::Uuid;

/// A record known by one name: a role, an agent, a client, a title.
pub(super) struct NamedRecord {
    pub(super) id: Uuid,
    pub(super) name: String,
}

impl NamedRecord {
    /// The record's id and the label its name makes.
    pub(super) fn into_label(self) -> (Uuid, EventLabel) {
        (self.id, EventLabel::of(&self.name))
    }
}

/// A record that may have been given a name, such as a delegation.
pub(super) struct MaybeNamedRecord {
    pub(super) id: Uuid,
    pub(super) name: Option<String>,
}

impl MaybeNamedRecord {
    /// The record's id and the label its name makes, or `None` when it has
    /// no name, so the caller names it by its id.
    pub(super) fn into_label(self) -> Option<(Uuid, EventLabel)> {
        let name = self.name?;
        Some((self.id, EventLabel::of(&name)))
    }
}

/// A person: a tenant's user or an organization's member, named by their
/// name with their address in brackets, as the domain names them.
pub(super) struct PersonRecord {
    pub(super) id: Uuid,
    pub(super) display_name: String,
    pub(super) email: String,
}

impl PersonRecord {
    /// The person's id and the label their name and address make.
    pub(super) fn into_label(self) -> (Uuid, EventLabel) {
        let label = EventLabel::of(&format!("{} ({})", self.display_name, self.email));
        (self.id, label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A person reads as their name with their address in brackets, as an
    /// event raised by the domain names them.
    #[test]
    fn a_person_reads_as_name_and_address() {
        let id = Uuid::now_v7();
        let record = PersonRecord {
            id,
            display_name: "Ann".to_owned(),
            email: "ann@acme.example".to_owned(),
        };

        assert_eq!(
            record.into_label(),
            (id, EventLabel::of("Ann (ann@acme.example)"))
        );
    }

    /// Converting a stored name into an event label removes its newline.
    #[test]
    fn a_stored_name_is_made_safe() {
        let record = NamedRecord {
            id: Uuid::now_v7(),
            name: "eve\nadmin signed in".to_owned(),
        };

        let (_, label) = record.into_label();

        assert!(!label.as_str().contains('\n'));
    }

    /// A record never given a name has no label, so the caller names it by
    /// its id.
    #[test]
    fn an_unnamed_record_has_no_label() {
        let record = MaybeNamedRecord {
            id: Uuid::now_v7(),
            name: None,
        };

        assert_eq!(record.into_label(), None);
    }
}
