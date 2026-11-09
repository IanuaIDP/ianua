//! The hash that links a tenant's audit record to the one before it:
//! SHA-256 of the record before it and the record's every column.
//!
//! The record is written out as length-prefixed text, so no value, a user
//! agent with a line break in it, can shift where one part ends and the
//! next begins. Its payload is written in the order of its field names,
//! the order the `payload` column reads back in, so a record read back
//! from storage hashes as it was written. The sequence number is not part
//! of it: the link to the record before already orders the chain.

use ianua_domain::shared::events::data::{EventData, FieldValue};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

/// The form of the hashed text, written first so a later form can be told
/// apart from this one.
const FORM: &str = "ianua.audit.v1";

/// The parts of a record its hash covers, in the order they are hashed.
pub(super) struct Hashed<'a> {
    pub(super) id: Uuid,
    pub(super) tenant_id: Uuid,
    pub(super) organization_id: Option<Uuid>,
    pub(super) actor: &'a str,
    pub(super) actor_kind: &'a str,
    pub(super) actor_id: Option<Uuid>,
    pub(super) event_type: &'a str,
    pub(super) target_id: Option<&'a str>,
    pub(super) ip_address: Option<&'a str>,
    pub(super) user_agent: Option<&'a str>,
    pub(super) payload: &'a EventData,
    pub(super) acted_through: &'a str,
    pub(super) through_operator_id: Option<Uuid>,
    pub(super) through_admin_id: Option<Uuid>,
    pub(super) as_user_id: Option<Uuid>,
    pub(super) support_impersonation_id: Option<Uuid>,
    pub(super) through_execution_id: Option<Uuid>,
    pub(super) occurred_at: OffsetDateTime,
}

/// The hash of `record` linked to the record before it, whose hash is
/// `prev`.
pub(super) fn entry_hash(prev: &[u8], record: &Hashed<'_>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(prev);
    hasher.update(record.text().0);
    hasher.finalize().to_vec()
}

/// Text written one length-prefixed part after another.
#[derive(Default)]
struct Text(Vec<u8>);

impl Text {
    /// Adds `part`, or a mark that it is absent.
    fn part(&mut self, part: Option<&str>) {
        let Some(part) = part else {
            self.0.extend_from_slice(b"-\n");
            return;
        };
        self.0.extend_from_slice(part.len().to_string().as_bytes());
        self.0.push(b':');
        self.0.extend_from_slice(part.as_bytes());
        self.0.push(b'\n');
    }

    fn id(&mut self, id: Option<Uuid>) {
        self.part(id.map(|id| id.to_string()).as_deref());
    }

    fn payload(&mut self, payload: &EventData) {
        let mut fields: Vec<&(String, FieldValue)> = payload.fields().iter().collect();
        fields.sort_by(|(a, _), (b, _)| a.cmp(b));
        self.part(Some(fields.len().to_string().as_str()));
        for (key, value) in fields {
            self.part(Some(key.as_str()));
            self.value(value);
        }
    }

    fn value(&mut self, value: &FieldValue) {
        match value {
            FieldValue::Text(text) => {
                self.part(Some("text"));
                self.part(Some(text.as_str()));
            }
            FieldValue::Reference(reference) => {
                self.part(Some("reference"));
                self.part(Some(reference.kind().as_str()));
                self.part(Some(reference.id()));
                self.part(Some(reference.label()));
            }
            FieldValue::Change(change) => {
                self.part(Some("change"));
                self.part(change.from());
                self.part(change.to());
            }
        }
    }
}

impl Hashed<'_> {
    /// The record as the text its hash covers.
    fn text(&self) -> Text {
        let mut text = Text::default();
        text.part(Some(FORM));
        text.id(Some(self.id));
        text.id(Some(self.tenant_id));
        text.id(self.organization_id);
        text.part(Some(self.actor));
        text.part(Some(self.actor_kind));
        text.id(self.actor_id);
        text.part(Some(self.event_type));
        text.part(self.target_id);
        text.part(self.ip_address);
        text.part(self.user_agent);
        text.payload(self.payload);
        text.part(Some(self.acted_through));
        text.id(self.through_operator_id);
        text.id(self.through_admin_id);
        text.id(self.as_user_id);
        text.id(self.support_impersonation_id);
        if self.acted_through == "workflow_run" {
            text.id(self.through_execution_id);
        }
        text.part(Some(moment(self.occurred_at).as_str()));
        text
    }
}

/// `at` to the microsecond, the precision the column keeps.
fn moment(at: OffsetDateTime) -> String {
    format!("{}.{:06}", at.unix_timestamp(), at.microsecond())
}

#[cfg(test)]
mod tests {
    use ianua_domain::shared::events::data::{RefKind, Reference};

    use super::*;

    const ZEROS: [u8; 32] = [0; 32];

    fn payload() -> EventData {
        EventData::new()
            .field("status", "active")
            .reference("role", Reference::new(RefKind::ROLE, "r-1", "viewer"))
    }

    fn record(payload: &EventData) -> Hashed<'_> {
        Hashed {
            id: Uuid::from_u128(1),
            tenant_id: Uuid::from_u128(2),
            organization_id: None,
            actor: "system",
            actor_kind: "system",
            actor_id: None,
            event_type: "tenant.renamed",
            target_id: None,
            ip_address: Some("203.0.113.7"),
            user_agent: None,
            payload,
            acted_through: "directly",
            through_operator_id: None,
            through_admin_id: None,
            as_user_id: None,
            support_impersonation_id: None,
            through_execution_id: None,
            occurred_at: OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
        }
    }

    /// The same record after the same link hashes the same, every time, as
    /// the writer and a later verifier must agree.
    #[test]
    fn the_same_record_hashes_the_same() {
        let data = payload();

        assert_eq!(
            entry_hash(&ZEROS, &record(&data)),
            entry_hash(&ZEROS, &record(&data))
        );
        assert_eq!(entry_hash(&ZEROS, &record(&data)).len(), 32);
    }

    /// Changing the record's address, actor, time or payload changes its hash.
    #[test]
    fn any_changed_part_changes_the_hash() {
        let data = payload();
        let other = EventData::new().field("status", "suspended");
        let original = entry_hash(&ZEROS, &record(&data));
        let moved = Hashed {
            ip_address: Some("198.51.100.1"),
            ..record(&data)
        };
        let blamed = Hashed {
            actor: "operator:1",
            ..record(&data)
        };
        let later = Hashed {
            occurred_at: OffsetDateTime::from_unix_timestamp(1_800_000_001).unwrap(),
            ..record(&data)
        };

        for edited in [moved, blamed, later, record(&other)] {
            assert_ne!(entry_hash(&ZEROS, &edited), original);
        }
    }

    /// Changing the preceding link changes the record's hash.
    #[test]
    fn the_link_before_is_part_of_the_hash() {
        let data = payload();

        assert_ne!(
            entry_hash(&ZEROS, &record(&data)),
            entry_hash(&[1; 32], &record(&data))
        );
    }

    /// A payload hashes the same whatever order its fields were added in,
    /// as the column reads them back by name.
    #[test]
    fn a_payload_hashes_by_its_field_names() {
        let one = EventData::new().field("a", "1").field("b", "2");
        let other = EventData::new().field("b", "2").field("a", "1");

        assert_eq!(
            entry_hash(&ZEROS, &record(&one)),
            entry_hash(&ZEROS, &record(&other))
        );
    }

    /// A target containing a line break hashes differently from the same
    /// text split between the target and address fields.
    #[test]
    fn a_line_break_in_a_value_cannot_move_a_part() {
        let data = payload();
        let joined = Hashed {
            target_id: Some("a\n-"),
            ip_address: None,
            ..record(&data)
        };
        let split = Hashed {
            target_id: Some("a"),
            ip_address: Some("-"),
            ..record(&data)
        };

        assert_ne!(entry_hash(&ZEROS, &joined), entry_hash(&ZEROS, &split));
    }
}
