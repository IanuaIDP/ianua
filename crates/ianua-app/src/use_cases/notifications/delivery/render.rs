//! What a notification about an event says, written from the event itself.
//!
//! An event payload is already written for a person to read: plain values,
//! references with the label they had when the event happened, and changes
//! from one value to another. So a notification's title and body come from
//! it, not from a text kept per event type. Payloads never carry secrets
//! ([`EventData`] refuses them), so the text is safe to show as it is.
//!
//! The title says what happened (`"Tenant activated"`). The body says who
//! did it and to what (`"Randi Weimann activated the tenant \"Acme
//! Corp\"."`). Someone scanning a list reads titles; someone who opens one
//! reads the body.

use ianua_domain::domains::notifications::notification::{
    AboutResource, CreateNotificationParams, Notification, title_label,
};
use ianua_domain::domains::notifications::reach::ToldAs;
use ianua_domain::domains::notifications::severity::NotificationSeverity;
use ianua_domain::shared::events::data::{EventData, FieldValue};
use ianua_domain::shared::validation::ValidationError;
use ianua_domain::types::{AuditRecordId, EventType, Label, NotificationId, Text};
use uuid::Uuid;

use crate::use_cases::notifications::delivery::notice::Occurrences;

/// Who did what an event records, and in which tenant, as a notification
/// names them.
#[derive(Debug, Clone, Copy, Default)]
pub(in crate::use_cases::notifications) struct Credit<'a> {
    /// The name of whoever acted, if the audience knows them.
    pub(in crate::use_cases::notifications) actor: Option<&'a str>,
    /// The tenant it happened in, for a notification read outside it.
    pub(in crate::use_cases::notifications) tenant: Option<&'a str>,
}

/// What every notification about one event says, whoever receives it.
#[derive(Debug, Clone)]
pub(in crate::use_cases::notifications) struct NotificationText {
    record: AuditRecordId,
    event_type: EventType,
    title: Label,
    body: Option<Text>,
    resource: AboutResource,
}

impl NotificationText {
    /// The text for the event recorded as `record`, of `event_type` and
    /// carrying `payload`, crediting what `credit` names.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] when the title written from the event's name
    ///   is not a valid title.
    pub(in crate::use_cases::notifications) fn of(
        record: AuditRecordId,
        event_type: EventType,
        payload: &EventData,
        credit: Credit<'_>,
    ) -> Result<Self, ValidationError> {
        Ok(Self {
            record,
            event_type,
            title: title_label(title_for_event(&event_type, payload))?,
            body: body_for_event(&event_type, payload, credit),
            resource: resource_for_event(payload)
                .map_or(AboutResource::Nothing, AboutResource::Resource),
        })
    }

    /// The text, saying after its body how often an alert's event happened
    /// since the last alert of its kind, when that was counted.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] when the longer body is not a valid body.
    pub(in crate::use_cases::notifications) fn counting(
        mut self,
        occurrences: Occurrences,
    ) -> Result<Self, ValidationError> {
        let Some(note) = occurrence_note(occurrences) else {
            return Ok(self);
        };
        let body = match &self.body {
            Some(body) => format!("{} {note}", body.as_str()),
            None => note,
        };
        self.body = Some(Text::new("body", truncate_chars(body, 500))?);
        Ok(self)
    }

    /// A new unread notification saying this to `recipient`, told as
    /// `told_as`. It is the same notification every time the same event is
    /// told to the same recipient.
    pub(in crate::use_cases::notifications) fn notification(
        &self,
        recipient: &Uuid,
        told_as: ToldAs,
    ) -> Notification {
        self.made(NotificationId::delivered(&self.record, recipient), told_as)
    }

    /// The one notification saying this on a shared dashboard feed and to
    /// the organization's destinations, told as to whoever oversees it.
    pub(in crate::use_cases::notifications) fn shared(&self) -> Notification {
        self.made(
            NotificationId::delivered(&self.record, self.record.as_uuid()),
            ToldAs::Overseer,
        )
    }

    fn made(&self, id: NotificationId, told_as: ToldAs) -> Notification {
        Notification::create(CreateNotificationParams {
            id,
            event_type: self.event_type,
            severity: NotificationSeverity::from_event_type(&self.event_type),
            title: self.title.clone(),
            body: self.body.clone(),
            resource_id: self.resource,
            told_as,
        })
    }
}

/// The sentence saying how often an alert's event happened since the last
/// alert, or `None` when that was not counted.
fn occurrence_note(occurrences: Occurrences) -> Option<String> {
    match occurrences {
        Occurrences::NotCounted => None,
        Occurrences::SinceLastAlert(1) => Some("It happened again.".to_owned()),
        Occurrences::SinceLastAlert(count) => {
            Some(format!("It happened {count} times since the last alert."))
        }
    }
}

/// Words rendered in upper case rather than title case.
const ACRONYMS: &[&str] = &[
    "scim", "sso", "mfa", "otp", "oidc", "saml", "jwt", "jwks", "api", "dns", "tls", "ip", "url",
    "id", "nats", "jit", "siem",
];

/// A title that says what happened, not which field moved: `"Tenant
/// Activated"`, not `"Status Changed"`. It is then sentence-cased
/// (`"Tenant activated"`), so it reads as a headline, not a shout.
///
/// The event name is prefixed with its context unless the name already
/// leads with it (`agents.agent_created` reads `"Agent Created"`), and a
/// trailing `"Status Changed"` becomes the outcome from the payload's
/// `status` change (`"Tenant Suspended"`). It never names the subject or the
/// actor. They belong in the body, so a title stays short.
fn title_for_event(event_type: &EventType, payload: &EventData) -> String {
    sentence_case(&event_words(event_type, payload))
}

/// The sentence a reader wants when they open a notification: who did what,
/// to what, as in `"Randi Weimann activated the tenant \"Acme Corp\"."`.
/// The credit's tenant names the tenant a management-plane notification is
/// about, added only when the subject is not already that tenant.
///
/// `None` when there is nothing to say, with no actor and no named subject:
/// the title's verb alone would add nothing.
fn body_for_event(event_type: &EventType, payload: &EventData, credit: Credit<'_>) -> Option<Text> {
    let actor = credit.actor.filter(|a| !a.is_empty());
    let words = event_words(event_type, payload);
    let verb = words.last()?.to_lowercase();
    let subject = subject_for(&words, payload);
    if actor.is_none() && subject.is_none() {
        return None;
    }
    let subject_label = subject.as_ref().map(|(_, label)| label.as_str());
    let scope = credit
        .tenant
        .filter(|tenant| !tenant.is_empty() && subject_label != Some(*tenant));

    let mut sentence = match actor {
        Some(actor) => format!("{actor} {verb}"),
        None => capitalize(&verb),
    };
    if let Some((kind, label)) = &subject {
        sentence.push_str(&format!(" the {kind} \"{label}\""));
    }
    if let Some(scope) = scope {
        sentence.push_str(&format!(" in \"{scope}\""));
    }
    sentence.push('.');

    Text::new("body", truncate_chars(sentence, 500)).ok()
}

/// The event name's words with a trailing `"Status Changed"` replaced by its
/// outcome, shared by the title (which stops here) and the body (which also
/// needs the verb and the subject reference).
fn event_words(event_type: &EventType, payload: &EventData) -> Vec<String> {
    let mut words = event_type_words(event_type);
    replace_status_changed_with_outcome(&mut words, payload);
    words
}

/// Lowercases every word except the first and any acronym/mixed-case word
/// (`"SCIM"`, `"OAuth"`), so a title reads as a sentence rather than a
/// stack of title-cased words.
fn sentence_case(words: &[String]) -> String {
    words
        .iter()
        .enumerate()
        .map(|(i, w)| {
            if i == 0 || is_kept_as_is(w) {
                w.clone()
            } else {
                w.to_lowercase()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether `word` is an acronym or otherwise-special casing (`"SCIM"`,
/// `"OAuth"`) that sentence-casing must not flatten to lowercase.
fn is_kept_as_is(word: &str) -> bool {
    word == "OAuth" || (word.chars().count() > 1 && !word.chars().any(char::is_lowercase))
}

fn capitalize(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

fn event_type_words(event_type: &EventType) -> Vec<String> {
    let raw = event_type.as_str();
    let (domain, rest) = raw.split_once('.').unwrap_or(("", raw));
    let rest_leads_with_domain = leading_word(rest)
        .is_some_and(|first| domain.starts_with(first) || first.starts_with(domain));

    let mut words: Vec<String> = Vec::new();
    if !domain.is_empty() && !rest_leads_with_domain {
        words.extend(domain.split('_').map(title_word));
    }
    words.extend(rest.split('_').map(title_word));
    words
}

/// Turns a trailing `"Status Changed"` into the outcome itself, when the
/// payload's `status` change names one that reads as a verb.
fn replace_status_changed_with_outcome(words: &mut Vec<String>, payload: &EventData) {
    if words.len() < 2 || words[words.len() - 2..] != ["Status", "Changed"] {
        return;
    }
    let Some(FieldValue::Change(change)) = payload.value("status") else {
        return;
    };
    let Some(outcome) = change.to().and_then(status_outcome) else {
        return;
    };
    words.truncate(words.len() - 2);
    words.push(outcome);
}

/// The past-tense reading of a status, when it has one: `"suspended"` reads
/// `"Suspended"`, `"active"` reads `"Activated"`. `None` keeps `"Status
/// Changed"`.
fn status_outcome(status: &str) -> Option<String> {
    let status = status.to_ascii_lowercase();
    match status.as_str() {
        "active" => Some("Activated".to_owned()),
        "inactive" => Some("Deactivated".to_owned()),
        s if s.ends_with("ed") || s.ends_with("ing") => Some(title_word(s)),
        _ => None,
    }
}

/// The payload's subject: the first reference whose kind is one of the
/// title's own words. So another reference the payload carries, such as an
/// unrelated user, is not taken for what the sentence is about (`"activated
/// the tenant \"Acme Corp\""`).
///
/// Returns the kind as a plain noun with the label. A bare label leaves the
/// reader to guess what was acted on: `"Aliona Dzhulai created \"wedfwe\""`
/// does not say what `wedfwe` is. So the sentence names it: `"created the
/// tenant \"wedfwe\""`.
fn subject_for(words: &[String], payload: &EventData) -> Option<(String, String)> {
    payload.fields().iter().find_map(|(_, value)| {
        let FieldValue::Reference(r) = value else {
            return None;
        };
        if r.label().is_empty() {
            return None;
        }
        let kind_words: Vec<String> = r.kind().as_str().split('_').map(title_word).collect();
        words
            .windows(kind_words.len().max(1))
            .any(|window| window == kind_words.as_slice())
            .then(|| (kind_noun(r.kind().as_str()), r.label().to_owned()))
    })
}

/// A reference kind as it reads mid-sentence: `"org_user"` reads `"org
/// user"`, `"model_provider"` reads `"model provider"`.
fn kind_noun(kind: &str) -> String {
    kind.split('_')
        .map(|w| {
            if ACRONYMS.contains(&w) {
                w.to_uppercase()
            } else {
                w.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The first entity reference in the payload, as the notification's linkable
/// resource.
fn resource_for_event(payload: &EventData) -> Option<Uuid> {
    payload.fields().iter().find_map(|(_, value)| {
        let FieldValue::Reference(r) = value else {
            return None;
        };
        Uuid::parse_str(r.id()).ok()
    })
}

fn leading_word(name: &str) -> Option<&str> {
    name.split('_').next().filter(|w| !w.is_empty())
}

fn title_word(word: &str) -> String {
    if word == "oauth" {
        return "OAuth".to_owned();
    }
    if ACRONYMS.contains(&word) {
        return word.to_uppercase();
    }
    let mut chars = word.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    let mut cased: String = first.to_uppercase().collect();
    cased.push_str(chars.as_str());
    cased
}

fn truncate_chars(s: String, max: usize) -> String {
    if s.chars().count() <= max {
        return s;
    }
    let mut truncated: String = s.chars().take(max - 1).collect();
    truncated.push('…');
    truncated
}

#[cfg(test)]
mod tests {
    use ianua_domain::shared::events::data::{RefKind, Reference};
    use ianua_domain::types::event_type::{
        AgentsEvent, AuthenticationEvent, FederationEvent, IdentityEvent, TenantEvent,
    };

    use super::*;

    fn credit<'a>(actor: Option<&'a str>, tenant: Option<&'a str>) -> Credit<'a> {
        Credit { actor, tenant }
    }

    /// A tenant's status changed. "Status changed" alone says nothing about
    /// what, so the title names the tenant first.
    #[test]
    fn title_names_the_domain_when_the_event_alone_is_ambiguous() {
        let et = EventType::Tenant(TenantEvent::StatusChanged);
        assert_eq!(
            title_for_event(&et, &EventData::new()),
            "Tenant status changed"
        );
    }

    /// A user registered. The title names the context once, before the event's
    /// own words.
    #[test]
    fn title_does_not_repeat_a_domain_the_event_already_leads_with() {
        let et = EventType::Identity(IdentityEvent::UserRegistered);
        assert_eq!(
            title_for_event(&et, &EventData::new()),
            "Identity user registered"
        );
        let et = EventType::Authentication(AuthenticationEvent::LoginSucceeded);
        assert_eq!(
            title_for_event(&et, &EventData::new()),
            "Authentication login succeeded"
        );
    }

    /// SCIM was switched on. The acronym reads in capitals, not as "Scim".
    #[test]
    fn title_uppercases_acronyms() {
        let et = EventType::Federation(FederationEvent::ScimEnabled);
        assert_eq!(
            title_for_event(&et, &EventData::new()),
            "Federation SCIM enabled"
        );
    }

    /// Acme was suspended. The title says "suspended", not "status changed".
    #[test]
    fn title_names_the_outcome_of_a_status_change() {
        let et = EventType::Tenant(TenantEvent::StatusChanged);
        let payload = EventData::new().change("status", "active", "suspended");
        assert_eq!(title_for_event(&et, &payload), "Tenant suspended");
    }

    /// Acme became active again. The title reads "activated", the word a reader
    /// expects.
    #[test]
    fn title_verbifies_adjective_statuses() {
        let et = EventType::Tenant(TenantEvent::StatusChanged);
        let payload = EventData::new().change("status", "suspended", "active");
        assert_eq!(title_for_event(&et, &payload), "Tenant activated");
    }

    /// A status with no past tense, such as "limbo", keeps "status changed"
    /// rather than a made-up word.
    #[test]
    fn title_keeps_status_changed_for_an_unverbifiable_status() {
        let et = EventType::Tenant(TenantEvent::StatusChanged);
        let payload = EventData::new().change("status", "active", "limbo");
        assert_eq!(title_for_event(&et, &payload), "Tenant status changed");
    }

    /// `agents.agent_created` names its subject in the event itself, so the
    /// title must not open with the context's name as well. "Agents agent
    /// created" is what a reader sees when the near-match between the two is
    /// missed.
    #[test]
    fn title_does_not_repeat_a_domain_the_event_merely_shortens() {
        let et = EventType::Agents(AgentsEvent::AgentCreated);

        assert_eq!(title_for_event(&et, &EventData::new()), "Agent created");
    }

    /// The outcome replaces exactly the trailing "Status Changed", however
    /// many words come before it. Dropping one word too many, or too few,
    /// renames the thing the notification is about.
    #[test]
    fn title_replaces_only_the_trailing_status_changed_in_a_longer_title() {
        let et = EventType::Agents(AgentsEvent::ModelProviderStatusChanged);
        let payload = EventData::new().change("status", "active", "suspended");

        assert_eq!(
            title_for_event(&et, &payload),
            "Agents model provider suspended"
        );
    }

    /// An inactive status reads as a deactivation, not as a bare status
    /// change: the word a reader scanning their notifications recognises.
    #[test]
    fn title_reads_an_inactive_status_as_a_deactivation() {
        let et = EventType::Tenant(TenantEvent::StatusChanged);
        let payload = EventData::new().change("status", "active", "inactive");

        assert_eq!(title_for_event(&et, &payload), "Tenant deactivated");
    }

    /// The title never names the subject or the actor. They belong in the
    /// body, so a reference in the payload does not change it.
    #[test]
    fn title_never_names_the_subject() {
        let et = EventType::Tenant(TenantEvent::StatusChanged);
        let payload = EventData::new()
            .reference(
                "tenant",
                Reference::new(RefKind::TENANT, Uuid::nil().to_string(), "acme-prod"),
            )
            .change("status", "active", "suspended");
        assert_eq!(title_for_event(&et, &payload), "Tenant suspended");
    }

    /// Randi suspended Acme. The body says who did it and to which tenant.
    #[test]
    fn body_names_the_actor_and_the_subject() {
        let et = EventType::Tenant(TenantEvent::StatusChanged);
        let payload = EventData::new()
            .reference(
                "tenant",
                Reference::new(RefKind::TENANT, Uuid::nil().to_string(), "Acme Corp"),
            )
            .change("status", "active", "suspended");

        let body = body_for_event(&et, &payload, credit(Some("Randi Weimann"), None)).unwrap();

        assert_eq!(
            body.as_str(),
            "Randi Weimann suspended the tenant \"Acme Corp\"."
        );
    }

    /// A tenant event also carries a user. The user is not taken for the tenant
    /// the sentence is about.
    #[test]
    fn body_skips_a_subject_of_a_different_kind() {
        let et = EventType::Tenant(TenantEvent::StatusChanged);
        let payload = EventData::new()
            .reference(
                "user",
                Reference::new(RefKind::USER, Uuid::nil().to_string(), "ada"),
            )
            .change("status", "active", "suspended");

        let body = body_for_event(&et, &payload, credit(Some("Randi Weimann"), None)).unwrap();

        assert_eq!(body.as_str(), "Randi Weimann suspended.");
    }

    /// A role was created. The role is the subject, though its kind is the
    /// event's last word but one.
    #[test]
    fn body_names_the_subject_after_any_word_matching_its_kind() {
        let et = EventType::Authorization(
            ianua_domain::types::event_type::AuthorizationEvent::RoleCreated,
        );
        let payload = EventData::new().reference(
            "role",
            Reference::new(RefKind::ROLE, Uuid::nil().to_string(), "Admin"),
        );

        let body = body_for_event(&et, &payload, credit(Some("Randi Weimann"), None)).unwrap();

        assert_eq!(body.as_str(), "Randi Weimann created the role \"Admin\".");
    }

    /// Nobody known acted. The sentence starts with the verb, capitalised.
    #[test]
    fn body_capitalizes_the_verb_when_the_actor_is_unknown() {
        let et = EventType::Tenant(TenantEvent::StatusChanged);
        let payload = EventData::new()
            .reference(
                "tenant",
                Reference::new(RefKind::TENANT, Uuid::nil().to_string(), "Acme Corp"),
            )
            .change("status", "active", "suspended");

        let body = body_for_event(&et, &payload, credit(None, None)).unwrap();

        assert_eq!(body.as_str(), "Suspended the tenant \"Acme Corp\".");
    }

    /// With no actor and no subject there is nothing to add to the title, so
    /// there is no body.
    #[test]
    fn body_is_none_without_an_actor_or_a_subject() {
        let et = EventType::Tenant(TenantEvent::StatusChanged);
        assert!(body_for_event(&et, &EventData::new(), credit(None, None)).is_none());
    }

    /// Randi signed in. The payload names no subject, so the body names only
    /// her.
    #[test]
    fn body_carries_the_actor_alone_when_the_payload_names_no_subject() {
        let et = EventType::Authentication(AuthenticationEvent::LoginSucceeded);
        let body =
            body_for_event(&et, &EventData::new(), credit(Some("Randi Weimann"), None)).unwrap();
        assert_eq!(body.as_str(), "Randi Weimann succeeded.");
    }

    /// A bare label leaves the reader to infer what was acted on. The body
    /// names the kind, so "wedfwe" is visibly a tenant and not a role, a group
    /// or a route.
    #[test]
    fn body_names_what_kind_of_thing_the_subject_is() {
        let et = EventType::Tenant(TenantEvent::Provisioned);
        let payload = EventData::new().reference(
            "tenant",
            Reference::new(RefKind::TENANT, Uuid::nil().to_string(), "wedfwe"),
        );

        let body = body_for_event(&et, &payload, credit(Some("Aliona Dzhulai"), None)).unwrap();

        assert_eq!(
            body.as_str(),
            "Aliona Dzhulai provisioned the tenant \"wedfwe\"."
        );
    }

    /// Before the event carried a tenant reference there was no subject to
    /// name, so the sentence fell through to the scope clause and read as
    /// though something had happened *inside* the new tenant:
    /// "Aliona Dzhulai provisioned in \"wedfwe\"".
    #[test]
    fn a_provisioned_tenant_is_the_subject_not_the_scope() {
        let et = EventType::Tenant(TenantEvent::Provisioned);
        let payload = EventData::new().reference(
            "tenant",
            Reference::new(RefKind::TENANT, Uuid::nil().to_string(), "wedfwe"),
        );

        let body = body_for_event(
            &et,
            &payload,
            credit(Some("Aliona Dzhulai"), Some("wedfwe")),
        )
        .unwrap();

        assert!(!body.as_str().contains(" in "), "{}", body.as_str());
    }

    /// Names the event's subject while recording the same suspension outcome.
    fn suspension_of(kind: RefKind, field: &str, name: &str) -> EventData {
        EventData::new()
            .reference(field, Reference::new(kind, Uuid::nil().to_string(), name))
            .change("status", "active", "suspended")
    }

    /// A management-plane notification about a tenant event names the
    /// tenant, but only when the subject itself is not already that tenant.
    /// Naming it twice would read as `"activated \"Acme Corp\" in \"Acme
    /// Corp\""`.
    #[test]
    fn body_names_the_scope_only_when_it_differs_from_the_subject() {
        let et = EventType::Tenant(TenantEvent::StatusChanged);
        let payload = suspension_of(RefKind::USER, "user", "Bob Smith");

        let with_different_scope = body_for_event(
            &et,
            &payload,
            credit(Some("Randi Weimann"), Some("Acme Corp")),
        )
        .unwrap();
        assert_eq!(
            with_different_scope.as_str(),
            "Randi Weimann suspended in \"Acme Corp\"."
        );

        let tenant_payload = suspension_of(RefKind::TENANT, "tenant", "Acme Corp");
        let matching_scope = body_for_event(
            &et,
            &tenant_payload,
            credit(Some("Randi Weimann"), Some("Acme Corp")),
        )
        .unwrap();
        assert_eq!(
            matching_scope.as_str(),
            "Randi Weimann suspended the tenant \"Acme Corp\"."
        );
    }

    /// A 600-character tenant name would overflow the body. It is cut to the
    /// limit and ends with an ellipsis.
    #[test]
    fn body_is_truncated_to_the_text_limit() {
        let et = EventType::Tenant(TenantEvent::StatusChanged);
        let payload = EventData::new().reference(
            "tenant",
            Reference::new(RefKind::TENANT, Uuid::nil().to_string(), "x".repeat(600)),
        );
        let body = body_for_event(&et, &payload, credit(Some("Randi Weimann"), None)).unwrap();
        assert_eq!(body.as_str().chars().count(), 500);
        assert!(body.as_str().ends_with('…'));
    }

    /// The notification links to the first record the payload names by id.
    #[test]
    fn resource_is_the_first_uuid_reference() {
        let id = Uuid::now_v7();
        let payload = EventData::new()
            .field("status", "active")
            .reference(
                "tenant",
                Reference::new(RefKind::TENANT, id.to_string(), "acme"),
            )
            .reference(
                "user",
                Reference::new(RefKind::USER, Uuid::now_v7().to_string(), "ada"),
            );
        assert_eq!(resource_for_event(&payload), Some(id));
    }

    /// A payload naming no record by id links to nothing.
    #[test]
    fn resource_is_none_without_a_uuid_reference() {
        let payload = EventData::new()
            .field("status", "active")
            .reference("route", Reference::new(RefKind::ROUTE, "not-a-uuid", "r"));
        assert_eq!(resource_for_event(&payload), None);
    }
}
