//! Every operation the PagerDuty integration offers, grouped by topic:
//! incidents, and the account's directory of services, escalation
//! policies, people and who is on call, each described once with the SDK's
//! [`Operation`], with the pickers its forms fill from PagerDuty's own
//! lists.
//!
//! PagerDuty wraps what a change sends in the object it changes, such as
//! `{"incident": {...}}`, so each body input is sent under that name, and
//! a reference to another object carries its type beside its id, as
//! PagerDuty asks.

mod directory;
mod incidents;

use ianua_integration::form::{Ask, PickerText};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place};

/// The account's services, picked by id and shown by name.
pub(crate) const SERVICES: PickerText = PickerText {
    filled_by: "list-services",
    items_at: "json.services",
    value_at: "id",
    label_at: "name",
    depends_on: None,
};

/// The account's escalation policies, picked by id and shown by name.
pub(crate) const ESCALATION_POLICIES: PickerText = PickerText {
    filled_by: "list-escalation-policies",
    items_at: "json.escalation_policies",
    value_at: "id",
    label_at: "name",
    depends_on: None,
};

/// The account's people, picked by id and shown by name.
pub(crate) const USERS: PickerText = PickerText {
    filled_by: "list-users",
    items_at: "json.users",
    value_at: "id",
    label_at: "name",
    depends_on: None,
};

/// How many a listing gives at most.
pub(crate) const LIMIT: Field = Field::optional(
    "limit",
    Kind::Count,
    Place::Query,
    "How many to list, at most 100; 25 when not given.",
)
.more_options();

/// Words a listing's names must hold.
pub(crate) const SEARCH: Field = Field::optional(
    "search",
    Kind::Text,
    Place::Query,
    "Only those whose name holds these words.",
)
.sent_as("query");

/// The people a listing is narrowed to, by their PagerDuty ids, `meaning`
/// saying how.
pub(crate) const fn user_filter(meaning: &'static str) -> Field {
    Field::optional("users", Kind::RepeatedList, Place::Query, meaning)
        .sent_as("user_ids[]")
        .asked_with(Ask::Picker(USERS))
        .more_options()
}

/// Every operation, topic by topic.
pub(crate) fn all() -> impl Iterator<Item = &'static Operation> {
    incidents::OPERATIONS.iter().chain(directory::OPERATIONS)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::data::{FieldName, FlowData};
    use ianua_domain::domains::workflows::execution::step::ActionOutcome;
    use ianua_domain::domains::workflows::integration::IntegrationKey;
    use ianua_integration::ServiceEndpoint;
    use ianua_integration::rest::checks::misdescribed;
    use ianua_integration::rest::request::{Call, call};
    use serde_json::json;

    use super::*;

    /// Every operation keeps the SDK's rules: a key used once, every input
    /// explained, every path input placed, every picker filled by a read,
    /// no body on a read, something given back.
    #[test]
    fn every_operation_keeps_the_rules() {
        let wrong = misdescribed(&IntegrationKey::new("pagerduty").unwrap(), all());

        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    fn arguments(entries: Vec<(&str, FlowData)>) -> FlowData {
        FlowData::map(
            entries
                .into_iter()
                .map(|(name, value)| (FieldName::new(name).unwrap(), value))
                .collect(),
        )
        .unwrap()
    }

    fn text(value: &str) -> FlowData {
        FlowData::text(value).unwrap()
    }

    fn made(key: &str, given: Vec<(&str, FlowData)>) -> Result<Call, ActionOutcome> {
        let operation = all().find(|operation| operation.key == key).unwrap();
        let pagerduty = ServiceEndpoint::at("https://api.pagerduty.com/").unwrap();
        call(operation, &pagerduty, &arguments(given))
    }

    /// Ann's workflow opens an incident on the checkout service: the title,
    /// urgency, details and key go inside PagerDuty's incident object, the
    /// service as a typed reference.
    #[test]
    fn creating_an_incident_wraps_it_with_a_service_reference() {
        let created = made(
            "create-incident",
            vec![
                ("service", text("PWIXJZS")),
                ("title", text("Checkout is failing")),
                ("urgency", text("high")),
                ("details", text("Error rate above 5% for ten minutes.")),
                ("incident_key", text("checkout errors")),
            ],
        )
        .unwrap();

        assert_eq!(created.url.as_str(), "https://api.pagerduty.com/incidents");
        assert_eq!(
            created.body,
            Some(json!({
                "incident": {
                    "type": "incident",
                    "title": "Checkout is failing",
                    "urgency": "high",
                    "incident_key": "checkout errors",
                    "service": { "id": "PWIXJZS", "type": "service_reference" },
                    "body": {
                        "type": "incident_body",
                        "details": "Error rate above 5% for ten minutes."
                    }
                }
            }))
        );
    }

    /// Creating an incident without its service or title fails request
    /// construction.
    #[test]
    fn an_incident_without_its_service_or_title_builds_no_call() {
        let without_service = made("create-incident", vec![("title", text("Checkout down"))]);
        let without_title = made("create-incident", vec![("service", text("PWIXJZS"))]);

        for refused in [without_service, without_title] {
            assert!(matches!(refused, Err(ActionOutcome::Failed(_))));
        }
    }

    /// Acknowledging names the incident in the address and sends only its
    /// new status, as a reference to it.
    #[test]
    fn acknowledging_sends_the_new_status() {
        let acknowledged =
            made("acknowledge-incident", vec![("incident", text("Q2LKJQ1"))]).unwrap();

        assert_eq!(
            acknowledged.url.as_str(),
            "https://api.pagerduty.com/incidents/Q2LKJQ1"
        );
        assert_eq!(
            acknowledged.body,
            Some(json!({
                "incident": { "type": "incident_reference", "status": "acknowledged" }
            }))
        );
    }

    /// Resolving sends the resolved status and the resolution when given.
    #[test]
    fn resolving_sends_the_resolution() {
        let resolved = made(
            "resolve-incident",
            vec![
                ("incident", text("Q2LKJQ1")),
                ("resolution", text("Rolled back the release.")),
            ],
        )
        .unwrap();

        assert_eq!(
            resolved.body,
            Some(json!({
                "incident": {
                    "type": "incident_reference",
                    "status": "resolved",
                    "resolution": "Rolled back the release."
                }
            }))
        );
    }

    /// Resolving an incident named `..` fails request construction.
    #[test]
    fn an_incident_named_to_climb_builds_no_call() {
        let climbing = made("resolve-incident", vec![("incident", text(".."))]);

        assert!(matches!(climbing, Err(ActionOutcome::Failed(_))));
    }

    /// A note goes to the incident's notes, its text inside PagerDuty's
    /// note object.
    #[test]
    fn a_note_goes_inside_the_note_object() {
        let noted = made(
            "add-note",
            vec![
                ("incident", text("Q2LKJQ1")),
                ("content", text("Database failover started.")),
            ],
        )
        .unwrap();

        assert_eq!(
            noted.url.as_str(),
            "https://api.pagerduty.com/incidents/Q2LKJQ1/notes"
        );
        assert_eq!(
            noted.body,
            Some(json!({ "note": { "content": "Database failover started." } }))
        );
    }

    /// Snoozing sends how long, in seconds, as a number.
    #[test]
    fn snoozing_sends_its_seconds() {
        let snoozed = made(
            "snooze-incident",
            vec![
                ("incident", text("Q2LKJQ1")),
                ("duration", FlowData::number(3600.0).unwrap()),
            ],
        )
        .unwrap();

        assert_eq!(
            snoozed.url.as_str(),
            "https://api.pagerduty.com/incidents/Q2LKJQ1/snooze"
        );
        assert_eq!(snoozed.body, Some(json!({ "duration": 3600 })));
    }

    /// A text value for the snooze duration fails request construction.
    #[test]
    fn a_snooze_written_in_words_builds_no_call() {
        let snoozed = made(
            "snooze-incident",
            vec![("incident", text("Q2LKJQ1")), ("duration", text("an hour"))],
        );

        assert!(matches!(snoozed, Err(ActionOutcome::Failed(_))));
    }

    /// Listing the checkout service's open incidents puts its filters in
    /// the query under PagerDuty's names, each status named once, newest
    /// first.
    #[test]
    fn listing_incidents_puts_its_filters_in_the_query() {
        let listed = made(
            "list-incidents",
            vec![
                (
                    "statuses",
                    FlowData::list(vec![text("triggered"), text("acknowledged")]).unwrap(),
                ),
                ("services", FlowData::list(vec![text("PWIXJZS")]).unwrap()),
                ("limit", FlowData::number(10.0).unwrap()),
            ],
        )
        .unwrap();

        assert_eq!(
            listed.url.as_str(),
            "https://api.pagerduty.com/incidents?sort_by=created_at%3Adesc&statuses%5B%5D=triggered\
             &statuses%5B%5D=acknowledged&service_ids%5B%5D=PWIXJZS&limit=10"
        );
        assert_eq!(listed.body, None, "a read sends no body");
    }

    /// Reading one incident names it in the address.
    #[test]
    fn reading_an_incident_names_it() {
        let read = made("get-incident", vec![("incident", text("Q2LKJQ1"))]).unwrap();

        assert_eq!(
            read.url.as_str(),
            "https://api.pagerduty.com/incidents/Q2LKJQ1"
        );
    }

    /// Who is on call now for one escalation policy asks only for each
    /// person's earliest turn.
    #[test]
    fn on_call_is_narrowed_to_an_escalation_policy() {
        let listed = made(
            "list-on-call",
            vec![(
                "escalation_policies",
                FlowData::list(vec![text("PT20YPA")]).unwrap(),
            )],
        )
        .unwrap();

        assert_eq!(
            listed.url.as_str(),
            "https://api.pagerduty.com/oncalls?earliest=true&escalation_policy_ids%5B%5D=PT20YPA"
        );
    }

    /// Ann opens the pickers: services, escalation policies and people are
    /// listed, each narrowed by the words she types.
    #[test]
    fn pickers_list_services_policies_and_people() {
        let typed = || vec![("search", text("checkout"))];

        let services = made("list-services", typed()).unwrap();
        let policies = made("list-escalation-policies", typed()).unwrap();
        let users = made("list-users", Vec::new()).unwrap();

        assert_eq!(
            services.url.as_str(),
            "https://api.pagerduty.com/services?query=checkout"
        );
        assert_eq!(
            policies.url.as_str(),
            "https://api.pagerduty.com/escalation_policies?query=checkout"
        );
        assert_eq!(users.url.as_str(), "https://api.pagerduty.com/users");
    }
}
