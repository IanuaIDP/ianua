//! Every operation the Google Calendar integration offers, grouped by
//! topic: calendars and events, each described once with the SDK's
//! [`Operation`].

mod calendars;
mod events;

use ianua_integration::form::{Ask, PickerText};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place};

/// The calendar a step acts on, in the path.
pub(crate) const CALENDAR: Field = Field::required(
    "calendar",
    Kind::Text,
    Place::Path,
    "The calendar's id: primary for the account's own, or an address such as team@group.calendar.google.com.",
)
.asked_with(Ask::Picker(PickerText {
    filled_by: "list-calendars",
    items_at: "json.items",
    value_at: "id",
    label_at: "summary",
    depends_on: None,
}))
.example("primary");

/// Every operation, topic by topic.
pub(crate) fn all() -> impl Iterator<Item = &'static Operation> {
    calendars::OPERATIONS.iter().chain(events::OPERATIONS)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::data::{FieldName, FlowData};
    use ianua_domain::domains::workflows::integration::IntegrationKey;
    use ianua_integration::ServiceEndpoint;
    use ianua_integration::rest::checks::misdescribed;
    use ianua_integration::rest::request::call;
    use serde_json::json;

    use super::*;

    /// Every operation keeps the SDK's rules.
    #[test]
    fn every_operation_keeps_the_rules() {
        let wrong = misdescribed(&IntegrationKey::new("google-calendar").unwrap(), all());

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

    fn operation(key: &str) -> &'static Operation {
        all().find(|operation| operation.key == key).unwrap()
    }

    fn api() -> ServiceEndpoint {
        ServiceEndpoint::at("https://www.googleapis.com/calendar/v3/").unwrap()
    }

    /// Creating an event nests its times where Google reads them, hands the
    /// people invited on, and asks Google to mail them when told to.
    #[test]
    fn creating_an_event_nests_its_times() {
        let given = arguments(vec![
            ("calendar", text("primary")),
            ("summary", text("Incident review")),
            ("start", text("2026-11-03T09:00:00+01:00")),
            ("end", text("2026-11-03T09:30:00+01:00")),
            (
                "attendees",
                FlowData::list(vec![arguments(vec![("email", text("ann@acme.test"))])]).unwrap(),
            ),
            ("notify", text("all")),
        ]);

        let made = call(operation("create-event"), &api(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://www.googleapis.com/calendar/v3/calendars/primary/events?sendUpdates=all"
        );
        assert_eq!(
            made.body,
            Some(json!({
                "summary": "Incident review",
                "start": { "dateTime": "2026-11-03T09:00:00+01:00" },
                "end": { "dateTime": "2026-11-03T09:30:00+01:00" },
                "attendees": [{ "email": "ann@acme.test" }]
            }))
        );
    }

    /// Listing events asks for each repeat on its own, soonest first, so
    /// the list can be read in order.
    #[test]
    fn listing_events_asks_for_them_in_order() {
        let given = arguments(vec![
            ("calendar", text("team@group.calendar.google.com")),
            ("from", text("2026-11-02T00:00:00Z")),
        ]);

        let made = call(operation("list-events"), &api(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://www.googleapis.com/calendar/v3/calendars/team@group.calendar.google.com/events\
             ?singleEvents=true&orderBy=startTime&timeMin=2026-11-02T00%3A00%3A00Z"
        );
    }

    /// An event without a start and a calendar ID of `..` each fail
    /// request construction.
    #[test]
    fn no_start_or_a_crooked_calendar_builds_no_call() {
        let untimed = arguments(vec![
            ("calendar", text("primary")),
            ("summary", text("Review")),
            ("end", text("2026-11-03T09:30:00+01:00")),
        ]);
        let climbing = arguments(vec![("calendar", text("..")), ("event", text("e1"))]);

        assert!(call(operation("create-event"), &api(), &untimed).is_err());
        assert!(call(operation("get-event"), &api(), &climbing).is_err());
    }
}
