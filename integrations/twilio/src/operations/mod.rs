//! Every operation the Twilio integration offers, grouped by topic:
//! messages, and calls with the account's numbers, each described once
//! with the SDK's [`Operation`]. Every path sits under the account's own
//! place in Twilio's API, which the account's SID names.

mod calls;
mod messages;

use ianua_integration::rest::operation::{Field, Kind, Operation, Place};

/// How many entries a listing gives at most, in the query.
pub(crate) const MOST: Field = Field::optional(
    "most",
    Kind::Count,
    Place::Query,
    "How many to give at most, up to 1,000; Twilio's default is 50.",
)
.sent_as("PageSize");

/// Every operation, topic by topic.
pub(crate) fn all() -> impl Iterator<Item = &'static Operation> {
    messages::OPERATIONS.iter().chain(calls::OPERATIONS)
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
        let wrong = misdescribed(&IntegrationKey::new("twilio").unwrap(), all());

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

    fn account() -> ServiceEndpoint {
        ServiceEndpoint::at("https://api.twilio.com/2010-04-01/Accounts/AC1").unwrap()
    }

    /// Sending a picture message writes Twilio's form, one `MediaUrl` per
    /// picture, to the account's messages.
    #[test]
    fn sending_a_message_writes_twilios_form() {
        let given = arguments(vec![
            ("to", text("+15551234567")),
            ("from", text("+15557654321")),
            ("body", text("The build failed")),
            (
                "media",
                FlowData::list(vec![
                    text("https://ci.acme.test/a.png"),
                    text("https://ci.acme.test/b.png"),
                ])
                .unwrap(),
            ),
        ]);

        let made = call(operation("send-message"), &account(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://api.twilio.com/2010-04-01/Accounts/AC1/Messages.json"
        );
        assert_eq!(
            made.payload().unwrap(),
            "Body=The+build+failed&From=%2B15557654321\
             &MediaUrl=https%3A%2F%2Fci.acme.test%2Fa.png\
             &MediaUrl=https%3A%2F%2Fci.acme.test%2Fb.png&To=%2B15551234567"
        );
    }

    /// Template values go as the JSON text Twilio reads them as.
    #[test]
    fn template_values_go_as_json_text() {
        let given = arguments(vec![
            ("to", text("+15551234567")),
            ("template", text("HX1")),
            ("template_values", arguments(vec![("1", text("Ann"))])),
        ]);

        let made = call(operation("send-message"), &account(), &given).unwrap();

        assert_eq!(
            made.body,
            Some(json!({
                "To": "+15551234567",
                "ContentSid": "HX1",
                "ContentVariables": { "1": "Ann" }
            }))
        );
        assert!(
            made.payload()
                .unwrap()
                .contains("ContentVariables=%7B%221%22%3A%22Ann%22%7D")
        );
    }

    /// A phone call does whatever its TwiML says, recording or forwarding
    /// included, so it may be high risk and a workflow holds it for an
    /// approval; a text says only what it is given.
    #[test]
    fn a_phone_call_waits_for_an_approval_and_a_text_does_not() {
        assert!(operation("start-call").effect.may_be_high_risk());
        assert!(!operation("send-message").effect.may_be_high_risk());
    }

    /// Cancelling a scheduled message posts its new status to the message,
    /// named with Twilio's `.json`.
    #[test]
    fn cancelling_a_message_posts_its_status() {
        let given = arguments(vec![("message", text("SM1"))]);

        let made = call(operation("cancel-message"), &account(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://api.twilio.com/2010-04-01/Accounts/AC1/Messages/SM1.json"
        );
        assert_eq!(made.payload().unwrap(), "Status=canceled");
    }

    /// A message without a destination number fails request construction.
    /// Slashes in a message SID are escaped within the account's message path.
    #[test]
    fn no_number_builds_no_call_and_a_crooked_sid_stays_in_place() {
        let unaddressed = arguments(vec![("body", text("Hello"))]);
        let climbing = arguments(vec![("message", text("../../AC2/Messages/SM9"))]);

        assert!(call(operation("send-message"), &account(), &unaddressed).is_err());
        let made = call(operation("get-message"), &account(), &climbing).unwrap();
        assert_eq!(
            made.url.as_str(),
            "https://api.twilio.com/2010-04-01/Accounts/AC1/Messages/..%2F..%2FAC2%2FMessages%2FSM9.json"
        );
    }
}
