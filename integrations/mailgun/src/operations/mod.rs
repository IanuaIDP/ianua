//! Every operation the Mailgun integration offers, grouped by topic:
//! messages, suppressions and mailing lists, each described once with the
//! SDK's [`Operation`].

mod lists;
mod messages;
mod suppressions;

use ianua_integration::rest::operation::{Field, Kind, Operation, Place};

/// The sending domain a step acts on, in the path.
pub(crate) const DOMAIN: Field = Field::required(
    "domain",
    Kind::Text,
    Place::Path,
    "The account's sending domain, such as mail.acme.test.",
);

/// Every operation, topic by topic.
pub(crate) fn all() -> impl Iterator<Item = &'static Operation> {
    messages::OPERATIONS
        .iter()
        .chain(suppressions::OPERATIONS)
        .chain(lists::OPERATIONS)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::data::{FieldName, FlowData};
    use ianua_domain::domains::workflows::integration::IntegrationKey;
    use ianua_integration::ServiceEndpoint;
    use ianua_integration::rest::checks::misdescribed;
    use ianua_integration::rest::request::call;

    use super::*;

    /// Every operation keeps the SDK's rules.
    #[test]
    fn every_operation_keeps_the_rules() {
        let wrong = misdescribed(&IntegrationKey::new("mailgun").unwrap(), all());

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

    fn list(values: &[&str]) -> FlowData {
        FlowData::list(values.iter().map(|value| text(value)).collect()).unwrap()
    }

    fn operation(key: &str) -> &'static Operation {
        all().find(|operation| operation.key == key).unwrap()
    }

    fn api() -> ServiceEndpoint {
        ServiceEndpoint::at("https://api.mailgun.net/").unwrap()
    }

    /// Sending from a template writes Mailgun's form: one `to` per
    /// recipient, one `o:tag` per tag and the template's values as JSON
    /// text.
    #[test]
    fn sending_from_a_template_writes_mailguns_form() {
        let given = arguments(vec![
            ("domain", text("mail.acme.test")),
            ("from", text("Ops <ops@mail.acme.test>")),
            ("to", list(&["ann@acme.test", "bob@acme.test"])),
            ("subject", text("Nightly build")),
            ("template", text("build-report")),
            (
                "template_values",
                arguments(vec![("result", text("failed"))]),
            ),
            ("tags", list(&["builds", "nightly"])),
        ]);

        let made = call(operation("send-message"), &api(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://api.mailgun.net/v3/mail.acme.test/messages"
        );
        assert_eq!(
            made.payload().unwrap(),
            "from=Ops+%3Cops%40mail.acme.test%3E&o%3Atag=builds&o%3Atag=nightly\
             &subject=Nightly+build&t%3Avariables=%7B%22result%22%3A%22failed%22%7D\
             &template=build-report&to=ann%40acme.test&to=bob%40acme.test"
        );
    }

    /// Adding a member writes its flags as Mailgun reads them.
    #[test]
    fn adding_a_member_writes_its_flags() {
        let given = arguments(vec![
            ("list", text("team@mail.acme.test")),
            ("address", text("ann@acme.test")),
            ("subscribed", FlowData::bool(true)),
            ("update", FlowData::bool(true)),
        ]);

        let made = call(operation("add-list-member"), &api(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://api.mailgun.net/v3/lists/team@mail.acme.test/members"
        );
        assert_eq!(
            made.payload().unwrap(),
            "address=ann%40acme.test&subscribed=true&upsert=true"
        );
    }

    /// A message without recipients and a domain named `..` each fail
    /// request construction.
    #[test]
    fn no_recipient_or_a_crooked_domain_builds_no_call() {
        let unaddressed = arguments(vec![
            ("domain", text("mail.acme.test")),
            ("from", text("ops@mail.acme.test")),
            ("subject", text("Hello")),
        ]);
        let climbing = arguments(vec![
            ("domain", text("..")),
            ("address", text("ann@acme.test")),
        ]);

        assert!(call(operation("send-message"), &api(), &unaddressed).is_err());
        assert!(call(operation("get-bounce"), &api(), &climbing).is_err());
    }
}
