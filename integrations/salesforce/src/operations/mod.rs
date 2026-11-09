//! Every operation the Salesforce integration offers, grouped by topic:
//! records of any kind of object, and the records a workflow adds most
//! often, each described once with the SDK's [`Operation`] under the
//! account's own domain's REST API.

mod records;
mod sales;

use ianua_integration::rest::operation::Operation;

/// Every operation, topic by topic.
pub(crate) fn all() -> impl Iterator<Item = &'static Operation> {
    records::OPERATIONS.iter().chain(sales::OPERATIONS)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::data::{FieldName, FlowData};
    use ianua_domain::domains::workflows::integration::IntegrationKey;
    use ianua_domain::types::{ActionClass, DeclaredAction};
    use ianua_integration::ServiceEndpoint;
    use ianua_integration::answer::flow_of;
    use ianua_integration::rest::checks::misdescribed;
    use ianua_integration::rest::request::call;
    use serde_json::json;

    use super::*;

    /// Every operation keeps the SDK's rules.
    #[test]
    fn every_operation_keeps_the_rules() {
        let wrong = misdescribed(&IntegrationKey::new("salesforce").unwrap(), all());

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
        ServiceEndpoint::at("https://acme.my.salesforce.com/services/data/v62.0/").unwrap()
    }

    /// A SOQL query goes in the query under Salesforce's name.
    #[test]
    fn a_query_goes_in_the_query() {
        let given = arguments(vec![("soql", text("SELECT Id FROM Account"))]);

        let made = call(operation("query"), &api(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://acme.my.salesforce.com/services/data/v62.0/query?q=SELECT+Id+FROM+Account"
        );
    }

    /// Changing an account lays its fields over the body itself, as
    /// Salesforce takes them.
    #[test]
    fn changing_a_record_sends_its_fields_as_the_body() {
        let given = arguments(vec![
            ("object", text("Account")),
            ("record", text("001A")),
            ("fields", flow_of(&json!({ "Industry": "Retail" })).unwrap()),
        ]);

        let made = call(operation("update-record"), &api(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://acme.my.salesforce.com/services/data/v62.0/sobjects/Account/001A"
        );
        assert_eq!(made.body, Some(json!({ "Industry": "Retail" })));
    }

    /// Adding a lead sends its inputs under Salesforce's field names.
    #[test]
    fn a_lead_is_sent_under_salesforces_names() {
        let given = arguments(vec![
            ("last_name", text("Lovelace")),
            ("company", text("Acme")),
            ("email", text("ada@acme.test")),
        ]);

        let made = call(operation("create-lead"), &api(), &given).unwrap();

        assert_eq!(
            made.body,
            Some(json!({ "LastName": "Lovelace", "Company": "Acme", "Email": "ada@acme.test" }))
        );
    }

    /// Only an administrator may restore a deleted record, so deleting is
    /// high risk.
    #[test]
    fn deleting_a_record_is_a_removal() {
        assert_eq!(
            operation("delete-record").effect,
            DeclaredAction::Declared(ActionClass::Delete)
        );
    }

    /// Non-object record fields and a record identifier of `..` each
    /// prevent request construction.
    #[test]
    fn crooked_fields_or_a_crooked_record_builds_no_call() {
        let flat = arguments(vec![("object", text("Account")), ("fields", text("Acme"))]);
        let climbing = arguments(vec![("object", text("Account")), ("record", text(".."))]);

        assert!(call(operation("create-record"), &api(), &flat).is_err());
        assert!(call(operation("get-record"), &api(), &climbing).is_err());
    }
}
