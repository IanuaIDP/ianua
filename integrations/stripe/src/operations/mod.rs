//! Every operation the Stripe integration offers, grouped by topic:
//! customers, and billing, each described once with the SDK's
//! [`Operation`]. Stripe takes every body as a form; amounts are in the
//! smallest unit of the currency, such as cents.

mod billing;
mod customers;

use ianua_integration::form::{Ask, PickerText};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place};

/// The account's customers, picked by id and shown by email.
pub(crate) const CUSTOMERS: PickerText = PickerText {
    filled_by: "list-customers",
    items_at: "json.data",
    value_at: "id",
    label_at: "email",
    depends_on: None,
};

/// The customer a step acts on, in the path.
pub(crate) const CUSTOMER: Field = Field::required(
    "customer",
    Kind::Text,
    Place::Path,
    "The customer's id, such as cus_NffrFeUfNV2Hib or an earlier step's json.id.",
)
.asked_with(Ask::Picker(CUSTOMERS));

/// How many a listing gives at most.
pub(crate) const LIMIT: Field = Field::optional(
    "limit",
    Kind::Count,
    Place::Query,
    "How many to give back, at most 100; 10 when not given.",
)
.more_options();

/// Every operation, topic by topic.
pub(crate) fn all() -> impl Iterator<Item = &'static Operation> {
    customers::OPERATIONS.iter().chain(billing::OPERATIONS)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::data::{FieldName, FlowData};
    use ianua_domain::domains::workflows::integration::IntegrationKey;
    use ianua_domain::types::{ActionClass, DeclaredAction};
    use ianua_integration::ServiceEndpoint;
    use ianua_integration::rest::checks::misdescribed;
    use ianua_integration::rest::request::call;
    use serde_json::json;

    use super::*;

    /// Every operation keeps the SDK's rules.
    #[test]
    fn every_operation_keeps_the_rules() {
        let wrong = misdescribed(&IntegrationKey::new("stripe").unwrap(), all());

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
        ServiceEndpoint::at("https://api.stripe.com/v1/").unwrap()
    }

    /// Refunding part of a payment sends the payment, the amount in cents
    /// and the reason as a form, and is financial.
    #[test]
    fn a_partial_refund_sends_its_amount_as_a_form() {
        let given = arguments(vec![
            ("payment", text("pi_123")),
            ("amount", FlowData::number(500.0).unwrap()),
            ("reason", text("requested_by_customer")),
        ]);
        let refund = operation("refund-payment");

        let made = call(refund, &api(), &given).unwrap();

        assert_eq!(made.url.as_str(), "https://api.stripe.com/v1/refunds");
        assert_eq!(
            made.payload().unwrap(),
            "amount=500&payment_intent=pi_123&reason=requested_by_customer"
        );
        assert_eq!(
            refund.effect,
            DeclaredAction::Declared(ActionClass::Financial)
        );
    }

    /// Listing one customer's open invoices puts both in the query, with
    /// the state under Stripe's name.
    #[test]
    fn listing_invoices_filters_in_the_query() {
        let given = arguments(vec![("customer", text("cus_1")), ("state", text("open"))]);

        let made = call(operation("list-invoices"), &api(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://api.stripe.com/v1/invoices?customer=cus_1&status=open"
        );
        assert_eq!(made.body, None);
    }

    /// Changing a customer posts the changed fields to the customer.
    #[test]
    fn changing_a_customer_posts_to_it() {
        let given = arguments(vec![
            ("customer", text("cus_1")),
            ("email", text("ann@acme.test")),
        ]);

        let made = call(operation("update-customer"), &api(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://api.stripe.com/v1/customers/cus_1"
        );
        assert_eq!(made.body, Some(json!({ "email": "ann@acme.test" })));
    }

    /// Every step that moves money or changes billing is financial, so it
    /// waits for an approval.
    #[test]
    fn money_moving_steps_are_financial() {
        for key in ["refund-payment", "send-invoice", "cancel-subscription"] {
            assert_eq!(
                operation(key).effect,
                DeclaredAction::Declared(ActionClass::Financial),
                "{key}"
            );
        }
    }

    /// A refund without a payment and a customer read using `..` both
    /// fail request construction.
    #[test]
    fn no_payment_or_a_crooked_customer_builds_no_call() {
        let unnamed = arguments(vec![("amount", FlowData::number(5.0).unwrap())]);
        let climbing = arguments(vec![("customer", text(".."))]);

        assert!(call(operation("refund-payment"), &api(), &unnamed).is_err());
        assert!(call(operation("get-customer"), &api(), &climbing).is_err());
    }
}
