//! Every operation the Notion integration offers, grouped by topic: pages,
//! and data sources, content, comments and people, each described once
//! with the SDK's [`Operation`]. Notion sees only the pages and databases a
//! workspace shared with the integration.

mod content;
mod pages;

use ianua_integration::form::{Ask, PickerText};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place};

/// The data sources of the databases shared with the integration, picked
/// by id and shown by title.
pub(crate) const DATA_SOURCES: PickerText = PickerText {
    filled_by: "list-data-sources",
    items_at: "json.results",
    value_at: "id",
    label_at: "title.0.plain_text",
    depends_on: None,
};

/// The data source a step queries, reads or adds a page to, sent at
/// `place`.
pub(crate) const fn data_source(place: Place) -> Field {
    Field::required(
        "data_source",
        Kind::Text,
        place,
        "The database's data source, by its id: a database has one unless it was split, and reading the database lists them.",
    )
    .asked_with(Ask::Picker(DATA_SOURCES))
}

/// The page a step acts on, in the path.
pub(crate) const PAGE: Field = Field::required(
    "page",
    Kind::Text,
    Place::Path,
    "The page, by its id: the last part of its address, or an earlier step's json.id.",
);

/// A page's properties, in the body.
pub(crate) const PROPERTIES: Field = Field::required(
    "properties",
    Kind::Values,
    Place::Body,
    "The properties, by name, as Notion writes them, such as {\"Name\": {\"title\": [{\"text\": {\"content\": \"Fix login\"}}]}, \"Status\": {\"status\": {\"name\": \"Open\"}}}.",
)
.asked_with(Ask::LongText);

/// How many a listing gives at most, under Notion's name, sent at `place`.
pub(crate) const fn limit(place: Place) -> Field {
    Field::optional(
        "limit",
        Kind::Count,
        place,
        "How many to give back, at most 100; 100 when not given.",
    )
    .sent_as("page_size")
    .more_options()
}

/// Every operation, topic by topic.
pub(crate) fn all() -> impl Iterator<Item = &'static Operation> {
    pages::OPERATIONS.iter().chain(content::OPERATIONS)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::data_classification::level::DataClassLevel;
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
        let wrong = misdescribed(&IntegrationKey::new("notion").unwrap(), all());

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

    fn values(value: &serde_json::Value) -> FlowData {
        flow_of(value).unwrap()
    }

    fn operation(key: &str) -> &'static Operation {
        all().find(|operation| operation.key == key).unwrap()
    }

    fn api() -> ServiceEndpoint {
        ServiceEndpoint::at("https://api.notion.com/v1/").unwrap()
    }

    /// Searching for pages nests what it looks for under Notion's filter.
    #[test]
    fn searching_filters_by_what_it_finds() {
        let given = arguments(vec![
            ("words", text("Roadmap")),
            ("kind", text("page")),
            ("limit", FlowData::number(10.0).unwrap()),
        ]);

        let made = call(operation("search"), &api(), &given).unwrap();

        assert_eq!(made.url.as_str(), "https://api.notion.com/v1/search");
        assert_eq!(
            made.body,
            Some(json!({
                "query": "Roadmap",
                "filter": { "value": "page", "property": "object" },
                "page_size": 10
            }))
        );
    }

    /// Adding a page names its database's data source as the parent, which
    /// a database split into several sources needs, and hands the
    /// properties on as they are.
    #[test]
    fn a_page_goes_in_its_data_source() {
        let properties = json!({ "Name": { "title": [{ "text": { "content": "Fix login" } }] } });
        let given = arguments(vec![
            ("data_source", text("s-1")),
            ("properties", values(&properties)),
        ]);

        let made = call(operation("create-page"), &api(), &given).unwrap();

        assert_eq!(
            made.body,
            Some(json!({ "parent": { "data_source_id": "s-1" }, "properties": properties }))
        );
    }

    /// Querying a database goes to its data source, where its entries
    /// live.
    #[test]
    fn a_query_goes_to_the_data_source() {
        let given = arguments(vec![("data_source", text("s-1"))]);

        let made = call(operation("query-data-source"), &api(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://api.notion.com/v1/data_sources/s-1/query"
        );
    }

    /// The databases offered in pickers are listed by searching for data
    /// sources, which is what a search finds from version 2025-09-03.
    #[test]
    fn databases_are_listed_as_data_sources() {
        let made = call(operation("list-data-sources"), &api(), &arguments(vec![])).unwrap();

        assert_eq!(
            made.body,
            Some(json!({ "filter": { "property": "object", "value": "data_source" } }))
        );
    }

    /// Reading a page's content asks for its page size in the query.
    #[test]
    fn reading_content_pages_through_the_query() {
        let given = arguments(vec![
            ("block", text("p-1")),
            ("limit", FlowData::number(50.0).unwrap()),
        ]);

        let made = call(operation("list-blocks"), &api(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://api.notion.com/v1/blocks/p-1/children?page_size=50"
        );
        assert_eq!(made.body, None);
    }

    /// Notion's trash keeps a page for 30 days, so moving it there is a
    /// write that sends only the flag.
    #[test]
    fn the_trash_is_a_write_of_the_flag() {
        let given = arguments(vec![("page", text("p-1"))]);
        let trash = operation("trash-page");

        let made = call(trash, &api(), &given).unwrap();

        assert_eq!(made.body, Some(json!({ "in_trash": true })));
        assert_eq!(trash.effect, DeclaredAction::Declared(ActionClass::Write));
    }

    /// A page creation without a data source and a page identifier of `..`
    /// both fail request construction.
    #[test]
    fn no_data_source_or_a_crooked_page_builds_no_call() {
        let orphan = arguments(vec![("properties", values(&json!({})))]);
        let climbing = arguments(vec![("page", text(".."))]);

        assert!(call(operation("create-page"), &api(), &orphan).is_err());
        assert!(call(operation("get-page"), &api(), &climbing).is_err());
    }

    /// The data source a page goes in is picked from those shared with the
    /// integration, which listing them gives back.
    #[test]
    fn the_data_source_is_picked_from_the_shared_ones() {
        let guide = operation("create-page").guide(None).unwrap();
        let source = FieldName::new("data_source").unwrap();
        let picker = guide
            .input(&source)
            .unwrap()
            .form()
            .block()
            .picker()
            .unwrap();
        let filler = operation(picker.filled_by().as_str());

        let spec = filler
            .spec(
                &IntegrationKey::new("notion").unwrap(),
                DataClassLevel::Internal,
            )
            .unwrap();

        assert_eq!(spec.effect(), DeclaredAction::Declared(ActionClass::Read));
        assert!(
            filler
                .outputs
                .iter()
                .any(|(path, _)| *path == picker.items_at().to_string())
        );
    }
}
