//! Every operation the Trello integration offers, grouped by topic: boards
//! and what is on them, and cards, each described once with the SDK's
//! [`Operation`], with the pickers its forms fill from Trello's own lists.
//!
//! Trello takes every value of a call in its query, as its API description
//! writes them, so no operation puts anything in a body.
//!
//! Trello's card calls name no board, so a step on a card's list, labels
//! or members asks for the board in the form only, to narrow what its
//! pickers offer, and sends Trello the list, label or member alone. Moving
//! a card names the board it goes to, so its list is picked from that
//! board.

mod boards;
mod cards;

use ianua_integration::form::{Ask, PickerText};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment};

/// The open boards the account's member can reach, picked by id and shown
/// by name.
pub(crate) const BOARDS: PickerText = PickerText {
    filled_by: "list-boards",
    items_at: "json",
    value_at: "id",
    label_at: "name",
    depends_on: None,
};

/// The chosen board's open lists, picked by id and shown by name.
pub(crate) const LISTS: PickerText = PickerText {
    filled_by: "list-lists",
    items_at: "json",
    value_at: "id",
    label_at: "name",
    depends_on: Some("board"),
};

/// The chosen board's labels, picked by id and shown by name.
pub(crate) const LABELS: PickerText = PickerText {
    filled_by: "list-labels",
    items_at: "json",
    value_at: "id",
    label_at: "name",
    depends_on: Some("board"),
};

/// The chosen board's members, picked by id and shown by full name.
pub(crate) const MEMBERS: PickerText = PickerText {
    filled_by: "list-members",
    items_at: "json",
    value_at: "id",
    label_at: "fullName",
    depends_on: Some("board"),
};

/// The board whose lists, labels or members a card step's pickers offer.
/// Trello is told only what is picked.
pub(crate) const PICKING_BOARD: Field = Field::optional(
    "board",
    Kind::Text,
    Place::Form,
    "The board whose lists, labels and members the pickers offer; Trello is told only what is picked.",
)
.asked_with(Ask::Picker(BOARDS));

/// The path of one card.
pub(crate) const ONE_CARD: &[Segment] = &[Segment::Fixed("cards"), Segment::Input("card")];

/// The board a board's list is read from, in the path.
pub(crate) const BOARD: Field = Field::required(
    "board",
    Kind::Text,
    Place::Path,
    "The board's id or short link, such as one list-boards gives.",
)
.asked_with(Ask::Picker(BOARDS));

/// The card a card operation acts on, in the path.
pub(crate) const CARD: Field = Field::required(
    "card",
    Kind::Text,
    Place::Path,
    "The card's id or short link, such as an earlier step's json.id.",
);

/// Every operation, topic by topic.
pub(crate) fn all() -> impl Iterator<Item = &'static Operation> {
    boards::OPERATIONS.iter().chain(cards::OPERATIONS)
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
    /// explained, every path input placed, no body on a read, something
    /// given back, and every picker filled by a read.
    #[test]
    fn every_operation_keeps_the_rules() {
        let wrong = misdescribed(&IntegrationKey::new("trello").unwrap(), all());

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
        let trello = ServiceEndpoint::at("https://api.trello.com/1/").unwrap();
        call(operation, &trello, &arguments(given))
    }

    /// Ann's workflow creates a card on the Inbox list with two labels:
    /// every value goes in the query under Trello's names, the labels
    /// joined by a comma, and the body stays empty.
    #[test]
    fn creating_a_card_puts_its_values_in_the_query() {
        let created = made(
            "create-card",
            vec![
                ("list", text("inboxlist1")),
                ("name", text("Call the supplier")),
                ("description", text("About the late order.")),
                ("position", text("top")),
                (
                    "labels",
                    FlowData::list(vec![text("urgentlabel"), text("salelabel")]).unwrap(),
                ),
            ],
        )
        .unwrap();

        assert_eq!(
            created.url.as_str(),
            "https://api.trello.com/1/cards?idList=inboxlist1&name=Call+the+supplier&desc=About+the+late+order.&pos=top&idLabels=urgentlabel%2Csalelabel"
        );
        assert_eq!(created.body, Some(json!({})));
    }

    /// Pat picks the board only to narrow the list picker. The board stays
    /// out of the call Trello is sent, and a step saved before the board
    /// was asked for makes the same call.
    #[test]
    fn the_board_a_picker_narrows_by_is_never_sent() {
        let with_board = made(
            "create-card",
            vec![
                ("board", text("salesboard")),
                ("list", text("inboxlist1")),
                ("name", text("Call the supplier")),
            ],
        )
        .unwrap();
        let saved_before = made(
            "create-card",
            vec![
                ("list", text("inboxlist1")),
                ("name", text("Call the supplier")),
            ],
        )
        .unwrap();

        assert!(!with_board.url.as_str().contains("salesboard"));
        assert_eq!(with_board.url, saved_before.url);
    }

    /// Adding a label names the card and the label alone, whichever board
    /// the label was picked from.
    #[test]
    fn a_label_picked_from_a_board_is_sent_alone() {
        let added = made(
            "add-label",
            vec![
                ("card", text("card42")),
                ("board", text("salesboard")),
                ("label", text("urgentlabel")),
            ],
        )
        .unwrap();

        assert_eq!(
            added.url.as_str(),
            "https://api.trello.com/1/cards/card42/idLabels?value=urgentlabel"
        );
    }

    /// Moving a card names its card in the path, and the board and list it
    /// goes to in the query.
    #[test]
    fn moving_a_card_names_the_board_and_list() {
        let moved = made(
            "move-card",
            vec![
                ("card", text("card42")),
                ("board", text("salesboard")),
                ("list", text("donelist")),
            ],
        )
        .unwrap();

        assert_eq!(
            moved.url.as_str(),
            "https://api.trello.com/1/cards/card42?idBoard=salesboard&idList=donelist"
        );
    }

    /// Archiving a card always sends closed as true, and nothing else.
    #[test]
    fn archiving_a_card_closes_it() {
        let archived = made("archive-card", vec![("card", text("card42"))]).unwrap();

        assert_eq!(
            archived.url.as_str(),
            "https://api.trello.com/1/cards/card42?closed=true"
        );
    }

    /// Marking a card's due date done sends the flag as true.
    #[test]
    fn updating_a_card_sends_its_due_flag() {
        let updated = made(
            "update-card",
            vec![
                ("card", text("card42")),
                ("name", text("Call the supplier again")),
                ("due_complete", FlowData::bool(true)),
            ],
        )
        .unwrap();

        assert_eq!(
            updated.url.as_str(),
            "https://api.trello.com/1/cards/card42?name=Call+the+supplier+again&dueComplete=true"
        );
    }

    /// A comment's text goes in the query under Trello's name.
    #[test]
    fn a_comment_sends_its_text() {
        let commented = made(
            "comment-on-card",
            vec![
                ("card", text("card42")),
                ("text", text("The order shipped today.")),
            ],
        )
        .unwrap();

        assert_eq!(
            commented.url.as_str(),
            "https://api.trello.com/1/cards/card42/actions/comments?text=The+order+shipped+today."
        );
    }

    /// Adding a label sends its id as Trello's value.
    #[test]
    fn adding_a_label_sends_its_id() {
        let labelled = made(
            "add-label",
            vec![("card", text("card42")), ("label", text("urgentlabel"))],
        )
        .unwrap();

        assert_eq!(
            labelled.url.as_str(),
            "https://api.trello.com/1/cards/card42/idLabels?value=urgentlabel"
        );
    }

    /// Deleting a card names it and sends no body.
    #[test]
    fn deleting_a_card_names_it() {
        let deleted = made("delete-card", vec![("card", text("card42"))]).unwrap();

        assert_eq!(
            deleted.url.as_str(),
            "https://api.trello.com/1/cards/card42"
        );
        assert_eq!(deleted.body, None);
    }

    /// Ann opens the board picker: the member's open boards are listed.
    /// Choosing the sales board then lists its open lists, and its labels,
    /// fifty at most.
    #[test]
    fn pickers_list_boards_then_their_lists_and_labels() {
        let boards = made("list-boards", Vec::new()).unwrap();
        let lists = made("list-lists", vec![("board", text("salesboard"))]).unwrap();
        let labels = made(
            "list-labels",
            vec![
                ("board", text("salesboard")),
                ("limit", FlowData::number(50.0).unwrap()),
            ],
        )
        .unwrap();

        assert_eq!(
            boards.url.as_str(),
            "https://api.trello.com/1/members/me/boards?filter=open"
        );
        assert_eq!(
            lists.url.as_str(),
            "https://api.trello.com/1/boards/salesboard/lists?filter=open"
        );
        assert_eq!(
            labels.url.as_str(),
            "https://api.trello.com/1/boards/salesboard/labels?limit=50"
        );
        assert_eq!(labels.body, None, "a read sends no body");
    }

    /// Listing members without a board fails request construction.
    #[test]
    fn listing_members_needs_a_board() {
        let listed = made("list-members", Vec::new());

        assert!(listed.is_err());
    }

    /// Creating a card without a list, reading a card named `..`, and
    /// listing labels with a text limit each fail request construction.
    #[test]
    fn a_missing_input_a_crooked_card_or_a_wrong_kind_builds_no_call() {
        let without_list = made("create-card", vec![("name", text("Call the supplier"))]);
        let climbing = made("get-card", vec![("card", text(".."))]);
        let worded = made(
            "list-labels",
            vec![("board", text("salesboard")), ("limit", text("fifty"))],
        );

        for refused in [without_list, climbing, worded] {
            assert!(matches!(refused, Err(ActionOutcome::Failed(_))));
        }
    }
}
