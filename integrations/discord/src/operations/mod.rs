//! Every operation the Discord integration offers, grouped by topic:
//! servers, with their channels, roles and members, and messages, each
//! described once with the SDK's [`Operation`], with the pickers its forms
//! fill from Discord's own lists.
//!
//! Discord's message calls name a channel but no server, so a message step
//! asks for the server in the form only, to narrow the channel picker, and
//! sends Discord the channel alone. Giving a role names the server, so its
//! role is picked from that server.

mod messages;
mod servers;

use ianua_integration::form::{Ask, PickerText};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place};

/// The servers the bot is in, picked by id and shown by name.
const SERVERS: PickerText = PickerText {
    filled_by: "list-servers",
    items_at: "json",
    value_at: "id",
    label_at: "name",
    depends_on: None,
};

/// The chosen server's roles, picked by id and shown by name.
pub(crate) const ROLES: PickerText = PickerText {
    filled_by: "list-roles",
    items_at: "json",
    value_at: "id",
    label_at: "name",
    depends_on: Some("server"),
};

/// The server a step acts in, in the path.
pub(crate) const SERVER: Field = Field::required(
    "server",
    Kind::Text,
    Place::Path,
    "The server's id, such as one list-servers gives.",
)
.asked_with(Ask::Picker(SERVERS));

/// The chosen server's channels, picked by id and shown by name.
const CHANNELS: PickerText = PickerText {
    filled_by: "list-channels",
    items_at: "json",
    value_at: "id",
    label_at: "name",
    depends_on: Some("server"),
};

/// The server whose channels the channel picker offers; Discord is told
/// only the channel.
pub(crate) const CHANNEL_SERVER: Field = Field::optional(
    "server",
    Kind::Text,
    Place::Form,
    "The server whose channels the channel picker offers; Discord is told only the channel.",
)
.asked_with(Ask::Picker(SERVERS));

/// The channel a message step acts in, in the path.
pub(crate) const CHANNEL: Field = Field::required(
    "channel",
    Kind::Text,
    Place::Path,
    "The channel's id, such as one list-channels gives; the bot must be able to see it.",
)
.example("1100000000000000001")
.asked_with(Ask::Picker(CHANNELS));

/// The message a step acts on, in the path.
pub(crate) const MESSAGE: Field = Field::required(
    "message",
    Kind::Text,
    Place::Path,
    "The message's id, such as an earlier step's json.id.",
);

/// Every operation, topic by topic.
pub(crate) fn all() -> impl Iterator<Item = &'static Operation> {
    servers::OPERATIONS.iter().chain(messages::OPERATIONS)
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
        let wrong = misdescribed(&IntegrationKey::new("discord").unwrap(), all());

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
        let discord = ServiceEndpoint::at("https://discord.com/api/v10/").unwrap();
        call(operation, &discord, &arguments(given))
    }

    /// Ann's workflow posts to the on-call channel as a reply to an alert,
    /// letting only people be pinged: the channel goes in the path, the
    /// text, the reply and the mentions in the body under Discord's names.
    #[test]
    fn posting_a_message_sends_its_text_reply_and_mentions() {
        let posted = made(
            "post-message",
            vec![
                ("channel", text("1100000000000000001")),
                ("content", text("The nightly build failed.")),
                ("reply_to", text("1200000000000000002")),
                ("mentions", FlowData::list(vec![text("users")]).unwrap()),
            ],
        )
        .unwrap();

        assert_eq!(
            posted.url.as_str(),
            "https://discord.com/api/v10/channels/1100000000000000001/messages"
        );
        assert_eq!(
            posted.body,
            Some(json!({
                "content": "The nightly build failed.",
                "message_reference": { "message_id": "1200000000000000002" },
                "allowed_mentions": { "parse": ["users"] }
            }))
        );
    }

    /// Ann's post says nothing of mentions, and its text holds @everyone.
    /// No one is pinged: the post allows no mentions at all.
    #[test]
    fn a_post_pings_no_one_unless_it_says_so() {
        let posted = made(
            "post-message",
            vec![
                ("channel", text("1100000000000000001")),
                ("content", text("@everyone the build failed.")),
            ],
        )
        .unwrap();

        assert_eq!(
            posted.body,
            Some(json!({
                "content": "@everyone the build failed.",
                "allowed_mentions": { "parse": [] }
            }))
        );
    }

    /// Editing a message names its channel and message, and sends the new
    /// text.
    #[test]
    fn editing_a_message_sends_its_new_text() {
        let edited = made(
            "edit-message",
            vec![
                ("channel", text("1100000000000000001")),
                ("message", text("1200000000000000002")),
                ("content", text("The nightly build is fixed.")),
            ],
        )
        .unwrap();

        assert_eq!(
            edited.url.as_str(),
            "https://discord.com/api/v10/channels/1100000000000000001/messages/1200000000000000002"
        );
        assert_eq!(
            edited.body,
            Some(json!({ "content": "The nightly build is fixed." }))
        );
    }

    /// Deleting a message names it and sends no body.
    #[test]
    fn deleting_a_message_names_it() {
        let deleted = made(
            "delete-message",
            vec![
                ("channel", text("1100000000000000001")),
                ("message", text("1200000000000000002")),
            ],
        )
        .unwrap();

        assert_eq!(
            deleted.url.as_str(),
            "https://discord.com/api/v10/channels/1100000000000000001/messages/1200000000000000002"
        );
        assert_eq!(deleted.body, None);
    }

    /// Reacting with a thumbs up escapes the emoji in the path, as the bot's
    /// own reaction; a server's own emoji keeps its name and id.
    #[test]
    fn a_reaction_escapes_its_emoji_in_the_path() {
        let reaction = |emoji: &str| {
            made(
                "add-reaction",
                vec![
                    ("channel", text("1100000000000000001")),
                    ("message", text("1200000000000000002")),
                    ("emoji", text(emoji)),
                ],
            )
            .unwrap()
        };

        let thumbs = reaction("\u{1f44d}");
        let custom = reaction("shipit:1300000000000000003");

        assert_eq!(
            thumbs.url.as_str(),
            "https://discord.com/api/v10/channels/1100000000000000001/messages/1200000000000000002/reactions/%F0%9F%91%8D/@me"
        );
        assert_eq!(
            custom.url.as_str(),
            "https://discord.com/api/v10/channels/1100000000000000001/messages/1200000000000000002/reactions/shipit:1300000000000000003/@me"
        );
    }

    /// Starting a thread from a message sends its name and when it is
    /// hidden, under Discord's names.
    #[test]
    fn starting_a_thread_sends_its_name() {
        let started = made(
            "start-thread",
            vec![
                ("channel", text("1100000000000000001")),
                ("message", text("1200000000000000002")),
                ("name", text("Nightly build")),
                ("archive_after", FlowData::number(1440.0).unwrap()),
            ],
        )
        .unwrap();

        assert_eq!(
            started.url.as_str(),
            "https://discord.com/api/v10/channels/1100000000000000001/messages/1200000000000000002/threads"
        );
        assert_eq!(
            started.body,
            Some(json!({ "name": "Nightly build", "auto_archive_duration": 1440 }))
        );
    }

    /// Reading recent messages puts the limit and the message to read
    /// before in the query.
    #[test]
    fn listing_messages_puts_its_filters_in_the_query() {
        let listed = made(
            "list-messages",
            vec![
                ("channel", text("1100000000000000001")),
                ("limit", FlowData::number(20.0).unwrap()),
                ("before", text("1200000000000000002")),
            ],
        )
        .unwrap();

        assert_eq!(
            listed.url.as_str(),
            "https://discord.com/api/v10/channels/1100000000000000001/messages?limit=20&before=1200000000000000002"
        );
        assert_eq!(listed.body, None, "a read sends no body");
    }

    /// Giving a member a role names the server, the member and the role in
    /// the path.
    #[test]
    fn giving_a_role_names_server_member_and_role() {
        let given = made(
            "add-role",
            vec![
                ("server", text("1000000000000000000")),
                ("member", text("1400000000000000004")),
                ("role", text("1500000000000000005")),
            ],
        )
        .unwrap();

        assert_eq!(
            given.url.as_str(),
            "https://discord.com/api/v10/guilds/1000000000000000000/members/1400000000000000004/roles/1500000000000000005"
        );
    }

    /// Ann opens the server picker: the bot's servers are listed. Choosing
    /// the team's server then lists its channels and its roles.
    #[test]
    fn pickers_list_servers_then_their_channels_and_roles() {
        let servers = made("list-servers", Vec::new()).unwrap();
        let channels = made(
            "list-channels",
            vec![("server", text("1000000000000000000"))],
        )
        .unwrap();
        let roles = made("list-roles", vec![("server", text("1000000000000000000"))]).unwrap();

        assert_eq!(
            servers.url.as_str(),
            "https://discord.com/api/v10/users/@me/guilds"
        );
        assert_eq!(
            channels.url.as_str(),
            "https://discord.com/api/v10/guilds/1000000000000000000/channels"
        );
        assert_eq!(
            roles.url.as_str(),
            "https://discord.com/api/v10/guilds/1000000000000000000/roles"
        );
        assert_eq!(roles.body, None, "a read sends no body");
    }

    /// Listing roles without a server fails request construction.
    #[test]
    fn listing_roles_needs_a_server() {
        let listed = made("list-roles", Vec::new());

        assert!(listed.is_err());
    }

    /// Missing message text, a channel ID of `..`, and a text value for the
    /// message limit each fail request construction.
    #[test]
    fn a_missing_input_a_crooked_channel_or_a_wrong_kind_builds_no_call() {
        let without_text = made(
            "post-message",
            vec![("channel", text("1100000000000000001"))],
        );
        let climbing = made(
            "post-message",
            vec![("channel", text("..")), ("content", text("Hello."))],
        );
        let worded = made(
            "list-messages",
            vec![
                ("channel", text("1100000000000000001")),
                ("limit", text("twenty")),
            ],
        );

        for refused in [without_text, climbing, worded] {
            assert!(matches!(refused, Err(ActionOutcome::Failed(_))));
        }
    }
}
