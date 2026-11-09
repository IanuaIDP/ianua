//! The workspace: listing its teams, a team's workflow states and labels,
//! its projects and its people, which the pickers are filled from.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::rest::operation::{Fixed, Operation, Shape, Verb};

use crate::operations::{DOCUMENT, GRAPHQL, LIMIT, TEAM};

/// Listing the teams the account can reach.
const LIST_TEAMS: &str = "query Teams($first: Int) { \
    teams(first: $first) { nodes { id key name } } }";

/// Listing one team's workflow states.
const LIST_STATES: &str = "query TeamStates($team: String!, $first: Int) { \
    team(id: $team) { states(first: $first) { nodes { id name type position } } } }";

/// Listing the labels one team may use: its own and the workspace's.
const LIST_LABELS: &str = "query TeamLabels($team: ID!, $first: Int) { \
    issueLabels(first: $first, filter: { or: [{ team: { id: { eq: $team } } }, { team: { null: true } }] }) { \
    nodes { id name color } } }";

/// Listing the workspace's projects.
const LIST_PROJECTS: &str = "query Projects($first: Int) { \
    projects(first: $first) { nodes { id name url status { name } } } }";

/// Listing the workspace's people.
const LIST_USERS: &str = "query Users($first: Int) { \
    users(first: $first) { nodes { id name displayName active } } }";

/// Every workspace operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "list-teams",
        title: "List teams",
        description: "Lists the teams the account's API key can reach, each with its id, key and name.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Post,
        path: GRAPHQL,
        fields: &[LIMIT],
        fixed: &[(DOCUMENT, Fixed::Text(LIST_TEAMS))],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "json.data.teams.nodes",
            "The teams, each with its id, key such as ENG, and name.",
        )],
    },
    Operation {
        key: "list-states",
        title: "List a team's states",
        description: "Lists the workflow states of one team, such as Todo, In Progress and Done, each with its id and type.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Post,
        path: GRAPHQL,
        fields: &[TEAM, LIMIT],
        fixed: &[(DOCUMENT, Fixed::Text(LIST_STATES))],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "json.data.team.states.nodes",
            "The states, each with its id, name and type, such as started or completed.",
        )],
    },
    Operation {
        key: "list-labels",
        title: "List labels",
        description: "Lists the labels one team may put on its issues: its own and the workspace's.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Post,
        path: GRAPHQL,
        fields: &[TEAM, LIMIT],
        fixed: &[(DOCUMENT, Fixed::Text(LIST_LABELS))],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "json.data.issueLabels.nodes",
            "The labels, each with its id, name and colour.",
        )],
    },
    Operation {
        key: "list-projects",
        title: "List projects",
        description: "Lists the workspace's projects, each with its id, name, status and address.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Post,
        path: GRAPHQL,
        fields: &[LIMIT],
        fixed: &[(DOCUMENT, Fixed::Text(LIST_PROJECTS))],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "json.data.projects.nodes",
            "The projects, each with its id, name, status and address.",
        )],
    },
    Operation {
        key: "list-users",
        title: "List people",
        description: "Lists the people in the workspace, each with their id, name and whether they are active.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Post,
        path: GRAPHQL,
        fields: &[LIMIT],
        fixed: &[(DOCUMENT, Fixed::Text(LIST_USERS))],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "json.data.users.nodes",
            "The people, each with their id, full name, display name and whether they are active.",
        )],
    },
];
