//! Data flow: where events, rights and data classes go.
//!
//! - An event type nothing listens to. It is heard when a notification
//!   category names it and `is_notifiable` does not leave it out, when its
//!   dotted string is written outside the event type lists (a worker or
//!   consumer subscribing), or when the app or an adapter names it.
//! - A right a role can grant that no rule checks: its action is named
//!   nowhere in the domain or the app outside the permission catalogue.
//! - A data class held on a type and never compared: the field's name is in
//!   no comparison or ordering call in the domain or the app.

use std::collections::BTreeSet;

use syn::visit::{self, Visit};
use syn::{BinOp, ExprBinary, ExprMethodCall};

use crate::finding::{Check, Finding};
use crate::model::Model;
use crate::model::domain::{EventType, Permission};
use crate::source::syntax::names_in_expr;
use crate::source::{Layer, SourceFile, Workspace};

/// Where the event type lists live; strings and paths there are the lists
/// themselves, not listeners.
const EVENT_TYPE_LISTS: &str = "types/event_type/";

/// Files that name every event type to decide one thing about each, such as
/// which store caches it drops, as `(crate, folder)`. Naming an event there
/// is not hearing it: the match covers every event by design, so counting
/// it would make every event heard.
const EVERY_EVENT_MATCHES: &[(&str, &str)] = &[("ianua-infra", "cache/stores/touched/")];

/// Where notification categories map events.
const NOTIFICATIONS: &str = "domains/notifications/";

/// Where the domain names the events that are security alerts: told to the
/// people who run a plane even though they stay out of the feeds.
const ALERTS: &str = "domains/notifications/alert.rs";

/// The enum that wraps each context's event type enum.
const EVENT_TYPE: &str = "EventType";

/// The action that covers every other action of its area.
const MANAGE: &str = "Manage";

/// Where rights are declared, parsed and printed.
const PERMISSION_CATALOGUE: &str = "domains/authorization/permission/";

/// Functions that name an event type to describe it, not to act on it.
const DESCRIBING: &[&str] = &["as_str", "parse", "is_notifiable", "event_type"];

/// Calls that compare or order their receiver and arguments.
const COMPARING: &[&str] = &[
    "cmp",
    "partial_cmp",
    "max",
    "min",
    "clamp",
    "covers",
    "permits",
    "admits",
    "allows",
    "exceeds",
    "clears",
    "at_most",
    "at_least",
    "within",
    "contains",
    "is_above",
    "is_below",
];

/// Every flow finding.
pub(crate) fn run(workspace: &Workspace, model: &Model) -> Vec<Finding> {
    let mut found = unheard_events(workspace, model);
    found.extend(unchecked_permissions(workspace, model));
    found.extend(uncompared_data_classes(workspace, model));
    found
}

/// What could hear an event: strings written outside the lists, event
/// types the notification categories name, and those the app or an
/// adapter names.
struct Listeners {
    strings: BTreeSet<String>,
    notified: BTreeSet<(String, String)>,
    notified_enums: BTreeSet<String>,
    alerted: BTreeSet<(String, String)>,
    named: BTreeSet<(String, String)>,
}

impl Listeners {
    fn of(workspace: &Workspace, model: &Model) -> Self {
        let mut listeners = Self {
            strings: BTreeSet::new(),
            notified: BTreeSet::new(),
            notified_enums: BTreeSet::new(),
            alerted: BTreeSet::new(),
            named: BTreeSet::new(),
        };
        for file in &workspace.files {
            listeners.add(file);
        }
        listeners.notified_enums = listeners
            .notified
            .iter()
            .filter(|(owner, _)| owner == EVENT_TYPE)
            .filter_map(|(_, variant)| model.domain.event_type_wrappers.get(variant).cloned())
            .collect();
        listeners
    }

    fn add(&mut self, file: &SourceFile) {
        if file.layer == Layer::Domain && file.path.starts_with(EVENT_TYPE_LISTS) {
            return;
        }
        let every_event = EVERY_EVENT_MATCHES.iter().any(|(crate_name, folder)| {
            file.crate_name == *crate_name && file.path.starts_with(folder)
        });
        if every_event {
            return;
        }
        let usage = file.usage();
        self.strings
            .extend(usage.strings.iter().map(|string| string.name.clone()));
        let acting = usage.pairs.iter().filter(|pair| {
            let describing = pair
                .within
                .as_deref()
                .is_some_and(|within| DESCRIBING.contains(&within));
            let declaring = pair
                .in_macro
                .as_deref()
                .is_some_and(|name| name.ends_with("_event"));
            !describing && !declaring
        });
        let target = match file.layer {
            Layer::Domain if file.path == ALERTS => &mut self.alerted,
            Layer::Domain if file.path.starts_with(NOTIFICATIONS) => &mut self.notified,
            Layer::Domain => return,
            Layer::App | Layer::Adapter => &mut self.named,
        };
        target.extend(acting.map(|pair| (pair.owner.clone(), pair.name.clone())));
    }

    fn hear(&self, model: &Model, event_type: &EventType) -> bool {
        let key = (event_type.enum_name.clone(), event_type.variant.clone());
        let mapped =
            self.notified.contains(&key) || self.notified_enums.contains(&event_type.enum_name);
        let notified = mapped && !quiet(model, event_type);
        notified
            || self.alerted.contains(&key)
            || self.strings.contains(&event_type.text)
            || self.named.contains(&key)
    }
}

/// Whether notifications leave `event_type` out, alone or with its whole
/// context.
fn quiet(model: &Model, event_type: &EventType) -> bool {
    let key = (event_type.enum_name.clone(), event_type.variant.clone());
    model.domain.quiet_event_types.contains(&key)
        || model.domain.quiet_enums.contains(&event_type.enum_name)
}

fn unheard_events(workspace: &Workspace, model: &Model) -> Vec<Finding> {
    let listeners = Listeners::of(workspace, model);
    model
        .domain
        .event_types
        .iter()
        .filter(|event_type| !listeners.hear(model, event_type))
        .map(|event_type| {
            let why = match quiet(model, event_type) {
                true => "left out of notifications, and no worker or consumer subscribes",
                false => "no notification category, worker or consumer names it",
            };
            Finding::new(
                Check::UnheardEvent,
                event_type.place.clone(),
                format!("{}::{}", event_type.enum_name, event_type.variant),
                format!(
                    "`{}` is only written to the audit trail: {why}",
                    event_type.text
                ),
            )
        })
        .collect()
}

fn unchecked_permissions(workspace: &Workspace, model: &Model) -> Vec<Finding> {
    let named: BTreeSet<(String, String)> = workspace
        .files
        .iter()
        .filter(|file| may_check_rights(file))
        .flat_map(|file| {
            file.usage()
                .pairs
                .iter()
                .map(|pair| (pair.owner.clone(), pair.name.clone()))
        })
        .collect();
    model
        .domain
        .permissions
        .iter()
        .filter(|permission| !checked(permission, &model.domain.permissions, &named))
        .map(|permission| {
            let (owner, name) = checked_as(permission);
            Finding::new(
                Check::UncheckedPermission,
                permission.place.clone(),
                permission.subject(),
                format!(
                    "nothing outside the permission catalogue names `{owner}::{name}`: granting it changes nothing"
                ),
            )
        })
        .collect()
}

/// Whether a file holds rules that check rights: the domain outside the
/// catalogue, and the app.
fn may_check_rights(file: &SourceFile) -> bool {
    match file.layer {
        Layer::Domain => !file.path.starts_with(PERMISSION_CATALOGUE),
        Layer::App => true,
        Layer::Adapter => false,
    }
}

/// Whether a rule checks `permission`: it names it, or it is its area's
/// `Manage`, which covers every other action of the area, and a rule names
/// one of those.
fn checked(
    permission: &Permission,
    all: &[Permission],
    named: &BTreeSet<(String, String)>,
) -> bool {
    if named.contains(&checked_as(permission)) {
        return true;
    }
    let Some((area, action)) = &permission.action else {
        return false;
    };
    action == MANAGE
        && all
            .iter()
            .filter_map(|other| other.action.as_ref())
            .any(|other| other.0 == *area && named.contains(other))
}

/// The path a rule writes to check `permission`.
fn checked_as(permission: &Permission) -> (String, String) {
    permission
        .action
        .clone()
        .unwrap_or_else(|| ("SystemPermission".to_owned(), permission.variant.clone()))
}

fn uncompared_data_classes(workspace: &Workspace, model: &Model) -> Vec<Finding> {
    let mut compared = Compared::default();
    for file in workspace
        .files
        .iter()
        .filter(|file| file.layer != Layer::Adapter)
    {
        if let Some(syntax) = file.syntax() {
            compared.visit_file(syntax);
        }
    }
    model
        .domain
        .data_class_fields
        .iter()
        .filter(|field| !compared.names.contains(&field.field))
        .map(|field| {
            let subject = format!("{}.{}", field.owner, field.field);
            Finding::new(
                Check::UncomparedDataClass,
                field.place.clone(),
                subject.clone(),
                format!("`{subject}` holds a data class that nothing compares against a clearance"),
            )
        })
        .collect()
}

/// Every name written inside a comparison or an ordering call.
#[derive(Default)]
struct Compared {
    names: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for Compared {
    fn visit_expr_binary(&mut self, expr: &'ast ExprBinary) {
        let comparing = matches!(
            expr.op,
            BinOp::Lt(_) | BinOp::Le(_) | BinOp::Gt(_) | BinOp::Ge(_) | BinOp::Eq(_) | BinOp::Ne(_)
        );
        if comparing {
            self.names.extend(names_in_expr(&expr.left));
            self.names.extend(names_in_expr(&expr.right));
        }
        visit::visit_expr_binary(self, expr);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        if COMPARING.contains(&call.method.to_string().as_str()) {
            self.names.extend(names_in_expr(&call.receiver));
            self.names.extend(call.args.iter().flat_map(names_in_expr));
        }
        visit::visit_expr_method_call(self, call);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::domain::DomainLists;
    use crate::source::planted::{adapter, domain, workspace};

    const EVENT_TYPES: &str = r#"
        event_types! {
            pub enum AgentsEvent {
                RunStarted => "agents.run_started",
                RunFinished => "agents.run_finished",
                TokenIssued => "agents.token_issued",
                Created => "agents.created",
            }
        }
        impl AgentsEvent {
            pub fn is_notifiable(&self) -> bool { !matches!(self, Self::TokenIssued | Self::RunStarted) }
        }
    "#;

    const CATEGORY: &str = r"
        fn of_agents(event: AgentsEvent) -> Category {
            match event {
                AgentsEvent::Created | AgentsEvent::TokenIssued | AgentsEvent::RunStarted => Category::Agents,
            }
        }
    ";

    const PERMISSIONS: &str = r"
        pub enum SystemPermission { Messaging(MessagingAction) }
        pub enum MessagingAction { Create, Delete, Manage }
        impl MessagingAction { fn as_str(self) -> &'static str { match self { Self::Create => MessagingAction::Delete } } }
    ";

    const TOPIC: &str = r"
        pub struct Topic { data_class: DataClassLevel, floor: DataClassLevel }
        impl Topic {
            pub fn read(&self, reader: &Reader) -> bool { self.data_class <= reader.clearance() }
            pub fn create(by: &MessagingControl) { by.ensure_may(MessagingAction::Create) }
        }
    ";

    fn findings() -> Vec<Finding> {
        let ws = workspace(vec![
            domain("types/event_type/agents.rs", EVENT_TYPES),
            domain("domains/notifications/category.rs", CATEGORY),
            domain("domains/authorization/permission/system.rs", PERMISSIONS),
            domain("domains/messaging/topic.rs", TOPIC),
            adapter(
                "ianua-server",
                "worker/events.rs",
                r#"const RUNS: &[&str] = &["agents.run_started"];"#,
            ),
        ]);
        run(&ws, &Model::build(&ws, &DomainLists::default()))
    }

    fn of(found: &[Finding], check: Check) -> Vec<String> {
        found
            .iter()
            .filter(|finding| finding.check == check)
            .map(|finding| finding.subject.clone())
            .collect()
    }

    #[test]
    fn an_event_neither_notified_nor_subscribed_is_unheard() {
        let found = findings();

        assert_eq!(
            of(&found, Check::UnheardEvent),
            ["AgentsEvent::RunFinished", "AgentsEvent::TokenIssued"]
        );
    }

    /// An event the domain makes a security alert is heard, though
    /// notifications leave it out of the feeds.
    #[test]
    fn a_security_alert_is_heard() {
        let ws = workspace(vec![
            domain("types/event_type/agents.rs", EVENT_TYPES),
            domain("domains/notifications/category.rs", CATEGORY),
            domain(
                "domains/notifications/alert.rs",
                "fn of(e: &AgentsEvent) -> bool { matches!(e, AgentsEvent::TokenIssued) }",
            ),
        ]);

        let found = run(&ws, &Model::build(&ws, &DomainLists::default()));

        assert!(!of(&found, Check::UnheardEvent).contains(&"AgentsEvent::TokenIssued".to_owned()));
    }

    /// Stops: the store caches' match, which names every event to decide
    /// which caches it drops, counts as hearing every event, so the check
    /// never finds an event nobody acts on.
    #[test]
    fn a_match_over_every_event_hears_none() {
        let ws = workspace(vec![
            domain("types/event_type/agents.rs", EVENT_TYPES),
            domain("domains/notifications/category.rs", CATEGORY),
            adapter(
                "ianua-infra",
                "cache/stores/touched/work.rs",
                "fn touched(e: AgentsEvent) { match e { AgentsEvent::RunFinished => (), AgentsEvent::TokenIssued => () } }",
            ),
        ]);

        let found = run(&ws, &Model::build(&ws, &DomainLists::default()));

        assert!(of(&found, Check::UnheardEvent).contains(&"AgentsEvent::RunFinished".to_owned()));
    }

    #[test]
    fn a_context_mapped_whole_is_heard_unless_left_out_whole() {
        let ws = contexts_mapped_whole();

        let found = run(&ws, &Model::build(&ws, &DomainLists::default()));

        assert_eq!(
            of(&found, Check::UnheardEvent),
            [
                "AgentsEvent::RunStarted",
                "AgentsEvent::TokenIssued",
                "NotificationsEvent::Sent"
            ]
        );
    }

    /// Agents' and notifications' events, the notifications left out of
    /// fan-out whole, and both mapped whole to one category.
    fn contexts_mapped_whole() -> Workspace {
        workspace(vec![
            domain("types/event_type/agents.rs", EVENT_TYPES),
            domain(
                "types/event_type/mod.rs",
                r"
                pub enum EventType { Agents(AgentsEvent), Notifications(NotificationsEvent) }
                impl EventType {
                    pub fn is_notifiable(&self) -> bool {
                        match self { Self::Notifications(_) => false, Self::Agents(e) => e.is_notifiable() }
                    }
                }",
            ),
            domain(
                "types/event_type/notifications.rs",
                r#"event_types! { pub enum NotificationsEvent { Sent => "notifications.sent", } }"#,
            ),
            domain(
                "domains/notifications/category.rs",
                r"fn of(event: &EventType) -> Category {
                    match event { EventType::Agents(_) | EventType::Notifications(_) => Category::All }
                }",
            ),
        ])
    }

    #[test]
    fn a_right_named_only_in_the_catalogue_is_unchecked() {
        let found = findings();

        assert_eq!(
            of(&found, Check::UncheckedPermission),
            ["Messaging(MessagingAction::Delete)"]
        );
    }

    #[test]
    fn a_data_class_field_in_no_comparison_is_uncompared() {
        let found = findings();

        assert_eq!(of(&found, Check::UncomparedDataClass), ["Topic.floor"]);
    }
}
