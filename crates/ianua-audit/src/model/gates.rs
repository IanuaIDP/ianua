//! Gates: capabilities a deployment may not have, found from the code.
//!
//! - **Asked**: an app port with a method that takes nothing and answers
//!   with an enum one of whose variants says the capability is not set up
//!   (`NotSetUp`, `NotConfigured`, `Unavailable`, `Disabled`, `Off`,
//!   `Missing`, `Absent`, `Unset`), such as `MailSetup::reach` answering
//!   `MailReach`. The ports it governs are those declared beside it whose
//!   name starts with its own first word: `Mailer` and `MailOutbox` for
//!   `MailSetup`, nothing for `TextMessaging`.
//! - **Optional**: a port a `*Ports` struct holds as an `Option`, such as
//!   `issuer: Option<Arc<dyn ChallengeIssuer>>`: none when it is not set up.
//! - **Setting**: an enum of an adapter crate's `config/` with such a
//!   variant, or `None`: listed, and read only through the ports it feeds.

use std::collections::BTreeSet;

use serde::Serialize;
use syn::Item;

use crate::model::Model;
use crate::model::app::{PortMethod, PortTrait};
use crate::model::evaluate::Index;
use crate::source::syntax::items_of;
use crate::source::{Layer, Place, Workspace};

/// Variant names that say a capability is not set up.
const OFF_WORDS: &[&str] = &[
    "NotSetUp",
    "NotConfigured",
    "Unavailable",
    "Disabled",
    "Off",
    "Missing",
    "Absent",
    "Unset",
];

/// One capability a deployment may not have.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Gate {
    /// How the code says whether it is there.
    pub(crate) kind: GateKind,
    /// Where it is declared.
    pub(crate) place: Place,
    /// The port traits that act through it, by name.
    pub(crate) acts: Vec<String>,
}

/// How the code says whether a capability is there.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GateKind {
    /// A port's method answers whether it is set up.
    Asked {
        /// The port trait.
        port: String,
        /// The method.
        method: String,
        /// The enum it answers with.
        answer: String,
        /// The variants that say it is set up.
        on: Vec<String>,
        /// The variants that say it is not.
        off: Vec<String>,
    },
    /// A port held as an `Option`.
    Optional {
        /// The port trait.
        port: String,
        /// The `*Ports` struct and field, as `Struct.field`.
        field: String,
    },
    /// A setting of an adapter crate.
    Setting {
        /// The enum.
        answer: String,
        /// The variants that say it is not set up.
        off: Vec<String>,
    },
}

impl Gate {
    /// How it reads, such as `MailSetup::reach` or `ChallengeIssuer`.
    pub(crate) fn name(&self) -> String {
        match &self.kind {
            GateKind::Asked { port, method, .. } => format!("{port}::{method}"),
            GateKind::Optional { port, .. } => port.clone(),
            GateKind::Setting { answer, .. } => answer.clone(),
        }
    }
}

/// Every gate of `workspace`, as `model` reads its ports.
pub(crate) fn find(workspace: &Workspace, model: &Model) -> Vec<Gate> {
    let files: Vec<_> = workspace
        .files
        .iter()
        .filter(|file| file.layer != Layer::Adapter)
        .collect();
    let index = Index::of(&files);
    let mut found = asked(model, &index);
    found.extend(optional(model));
    found.extend(settings(workspace));
    found
}

fn asked(model: &Model, index: &Index<'_>) -> Vec<Gate> {
    model
        .app
        .ports
        .iter()
        .flat_map(|port| {
            (port.methods.iter())
                .filter(|method| method.param_types.is_empty())
                .filter_map(move |method| asked_gate(model, index, port, method))
        })
        .collect()
}

/// The gate `method` of `port` is, when it answers an enum some of whose
/// variants say not set up and some say set up.
fn asked_gate(
    model: &Model,
    index: &Index<'_>,
    port: &PortTrait,
    method: &PortMethod,
) -> Option<Gate> {
    let answer = index.enum_named(method.returns.as_deref()?)?;
    let (off, on): (Vec<String>, Vec<String>) = (answer.variants.iter())
        .map(|variant| variant.name.clone())
        .partition(|variant| OFF_WORDS.contains(&variant.as_str()));
    if off.is_empty() || on.is_empty() {
        return None;
    }
    Some(Gate {
        acts: governed(model, port),
        place: method.place.clone(),
        kind: GateKind::Asked {
            port: port.name.clone(),
            method: method.name.clone(),
            answer: answer.name.clone(),
            on,
            off,
        },
    })
}

/// The ports declared beside `gate` whose name starts with its first word.
fn governed(model: &Model, gate: &crate::model::app::PortTrait) -> Vec<String> {
    let first = first_word(&gate.name);
    model
        .app
        .ports
        .iter()
        .filter(|port| port.item.module == gate.item.module && port.name != gate.name)
        .filter(|port| port.name.starts_with(&first))
        .map(|port| port.name.clone())
        .collect()
}

/// The first word of a name written in camel case: `Mail` for `MailSetup`.
fn first_word(name: &str) -> String {
    let mut word = String::new();
    for (at, character) in name.chars().enumerate() {
        if at > 0 && character.is_ascii_uppercase() {
            break;
        }
        word.push(character);
    }
    word
}

fn optional(model: &Model) -> Vec<Gate> {
    let mut seen = BTreeSet::new();
    model
        .app
        .ports_structs
        .iter()
        .flat_map(|ports| ports.fields.iter().map(move |field| (ports, field)))
        .filter(|(_, field)| {
            field
                .written
                .as_deref()
                .is_some_and(|written| written.starts_with("Option<"))
        })
        .filter_map(|(ports, field)| {
            let port = model.app.port_at(field.port.found()?)?;
            seen.insert(port.name.clone()).then(|| Gate {
                place: port.place.clone(),
                acts: vec![port.name.clone()],
                kind: GateKind::Optional {
                    port: port.name.clone(),
                    field: format!("{}.{}", ports.item.name, field.name),
                },
            })
        })
        .collect()
}

fn settings(workspace: &Workspace) -> Vec<Gate> {
    workspace
        .layer(Layer::Adapter)
        .filter(|file| file.path.starts_with("config/") || file.path.contains("/config/"))
        .flat_map(|file| {
            file.syntax()
                .map(items_of)
                .unwrap_or_default()
                .into_iter()
                .filter_map(move |item| {
                    let Item::Enum(declared) = item else {
                        return None;
                    };
                    let off: Vec<String> = declared
                        .variants
                        .iter()
                        .map(|variant| variant.ident.to_string())
                        .filter(|name| name == "None" || OFF_WORDS.contains(&name.as_str()))
                        .collect();
                    (!off.is_empty()).then(|| Gate {
                        place: Place::of(file, &declared.ident),
                        acts: Vec::new(),
                        kind: GateKind::Setting {
                            answer: declared.ident.to_string(),
                            off,
                        },
                    })
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::domain::DomainLists;
    use crate::source::planted::{adapter, app, domain, workspace};

    #[test]
    fn gates_are_found_from_ports_options_and_settings() {
        let ws = mail_and_puzzle_gates();
        let model = Model::build(&ws, &DomainLists::default());

        let found = find(&ws, &model);

        let names: Vec<String> = found.iter().map(Gate::name).collect();
        assert_eq!(names, ["MailSetup::reach", "ChallengeIssuer", "MailServer"]);
        assert_eq!(found[0].acts, ["Mailer"]);
        assert_eq!(
            found[0].kind,
            GateKind::Asked {
                port: "MailSetup".to_owned(),
                method: "reach".to_owned(),
                answer: "MailReach".to_owned(),
                on: vec!["Available".to_owned()],
                off: vec!["NotSetUp".to_owned()],
            }
        );
    }

    /// A mail port answering whether mail is set up, an optional puzzle
    /// issuer, and the server's mail setting that may be off.
    fn mail_and_puzzle_gates() -> Workspace {
        workspace(vec![
            domain(
                "domains/authentication/mfa/owed.rs",
                "pub enum MailReach { Available, NotSetUp }",
            ),
            app(
                "ports/shared/mail.rs",
                "pub trait MailSetup: Send + Sync { fn reach(&self) -> MailReach; }
                 pub trait Mailer: Send + Sync { async fn send(&self, to: &Email) -> Result<(), DomainError>; }
                 pub trait EmailSender: Send + Sync { async fn deliver(&self) -> Result<(), DomainError>; }",
            ),
            app(
                "ports/authentication.rs",
                "pub trait ChallengeIssuer: Send + Sync { async fn issue(&self) -> Result<Puzzle, DomainError>; }",
            ),
            app(
                "use_cases/authentication/puzzle.rs",
                "pub struct PuzzlePorts { pub issuer: Option<Arc<dyn ChallengeIssuer>> }",
            ),
            adapter(
                "ianua-server",
                "config/serving/mail.rs",
                "pub enum MailServer { NotSetUp, Smtp(SmtpAccount) }",
            ),
        ])
    }
}
