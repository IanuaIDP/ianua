//! `impact`: everything that reaches a port method, a port, a domain type
//! or change, or a use case, grouped by layer with `file:line` and counted:
//! the list to brief a change with before editing.
//!
//! Use cases, services and domain changes are joined through the facts
//! (see [`crate::model::facts`]); implementations by `impl Trait for Type`;
//! other adapter code, fakes and tests by the names they write: a file
//! counts when it names the target, a fake of it, or a use case that
//! reaches it. A use case name that several contexts share counts only
//! where a `use` imports it from its own module, or in its own file's unit
//! tests.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::Serialize;
use syn::Item;

use crate::allow::Parked;
use crate::model::Model;
use crate::model::app::{PortLookup, PortMethod, PortTrait};
use crate::model::domain::{Behaviour, BehaviourKind};
use crate::model::facts::{Call, Facts, UseCaseFacts};
use crate::model::paths::{AppItem, Modules, Origin, WrittenIn};
use crate::report::explain::ambiguous;
use crate::report::{Paint, Style};
use crate::source::syntax::{impl_fns, implemented_path, imports_of, items_of, line_of, type_name};
use crate::source::usage::Usage;
use crate::source::{Layer, Place, SourceFile, SupportFile, SupportKind, Workspace};

/// How many close names an unknown name's message offers.
const SUGGESTIONS: usize = 8;

/// Where something that reaches the target sits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Group {
    /// Domain code.
    Domain,
    /// A use case, through its `execute` or a helper it calls.
    UseCase,
    /// App code outside the use cases: services and app impls of ports.
    Service,
    /// An adapter crate.
    Adapter,
    /// A `test_support` file.
    Fake,
    /// A test: a file under `tests/` or a file's own unit tests.
    Test,
}

impl Group {
    /// Every group, in report order.
    const ALL: [Self; 6] = [
        Self::Domain,
        Self::UseCase,
        Self::Service,
        Self::Adapter,
        Self::Fake,
        Self::Test,
    ];

    fn title(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::UseCase => "use cases",
            Self::Service => "app services",
            Self::Adapter => "adapters",
            Self::Fake => "fakes",
            Self::Test => "tests",
        }
    }
}

/// Everything that reaches one target.
#[derive(Debug, Serialize)]
pub(crate) struct Impact {
    /// The name asked for.
    pub(crate) target: String,
    /// What it is, such as `port method`.
    pub(crate) kind: &'static str,
    /// Where it is declared.
    pub(crate) place: Place,
    /// What reaches it, by group, file and line.
    pub(crate) entries: Vec<Entry>,
}

/// One place that reaches the target.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct Entry {
    /// Its group.
    pub(crate) group: Group,
    /// Where.
    #[serde(flatten)]
    pub(crate) place: Place,
    /// How it reaches the target.
    pub(crate) what: String,
}

impl Impact {
    /// The impact with each entry in a parked crate marked `(parked)`: it
    /// is still read and listed, waiting for its crate's rebuild.
    pub(crate) fn marking_parked(mut self, parked: &[Parked]) -> Self {
        for entry in &mut self.entries {
            if parked.iter().any(|found| found.holds(&entry.place.file)) {
                entry.what.push_str(" (parked)");
            }
        }
        self
    }
}

/// What a name given to `impact` stands for.
enum Target<'a> {
    PortMethod(&'a PortTrait, &'a PortMethod),
    Port(&'a PortTrait),
    Change(&'a Behaviour),
    Type(String, Place),
    UseCase(&'a UseCaseFacts),
}

impl Target<'_> {
    fn kind(&self) -> &'static str {
        match self {
            Self::PortMethod(..) => "port method",
            Self::Port(_) => "port",
            Self::Change(behaviour) if behaviour.kind == BehaviourKind::Create => "domain creator",
            Self::Change(_) => "domain change",
            Self::Type(..) => "domain type",
            Self::UseCase(_) => "use case",
        }
    }

    fn place(&self) -> Place {
        match self {
            Self::PortMethod(_, method) => method.place.clone(),
            Self::Port(port) => port.place.clone(),
            Self::Change(behaviour) => behaviour.place.clone(),
            Self::Type(_, place) => place.clone(),
            Self::UseCase(use_case) => use_case.place.clone(),
        }
    }
}

/// Everything that reaches `name`: a port method (`WebhookStore::save`), a
/// port, a domain type or change (`WebhookSubscription::pause`), or a use
/// case (`CreateUseCase` or `webhooks::CreateUseCase`).
///
/// # Errors
///
/// A message saying why, when `name` names nothing or more than one use
/// case.
pub(crate) fn build(
    workspace: &Workspace,
    model: &Model,
    facts: &Facts,
    name: &str,
) -> Result<Impact, String> {
    let reader = Reader {
        workspace,
        model,
        facts,
        modules: Modules::of(workspace),
    };
    let target = reader.target(name)?;
    let entries: BTreeSet<Entry> = reader.entries(&target).into_iter().collect();
    Ok(Impact {
        target: name.to_owned(),
        kind: target.kind(),
        place: target.place(),
        entries: entries.into_iter().collect(),
    })
}

/// A line of a file and how it reaches the target.
type Mention = (usize, String);

struct Reader<'a> {
    workspace: &'a Workspace,
    model: &'a Model,
    facts: &'a Facts,
    modules: Modules<'a>,
}

/// A file as the name matchers read it: what it names, its syntax when the
/// whole file is read, and the app module it is, if it is one.
struct Written<'f> {
    usage: &'f Usage,
    syntax: Option<&'f syn::File>,
    here: Option<Vec<String>>,
}

impl<'f> Written<'f> {
    /// Where a path in this file is written.
    fn at(&self) -> WrittenIn<'_> {
        WrittenIn {
            syntax: self.syntax,
            here: self.here.as_deref(),
        }
    }

    fn source(file: &'f SourceFile) -> Self {
        Self {
            usage: file.usage(),
            syntax: file.syntax(),
            here: (file.layer == Layer::App).then(|| file.module_path()),
        }
    }

    fn support(file: &'f SupportFile) -> Self {
        Self {
            usage: file.usage(),
            syntax: file.syntax(),
            here: app_support_module(file),
        }
    }

    fn unit_tests(file: &'f SourceFile) -> Self {
        Self {
            usage: file.test_usage(),
            syntax: None,
            here: None,
        }
    }
}

/// The app module a `test_support` file of the app crate is.
fn app_support_module(file: &SupportFile) -> Option<Vec<String>> {
    let below = file
        .path
        .strip_prefix("src/")
        .filter(|_| file.crate_name == APP_CRATE_FOLDER)?;
    let mut parts: Vec<String> = below
        .trim_end_matches(".rs")
        .split('/')
        .map(str::to_owned)
        .collect();
    if parts.last().is_some_and(|last| last == "mod") {
        parts.pop();
    }
    Some(parts)
}

/// The app crate's folder.
const APP_CRATE_FOLDER: &str = "ianua-app";

impl<'a> Reader<'a> {
    fn target(&self, name: &str) -> Result<Target<'a>, String> {
        if let Some(port) = self.port_target(name)? {
            return Ok(port);
        }
        if let Some((head, tail)) = name.split_once("::") {
            return self.qualified(name, head, tail);
        }
        let named: Vec<&'a UseCaseFacts> = self
            .facts
            .use_cases
            .iter()
            .filter(|found| found.name == name)
            .collect();
        if !named.is_empty() {
            return one_use_case(name, &named);
        }
        let Some(place) = self.domain_type(name) else {
            return Err(self.unknown(name));
        };
        Ok(Target::Type(name.to_owned(), place))
    }

    /// The port or port method `name` stands for: `Port`, `Port::method`,
    /// or either after the port's context, `oauth::AssertionReplayGuard`,
    /// for a name several ports share. `None` when it names no port.
    ///
    /// # Errors
    ///
    /// A message listing the ports, when the name fits several.
    fn port_target(&self, name: &str) -> Result<Option<Target<'a>>, String> {
        let segments: Vec<&str> = name.split("::").collect();
        if let Some((port, qualifier)) = segments.split_last() {
            let ports = self.ports_matching(port, qualifier);
            if let Some(found) = one_port(name, &ports)? {
                return Ok(Some(Target::Port(found)));
            }
        }
        let [qualifier @ .., port, method] = segments.as_slice() else {
            return Ok(None);
        };
        let ports: Vec<&'a PortTrait> = self
            .ports_matching(port, qualifier)
            .into_iter()
            .filter(|found| found.methods.iter().any(|known| known.name == *method))
            .collect();
        let Some(found) = one_port(name, &ports)? else {
            return Ok(None);
        };
        let declared = found.methods.iter().find(|known| known.name == *method);
        Ok(declared.map(|declared| Target::PortMethod(found, declared)))
    }

    /// The ports named `name` whose module path holds `qualifier`, in
    /// order, such as `["oauth"]` for `ports::oauth::proofs`.
    fn ports_matching(&self, name: &str, qualifier: &[&str]) -> Vec<&'a PortTrait> {
        self.model
            .app
            .ports_named(name)
            .filter(|port| {
                qualifier.is_empty()
                    || port
                        .item
                        .module
                        .windows(qualifier.len())
                        .any(|window| window.iter().zip(qualifier).all(|(a, b)| a == b))
            })
            .collect()
    }

    fn qualified(&self, name: &str, head: &str, tail: &str) -> Result<Target<'a>, String> {
        let behaviour = self
            .model
            .domain
            .behaviours
            .iter()
            .find(|found| found.owner == head && found.name == tail);
        if let Some(behaviour) = behaviour {
            return Ok(Target::Change(behaviour));
        }
        let named: Vec<&'a UseCaseFacts> = self
            .facts
            .use_cases
            .iter()
            .filter(|found| found.context == head && found.name == tail)
            .collect();
        if named.is_empty() {
            return Err(self.unknown(name));
        }
        one_use_case(name, &named)
    }

    /// Where the domain declares the type `name`.
    fn domain_type(&self, name: &str) -> Option<Place> {
        let aggregate = self
            .model
            .domain
            .aggregates
            .iter()
            .find(|found| found.name == name)
            .map(|found| found.place.clone());
        aggregate.or_else(|| {
            self.workspace
                .layer(Layer::Domain)
                .find_map(|file| declared_in(file, name))
        })
    }

    fn unknown(&self, name: &str) -> String {
        let wanted = name.to_lowercase();
        let ports = self.model.app.ports.iter().flat_map(|port| {
            std::iter::once(port.name.clone()).chain(
                port.methods
                    .iter()
                    .map(|method| format!("{}::{}", port.name, method.name)),
            )
        });
        let domain = self
            .model
            .domain
            .behaviours
            .iter()
            .flat_map(|found| [found.owner.clone(), found.subject()]);
        let use_cases = self.facts.use_cases.iter().map(|found| found.name.clone());
        let close: Vec<String> = ports
            .chain(domain)
            .chain(use_cases)
            .filter(|candidate| candidate.to_lowercase().contains(&wanted))
            .collect::<BTreeSet<String>>()
            .into_iter()
            .take(SUGGESTIONS)
            .collect();
        let message =
            format!("no port, port method, use case, domain type or change named `{name}`");
        match close.as_slice() {
            [] => message,
            _ => format!("{message}; close names: {}", close.join(", ")),
        }
    }

    fn entries(&self, target: &Target<'a>) -> Vec<Entry> {
        match target {
            Target::PortMethod(port, method) => self.port_entries(port, Some(&method.name)),
            Target::Port(port) => self.port_entries(port, None),
            Target::Change(behaviour) => self.change_entries(behaviour),
            Target::Type(name, place) => self.type_entries(name, place),
            Target::UseCase(use_case) => self.use_case_entries(use_case),
        }
    }

    fn port_entries(&self, port: &PortTrait, method: Option<&str>) -> Vec<Entry> {
        let reaching: Vec<&UseCaseFacts> = self
            .facts
            .use_cases
            .iter()
            .filter(|use_case| !use_case_port_entries(use_case, &port.item, method).is_empty())
            .collect();
        let mut found: Vec<Entry> = reaching
            .iter()
            .flat_map(|use_case| use_case_port_entries(use_case, &port.item, method))
            .collect();
        found.extend(self.service_port_calls(&port.item, method));
        let implementations = self.implementations(&port.item, method);
        let implementing: BTreeSet<String> = implementations
            .iter()
            .map(|entry| entry.place.file.clone())
            .collect();
        found.extend(implementations);
        found.extend(self.adapters_calling(port, method, &implementing));
        let (fakes, fake_types) = self.fakes_implementing(&port.item, method);
        found.extend(fakes);
        let by_name = |written: &Written<'_>| {
            let fake = first_named(written.usage, &fake_types);
            let named = self
                .names_port(written, port)
                .map(|line| (line, format!("names {}", port.name)));
            fake.into_iter().chain(named).min()
        };
        found.extend(self.tests_by(by_name, &reaching));
        found
    }

    /// The line of `written` naming `port`. A name several ports share
    /// counts only where an import or a path written in the file leads to
    /// this one.
    fn names_port(&self, written: &Written<'_>, port: &PortTrait) -> Option<usize> {
        let line = *written.usage.idents.get(&port.name)?;
        if self.model.app.ports_named(&port.name).count() == 1 {
            return Some(line);
        }
        let by_import = written
            .syntax
            .map(imports_of)
            .unwrap_or_default()
            .into_iter()
            .filter(|import| import.original == port.name)
            .map(|import| vec![import.local]);
        let by_path = written
            .usage
            .pairs
            .iter()
            .filter(|pair| pair.name == port.name)
            .map(|pair| vec![pair.owner.clone(), pair.name.clone()]);
        let wanted = PortLookup::Found(port.item.clone());
        by_import
            .chain(by_path)
            .any(|path| self.port_written(written, &path) == wanted)
            .then_some(line)
    }

    /// The port the path `path` names in `written`.
    fn port_written(&self, written: &Written<'_>, path: &[String]) -> PortLookup {
        self.model
            .app
            .port_written(&self.modules, written.at(), path)
    }

    fn service_port_calls(&self, port: &AppItem, method: Option<&str>) -> Vec<Entry> {
        self.facts
            .services
            .iter()
            .flat_map(|service| {
                service
                    .port_calls
                    .iter()
                    .filter(|(called, name, _)| called == port && method.is_none_or(|m| m == name))
                    .map(|(_, name, place)| Entry {
                        group: Group::Service,
                        place: place.clone(),
                        what: format!("{} calls {name}", service.function),
                    })
            })
            .collect()
    }

    fn implementations(&self, port: &AppItem, method: Option<&str>) -> Vec<Entry> {
        self.model
            .impls
            .iter()
            .filter(|block| block.implements(port))
            .map(|block| {
                let group = match block.layer {
                    Layer::Domain => Group::Domain,
                    Layer::App => Group::Service,
                    Layer::Adapter => Group::Adapter,
                };
                let written =
                    method.is_none_or(|name| block.methods.iter().any(|found| found == name));
                let what = match written {
                    true => format!("{} implements it ({})", block.self_type, block.crate_name),
                    false => format!(
                        "{} implements the port and keeps the default body ({})",
                        block.self_type, block.crate_name
                    ),
                };
                let place = method.map_or_else(|| block.place.clone(), |name| block.place_of(name));
                Entry { group, place, what }
            })
            .collect()
    }

    fn adapters_calling(
        &self,
        port: &PortTrait,
        method: Option<&str>,
        implementing: &BTreeSet<String>,
    ) -> Vec<Entry> {
        self.workspace
            .layer(Layer::Adapter)
            .filter(|file| !implementing.contains(&file.display_path()))
            .filter_map(|file| {
                let usage = file.usage();
                let named = self.names_port(&Written::source(file), port)?;
                let (line, what) = match method {
                    Some(name) => (
                        usage
                            .method_calls
                            .iter()
                            .find(|call| call.name == name)?
                            .line,
                        format!("names {} and calls `{name}`", port.name),
                    ),
                    None => (named, "names it".to_owned()),
                };
                Some(Entry {
                    group: Group::Adapter,
                    place: Place::at(file, line),
                    what,
                })
            })
            .collect()
    }

    /// The fakes implementing `port`, and their types' names.
    fn fakes_implementing(
        &self,
        port: &AppItem,
        method: Option<&str>,
    ) -> (Vec<Entry>, BTreeSet<String>) {
        let mut entries = Vec::new();
        let mut types = BTreeSet::new();
        for file in self.support(SupportKind::Fake) {
            let written = Written::support(file);
            let Some(syntax) = written.syntax else {
                continue;
            };
            let of_port = |path: &[String]| self.port_written(&written, path).found() == Some(port);
            for (self_type, line) in implementing(syntax, of_port, method) {
                entries.push(Entry {
                    group: Group::Fake,
                    place: Place {
                        file: file.display_path(),
                        line,
                    },
                    what: format!("{self_type} implements it"),
                });
                types.insert(self_type);
            }
        }
        (entries, types)
    }

    fn change_entries(&self, behaviour: &Behaviour) -> Vec<Entry> {
        let reaching = self.callers_of(&behaviour.owner, Some(&behaviour.name));
        let mut found: Vec<Entry> = self
            .facts
            .use_cases
            .iter()
            .flat_map(|use_case| {
                change_call_entries(use_case, &behaviour.owner, Some(&behaviour.name))
            })
            .collect();
        found.extend(self.service_changes(&behaviour.owner, Some(&behaviour.name)));
        let calls = |usage: &Usage| self.calls_change(usage, behaviour);
        found.extend(
            self.workspace
                .layer(Layer::Domain)
                .filter(|file| file.display_path() != behaviour.place.file)
                .filter_map(|file| mentioned(Group::Domain, file, calls(file.usage()))),
        );
        found.extend(
            self.workspace
                .layer(Layer::Adapter)
                .filter_map(|file| mentioned(Group::Adapter, file, calls(file.usage()))),
        );
        found.extend(self.support_mentions(SupportKind::Fake, Group::Fake, calls));
        found.extend(self.tests_by(|written| calls(written.usage), &reaching));
        found
    }

    /// The line of `usage` that calls `behaviour`: a creator by its path,
    /// a change by its name in a file that names its type.
    fn calls_change(&self, usage: &Usage, behaviour: &Behaviour) -> Option<Mention> {
        match behaviour.kind {
            BehaviourKind::Create => usage
                .pairs
                .iter()
                .find(|pair| {
                    pair.name == behaviour.name
                        && self.stands_for(usage.unaliased(&pair.owner), &behaviour.owner)
                })
                .map(|pair| (pair.line, format!("calls {}", behaviour.subject()))),
            BehaviourKind::Change => {
                usage.idents.get(&behaviour.owner)?;
                usage
                    .method_calls
                    .iter()
                    .find(|call| call.name == behaviour.name)
                    .map(|call| {
                        (
                            call.line,
                            format!("names {} and calls `{}`", behaviour.owner, behaviour.name),
                        )
                    })
            }
        }
    }

    /// Whether `written` is `owner` or a domain alias of it.
    fn stands_for(&self, written: &str, owner: &str) -> bool {
        written == owner
            || self
                .model
                .domain
                .aliases
                .get(written)
                .is_some_and(|target| target == owner)
    }

    fn type_entries(&self, name: &str, place: &Place) -> Vec<Entry> {
        let reaching = self.callers_of(name, None);
        let mut found: Vec<Entry> = (self.model.domain.behaviours.iter())
            .filter(|behaviour| behaviour.owner == name)
            .map(|behaviour| Entry {
                group: Group::Domain,
                place: behaviour.place.clone(),
                what: format!("{} {}", behaviour.kind.as_str(), behaviour.subject()),
            })
            .collect();
        let names =
            |usage: &Usage| (usage.idents.get(name)).map(|line| (*line, "names it".to_owned()));
        let domain =
            (self.workspace.layer(Layer::Domain)).filter(|file| file.display_path() != place.file);
        found.extend(domain.filter_map(|file| mentioned(Group::Domain, file, names(file.usage()))));
        let changes = self.facts.use_cases.iter();
        found.extend(changes.flat_map(|use_case| change_call_entries(use_case, name, None)));
        found.extend(self.use_cases_naming(name, &reaching));
        found.extend(self.service_changes(name, None));
        let adapters = self.workspace.layer(Layer::Adapter);
        found.extend(
            adapters.filter_map(|file| mentioned(Group::Adapter, file, names(file.usage()))),
        );
        found.extend(self.support_mentions(SupportKind::Fake, Group::Fake, names));
        found.extend(self.tests_by(|written| names(written.usage), &reaching));
        found
    }

    /// The use cases whose file names `name` though no change of it is
    /// read in them.
    fn use_cases_naming(&self, name: &str, reaching: &[&UseCaseFacts]) -> Vec<Entry> {
        self.model
            .app
            .use_cases
            .iter()
            .zip(&self.facts.use_cases)
            .filter(|(_, facts)| !reaching.iter().any(|found| found.place == facts.place))
            .filter_map(|(use_case, facts)| {
                let file = &self.workspace.files[use_case.file_index];
                let line = *file.usage().idents.get(name)?;
                Some(Entry {
                    group: Group::UseCase,
                    place: Place::at(file, line),
                    what: format!("{} ({}) names it", facts.name, facts.context),
                })
            })
            .collect()
    }

    fn use_case_entries(&self, use_case: &UseCaseFacts) -> Vec<Entry> {
        let names = |written: &Written<'_>| {
            self.names_use_case(written, use_case)
                .map(|line| (line, "names it".to_owned()))
        };
        let others = self
            .workspace
            .files
            .iter()
            .filter(|file| {
                file.layer != Layer::Domain && file.display_path() != use_case.place.file
            })
            .filter_map(|file| {
                let group = match (file.layer, file.path.starts_with("use_cases/")) {
                    (Layer::Adapter, _) => Group::Adapter,
                    (_, true) => Group::UseCase,
                    (_, false) => Group::Service,
                };
                mentioned(group, file, names(&Written::source(file)))
            });
        let mut found: Vec<Entry> = others.collect();
        found.extend(
            self.support(SupportKind::Fake).filter_map(|file| {
                support_entry(Group::Fake, file, names(&Written::support(file)))
            }),
        );
        found.extend(self.tests_by(names, &[use_case]));
        found
    }

    /// The line of `written` naming `use_case`. A name several use cases
    /// share counts only where an import or a path written in the file
    /// leads to its own module.
    fn names_use_case(&self, written: &Written<'_>, use_case: &UseCaseFacts) -> Option<usize> {
        let line = *written.usage.idents.get(&use_case.name)?;
        let named = |found: &&UseCaseFacts| found.name == use_case.name;
        if self.facts.use_cases.iter().filter(named).count() <= 1 {
            return Some(line);
        }
        let wanted = Origin::Declared(AppItem {
            module: self.module_of(use_case)?,
            name: use_case.name.clone(),
        });
        let by_import = (written
            .syntax
            .map(imports_of)
            .unwrap_or_default()
            .into_iter())
        .filter(|import| import.original == use_case.name)
        .map(|import| vec![import.local]);
        let by_path = (written.usage.pairs.iter())
            .filter(|pair| pair.name == use_case.name)
            .map(|pair| vec![pair.owner.clone(), pair.name.clone()]);
        (by_import.chain(by_path))
            .any(|path| self.modules.origin_in(written.at(), &path) == wanted)
            .then_some(line)
    }

    /// The module path of the file `use_case` is in.
    fn module_of(&self, use_case: &UseCaseFacts) -> Option<Vec<String>> {
        self.model
            .app
            .use_cases
            .iter()
            .find(|found| found.place == use_case.place)
            .map(|found| self.workspace.files[found.file_index].module_path())
    }

    /// The use cases that call `name` of `owner`, or any change of it.
    fn callers_of(&self, owner: &str, name: Option<&str>) -> Vec<&'a UseCaseFacts> {
        self.facts
            .use_cases
            .iter()
            .filter(|use_case| !change_call_entries(use_case, owner, name).is_empty())
            .collect()
    }

    fn service_changes(&self, owner: &str, name: Option<&str>) -> Vec<Entry> {
        self.facts
            .services
            .iter()
            .flat_map(|service| {
                service
                    .changes
                    .iter()
                    .filter(|(called, change, _)| {
                        called == owner && name.is_none_or(|wanted| wanted == change)
                    })
                    .map(|(called, change, place)| Entry {
                        group: Group::Service,
                        place: place.clone(),
                        what: format!("{} calls {called}::{change}", service.function),
                    })
            })
            .collect()
    }

    fn support(&self, kind: SupportKind) -> impl Iterator<Item = &'a SupportFile> {
        self.workspace
            .support
            .iter()
            .filter(move |file| file.kind == kind)
    }

    fn support_mentions(
        &self,
        kind: SupportKind,
        group: Group,
        mention: impl Fn(&Usage) -> Option<Mention>,
    ) -> Vec<Entry> {
        self.support(kind)
            .filter_map(|file| support_entry(group, file, mention(file.usage())))
            .collect()
    }

    /// The first line of `written` naming one of `reaching`, and which.
    fn first_naming(&self, written: &Written<'_>, reaching: &[&UseCaseFacts]) -> Option<Mention> {
        (reaching.iter())
            .filter_map(|use_case| {
                let line = self.names_use_case(written, use_case)?;
                Some((line, format!("names {}", use_case.name)))
            })
            .min()
    }

    /// The tests that reach the target: files under `tests/` that `mention`
    /// finds or that name one of `reaching`, and unit tests that `mention`
    /// finds or that sit in the file of one of `reaching`.
    fn tests_by(
        &self,
        mention: impl Fn(&Written<'_>) -> Option<Mention>,
        reaching: &[&UseCaseFacts],
    ) -> Vec<Entry> {
        let in_tests = self.support(SupportKind::Test).filter_map(|file| {
            let written = Written::support(file);
            let by_target = mention(&written);
            let by_use_case = self.first_naming(&written, reaching);
            let found = by_target.into_iter().chain(by_use_case).min();
            support_entry(Group::Test, file, found)
        });
        let unit = self.workspace.files.iter().filter_map(|file| {
            let usage = file.test_usage();
            let own = reaching
                .iter()
                .find(|use_case| use_case.place.file == file.display_path())
                .filter(|_| !usage.idents.is_empty())
                .map(|use_case| {
                    (
                        first_line(usage),
                        format!("unit tests of {}", use_case.name),
                    )
                });
            let found = own.or_else(|| {
                mention(&Written::unit_tests(file))
                    .map(|(line, what)| (line, format!("unit tests: {what}")))
            });
            mentioned(Group::Test, file, found)
        });
        in_tests.chain(unit).collect()
    }
}

/// The one port of `ports`, none when empty.
///
/// # Errors
///
/// A message listing them, when `name` fits several.
fn one_port<'a>(name: &str, ports: &[&'a PortTrait]) -> Result<Option<&'a PortTrait>, String> {
    match ports {
        [] => Ok(None),
        [only] => Ok(Some(only)),
        _ => {
            let paths: Vec<String> = ports.iter().map(|port| port.item.path()).collect();
            let example = ports
                .first()
                .and_then(|port| port.item.module.get(1).map(|context| (context, &port.name)))
                .map_or_else(String::new, |(context, port)| {
                    format!("; name one after its context, such as `{context}::{port}`")
                });
            Err(format!(
                "`{name}` names {} ports: {}{example}",
                ports.len(),
                paths.join(", ")
            ))
        }
    }
}

fn one_use_case<'a>(name: &str, named: &[&'a UseCaseFacts]) -> Result<Target<'a>, String> {
    match named {
        [only] => Ok(Target::UseCase(only)),
        _ => Err(ambiguous(name, named)),
    }
}

/// Where `file` declares a struct, enum or trait named `name`.
fn declared_in(file: &SourceFile, name: &str) -> Option<Place> {
    items_of(file.syntax()?).into_iter().find_map(|item| {
        let ident = match item {
            Item::Struct(declared) => &declared.ident,
            Item::Enum(declared) => &declared.ident,
            Item::Trait(declared) => &declared.ident,
            _ => return None,
        };
        (ident == name).then(|| Place::of(file, ident))
    })
}

/// The entry for `call`, a port call `use_case` makes.
fn port_call_entry(use_case: &UseCaseFacts, call: &Call) -> Entry {
    let text = format!(
        "{} ({}) calls {}",
        use_case.name, use_case.context, call.name
    );
    Entry {
        group: Group::UseCase,
        place: call.place.clone(),
        what: with_via(&text, call.via.as_deref()),
    }
}

/// The entries for the calls `use_case` makes of `method` of `port`, or of
/// any of its methods; when none and any method is wanted, one saying it
/// holds the port.
fn use_case_port_entries(
    use_case: &UseCaseFacts,
    port: &AppItem,
    method: Option<&str>,
) -> Vec<Entry> {
    use_case
        .ports
        .iter()
        .filter(|held| held.port.as_ref() == Some(port))
        .flat_map(|held| {
            let calls: Vec<Entry> = (held.calls.iter())
                .filter(|call| method.is_none_or(|wanted| wanted == call.name))
                .map(|call| port_call_entry(use_case, call))
                .collect();
            let holds = (calls.is_empty() && method.is_none()).then(|| Entry {
                group: Group::UseCase,
                place: use_case.place.clone(),
                what: format!(
                    "{} ({}) holds it in {}, no call read",
                    use_case.name,
                    use_case.context,
                    held.field.as_deref().unwrap_or("a field not read")
                ),
            });
            calls.into_iter().chain(holds)
        })
        .collect()
}

/// The entries for the calls `use_case` makes of `name` of `owner`, or of
/// any change of it.
fn change_call_entries(use_case: &UseCaseFacts, owner: &str, name: Option<&str>) -> Vec<Entry> {
    use_case
        .changes
        .iter()
        .filter(|change| change.owner == owner && name.is_none_or(|wanted| wanted == change.name))
        .map(|change| Entry {
            group: Group::UseCase,
            place: change.place.clone(),
            what: with_via(
                &format!(
                    "{} ({}) calls {}",
                    use_case.name,
                    use_case.context,
                    change.subject()
                ),
                change.via.as_deref(),
            ),
        })
        .collect()
}

/// Every `impl Trait for Type` in `syntax` whose trait's path `of_port`
/// says is the port, each type with the line of `method`, or of the `impl`
/// when no method is wanted or written.
fn implementing(
    syntax: &syn::File,
    of_port: impl Fn(&[String]) -> bool,
    method: Option<&str>,
) -> Vec<(String, usize)> {
    items_of(syntax)
        .into_iter()
        .filter_map(|item| match item {
            Item::Impl(block) if implemented_path(block).is_some_and(|path| of_port(&path)) => {
                Some(block)
            }
            _ => None,
        })
        .filter_map(|block| {
            let self_type = type_name(&block.self_ty)?;
            let line = method
                .and_then(|name| impl_fns(block).find(|function| function.sig.ident == name))
                .map_or_else(
                    || line_of(&block.self_ty),
                    |function| line_of(&function.sig.ident),
                );
            Some((self_type, line))
        })
        .collect()
}

/// The first line of `usage` naming one of `names`.
fn first_named(usage: &Usage, names: &BTreeSet<String>) -> Option<Mention> {
    names
        .iter()
        .filter_map(|name| Some((*usage.idents.get(name)?, format!("names {name}"))))
        .min()
}

fn first_line(usage: &Usage) -> usize {
    usage.idents.values().min().copied().unwrap_or(0)
}

fn mentioned(group: Group, file: &SourceFile, found: Option<Mention>) -> Option<Entry> {
    let (line, what) = found?;
    Some(Entry {
        group,
        place: Place::at(file, line),
        what,
    })
}

fn support_entry(group: Group, file: &SupportFile, found: Option<Mention>) -> Option<Entry> {
    let (line, what) = found?;
    Some(Entry {
        group,
        place: Place {
            file: file.display_path(),
            line,
        },
        what,
    })
}

fn with_via(text: &str, via: Option<&str>) -> String {
    match via {
        Some(via) => format!("{text} via {via}"),
        None => text.to_owned(),
    }
}

fn location(place: &Place) -> String {
    format!("{}:{}", place.file, place.line)
}

/// How many entries each group holds.
fn counts(impact: &Impact) -> BTreeMap<Group, usize> {
    let mut counted: BTreeMap<Group, usize> =
        Group::ALL.into_iter().map(|group| (group, 0)).collect();
    for entry in &impact.entries {
        *counted.entry(entry.group).or_default() += 1;
    }
    counted
}

/// `12 places: domain 0, use cases 8, ...`.
fn count_line(impact: &Impact) -> String {
    let counted = counts(impact);
    let parts: Vec<String> = Group::ALL
        .into_iter()
        .map(|group| {
            format!(
                "{} {}",
                group.title(),
                counted.get(&group).copied().unwrap_or(0)
            )
        })
        .collect();
    format!("{} places: {}", impact.entries.len(), parts.join(", "))
}

fn of_group(impact: &Impact, group: Group) -> Vec<&Entry> {
    impact
        .entries
        .iter()
        .filter(|entry| entry.group == group)
        .collect()
}

/// The impact as text for a terminal.
pub(crate) fn render_text(impact: &Impact, style: Style) -> String {
    let mut out = format!(
        "{} {}  {}  {}\n",
        style.paint("impact of", Paint::Heading),
        style.paint(&impact.target, Paint::Heading),
        impact.kind,
        style.paint(&location(&impact.place), Paint::Dim)
    );
    for group in Group::ALL {
        let entries = of_group(impact, group);
        if entries.is_empty() {
            continue;
        }
        let _ = writeln!(
            out,
            "\n{} ({})",
            style.paint(group.title(), Paint::Heading),
            entries.len()
        );
        for entry in entries {
            let _ = writeln!(
                out,
                "  {}  {}",
                style.paint(&location(&entry.place), Paint::Dim),
                entry.what
            );
        }
    }
    let _ = writeln!(out, "\n{}", count_line(impact));
    out
}

/// The impact as Markdown.
pub(crate) fn render_markdown(impact: &Impact) -> String {
    let mut out = format!(
        "## Impact of `{}`\n\n{}, declared at `{}`.\n",
        impact.target,
        impact.kind,
        location(&impact.place)
    );
    for group in Group::ALL {
        let entries = of_group(impact, group);
        if entries.is_empty() {
            continue;
        }
        let _ = writeln!(out, "\n### {} ({})\n", group.title(), entries.len());
        for entry in entries {
            let _ = writeln!(out, "- `{}`: {}", location(&entry.place), entry.what);
        }
    }
    let _ = writeln!(out, "\n{}", count_line(impact));
    out
}

#[derive(Serialize)]
struct JsonImpact<'a> {
    #[serde(flatten)]
    impact: &'a Impact,
    counts: BTreeMap<Group, usize>,
}

/// The impact as pretty JSON, with a count per group.
///
/// # Errors
///
/// Fails only if serialising fails, which these plain types do not.
pub(crate) fn render_json(impact: &Impact) -> serde_json::Result<String> {
    serde_json::to_string_pretty(&JsonImpact {
        impact,
        counts: counts(impact),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::facts::planted::{
        CREATE, LIMITS, LIST, LOOKUP, PAUSE, PORTS, ROOM, SUBSCRIPTION, model,
    };
    use crate::source::planted::{adapter, app, domain, fake, test, with_support};

    const PG_STORE: &str = r"
        impl WebhookStore for PgWebhookStore {
            async fn find_by_id(&self) -> Result<Option<WebhookSubscription<ResolvedTenant>>, DomainError> { load() }
            async fn save(&self) -> Result<(), DomainError> { store() }
        }
    ";

    const HANDLER: &str = r"
        use ianua_app::use_cases::webhooks::subscriptions::create::CreateUseCase;
        async fn create(state: State) -> Response { state.create.execute(&caller, &auditor, request).await }
    ";

    const FAKE_STORE: &str = r"
        impl WebhookStore for FakeWebhookStore {
            async fn find_by_id(&self) -> Result<Option<WebhookSubscription<ResolvedTenant>>, DomainError> { found() }
            async fn save(&self) -> Result<(), DomainError> { Ok(()) }
        }
    ";

    const API_TEST: &str = r"
        #[test]
        fn creates_a_webhook() { let store = FakeWebhookStore::empty(); }
    ";

    fn impact(name: &str) -> Result<Impact, String> {
        let ws = with_support(
            vec![
                domain("domains/webhooks/subscription.rs", SUBSCRIPTION),
                app("ports/webhooks.rs", PORTS),
                app("ports/limits.rs", LIMITS),
                app("services/limits/room.rs", ROOM),
                app("use_cases/webhooks/lookup.rs", LOOKUP),
                app("use_cases/webhooks/subscriptions/create.rs", CREATE),
                app("use_cases/webhooks/subscriptions/pause.rs", PAUSE),
                app("use_cases/webhooks/subscriptions/list.rs", LIST),
                adapter("ianua-infra", "postgres/webhooks.rs", PG_STORE),
                adapter("ianua-api", "handlers/webhooks.rs", HANDLER),
            ],
            vec![
                fake("ianua-app", "src/test_support/webhooks.rs", FAKE_STORE),
                test("ianua-api", "tests/api/webhooks.rs", API_TEST),
            ],
        );
        let model = model(&ws);
        let facts = Facts::build(&ws, &model);
        build(&ws, &model, &facts, name)
    }

    fn lines(found: &Impact, group: Group) -> Vec<String> {
        of_group(found, group)
            .into_iter()
            .map(|entry| format!("{}:{}  {}", entry.place.file, entry.place.line, entry.what))
            .collect()
    }

    #[test]
    fn a_port_method_reaches_its_callers_implementations_fakes_and_tests() {
        let found = impact("WebhookStore::save").unwrap();

        let use_cases: Vec<&str> = of_group(&found, Group::UseCase)
            .into_iter()
            .map(|entry| entry.what.as_str())
            .collect();
        assert_eq!(found.kind, "port method");
        assert_eq!(
            use_cases,
            [
                "CreateUseCase (webhooks) calls save",
                "PauseUseCase (webhooks) calls save"
            ]
        );
        assert_eq!(
            lines(&found, Group::Adapter),
            [
                "crates/ianua-infra/src/postgres/webhooks.rs:4  PgWebhookStore implements it (ianua-infra)"
            ]
        );
        assert_eq!(
            lines(&found, Group::Fake),
            ["crates/ianua-app/src/test_support/webhooks.rs:4  FakeWebhookStore implements it"]
        );
        assert_eq!(
            lines(&found, Group::Test),
            ["crates/ianua-api/tests/api/webhooks.rs:3  names FakeWebhookStore"]
        );
    }

    #[test]
    fn a_file_of_a_parked_crate_is_still_listed_and_marked() {
        let parked = [Parked {
            crate_name: "ianua-infra".to_owned(),
            reason: "rebuilt".to_owned(),
        }];

        let found = impact("WebhookStore::save")
            .unwrap()
            .marking_parked(&parked);

        assert_eq!(
            lines(&found, Group::Adapter),
            [
                "crates/ianua-infra/src/postgres/webhooks.rs:4  PgWebhookStore implements it (ianua-infra) (parked)"
            ]
        );
    }

    #[test]
    fn the_count_line_counts_every_group() {
        let found = impact("WebhookStore::save").unwrap();

        let text = render_text(&found, Style::new(false));

        assert!(text.starts_with(
            "impact of WebhookStore::save  port method  crates/ianua-app/src/ports/webhooks.rs:"
        ));
        assert!(text.ends_with(
            "\n5 places: domain 0, use cases 2, app services 0, adapters 1, fakes 1, tests 1\n"
        ));
    }

    #[test]
    fn a_port_method_called_through_a_helper_says_which() {
        let found = impact("WebhookStore::find_by_id").unwrap();

        let use_cases: Vec<&str> = of_group(&found, Group::UseCase)
            .into_iter()
            .map(|entry| entry.what.as_str())
            .collect();
        assert_eq!(
            use_cases,
            ["PauseUseCase (webhooks) calls find_by_id via existing_subscription"]
        );
    }

    #[test]
    fn a_service_calling_a_port_is_in_the_app_services() {
        let found = impact("LimitEnforcer").unwrap();

        assert_eq!(found.kind, "port");
        assert_eq!(
            of_group(&found, Group::Service)[0].what,
            "ensure_room_in_tenant calls check_tenant_limit"
        );
    }

    #[test]
    fn a_domain_change_reaches_the_use_cases_that_call_it() {
        let found = impact("WebhookSubscription::pause").unwrap();

        assert_eq!(found.kind, "domain change");
        assert_eq!(
            of_group(&found, Group::UseCase)[0].what,
            "PauseUseCase (webhooks) calls WebhookSubscription::pause"
        );
    }

    #[test]
    fn a_use_case_reaches_the_adapters_that_import_it() {
        let found = impact("CreateUseCase").unwrap();

        assert_eq!(
            lines(&found, Group::Adapter),
            ["crates/ianua-api/src/handlers/webhooks.rs:2  names it"]
        );
    }

    /// Two contexts have a `CreateUseCase`. The webhooks one is wired
    /// through its module path, the messaging one by an import; each
    /// adapter counts only for its own.
    #[test]
    fn a_shared_use_case_name_counts_only_where_its_path_leads_to_it() {
        let ws = shared_create_use_cases();
        let model = model(&ws);
        let facts = Facts::build(&ws, &model);

        let found = build(&ws, &model, &facts, "webhooks::CreateUseCase").unwrap();

        assert_eq!(
            lines(&found, Group::Adapter),
            ["crates/ianua-api/src/state/webhooks.rs:2  names it"]
        );
    }

    /// Webhooks' and messaging's `CreateUseCase`, each wired by its own
    /// adapter: one through its module path, one by an import.
    fn shared_create_use_cases() -> Workspace {
        with_support(
            vec![
                app(
                    "use_cases/webhooks/subscriptions/mod.rs",
                    "pub mod create;\npub use create::CreateUseCase;",
                ),
                app("use_cases/webhooks/subscriptions/create.rs", CREATE),
                app(
                    "use_cases/messaging/create.rs",
                    "pub struct CreateUseCase;\nimpl Command for CreateUseCase {}",
                ),
                adapter(
                    "ianua-api",
                    "state/webhooks.rs",
                    "use ianua_app::use_cases::webhooks::subscriptions;\nfn wire() { subscriptions::CreateUseCase::new(ports); }",
                ),
                adapter(
                    "ianua-api",
                    "state/messaging.rs",
                    "use ianua_app::use_cases::messaging::create::CreateUseCase;\nfn wire() { CreateUseCase::new(ports); }",
                ),
            ],
            Vec::new(),
        )
    }

    #[test]
    fn an_unknown_name_is_refused_with_close_names() {
        let message = impact("WebhookStore::delete").unwrap_err();

        assert_eq!(
            message,
            "no port, port method, use case, domain type or change named `WebhookStore::delete`"
        );
        assert!(
            impact("Store")
                .unwrap_err()
                .contains("close names: WebhookStore")
        );
    }

    #[test]
    fn markdown_and_json_carry_the_same_entries() {
        let found = impact("WebhookStore::save").unwrap();

        let markdown = render_markdown(&found);
        let value: serde_json::Value = serde_json::from_str(&render_json(&found).unwrap()).unwrap();

        assert!(markdown.contains("### fakes (1)\n\n- `crates/ianua-app/src/test_support/webhooks.rs:4`: FakeWebhookStore implements it\n"));
        assert_eq!(value["counts"]["use-case"], 2);
        assert_eq!(value["entries"][0]["group"], "use-case");
    }
}
