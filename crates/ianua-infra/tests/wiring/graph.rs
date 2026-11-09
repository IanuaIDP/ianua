//! The wiring graph: every port the app defines, the adapters that
//! implement it, and the use cases and state that use it.

use std::collections::{BTreeMap, BTreeSet};

use syn::Item;
use syn::visit::{self, Visit};

use crate::sources::{CRATES, Source, sources_of};

/// Traits under `ports/` that mark a store rather than describe one.
const MARKERS: &[&str] = &["TenantScoped"];

/// An adapter: a type implementing a port, and where it lives.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub(crate) struct Adapter {
    /// The crate it is in.
    #[serde(rename = "crate")]
    pub crate_name: &'static str,
    /// Its type's name.
    pub name: String,
    /// Its file, under the crate's `src/`.
    pub file: String,
}

/// One port and everything wired to it.
#[derive(Debug, Default, serde::Serialize)]
pub(crate) struct Port {
    /// The module under `ports/` it is declared in.
    pub module: String,
    /// The types implementing it outside tests.
    pub adapters: BTreeSet<Adapter>,
    /// The files that hold it as a `dyn` port: use cases, services and
    /// the API's state.
    pub used_by: BTreeSet<String>,
}

/// Every port, by name.
#[derive(Debug, Default, serde::Serialize)]
pub(crate) struct Graph {
    /// The ports, in name order.
    pub ports: BTreeMap<String, Port>,
}

impl Graph {
    /// The graph as the source stands now.
    pub(crate) fn read() -> Self {
        let sources: Vec<Source> = CRATES.iter().flat_map(|name| sources_of(name)).collect();
        let mut graph = Self::default();
        graph.declare_ports(&sources);
        graph.add_adapters(&sources);
        graph.add_uses(&sources);
        graph
    }

    /// The ports nothing implements yet.
    pub(crate) fn unbuilt(&self) -> BTreeSet<&str> {
        self.ports
            .iter()
            .filter(|(_, port)| port.adapters.is_empty())
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// The ports nothing uses.
    pub(crate) fn unused(&self) -> BTreeSet<&str> {
        self.ports
            .iter()
            .filter(|(_, port)| port.used_by.is_empty())
            .map(|(name, _)| name.as_str())
            .collect()
    }

    fn declare_ports(&mut self, sources: &[Source]) {
        for source in sources.iter().filter(|source| is_port_file(source)) {
            for item in &source.items {
                let Item::Trait(declared) = item else {
                    continue;
                };
                let name = declared.ident.to_string();
                if MARKERS.contains(&name.as_str()) {
                    continue;
                }
                let module = source
                    .path
                    .trim_start_matches("ports/")
                    .trim_end_matches(".rs");
                self.ports.entry(name).or_default().module =
                    module.trim_end_matches("/mod").to_owned();
            }
        }
    }

    fn add_adapters(&mut self, sources: &[Source]) {
        for source in sources {
            for item in &source.items {
                let Some((port, adapter)) = implemented(item) else {
                    continue;
                };
                let Some(entry) = self.ports.get_mut(&port) else {
                    continue;
                };
                entry.adapters.insert(Adapter {
                    crate_name: source.crate_name,
                    name: adapter,
                    file: source.path.clone(),
                });
            }
        }
    }

    fn add_uses(&mut self, sources: &[Source]) {
        for source in sources {
            let mut named = NamedPorts::default();
            source
                .items
                .iter()
                .filter(|item| !(is_port_file(source) && matches!(item, Item::Use(_))))
                .for_each(|item| named.visit_item(item));
            for port in named.names {
                if let Some(entry) = self.ports.get_mut(&port) {
                    entry
                        .used_by
                        .insert(format!("{}/{}", source.crate_name, source.path));
                }
            }
        }
    }
}

/// Whether `source` declares ports: a file of the app's `ports/` folder.
fn is_port_file(source: &Source) -> bool {
    source.crate_name == "ianua-app" && source.path.starts_with("ports/")
}

/// The trait and type of an `impl Trait for Type` block.
fn implemented(item: &Item) -> Option<(String, String)> {
    let Item::Impl(block) = item else {
        return None;
    };
    let (_, path, _) = block.trait_.as_ref()?;
    let port = path.segments.last()?.ident.to_string();
    let syn::Type::Path(adapter) = block.self_ty.as_ref() else {
        return None;
    };
    let name = adapter.path.segments.last()?.ident.to_string();
    Some((port, name))
}

/// Every name a file uses: in paths, types, bounds and imports. The trait
/// an `impl Trait for Type` block implements is left out, since
/// implementing a port is not using it, and so are the re-exports of the
/// `ports/` folder, which only list the ports.
#[derive(Default)]
struct NamedPorts {
    names: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for NamedPorts {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        if let Some(segment) = path.segments.last() {
            self.names.insert(segment.ident.to_string());
        }
        visit::visit_path(self, path);
    }

    fn visit_use_name(&mut self, used: &'ast syn::UseName) {
        self.names.insert(used.ident.to_string());
    }

    fn visit_use_rename(&mut self, used: &'ast syn::UseRename) {
        self.names.insert(used.ident.to_string());
    }

    fn visit_item_impl(&mut self, block: &'ast syn::ItemImpl) {
        self.visit_type(&block.self_ty);
        block
            .items
            .iter()
            .for_each(|item| self.visit_impl_item(item));
    }
}
