//! Where a name written in a file comes from in the app: through the file's
//! `use` items, and the `pub use` re-exports of the modules they name, to
//! the module that declares it.
//!
//! Many app items share a name: seventeen contexts declare a `CreatePorts`.
//! So an item is known by its module and name, and a name is followed from
//! where it is written. An app file's paths start at `crate`, `self`,
//! `super` or one of its child modules; an adapter's at `ianua_app`. A
//! module's `pub use x::*` is followed when looking for what it re-exports.
//! A name the writing file neither imports by name nor writes with such a
//! path, one behind its own glob import among them, is not followed.

use std::collections::BTreeMap;

use serde::Serialize;
use syn::Item;

use crate::source::syntax::{Import, globs_of, imports_of, items_of};
use crate::source::{Layer, SourceFile, Workspace};

/// The app crate's name as other crates write it.
const APP_CRATE: &str = "ianua_app";

/// How many `pub use` re-exports a name is followed through.
const REEXPORTS: usize = 4;

/// An app item, by the module that declares it and its name there.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub(crate) struct AppItem {
    /// The module path from the app crate's root, such as
    /// `["use_cases", "webhooks", "subscriptions", "create"]`.
    pub(crate) module: Vec<String>,
    /// The item's name.
    pub(crate) name: String,
}

impl AppItem {
    /// The item declared as `name` in `file`.
    pub(crate) fn in_file(file: &SourceFile, name: &str) -> Self {
        Self {
            module: file.module_path(),
            name: name.to_owned(),
        }
    }

    /// Its path from the app crate's root, such as
    /// `ports::oauth::proofs::AssertionReplayGuard`.
    pub(crate) fn path(&self) -> String {
        self.module
            .iter()
            .chain(std::iter::once(&self.name))
            .cloned()
            .collect::<Vec<_>>()
            .join("::")
    }
}

/// Where a written name comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Origin {
    /// An app module declares it.
    Declared(AppItem),
    /// It is imported from this app module, which neither declares nor
    /// re-exports it.
    Missing(String),
    /// It comes from elsewhere, or the reader cannot follow it.
    Outside,
}

/// Where a path is written: the file read as `syntax`, when the whole
/// file is read, and the app module `here` it is (`None` outside the app).
#[derive(Clone, Copy)]
pub(crate) struct WrittenIn<'w> {
    pub(crate) syntax: Option<&'w syn::File>,
    pub(crate) here: Option<&'w [String]>,
}

/// The app's files by module.
pub(crate) struct Modules<'w> {
    workspace: &'w Workspace,
    by_path: BTreeMap<Vec<String>, usize>,
}

impl<'w> Modules<'w> {
    /// The app modules of `workspace`.
    pub(crate) fn of(workspace: &'w Workspace) -> Self {
        Self {
            workspace,
            by_path: workspace
                .files
                .iter()
                .enumerate()
                .filter(|(_, file)| file.layer == Layer::App)
                .map(|(index, file)| (file.module_path(), index))
                .collect(),
        }
    }

    /// The file of the app module `module`.
    pub(crate) fn file(&self, module: &[String]) -> Option<&'w SourceFile> {
        self.by_path
            .get(module)
            .map(|index| &self.workspace.files[*index])
    }

    /// Where the path `written`, written in `file`, comes from.
    pub(crate) fn origin(&self, file: &SourceFile, written: &[String]) -> Origin {
        let here = (file.layer == Layer::App).then(|| file.module_path());
        let at = WrittenIn {
            syntax: file.syntax(),
            here: here.as_deref(),
        };
        self.origin_in(at, written)
    }

    /// Where the path `written`, written `at` a file, comes from.
    pub(crate) fn origin_in(&self, at: WrittenIn<'_>, written: &[String]) -> Origin {
        let imports = at.syntax.map(imports_of).unwrap_or_default();
        let Some(path) = self.expanded(&imports, written, at.here) else {
            return Origin::Outside;
        };
        let Some((name, module)) = path.split_last() else {
            return Origin::Outside;
        };
        self.follow(module, name, REEXPORTS)
    }

    /// `written` as a path from the app's root, its first name read
    /// through `imports`.
    fn expanded(
        &self,
        imports: &[Import],
        written: &[String],
        here: Option<&[String]>,
    ) -> Option<Vec<String>> {
        let (first, rest) = written.split_first()?;
        let mut path = match imports.iter().find(|import| import.local == *first) {
            Some(import) => {
                let mut module = self.absolute(&import.prefix, here)?;
                module.push(import.original.clone());
                module
            }
            None if rest.is_empty() => return None,
            None => self.absolute(std::slice::from_ref(first), here)?,
        };
        path.extend(rest.iter().cloned());
        Some(path)
    }

    /// The module path `segments`, written in the module `here` (`None`
    /// outside the app), from the app's root.
    fn absolute(&self, segments: &[String], here: Option<&[String]>) -> Option<Vec<String>> {
        let (first, rest) = segments.split_first()?;
        match first.as_str() {
            APP_CRATE => Some(rest.to_vec()),
            "crate" => here.map(|_| rest.to_vec()),
            "self" | "super" => below(segments, here?),
            _ => {
                let here = here?;
                let child = [here, &segments[..1]].concat();
                self.by_path
                    .contains_key(&child)
                    .then(|| [here, segments].concat())
            }
        }
    }

    /// Where `name` of `module` is declared, through at most `hops`
    /// re-exports.
    fn follow(&self, module: &[String], name: &str, hops: usize) -> Origin {
        let shown = || format!("crate::{}", module.join("::"));
        let Some(file) = self.file(module) else {
            return Origin::Missing(shown());
        };
        if declares(file, name) {
            return Origin::Declared(AppItem {
                module: module.to_vec(),
                name: name.to_owned(),
            });
        }
        if hops == 0 {
            return Origin::Missing(shown());
        }
        let reexport = file
            .syntax()
            .map(imports_of)
            .unwrap_or_default()
            .into_iter()
            .find(|import| import.local == name);
        let Some(import) = reexport else {
            return self
                .through_globs(module, name, hops - 1)
                .unwrap_or_else(|| Origin::Missing(shown()));
        };
        let Some(next) = self.absolute(&import.prefix, Some(module)) else {
            return Origin::Outside;
        };
        self.follow(&next, &import.original, hops - 1)
    }

    /// Where `name` is declared behind one of the `use x::*` items of the
    /// module `module`, if behind any.
    fn through_globs(&self, module: &[String], name: &str, hops: usize) -> Option<Origin> {
        self.file(module)?
            .syntax()
            .map(globs_of)
            .unwrap_or_default()
            .iter()
            .filter_map(|prefix| self.absolute(prefix, Some(module)))
            .map(|next| self.follow(&next, name, hops))
            .find(|origin| matches!(origin, Origin::Declared(_)))
    }
}

/// `path`, made of leading `self` and `super` and the rest, below `here`.
fn below(path: &[String], here: &[String]) -> Option<Vec<String>> {
    match path.split_first() {
        Some((first, rest)) if first == "self" => below(rest, here),
        Some((first, rest)) if first == "super" => below(rest, here.split_last()?.1),
        _ => Some(here.iter().chain(path).cloned().collect()),
    }
}

/// Whether `file` declares an item named `name`.
fn declares(file: &SourceFile, name: &str) -> bool {
    file.syntax().is_some_and(|syntax| {
        items_of(syntax).into_iter().any(|item| {
            let ident = match item {
                Item::Struct(declared) => &declared.ident,
                Item::Enum(declared) => &declared.ident,
                Item::Trait(declared) => &declared.ident,
                Item::Fn(declared) => &declared.sig.ident,
                Item::Type(declared) => &declared.ident,
                _ => return false,
            };
            ident == name
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::planted::{adapter, app, workspace};

    fn item(module: &[&str], name: &str) -> Origin {
        Origin::Declared(AppItem {
            module: module.iter().map(|part| (*part).to_owned()).collect(),
            name: name.to_owned(),
        })
    }

    fn written(path: &[&str]) -> Vec<String> {
        path.iter().map(|part| (*part).to_owned()).collect()
    }

    fn files() -> Workspace {
        workspace(vec![
            app(
                "use_cases/groups/mod.rs",
                "pub mod create;\npub use create::{CreatePorts, CreateUseCase};",
            ),
            app("use_cases/groups/create.rs", "pub struct CreatePorts;"),
            app("use_cases/topics/create.rs", "pub struct CreatePorts;"),
            app(
                "use_cases/groups/rename.rs",
                "use super::create::CreatePorts as Shared;\nuse crate::use_cases::gone::Missing;",
            ),
            adapter(
                "ianua-server",
                "bootstrap.rs",
                "use ianua_app::use_cases::groups::{CreatePorts, CreateUseCase};\nuse ianua_app::use_cases::topics;",
            ),
        ])
    }

    fn file<'w>(ws: &'w Workspace, path: &str) -> &'w SourceFile {
        ws.files.iter().find(|file| file.path == path).unwrap()
    }

    #[test]
    fn a_name_an_adapter_imports_is_followed_through_a_reexport() {
        let ws = files();
        let modules = Modules::of(&ws);

        let found = modules.origin(file(&ws, "bootstrap.rs"), &written(&["CreatePorts"]));

        assert_eq!(
            found,
            item(&["use_cases", "groups", "create"], "CreatePorts")
        );
    }

    #[test]
    fn a_path_through_an_imported_module_reaches_that_modules_item() {
        let ws = files();
        let modules = Modules::of(&ws);

        let found = modules.origin(
            file(&ws, "bootstrap.rs"),
            &written(&["topics", "create", "CreatePorts"]),
        );

        assert_eq!(
            found,
            item(&["use_cases", "topics", "create"], "CreatePorts")
        );
    }

    #[test]
    fn a_renamed_super_import_reaches_the_original() {
        let ws = files();
        let modules = Modules::of(&ws);
        let rename = file(&ws, "use_cases/groups/rename.rs");

        let shared = modules.origin(rename, &written(&["Shared"]));
        let missing = modules.origin(rename, &written(&["Missing"]));

        assert_eq!(
            shared,
            item(&["use_cases", "groups", "create"], "CreatePorts")
        );
        assert_eq!(
            missing,
            Origin::Missing("crate::use_cases::gone".to_owned())
        );
    }

    #[test]
    fn a_name_is_followed_through_a_glob_reexport() {
        let ws = workspace(vec![
            app(
                "ports/runtime/mod.rs",
                "mod fleet;\nmod unit_of_work;\npub use fleet::*;\npub use unit_of_work::*;",
            ),
            app("ports/runtime/fleet.rs", "pub trait Fleet {}"),
            app(
                "ports/runtime/unit_of_work.rs",
                "pub async fn atomically() {}",
            ),
            app(
                "use_cases/jobs/run.rs",
                "use crate::ports::runtime::atomically;",
            ),
        ]);
        let modules = Modules::of(&ws);

        let found = modules.origin(
            file(&ws, "use_cases/jobs/run.rs"),
            &written(&["atomically"]),
        );

        assert_eq!(
            found,
            item(&["ports", "runtime", "unit_of_work"], "atomically")
        );
    }

    #[test]
    fn a_name_neither_imported_nor_written_with_a_path_is_not_followed() {
        let ws = files();
        let modules = Modules::of(&ws);

        let found = modules.origin(file(&ws, "bootstrap.rs"), &written(&["Unknown"]));

        assert_eq!(found, Origin::Outside);
    }
}
