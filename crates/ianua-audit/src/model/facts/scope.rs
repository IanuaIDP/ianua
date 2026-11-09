//! The functions a body can call by name: the methods of its own type, the
//! free functions of its file, and the app functions its file imports.

use std::collections::BTreeMap;

use syn::{Block, ImplItemFn, Item, ItemFn, Signature};

use super::known::Known;
use crate::model::paths::{AppItem, Origin};
use crate::source::SourceFile;
use crate::source::syntax::{impl_fns, items_of, type_name};

/// A function with a body the reader can follow.
#[derive(Clone)]
pub(super) struct FnRef<'a> {
    /// The type whose `impl` holds it, if any.
    pub(super) owner: Option<String>,
    /// Its name.
    pub(super) name: String,
    /// The file it is in.
    pub(super) file: &'a SourceFile,
    /// Its signature.
    pub(super) sig: &'a Signature,
    /// Its body.
    pub(super) block: &'a Block,
}

impl<'a> FnRef<'a> {
    /// A function of `owner`'s `impl` in `file`.
    pub(super) fn of_impl(
        file: &'a SourceFile,
        owner: Option<&str>,
        function: &'a ImplItemFn,
    ) -> Self {
        Self {
            owner: owner.map(str::to_owned),
            name: function.sig.ident.to_string(),
            file,
            sig: &function.sig,
            block: &function.block,
        }
    }

    fn free(file: &'a SourceFile, function: &'a ItemFn) -> Self {
        Self {
            owner: None,
            name: function.sig.ident.to_string(),
            file,
            sig: &function.sig,
            block: &function.block,
        }
    }

    /// `Owner::name`, or the bare name of a free function.
    pub(super) fn label(&self) -> String {
        self.owner.as_ref().map_or_else(
            || self.name.clone(),
            |owner| format!("{owner}::{}", self.name),
        )
    }

    /// What tells it apart from every other function.
    pub(super) fn key(&self) -> (String, Option<String>, String) {
        (
            self.file.path.clone(),
            self.owner.clone(),
            self.name.clone(),
        )
    }
}

/// What a call by a bare name reaches.
pub(super) enum Lookup<'a> {
    /// A function the reader can follow.
    Found(FnRef<'a>),
    /// A function the file imports from the app by this module path, which
    /// the reader could not find there.
    NotRead(String),
    /// Anything else: a function of another crate, or no function at all.
    Elsewhere,
}

/// The functions one body can call by name.
pub(super) struct Scope<'a> {
    file: &'a SourceFile,
    owner: Option<String>,
    own: BTreeMap<String, FnRef<'a>>,
    free: BTreeMap<String, FnRef<'a>>,
}

impl<'a> Scope<'a> {
    /// What a function of `owner` in `file` can call by name.
    pub(super) fn of(file: &'a SourceFile, owner: Option<&str>) -> Self {
        Self {
            file,
            owner: owner.map(str::to_owned),
            own: owner
                .map(|owner| own_methods(file, owner))
                .unwrap_or_default(),
            free: free_functions(file),
        }
    }

    /// The type whose functions `self.name(..)` and `Self::name(..)` call.
    pub(super) fn owner(&self) -> Option<&str> {
        self.owner.as_deref()
    }

    /// The file the body is in.
    pub(super) fn file(&self) -> &'a SourceFile {
        self.file
    }

    /// The method `name` of the body's own type.
    pub(super) fn own_method(&self, name: &str) -> Option<FnRef<'a>> {
        self.own.get(name).cloned()
    }

    /// What a call of the bare name `name` reaches: a function of the same
    /// file, or the app function the file's imports lead to.
    pub(super) fn free_fn(&self, known: &Known<'a>, name: &str) -> Lookup<'a> {
        if let Some(found) = self.free.get(name) {
            return Lookup::Found(found.clone());
        }
        match known.modules().origin(self.file, &[name.to_owned()]) {
            Origin::Declared(item) => function_at(known, &item),
            Origin::Missing(module) => Lookup::NotRead(module),
            Origin::Outside => Lookup::Elsewhere,
        }
    }

    /// The app function a call through a module path reaches, such as
    /// `sign_in_gate::admit`, when the path leads to one.
    pub(super) fn path_fn(&self, known: &Known<'a>, path: &[String]) -> Option<FnRef<'a>> {
        let Origin::Declared(item) = known.modules().origin(self.file, path) else {
            return None;
        };
        match function_at(known, &item) {
            Lookup::Found(found) => Some(found),
            Lookup::NotRead(_) | Lookup::Elsewhere => None,
        }
    }
}

/// The free function `item` names.
fn function_at<'a>(known: &Known<'a>, item: &AppItem) -> Lookup<'a> {
    let found = known
        .modules()
        .file(&item.module)
        .and_then(|file| free_functions(file).remove(&item.name));
    match found {
        Some(function) => Lookup::Found(function),
        None => Lookup::NotRead(format!("crate::{}", item.module.join("::"))),
    }
}

/// Every function with a body in `file`: its free functions and the
/// functions of every `impl` in it.
pub(super) fn functions_of(file: &SourceFile) -> Vec<FnRef<'_>> {
    let Some(syntax) = file.syntax() else {
        return Vec::new();
    };
    items_of(syntax)
        .into_iter()
        .flat_map(|item| match item {
            Item::Fn(function) => vec![FnRef::free(file, function)],
            Item::Impl(block) => {
                let owner = type_name(&block.self_ty);
                impl_fns(block)
                    .map(|function| FnRef::of_impl(file, owner.as_deref(), function))
                    .collect()
            }
            _ => Vec::new(),
        })
        .collect()
}

fn own_methods<'a>(file: &'a SourceFile, owner: &str) -> BTreeMap<String, FnRef<'a>> {
    let Some(syntax) = file.syntax() else {
        return BTreeMap::new();
    };
    items_of(syntax)
        .into_iter()
        .filter_map(|item| match item {
            Item::Impl(block) if type_name(&block.self_ty).as_deref() == Some(owner) => Some(block),
            _ => None,
        })
        .flat_map(impl_fns)
        .map(|function| {
            let found = FnRef::of_impl(file, Some(owner), function);
            (found.name.clone(), found)
        })
        .collect()
}

fn free_functions(file: &SourceFile) -> BTreeMap<String, FnRef<'_>> {
    let Some(syntax) = file.syntax() else {
        return BTreeMap::new();
    };
    items_of(syntax)
        .into_iter()
        .filter_map(|item| match item {
            Item::Fn(function) => Some(FnRef::free(file, function)),
            _ => None,
        })
        .map(|found| (found.name.clone(), found))
        .collect()
}
