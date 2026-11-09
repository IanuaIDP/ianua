//! Names that never repeat where they live. A path is read as one phrase,
//! so each word in it says something new:
//!
//! - **Files**: a file name never repeats its folder's name, nor the name
//!   of the folder above it, anywhere in it, singular or plural.
//!   `executions/rerun.rs`, never `executions/rerun_execution.rs`;
//!   `tenant/lifecycle/archive.rs`, never `archive_tenant.rs`.
//! - **Use case types**: a `UseCase`, its `Ports` and its `Request` never
//!   repeat their folder's word. Callers write the folder, so
//!   `executions::ListUseCase` reads once, where `ListExecutionsUseCase`
//!   would say "executions" twice.
//!
//! - **Paths**: a module is named by its full path, `crate::...`, never
//!   climbed to with `super::`. A test module's `use super::*;` is the one
//!   exception: it means the file it tests.
//!
//! A name that must stay, because the short one is a keyword, is taken, or
//! means another type, is listed with the reason.

use syn::Item;

use crate::conventions::app::source::{Check, Findings, SourceFile, app_files, line_of};

/// Files that keep their folder's name, with the reason.
const FILE_NAMES_ALLOWED: &[(&str, &str)] = &[
    (
        "use_cases/agents/runs/control/run_pause.rs",
        "`pause.rs` beside it already holds the pause use case; this is the paused run it reads",
    ),
    (
        "use_cases/authorization/groups/move_group.rs",
        "`move` is a Rust keyword",
    ),
];

/// Use case types that keep their folder's word, with the reason.
const TYPE_NAMES_ALLOWED: &[(&str, &str)] = &[
    (
        "GrantDelegationRequest",
        "`GrantRequest` is the organization's tenant grant request",
    ),
    (
        "CheckAccessRequest",
        "`AccessRequest` is the domain's just-in-time access request",
    ),
    (
        "AppSignInPageRequest",
        "`PageRequest` is the listing's page of a list",
    ),
    (
        "RequestAccessRequest",
        "the request of the request-access use case; without its verb it is a bare `Request`",
    ),
    (
        "ReviewRequest",
        "one reviewer's request; without its noun it is a bare `Request`",
    ),
    (
        "BreakGlassGrantRequest",
        "`GrantRequest` is the organization's tenant grant request",
    ),
];

/// Folders whose name a grandchild may repeat: the layers themselves.
const LAYER_FOLDERS: &[&str] = &["", "use_cases", "ports", "services", "test_support"];

/// Files repeating their folder's or their parent folder's name.
pub(crate) fn files_repeating_their_folder(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        let parts: Vec<&str> = file.path.trim_end_matches(".rs").split('/').collect();
        let Some((stem, folders)) = parts.split_last() else {
            continue;
        };
        if *stem == "mod" || allowed_file(&file.path) {
            continue;
        }
        let folder = folders.last().copied().unwrap_or("");
        let parent = folders.iter().rev().nth(1).copied().unwrap_or("");
        let repeated = [folder, parent]
            .into_iter()
            .filter(|name| !name.is_empty() && !LAYER_FOLDERS.contains(name))
            .find(|name| repeats(stem, name));
        if let Some(name) = repeated {
            findings.flag_file(
                file,
                format!("`{stem}` repeats its folder `{name}`; name it by what it adds"),
            );
        }
    }
    findings
}

/// Use case types repeating their folder's word.
pub(crate) fn use_case_types_repeating_their_folder(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files
        .iter()
        .filter(|file| file.path.starts_with("use_cases/"))
    {
        let Some(folder) = menu_folder(files, &file.path) else {
            continue;
        };
        for (name, line) in use_case_family(file) {
            if TYPE_NAMES_ALLOWED.iter().any(|(listed, _)| *listed == name) {
                continue;
            }
            if repeats(&snake(&name), folder) {
                findings.flag_at(
                    &file.path,
                    line,
                    format!("`{name}` repeats its folder `{folder}`; callers write `{folder}::`"),
                );
            }
        }
    }
    findings
}

/// Paths climbing with `super::`, in code or docs, other than a test
/// module's `use super::*;`.
pub(crate) fn relative_paths(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for (index, line) in file.lines().iter().enumerate() {
            let climbs = line
                .match_indices("super::")
                .any(|(at, _)| !line[at..].starts_with("super::*"));
            if climbs {
                findings.flag_at(
                    &file.path,
                    index + 1,
                    "names a module through `super::`; write its `crate::` path",
                );
            }
        }
    }
    findings
}

/// The folder whose menu callers write for the file at `path`: its own
/// folder, or, when that folder is a topic group its parent re-exports
/// (declared without `pub`), the nearest folder above it that is public.
fn menu_folder<'a>(files: &[SourceFile], path: &'a str) -> Option<&'a str> {
    let mut folder = path.rsplit_once('/')?.0;
    loop {
        let (parent, name) = folder.rsplit_once('/')?;
        if declared_public(files, parent, name) {
            return Some(name);
        }
        folder = parent;
    }
}

/// Whether the module `parent` declares `name` as `pub mod`, or has no
/// module file of its own to say otherwise.
fn declared_public(files: &[SourceFile], parent: &str, name: &str) -> bool {
    let menus = [format!("{parent}/mod.rs"), format!("{parent}.rs")];
    let public = format!("pub mod {name};");
    let menu = files.iter().find(|file| menus.contains(&file.path));
    menu.is_none_or(|file| file.lines().iter().any(|line| line.trim() == public))
}

/// Listed names that no longer exist.
fn stale_allowances(files: &[SourceFile]) -> Vec<String> {
    let mut stale: Vec<String> = FILE_NAMES_ALLOWED
        .iter()
        .filter(|(path, _)| !files.iter().any(|file| file.path == *path))
        .map(|(path, _)| (*path).to_owned())
        .collect();
    let types: Vec<String> = files
        .iter()
        .flat_map(use_case_family)
        .map(|(name, _)| name)
        .collect();
    stale.extend(
        TYPE_NAMES_ALLOWED
            .iter()
            .filter(|(name, _)| !types.iter().any(|held| held == name))
            .map(|(name, _)| (*name).to_owned()),
    );
    stale
}

fn allowed_file(path: &str) -> bool {
    FILE_NAMES_ALLOWED.iter().any(|(listed, _)| *listed == path)
}

/// The public `UseCase`, `Ports` and `Request` types `file` declares, with
/// their lines.
fn use_case_family(file: &SourceFile) -> Vec<(String, usize)> {
    file.items()
        .iter()
        .filter_map(|item| match item {
            Item::Struct(item) if is_public(&item.vis) => {
                Some((item.ident.to_string(), line_of(item)))
            }
            Item::Enum(item) if is_public(&item.vis) => {
                Some((item.ident.to_string(), line_of(item)))
            }
            _ => None,
        })
        .filter(|(name, _)| {
            ["UseCase", "Ports", "Request"]
                .iter()
                .any(|end| name.ends_with(end))
        })
        .collect()
}

fn is_public(visibility: &syn::Visibility) -> bool {
    matches!(visibility, syn::Visibility::Public(_))
}

/// Whether `stem`, in snake case, holds `folder`'s words in a row, singular
/// or plural, beside at least one word of its own.
fn repeats(stem: &str, folder: &str) -> bool {
    let words: Vec<&str> = stem.split('_').collect();
    let folder_words: Vec<String> = folder.split('_').map(str::to_owned).collect();
    let mut single = folder_words.clone();
    if let Some(last) = single.last_mut() {
        *last = singular(last);
    }
    [folder_words, single].iter().any(|form| {
        words.len() > form.len()
            && words
                .windows(form.len())
                .any(|window| window.iter().zip(form).all(|(word, part)| word == part))
    })
}

fn singular(word: &str) -> String {
    if let Some(root) = word.strip_suffix("ies") {
        return format!("{root}y");
    }
    if let Some(root) = word.strip_suffix("sses") {
        return format!("{root}ss");
    }
    if word.ends_with('s') && !word.ends_with("ss") {
        return word[..word.len() - 1].to_owned();
    }
    word.to_owned()
}

/// `name`, in snake case.
fn snake(name: &str) -> String {
    let mut out = String::new();
    for (index, ch) in name.chars().enumerate() {
        if ch.is_uppercase() && index > 0 {
            out.push('_');
        }
        out.extend(ch.to_lowercase());
    }
    out
}

/// A planted file that repeats its folder in its name and in its types.
const PLANTED: &str = "use super::get::GetUseCase;\npub struct ListExecutionsUseCase;\npub struct ListExecutionsPorts;";

#[cfg_attr(test, test)]
pub(crate) fn no_file_repeats_its_folder() {
    files_repeating_their_folder(&app_files()).assert_none("files repeating their folder");
}

#[cfg_attr(test, test)]
pub(crate) fn no_use_case_type_repeats_its_folder() {
    use_case_types_repeating_their_folder(&app_files())
        .assert_none("use case types repeating their folder");
}

#[cfg_attr(test, test)]
pub(crate) fn no_path_climbs_with_super() {
    relative_paths(&app_files()).assert_none("paths climbing with super");
}

#[cfg_attr(test, test)]
pub(crate) fn every_listed_name_still_exists() {
    let stale = stale_allowances(&app_files());
    assert!(
        stale.is_empty(),
        "listed names that no longer exist: {stale:?}"
    );
}

#[cfg_attr(test, test)]
pub(crate) fn every_naming_check_finds_its_planted_repeat() {
    let files = [SourceFile::planted(
        "use_cases/workflows/executions/list_executions.rs",
        PLANTED,
    )];
    let checks: [(&str, Check); 3] = [
        ("file", files_repeating_their_folder),
        ("type", use_case_types_repeating_their_folder),
        ("relative path", relative_paths),
    ];
    let missed: Vec<&str> = checks
        .iter()
        .filter(|(_, check)| check(&files).is_empty())
        .map(|(name, _)| *name)
        .collect();
    assert!(
        missed.is_empty(),
        "checks that missed their planted repeat: {missed:?}"
    );
}
