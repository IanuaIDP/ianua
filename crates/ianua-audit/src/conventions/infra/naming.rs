//! Names and folders that read as one phrase, as in the domain and the app:
//!
//! - **Files**: a file name never repeats its folder's name, nor the name
//!   of the folder above it, singular or plural. `postgres/users/sessions.rs`,
//!   never `postgres/users/user_sessions.rs`.
//! - **Adapters**: a type that implements a port is named by its provider
//!   and the port, so a reader sees at once what it is and where it talks
//!   to: `PgUserStore` implements `UserStore`, `CacheRateLimiter`
//!   implements `RateLimiter`. A folder is named by its role, never by
//!   the product behind it, so the product can change. Adapters in a
//!   folder with no fixed prefix, such as crypto, mail, dns or cloud, lead
//!   with their algorithm or vendor instead: `Argon2PasswordHasher`,
//!   `SmtpMailTransport`, `RecursiveDnsResolver`. A port's name is never
//!   shortened or reworded in its adapter's name.
//! - **Folders**: a folder holds at most [`MAX_FOLDER_ENTRIES`] files and
//!   folders; past that its files are grouped into topic folders.
//!
//! A name that must stay, because the short one is a keyword or is taken,
//! is listed with the reason.

use std::fs;

use syn::Item;

use crate::conventions::infra::source::{Findings, SourceFile, folders, infra_files};

/// Files that keep their folder's name, with the reason.
const FILE_NAMES_ALLOWED: &[(&str, &str)] = &[];

/// Folders whose name a grandchild may repeat: the layers themselves.
const LAYER_FOLDERS: &[&str] = &["", "test_support"];

/// Folders that hold one entry per module of the app's ports, so a store is
/// found under its port's name. They are as long as the ports list is, and
/// a topic split would break that match, so the cap does not hold them.
const MIRRORS_THE_PORTS: &[&str] = &["postgres", "test_support/rows"];

/// The crate's own folder, holding one folder per provider. A provider's
/// prefix is read from its top folder, so the providers cannot be grouped
/// under topic folders, and the cap does not hold the crate's folder.
const HOLDS_THE_PROVIDERS: &str = "";

/// The most files and folders one folder holds before it is split by topic.
pub(crate) const MAX_FOLDER_ENTRIES: usize = 12;

/// The provider prefix of an adapter, by the folder it lives in.
const PROVIDERS: &[(&str, &str)] = &[
    ("postgres", "Pg"),
    ("cache", "Cache"),
    ("bus", "Bus"),
    ("outbox", "Outbox"),
    ("inbox", "Inbox"),
    ("runtime", "Local"),
    ("crypto", ""),
    ("mail", ""),
    ("http", "Http"),
    ("files", "File"),
    ("bundled", "Bundled"),
    ("pages", "Template"),
    ("integrations", "Installed"),
    ("geo", "Mmdb"),
    ("billing", ""),
    ("cloud", ""),
    ("css", ""),
    ("dns", ""),
    ("proofs", ""),
    ("reading", ""),
    ("saml", ""),
    ("secrets", ""),
    ("sms", ""),
    ("tls", ""),
    ("vectors", "Vector"),
];

/// Traits implemented in infra that are not ports, so their implementers
/// keep their own names. `Integration` is the contract of the integration
/// crates, each implementer named by its service, as `HttpRequests` is.
const NOT_PORTS: &[&str] = &[
    "Integration",
    "Resolve",
    "Debug",
    "Display",
    "Default",
    "Clone",
    "Drop",
    "From",
    "TryFrom",
    "FromStr",
    "Error",
    "Deref",
    "DerefMut",
    "AsRef",
    "PartialEq",
    "Eq",
    "Hash",
    "Serialize",
    "Deserialize",
    "Iterator",
    "Future",
    "Stream",
    "AsyncRead",
    "TenantScoped",
    "SortKeys",
    "AdditionalClaims",
    "AsyncHttpClient",
];

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

/// Adapters not named by their provider and the port they implement.
pub(crate) fn adapters_misnamed(files: &[SourceFile]) -> Findings {
    let own_traits = traits_defined_in(files);
    let mut findings = Findings::default();
    for file in files {
        let Some(prefix) = provider_prefix(&file.path) else {
            continue;
        };
        for (port, adapter, line) in file.trait_impls() {
            if NOT_PORTS.contains(&port.as_str()) || own_traits.contains(&port) {
                continue;
            }
            if !named_for(&adapter, prefix, &port) {
                findings.flag_at(
                    &file.path,
                    line,
                    format!("`{adapter}` implements `{port}`; name it `{prefix}…{port}`, as `{prefix}{port}`"),
                );
            }
        }
    }
    findings
}

/// The traits the infra defines for itself, such as how a sort field is a
/// column. A port is always defined by the domain or the app, so these
/// are never ports.
fn traits_defined_in(files: &[SourceFile]) -> Vec<String> {
    files
        .iter()
        .flat_map(SourceFile::items)
        .filter_map(|item| match item {
            Item::Trait(defined) => Some(defined.ident.to_string()),
            _ => None,
        })
        .collect()
}

/// Folders holding more than `cap` files and folders.
pub(crate) fn crowded_folders(found: &[(String, usize)], cap: usize) -> Findings {
    let mut findings = Findings::default();
    for (folder, held) in found.iter().filter(|(folder, held)| {
        *held > cap
            && folder != HOLDS_THE_PROVIDERS
            && !MIRRORS_THE_PORTS.contains(&folder.as_str())
    }) {
        let shown = if folder.is_empty() { "src" } else { folder };
        findings.flag_at(
            shown,
            0,
            format!("holds {held} entries; group them into topic folders (at most {cap})"),
        );
    }
    findings
}

/// Whether `adapter` is `prefix` and `port`: exactly that where the
/// provider fixes a prefix, or any word of its own before the port, such as
/// `Argon2PasswordHasher`, where it does not. A stand-in for a provider a
/// deployment did not set up is `No` and the port, such as `NoGeolocator`,
/// in any folder.
fn named_for(adapter: &str, prefix: &str, port: &str) -> bool {
    let Some(head) = adapter.strip_suffix(port) else {
        return false;
    };
    match prefix {
        _ if head == STAND_IN => true,
        "" => !head.is_empty(),
        fixed => head == fixed,
    }
}

/// The head of an adapter standing in for a provider that is not set up.
const STAND_IN: &str = "No";

/// The adapter prefix for a file at `path`, by its top folder.
fn provider_prefix(path: &str) -> Option<&'static str> {
    let top = path.split('/').next()?;
    PROVIDERS
        .iter()
        .find(|(folder, _)| *folder == top)
        .map(|(_, prefix)| *prefix)
}

fn allowed_file(path: &str) -> bool {
    FILE_NAMES_ALLOWED.iter().any(|(listed, _)| *listed == path)
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

/// The folders directly under `postgres/` that hold a context's stores:
/// every one but the foundation.
fn context_folders(found: &[(String, usize)]) -> Vec<String> {
    found
        .iter()
        .filter_map(|(folder, _)| folder.strip_prefix("postgres/"))
        .filter(|rest| !rest.contains('/') && *rest != "foundation")
        .map(str::to_owned)
        .collect()
}

/// The modules of the app's ports, each a context a store folder may be
/// named after.
fn port_modules() -> Vec<String> {
    let ports = crate::conventions::crate_dir("ianua-infra").join("../ianua-app/src/ports");
    let Ok(entries) = fs::read_dir(ports) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let module = name.strip_suffix(".rs").unwrap_or(&name).to_owned();
            (module != "mod").then_some(module)
        })
        .collect()
}

/// Context folders not named after a module of the app's ports.
pub(crate) fn contexts_named_apart_from_their_ports(
    contexts: &[String],
    ports: &[String],
) -> Findings {
    let mut findings = Findings::default();
    for context in contexts.iter().filter(|context| !ports.contains(context)) {
        findings.flag_at(
            &format!("postgres/{context}"),
            1,
            "is named after no module of the app's ports; name it after the ports it implements",
        );
    }
    findings
}

/// A planted store whose file repeats its folder and whose adapter is not
/// named by its provider and port.
const PLANTED: &str = "pub struct UserRepo;\nimpl UserStore for UserRepo {}";

/// No file repeats the folder it sits in.
#[cfg_attr(test, test)]
pub(crate) fn no_file_repeats_its_folder() {
    files_repeating_their_folder(&infra_files()).assert_none("files repeating their folder");
}

/// Every adapter is named by its provider and its port.
#[cfg_attr(test, test)]
pub(crate) fn every_adapter_is_named_by_its_provider_and_port() {
    adapters_misnamed(&infra_files()).assert_none("adapters not named by provider and port");
}

/// No folder is crowded past the cap.
#[cfg_attr(test, test)]
pub(crate) fn no_folder_is_crowded() {
    crowded_folders(&folders(), MAX_FOLDER_ENTRIES).assert_none("crowded folders");
}

/// Stops: a store folder named for something the app does not call it, so
/// the store of a port cannot be found by the port's name.
#[cfg_attr(test, test)]
pub(crate) fn every_context_folder_is_named_after_its_ports() {
    contexts_named_apart_from_their_ports(&context_folders(&folders()), &port_modules())
        .assert_none("context folders named apart from their ports");
}

/// Every listed file name still exists, so the list never keeps a reason
/// for something gone.
#[cfg_attr(test, test)]
pub(crate) fn every_listed_file_name_still_exists() {
    let files = infra_files();
    let stale: Vec<&str> = FILE_NAMES_ALLOWED
        .iter()
        .map(|(path, _)| *path)
        .filter(|path| !files.iter().any(|file| file.path == *path))
        .collect();
    assert!(
        stale.is_empty(),
        "listed names that no longer exist: {stale:?}"
    );
}

/// Each naming check finds the repeat planted for it, so a check that
/// silently matches nothing fails here.
#[cfg_attr(test, test)]
pub(crate) fn every_naming_check_finds_its_planted_repeat() {
    let files = [SourceFile::planted("postgres/users/user_store.rs", PLANTED)];
    let crowded = [("postgres/users".to_owned(), MAX_FOLDER_ENTRIES + 1)];

    assert!(!files_repeating_their_folder(&files).is_empty());
    assert!(!adapters_misnamed(&files).is_empty());
    assert!(!crowded_folders(&crowded, MAX_FOLDER_ENTRIES).is_empty());
    assert!(
        !contexts_named_apart_from_their_ports(&["people".to_owned()], &port_modules()).is_empty()
    );
}

/// A stand-in named `No` and its port passes in a folder whose provider
/// fixes another prefix; any other word there is still found.
#[cfg_attr(test, test)]
pub(crate) fn a_stand_in_is_named_no_and_its_port() {
    assert!(named_for("NoGeolocator", "Mmdb", "Geolocator"));
    assert!(!named_for("NoCityDatabase", "Mmdb", "Geolocator"));
    assert!(!named_for("FakeGeolocator", "Mmdb", "Geolocator"));
}
