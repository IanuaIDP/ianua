//! The commands and the explicit paths each one reads and writes.

use std::path::PathBuf;

use crate::drafts::ImportMode;
use crate::error::{Error, Result};
use crate::rewrite::Mode as RewriteMode;

/// The commands and their required paths.
pub(crate) const HELP: &str = "ianua-translate

USAGE:
    ianua-translate collect --root <workspace> --out <catalog.json>
    ianua-translate check --root <workspace> --catalog <catalog.json>
    ianua-translate import --catalog <catalog.json> --drafts <directory>
    ianua-translate revise --catalog <catalog.json> --drafts <directory>
    ianua-translate write-fluent --catalog <catalog.json> --out <locales>
    ianua-translate check-fluent --catalog <catalog.json> --locales <locales>
    ianua-translate rewrite-preview --root <workspace> --catalog <catalog.json>
    ianua-translate rewrite --root <workspace> --catalog <catalog.json>

Collect inventories production Rust messages and complete mail/page templates,
keeping translations and message keys for sources that have not changed.
Check refuses a stale inventory, a message without a key or a translation that
changes its placeholders.
Write-fluent writes one Fluent file per topic and language, and translated
copies of the templates and mail subjects; check-fluent refuses any difference.
Rewrite wraps every literal or formatted refusal in the source as
message!(\"<key>\", ...); rewrite-preview counts what it would change.
The catalog records English plus Ukrainian, German, French, Georgian, Spanish,
Simplified Chinese and Japanese. Untranslated entries remain explicitly empty.
";

/// One operation with the paths it needs.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Command {
    /// Print usage without reading the workspace.
    Help,
    /// Collect messages, preserving existing translations and keys in the destination.
    Collect { root: PathBuf, out: PathBuf },
    /// Verify source coverage, keys and the translations already supplied.
    Check { root: PathBuf, catalog: PathBuf },
    /// Import authored draft tables into the catalog.
    Import {
        catalog: PathBuf,
        drafts: PathBuf,
        mode: ImportMode,
    },
    /// Write the Fluent resources and translated templates.
    WriteFluent { catalog: PathBuf, out: PathBuf },
    /// Verify the Fluent resources and translated templates on disk.
    CheckFluent { catalog: PathBuf, locales: PathBuf },
    /// Key every literal or formatted refusal in the source.
    Rewrite {
        root: PathBuf,
        catalog: PathBuf,
        mode: RewriteMode,
    },
}

/// Parses a command with explicit paths, refusing unknown or repeated options.
///
/// # Errors
///
/// Returns a usage error when a command, option or required value is absent.
pub(crate) fn parse(args: impl IntoIterator<Item = String>) -> Result<Command> {
    let mut args = args.into_iter();
    let Some(name) = args
        .next()
        .filter(|name| !matches!(name.as_str(), "--help" | "-h"))
    else {
        return Ok(Command::Help);
    };
    let flags = flags(&name)?;
    let [first, second] = paths(args, flags)?;
    Ok(named(&name, first, second))
}

/// The command `name` names, with its two paths in the order it uses them.
fn named(name: &str, first: PathBuf, second: PathBuf) -> Command {
    match name {
        "collect" => Command::Collect {
            root: first,
            out: second,
        },
        "check" => Command::Check {
            root: first,
            catalog: second,
        },
        "import" => import(first, second, ImportMode::Fill),
        "revise" => import(first, second, ImportMode::Revise),
        "write-fluent" => Command::WriteFluent {
            catalog: first,
            out: second,
        },
        "check-fluent" => Command::CheckFluent {
            catalog: first,
            locales: second,
        },
        "rewrite-preview" => rewrite(first, second, RewriteMode::DryRun),
        _ => rewrite(first, second, RewriteMode::Apply),
    }
}

/// The two path options a command requires, in the order it uses them.
fn flags(command: &str) -> Result<[&'static str; 2]> {
    match command {
        "collect" => Ok(["--root", "--out"]),
        "check" => Ok(["--root", "--catalog"]),
        "import" | "revise" => Ok(["--catalog", "--drafts"]),
        "write-fluent" => Ok(["--catalog", "--out"]),
        "check-fluent" => Ok(["--catalog", "--locales"]),
        "rewrite" | "rewrite-preview" => Ok(["--root", "--catalog"]),
        _ => Err(Error::Usage(format!(
            "unknown command {command}; expected collect, check, import, revise, write-fluent, check-fluent, rewrite or rewrite-preview"
        ))),
    }
}

/// Reads each flag's path exactly once, in the order the flags are listed.
fn paths(args: impl Iterator<Item = String>, flags: [&'static str; 2]) -> Result<[PathBuf; 2]> {
    let mut found: [Option<PathBuf>; 2] = [None, None];
    let mut args = args.peekable();
    while let Some(flag) = args.next() {
        let Some(index) = flags.iter().position(|known| *known == flag) else {
            return Err(Error::Usage(format!("unknown option {flag}")));
        };
        if found[index].is_some() {
            return Err(Error::Usage(format!("repeated option {flag}")));
        }
        let value = args.next_if(|value| !value.starts_with("--"));
        let value = value.ok_or_else(|| Error::Usage(format!("{flag} needs a path")))?;
        found[index] = Some(PathBuf::from(value));
    }
    let [first, second] = found;
    Ok([required(first, flags[0])?, required(second, flags[1])?])
}

fn required(path: Option<PathBuf>, flag: &str) -> Result<PathBuf> {
    path.ok_or_else(|| Error::Usage(format!("{flag} is required")))
}

fn rewrite(root: PathBuf, catalog: PathBuf, mode: RewriteMode) -> Command {
    Command::Rewrite {
        root,
        catalog,
        mode,
    }
}

fn import(catalog: PathBuf, drafts: PathBuf, mode: ImportMode) -> Command {
    Command::Import {
        catalog,
        drafts,
        mode,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(args: &[&str]) -> Result<Command> {
        parse(args.iter().map(|arg| (*arg).to_owned()))
    }

    /// A maintainer selects explicit paths for collection instead of changing files by default.
    #[test]
    fn collection_requires_explicit_paths() {
        let parsed_command = parsed(&["collect", "--root", ".", "--out", "catalog.json"]).unwrap();
        assert!(matches!(parsed_command, Command::Collect { .. }));
        assert!(parsed(&["collect"]).is_err());
    }

    /// A misspelled destination flag or repeated output option fails command parsing.
    #[test]
    fn unknown_and_repeated_options_are_refused() {
        assert!(parsed(&["collect", "--output", "x"]).is_err());
        assert!(parsed(&["collect", "--out", "a", "--out", "b"]).is_err());
    }

    /// Options may come in any order and still land on the right path.
    #[test]
    fn option_order_does_not_matter() {
        let command = parsed(&["write-fluent", "--out", "locales", "--catalog", "c.json"]).unwrap();
        assert_eq!(
            command,
            Command::WriteFluent {
                catalog: PathBuf::from("c.json"),
                out: PathBuf::from("locales"),
            }
        );
    }

    /// A catalog option without a path is refused even when another option follows it.
    #[test]
    fn an_option_without_a_value_is_refused() {
        assert!(parsed(&["check-fluent", "--catalog", "--locales", "x"]).is_err());
    }

    /// Revise is an import that applies corrections.
    #[test]
    fn revise_imports_in_revise_mode() {
        let command = parsed(&["revise", "--catalog", "c.json", "--drafts", "d"]).unwrap();
        assert!(matches!(
            command,
            Command::Import {
                mode: ImportMode::Revise,
                ..
            }
        ));
    }
}
