//! `ianua-translate` collects the backend's outward messages into a
//! translation catalog, checks it against the source, imports authored
//! drafts and writes the Fluent resources the backend renders from.
//! It never changes running behavior by itself.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]

mod catalog;
mod cli;
mod collect;
mod drafts;
mod error;
mod fluent;
mod language;
mod rewrite;
mod validation;

use std::path::Path;
use std::process::ExitCode;

use crate::catalog::Catalog;
use crate::cli::Command;
use crate::drafts::ImportMode;
use crate::error::Result;
use crate::fluent::Locales;

fn main() -> ExitCode {
    let outcome = cli::parse(std::env::args().skip(1)).and_then(run);
    let Err(error) = outcome else {
        return ExitCode::SUCCESS;
    };
    eprintln!("ianua-translate: {error}");
    ExitCode::FAILURE
}

/// Carries out one command and prints what it did.
fn run(command: Command) -> Result<()> {
    let report = match command {
        Command::Help => cli::HELP.to_owned(),
        Command::Collect { root, out } => collect(&root, &out)?,
        Command::Check { root, catalog } => check(&root, &catalog)?,
        Command::Import {
            catalog,
            drafts,
            mode,
        } => import(&catalog, &drafts, mode)?,
        Command::WriteFluent { catalog, out } => write_fluent(&catalog, &out)?,
        Command::CheckFluent { catalog, locales } => check_fluent(&catalog, &locales)?,
        Command::Rewrite {
            root,
            catalog,
            mode,
        } => rewrite::rewrite(&root, &Catalog::read(&catalog)?, mode)?.to_string(),
    };
    println!("{report}");
    Ok(())
}

fn collect(root: &Path, out: &Path) -> Result<String> {
    let mut catalog = collect::collect(root)?;
    catalog.write(out)?;
    Ok(catalog.summary())
}

fn check(root: &Path, path: &Path) -> Result<String> {
    let expected = collect::collect(root)?;
    let catalog = Catalog::read(path)?;
    catalog.check_sources(&expected)?;
    Ok(catalog.summary())
}

fn import(path: &Path, drafts: &Path, mode: ImportMode) -> Result<String> {
    let mut catalog = Catalog::read(path)?;
    let imported = drafts::import(&mut catalog, drafts, mode)?;
    catalog.save(path)?;
    Ok(format!(
        "Updated {imported} language drafts; {}",
        catalog.summary()
    ))
}

fn write_fluent(path: &Path, out: &Path) -> Result<String> {
    let locales = Locales::from_catalog(&Catalog::read(path)?)?;
    let changed = locales.write(out)?;
    Ok(format!(
        "{} generated files; {changed} written or removed",
        locales.len()
    ))
}

fn check_fluent(path: &Path, out: &Path) -> Result<String> {
    let locales = Locales::from_catalog(&Catalog::read(path)?)?;
    locales.ensure_current(out)?;
    Ok(format!("{} generated files are current", locales.len()))
}
