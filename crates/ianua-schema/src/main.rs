//! `ianua-schema` keeps the migrations and the written schema in step, the
//! way Atlas does: the schema says what the database should be, and the
//! tool writes the migration that gets it there.
//!
//! - `check` builds a database from `migrations/` and one from `schema/`,
//!   for the platform and for a tenant's own database, and fails when they
//!   differ, or when a released migration changed or is gone.
//! - `diff <name>` writes the next migration from the difference, refusing
//!   any change that would lose data unless the schema says so on purpose,
//!   and checks that the migrations then build the schema.
//! - `release` records the migrations as released: from then on each one
//!   is never edited or removed.
//!
//! Databases are made on the server `SCHEMA_DATABASE_URL` names, or in a
//! Postgres container the tool starts.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]

mod catalog;
mod compare;
mod databases;
mod directives;
mod lock;
mod notes;
mod plan;
mod sources;
mod write;

use std::collections::BTreeMap;
use std::fs;
use std::process::ExitCode;

use anyhow::{Context as _, Result, bail};

use crate::databases::{Scope, Server};
use crate::plan::Inputs;
use crate::sources::{Sources, sql_files};

/// What `--help` prints.
const HELP: &str = "\
ianua-schema: keeps the migrations and the written schema in step.

USAGE:
    ianua-schema check          the migrations build exactly the schema, and no
                                released migration changed
    ianua-schema diff <name>    write the next migration from the schema, such
                                as `diff pause_keys`
    ianua-schema release        record every migration as released

The schema is crates/ianua-infra/schema/. A change that loses data is refused
until the schema says so on purpose, on a comment line of its own:
    -- schema: drops <table>[.<column>] because <reason>
    -- schema: changes <table>.<column> because <reason>
    -- schema: renamed <table>[.<column>] to <new>

Databases are made on SCHEMA_DATABASE_URL (a server the tool may create and
drop databases on), or in a Postgres container the tool starts.
";

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let ran = match words.as_slice() {
        ["check"] => check().await,
        ["diff", name] => diff(name).await,
        ["release"] => release(),
        [] | ["help" | "--help" | "-h"] => {
            print!("{HELP}");
            Ok(true)
        }
        _ => {
            eprint!("{HELP}");
            Ok(false)
        }
    };
    match ran {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("ianua-schema: {error:#}");
            ExitCode::FAILURE
        }
    }
}

/// Whether the migrations build the schema and every released one stands.
async fn check() -> Result<bool> {
    let sources = Sources::of_the_workspace();
    let mut held = released_stand(&sources)?;
    let server = Server::reach().await?;
    for scope in Scope::BOTH {
        let lines = differences(&server, &sources, scope).await?;
        if lines.is_empty() {
            println!("{}: the migrations build the schema", scope.label());
            continue;
        }
        held = false;
        println!("{}: the migrations do not build the schema:", scope.label());
        for line in lines {
            println!("  {line}");
        }
    }
    Ok(held)
}

/// Writes the next migration called `name`, when the schema asks for one
/// and nothing in it is refused.
async fn diff(name: &str) -> Result<bool> {
    if !write::is_a_name(name) {
        bail!("`{name}` is not a migration's name: lower case words joined by `_`");
    }
    let sources = Sources::of_the_workspace();
    if !released_stand(&sources)? {
        return Ok(false);
    }
    let schema_files = sql_files(&sources.schema).context("reading schema/")?;
    let migration_files = sql_files(&sources.migrations).context("reading migrations/")?;
    let texts = schema_files.iter().map(|(_, text)| text.as_str());
    let Some(directives) = readable_directives(texts.clone()) else {
        return Ok(false);
    };
    let notes = notes::read(texts);
    let mut parts: BTreeMap<_, _> = sources::parts(&migration_files);
    parts.extend(sources::parts(&schema_files));
    let server = Server::reach().await?;
    let released = server.built(&sources.migrations, Scope::Platform).await?;
    let wanted = server.built(&sources.schema, Scope::Platform).await?;
    let inputs = Inputs {
        directives: &directives,
        notes: &notes,
        parts: &parts,
    };
    let plan = plan::plan(&released, &wanted, &inputs);
    write_plan(&plan, &server, &sources, name).await
}

/// The `-- schema:` directives in `texts`, or `None` once each line that
/// could not be read is told.
fn readable_directives<'a>(
    texts: impl IntoIterator<Item = &'a str>,
) -> Option<directives::Directives> {
    directives::read(texts)
        .inspect_err(|unreadable| {
            for line in unreadable {
                println!("{}: {}", line.line, line.why);
            }
        })
        .ok()
}

/// Writes `plan` as the next migrations called `name`, unless it refuses
/// something or has nothing to write, then checks they build the schema.
async fn write_plan(
    plan: &plan::Plan,
    server: &Server,
    sources: &Sources,
    name: &str,
) -> Result<bool> {
    if !plan.refusals.is_empty() {
        println!("nothing was written; the schema asks for changes that are refused:");
        for refusal in &plan.refusals {
            println!("  {refusal}");
        }
        return Ok(false);
    }
    if plan.statements.is_empty() {
        println!("the migrations already build the schema; nothing to write");
        return Ok(true);
    }
    for file in write::files(plan, sources.next_number()?, name) {
        fs::write(sources.migrations.join(&file.name), &file.text)
            .with_context(|| format!("writing {}", file.name))?;
        println!("wrote migrations/{}", file.name);
    }
    written_reaches_schema(server, sources).await
}

/// Whether the migrations, the new ones included, build the schema; what
/// is left over is told, to finish by hand.
async fn written_reaches_schema(server: &Server, sources: &Sources) -> Result<bool> {
    let mut reached = true;
    for scope in Scope::BOTH {
        let lines = differences(server, sources, scope).await?;
        if lines.is_empty() {
            continue;
        }
        reached = false;
        println!(
            "the written migration does not reach the schema for {}; finish it by hand:",
            scope.label()
        );
        for line in lines {
            println!("  {line}");
        }
    }
    Ok(reached)
}

/// Records every migration as released.
fn release() -> Result<bool> {
    let sources = Sources::of_the_workspace();
    let text = lock::written(&sources.migrations).context("reading migrations/")?;
    let count = text.lines().filter(|line| !line.starts_with('#')).count();
    fs::write(&sources.lock, text).context("writing the lock")?;
    println!("recorded {count} migrations as released");
    Ok(true)
}

/// Whether every released migration is still there, unchanged; what is
/// not is told.
fn released_stand(sources: &Sources) -> Result<bool> {
    let released = lock::read(&sources.lock).context("reading the lock")?;
    let problems = lock::broken(&released, &sources.migrations).context("reading migrations/")?;
    for problem in &problems {
        println!("{problem}");
    }
    Ok(problems.is_empty())
}

/// How what the migrations build differs from what the schema builds, as
/// `scope`.
async fn differences(server: &Server, sources: &Sources, scope: Scope) -> Result<Vec<String>> {
    let built = server.built(&sources.migrations, scope).await?;
    let wanted = server.built(&sources.schema, scope).await?;
    Ok(compare::differences(&built, &wanted))
}
