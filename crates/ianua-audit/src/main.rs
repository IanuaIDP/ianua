//! `ianua-audit` reads the ianua source without building it and reports
//! where the layers are not connected: domain behaviour the app never
//! reaches, events nothing raises, ports no adapter implements, use cases
//! nothing drives, and events, rights and data classes that go nowhere.
//! It finds logic conflicts too: plan limits two paths disagree on,
//! statuses moved out of a final state, changes that check no right, and
//! commands that save what a change raised without recording it, each
//! drawn only from what it read and counted as unsaid otherwise.
//!
//! `check` runs the house rules each layer's code is written to, the
//! shape of the app's own security code among them, from `conventions`.
//!
//! It also explains the code from the code: `explain` prints a short card
//! of what a use case or domain change calls, checks, raises and records,
//! and `impact` lists everything that reaches a port, a domain type or a
//! use case, to brief a change with.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]

mod allow;
mod checks;
mod cli;
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a check stops with a panic when its rule is broken or its files cannot be read, and `check` reports each stop"
)]
mod conventions;
mod finding;
mod model;
mod report;
mod source;

use std::collections::BTreeSet;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::{env, fs};

use anyhow::{Context, Result, bail};

use crate::allow::Allowlist;
use crate::cli::{Colour, Format, HELP, Mode, Options};
use crate::finding::{Check, Finding};
use crate::model::Model;
use crate::model::app::{APP_LISTS, silent_commands};
use crate::model::domain::DomainLists;
use crate::model::facts::Facts;
use crate::model::rules::Rules;
use crate::report::{Report, Style, explain, graph, impact, json, mermaid, rules, terminal};
use crate::source::Workspace;

/// Where the domain's conventions list the caller proofs and the
/// observations.
const DOMAIN_LISTS: &str = "crates/ianua-audit/src/conventions/domain/lists.rs";

/// The allowlist read when `--allow` is not given.
const DEFAULT_ALLOWLIST: &str = "crates/ianua-audit/allow.toml";

/// The exit code of a usage or reading error, an unknown or ambiguous name
/// among them.
const USAGE_ERROR: u8 = 2;

fn main() -> ExitCode {
    match run(env::args().skip(1)) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{}", error_line(&error));
            ExitCode::from(USAGE_ERROR)
        }
    }
}

/// How an error is printed: the program's name, then the error with its
/// causes.
fn error_line(error: &anyhow::Error) -> String {
    format!("ianua-audit: {error:#}")
}

fn run(args: impl IntoIterator<Item = String>) -> Result<ExitCode> {
    let options = cli::parse(args)?;
    match &options.mode {
        Mode::Help => {
            emit(&options, HELP)?;
            Ok(ExitCode::SUCCESS)
        }
        Mode::Checks => {
            emit(&options, &checks_table())?;
            Ok(ExitCode::SUCCESS)
        }
        Mode::Report => run_report(&options),
        Mode::Graph(context) => run_graph(&options, context),
        Mode::Explain(name) => run_explain(&options, name),
        Mode::Impact(name) => run_impact(&options, name),
        Mode::Rules(context) => run_rules(&options, context.as_deref()),
        Mode::Conventions(layer) => run_conventions(&options, layer.as_deref()),
        Mode::Fields(prefix) => run_fields(&options, prefix),
    }
}

/// Prints how each column of the tables starting with `prefix` is kept.
fn run_fields(options: &Options, prefix: &str) -> Result<ExitCode> {
    conventions::read_from(&workspace_root(options.root.as_deref())?);
    let markdown = options.format == Format::Markdown;
    let Some(page) = report::fields::page(prefix, markdown) else {
        bail!("no table starts with `{prefix}`");
    };
    emit(options, &page)?;
    Ok(ExitCode::SUCCESS)
}

/// Runs the house rules, of `layer` when one is named, and lists each
/// broken one with what it said; exits 1 when any is broken.
fn run_conventions(options: &Options, layer: Option<&str>) -> Result<ExitCode> {
    conventions::read_from(&workspace_root(options.root.as_deref())?);
    let layers: Vec<String> = layer.map(str::to_owned).into_iter().collect();
    let chosen = conventions::chosen(&layers);
    if chosen.is_empty() {
        bail!(
            "no house rules for a layer `{}`; layers: domain, app, infra, api",
            layers.join("")
        );
    }
    let broken = conventions::broken(&chosen);
    let mut text = String::new();
    for found in &broken {
        text.push_str(&format!(
            "broken: {}::{}\n  {}\n\n",
            found.check.layer,
            found.check.name,
            found.said.replace('\n', "\n  ")
        ));
    }
    text.push_str(&format!(
        "{} of {} house rules hold\n",
        chosen.len() - broken.len(),
        chosen.len()
    ));
    emit(options, &text)?;
    if broken.is_empty() {
        return Ok(ExitCode::SUCCESS);
    }
    Ok(ExitCode::FAILURE)
}

/// The workspace, read and modelled, with its root.
struct Loaded {
    root: PathBuf,
    workspace: Workspace,
    model: Model,
}

fn load(options: &Options) -> Result<Loaded> {
    load_at(workspace_root(options.root.as_deref())?)
}

/// The workspace at `root`, read and modelled.
fn load_at(root: PathBuf) -> Result<Loaded> {
    let workspace = Workspace::load(&root)?;
    let lists = fs::read_to_string(root.join(DOMAIN_LISTS)).unwrap_or_default();
    let mut model = Model::build(&workspace, &DomainLists::read(&lists));
    let app_lists = fs::read_to_string(root.join(APP_LISTS)).unwrap_or_default();
    model.app.silent_commands = silent_commands(&app_lists);
    Ok(Loaded {
        root,
        workspace,
        model,
    })
}

/// `given`, or the nearest folder up from here holding a workspace
/// `Cargo.toml` and `crates/ianua-domain`.
fn workspace_root(given: Option<&Path>) -> Result<PathBuf> {
    if let Some(root) = given {
        return Ok(root.to_path_buf());
    }
    let here = env::current_dir().context("reading the current directory")?;
    let found = here.ancestors().find(|dir| {
        let manifest = fs::read_to_string(dir.join("Cargo.toml")).unwrap_or_default();
        manifest.contains("[workspace]") && dir.join("crates/ianua-domain").is_dir()
    });
    match found {
        Some(root) => Ok(root.to_path_buf()),
        None => bail!("no ianua workspace above {}; pass --root", here.display()),
    }
}

fn allowlist(options: &Options, root: &Path) -> Result<Allowlist> {
    let (path, required) = match &options.allow {
        Some(path) => (path.clone(), true),
        None => (root.join(DEFAULT_ALLOWLIST), false),
    };
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(_) if !required => return Ok(Allowlist::default()),
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", path.display()));
        }
    };
    let shown = path
        .strip_prefix(root)
        .unwrap_or(&path)
        .display()
        .to_string();
    Allowlist::parse(&text, &shown)
}

fn run_report(options: &Options) -> Result<ExitCode> {
    let loaded = load(options)?;
    let report = report_of(options, &loaded)?;
    let text = match options.format {
        Format::Text => terminal::render(&report, style(options), options.limit, options.unsaid),
        Format::Json => json::render(&report)?,
        Format::Mermaid => mermaid::render_report(&report),
        Format::Markdown => bail!(unwritten("report", "text, json or mermaid", options.format)),
    };
    emit(options, &text)?;
    let failed = options
        .fail_on
        .is_some_and(|threshold| report.fails(threshold));
    Ok(if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

/// The crates `allowed` parks, by name.
fn parked_crates(allowed: &Allowlist) -> BTreeSet<String> {
    (allowed.parked.iter())
        .map(|crate_parked| crate_parked.crate_name.clone())
        .collect()
}

/// What `loaded` breaks, the allow list applied, parked crates set apart
/// and only the checks `options` names kept.
fn report_of(options: &Options, loaded: &Loaded) -> Result<Report> {
    let allowed = allowlist(options, &loaded.root)?;
    let parked = parked_crates(&allowed);
    let found = checks::run_all(&loaded.workspace, &loaded.model, &parked);
    let mut applied = allowed.apply(found.findings);
    let unknown = allowed.unknown_parked(&crate_names(&loaded.workspace));
    applied.kept.extend(unknown);
    let (kept, parked) = report::park(applied.kept, &allowed.parked);
    let mut findings = selected(kept, &options.checks);
    checks::sort(&mut findings);
    Ok(Report {
        findings,
        parked,
        allowed: applied
            .allowed
            .into_iter()
            .filter(|(finding, _)| wanted(finding, &options.checks))
            .collect(),
        silenced: found
            .silenced
            .into_iter()
            .filter(|(check, _)| wanted_check(*check, &options.checks))
            .collect(),
        unsaid: found
            .unsaid
            .into_iter()
            .filter(|unsaid| wanted_check(unsaid.check, &options.checks))
            .collect(),
        files_read: loaded.workspace.files.len(),
    })
}

/// The crate folders the workspace reads.
fn crate_names(workspace: &Workspace) -> BTreeSet<String> {
    workspace
        .files
        .iter()
        .map(|file| file.crate_name.clone())
        .chain(workspace.support.iter().map(|file| file.crate_name.clone()))
        .collect()
}

/// The findings whose check id starts with one of `prefixes`; all of them
/// when there are none. Unused allowlist entries are kept only then, since
/// a narrowed run leaves entries for other checks unmatched.
fn selected(findings: Vec<Finding>, prefixes: &[String]) -> Vec<Finding> {
    findings
        .into_iter()
        .filter(|finding| prefixes.is_empty() || finding.check != Check::UnusedAllow)
        .filter(|finding| wanted(finding, prefixes))
        .collect()
}

fn wanted(finding: &Finding, prefixes: &[String]) -> bool {
    wanted_check(finding.check, prefixes)
}

fn wanted_check(check: Check, prefixes: &[String]) -> bool {
    prefixes.is_empty()
        || prefixes
            .iter()
            .any(|prefix| check.id().starts_with(prefix.as_str()))
}

fn run_graph(options: &Options, context: &str) -> Result<ExitCode> {
    let loaded = load(options)?;
    let Some(drawn) = graph::build(&loaded.workspace, &loaded.model, context) else {
        bail!(
            "no context `{context}`; known contexts: {}",
            graph::contexts(&loaded.model).join(", ")
        );
    };
    let text = match options.format {
        Format::Text => graph::render_ascii(&drawn, style(options)),
        Format::Json => serde_json::to_string_pretty(&drawn)?,
        Format::Mermaid => mermaid::render_graph(&drawn),
        Format::Markdown => bail!(unwritten("graph", "text, json or mermaid", options.format)),
    };
    emit(options, &text)?;
    Ok(ExitCode::SUCCESS)
}

fn run_explain(options: &Options, name: &str) -> Result<ExitCode> {
    let loaded = load(options)?;
    emit(options, &explain_text(&loaded, options, name)?)?;
    Ok(ExitCode::SUCCESS)
}

/// The cards `name` stands for, in the format asked for.
fn explain_text(loaded: &Loaded, options: &Options, name: &str) -> Result<String> {
    let facts = Facts::build(&loaded.workspace, &loaded.model);
    let found = explain::find(&facts, name).map_err(anyhow::Error::msg)?;
    match options.format {
        Format::Text => Ok(explain::render_text(&found, style(options))),
        Format::Json => Ok(explain::render_json(&found)?),
        Format::Markdown => Ok(explain::render_markdown(&found)),
        Format::Mermaid => bail!(unwritten(
            "explain",
            "text, json or markdown",
            options.format
        )),
    }
}

fn run_impact(options: &Options, name: &str) -> Result<ExitCode> {
    let loaded = load(options)?;
    emit(options, &impact_text(&loaded, options, name)?)?;
    Ok(ExitCode::SUCCESS)
}

/// What reaches `name`, in the format asked for.
fn impact_text(loaded: &Loaded, options: &Options, name: &str) -> Result<String> {
    let facts = Facts::build(&loaded.workspace, &loaded.model);
    let parked = allowlist(options, &loaded.root)?.parked;
    let found = impact::build(&loaded.workspace, &loaded.model, &facts, name)
        .map_err(anyhow::Error::msg)?
        .marking_parked(&parked);
    match options.format {
        Format::Text => Ok(impact::render_text(&found, style(options))),
        Format::Json => Ok(impact::render_json(&found)?),
        Format::Markdown => Ok(impact::render_markdown(&found)),
        Format::Mermaid => bail!(unwritten(
            "impact",
            "text, json or markdown",
            options.format
        )),
    }
}

fn run_rules(options: &Options, context: Option<&str>) -> Result<ExitCode> {
    let loaded = load(options)?;
    emit(options, &rules_text(&loaded, options, context)?)?;
    Ok(ExitCode::SUCCESS)
}

/// The domain's rules, of `context` when one is named, in the format asked
/// for.
fn rules_text(loaded: &Loaded, options: &Options, context: Option<&str>) -> Result<String> {
    let all = domain_rules(loaded);
    let rules = match context {
        None => all,
        Some(name) if all.contexts().contains(name) => all.of_context(name),
        Some(name) => bail!(
            "no rules read in a context `{name}`; contexts with rules: {}",
            all.contexts().into_iter().collect::<Vec<_>>().join(", ")
        ),
    };
    match options.format {
        Format::Text => Ok(rules::render_text(&rules, style(options))),
        Format::Json => Ok(rules::render_json(&rules)?),
        Format::Markdown => Ok(rules::render_page(&rules)),
        Format::Mermaid => bail!(unwritten("rules", "text, json or markdown", options.format)),
    }
}

/// The rules of the domain `loaded` holds.
fn domain_rules(loaded: &Loaded) -> Rules {
    let facts = Facts::build(&loaded.workspace, &loaded.model);
    Rules::build(&loaded.workspace, &loaded.model, &facts)
}

/// Why `command` refuses `format`.
fn unwritten(command: &str, offered: &str, format: Format) -> String {
    format!(
        "`{command}` writes {offered}, not `--format {}`",
        format.as_str()
    )
}

fn checks_table() -> String {
    let width = Check::ALL
        .iter()
        .map(|check| check.id().len())
        .max()
        .unwrap_or(0);
    Check::ALL
        .iter()
        .map(|check| {
            format!(
                "{:<width$}  {:<6}  {}\n",
                check.id(),
                check.severity().as_str(),
                check.title()
            )
        })
        .collect()
}

/// Colours only for text on a terminal, unless switched off.
fn style(options: &Options) -> Style {
    let colour = options.colour == Colour::Auto
        && options.format == Format::Text
        && options.out.is_none()
        && env::var_os("NO_COLOR").is_none()
        && io::stdout().is_terminal();
    Style::new(colour)
}

fn emit(options: &Options, text: &str) -> Result<()> {
    if let Some(path) = &options.out {
        return fs::write(path, text).with_context(|| format!("writing {}", path.display()));
    }
    io::stdout()
        .lock()
        .write_all(text.as_bytes())
        .context("writing to stdout")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::facts::planted::{model, planted};

    fn loaded() -> Loaded {
        let workspace = planted();
        let model = model(&workspace);
        Loaded {
            root: PathBuf::new(),
            workspace,
            model,
        }
    }

    fn options(format: Format) -> Options {
        Options {
            format,
            colour: Colour::Never,
            ..Options::default()
        }
    }

    /// Where the docs page of the domain's rules is kept, from the
    /// workspace root.
    const RULES_PAGE: &str = "docs/src/content/docs/reference/rules.mdx";

    /// The docs page of the domain's rules is what `rules --markdown`
    /// writes from the code as it is now. `IANUA_WRITE_RULES=1` writes it.
    #[test]
    fn the_committed_rules_page_is_current() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let loaded = load_at(root.clone()).unwrap();
        let page = rules::render_page(&domain_rules(&loaded));
        let path = root.join(RULES_PAGE);

        if env::var_os("IANUA_WRITE_RULES").is_some() {
            fs::write(&path, &page).unwrap();
            return;
        }

        let committed = fs::read_to_string(&path).unwrap_or_default();
        assert!(
            committed == page,
            "{} is not what the code says now; run this test with IANUA_WRITE_RULES=1 to write it",
            RULES_PAGE
        );
    }

    #[test]
    fn rules_of_a_context_with_none_is_an_error_that_lists_those_with_some() {
        let error = rules_text(&loaded(), &options(Format::Text), "nowhere".into()).unwrap_err();

        assert!(
            error
                .to_string()
                .starts_with("no rules read in a context `nowhere`")
        );
    }

    #[test]
    fn an_unknown_name_is_an_error_that_says_so() {
        let error = explain_text(&loaded(), &options(Format::Text), "Nowhere").unwrap_err();

        assert_eq!(
            error_line(&error),
            "ianua-audit: no use case, context, domain type or change named `Nowhere`"
        );
    }

    #[test]
    fn an_ambiguous_name_is_an_error_that_lists_the_choices() {
        let mut loaded = loaded();
        loaded.workspace.files.push(source::planted::app(
            "use_cases/messaging/pause.rs",
            "pub struct PauseUseCase;\nimpl Command for PauseUseCase {}",
        ));
        loaded.model = model(&loaded.workspace);

        let error = impact_text(&loaded, &options(Format::Text), "PauseUseCase").unwrap_err();

        assert!(
            error
                .to_string()
                .starts_with("`PauseUseCase` names 2 use cases")
        );
    }

    #[test]
    fn a_format_a_command_does_not_write_is_refused() {
        let error =
            impact_text(&loaded(), &options(Format::Mermaid), "WebhookStore::save").unwrap_err();

        assert_eq!(
            error.to_string(),
            "`impact` writes text, json or markdown, not `--format mermaid`"
        );
    }

    #[test]
    fn explain_writes_markdown_when_asked() {
        let text = explain_text(&loaded(), &options(Format::Markdown), "PauseUseCase").unwrap();

        assert!(text.starts_with("### `PauseUseCase`"));
    }

    #[test]
    fn impact_writes_its_count_line_last() {
        let text = impact_text(&loaded(), &options(Format::Text), "WebhookStore").unwrap();

        assert!(
            text.trim_end()
                .lines()
                .last()
                .unwrap()
                .contains(" places: ")
        );
    }
}
