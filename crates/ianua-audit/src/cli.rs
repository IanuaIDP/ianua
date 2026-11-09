//! The command line, parsed by hand.

use std::path::PathBuf;

use anyhow::{Result, bail};

use crate::finding::Severity;
use crate::report::terminal::UnsaidLines;

/// What the help flag prints.
pub(crate) const HELP: &str = "\
ianua-audit: reads the ianua source and reports where its layers are not
connected. It parses the code; it does not build it.

USAGE:
    ianua-audit [report] [OPTIONS]
    ianua-audit graph <context> [OPTIONS]
    ianua-audit explain <name> [OPTIONS]
    ianua-audit impact <name> [OPTIONS]
    ianua-audit rules [context] [OPTIONS]
    ianua-audit checks
    ianua-audit check [layer] [OPTIONS]
    ianua-audit fields <table> [OPTIONS]

COMMANDS:
    report             Every finding, grouped by severity and check (default)
    graph <context>    One context drawn from domain to adapters, such as
                       `graph messaging`; unreached nodes are marked
    explain <name>     A short card of what the code says: a use case
                       (`CreateUseCase`, `webhooks::CreateUseCase`), every
                       use case of a context (`webhooks`), a domain type
                       (`WebhookSubscription`) or one of its changes
                       (`WebhookSubscription::create`)
    impact <name>      Everything that reaches a port method
                       (`WebhookStore::save`), a port, a domain type or
                       change, or a use case, by layer with file:line
    rules [context]    The domain's decisions as tables, its status
                       machines with who moves them, and what each change
                       refuses, all read from the code; `--markdown` writes
                       the docs page
    checks             The checks with their ids and severities
    check [layer]      The house rules each layer is written to: every
                       one, or one layer's (`domain`, `app`, `infra`,
                       `api`); lists each broken rule with what is wrong
                       and exits 1 when any is broken
    fields <table>     Each column of the tables starting with this, such
                       as `fields workflow_`: the store's field it is read
                       into and the queries that write and read it;
                       `--markdown` for a docs table

OPTIONS:
    --format <text|json|mermaid|markdown>
                                   Output format (default text); mermaid
                                   for report and graph, markdown for
                                   explain, impact and rules
    --markdown                     The same as `--format markdown`
    --out <file>                   Write to a file instead of stdout
    --no-color                     No ANSI colours (also off when not a TTY
                                   or when NO_COLOR is set)
    --fail-on <high|medium|low|info>
                                   Exit 1 when a finding this serious or worse
                                   is left after the allowlist
    --check <id prefix>            Only checks whose id starts with this,
                                   such as `adapters` or `reach.event`;
                                   may be given more than once
    --limit <n>                    Show at most n findings per check in text
                                   output (the summary still counts all)
    --unsaid                       List each conclusion left unsaid with the
                                   point the reader could not read (JSON
                                   always lists them)
    --root <dir>                   The workspace root (default: found from
                                   the current directory)
    --allow <file>                 The allowlist (default
                                   crates/ianua-audit/allow.toml)
    -h, --help                     This text
";

/// What to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Report every finding.
    Report,
    /// Draw one context.
    Graph(String),
    /// Explain one name in cards.
    Explain(String),
    /// List what reaches one name.
    Impact(String),
    /// Print the domain's rules, of one context when one is named.
    Rules(Option<String>),
    /// List the checks.
    Checks,
    /// Run the house rules, of one layer when one is named.
    Conventions(Option<String>),
    /// Show how the columns of the tables starting with this are kept.
    Fields(String),
    /// Print the help.
    Help,
}

/// How to write the output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Format {
    /// Text for a terminal.
    Text,
    /// JSON.
    Json,
    /// A Mermaid flowchart.
    Mermaid,
    /// Markdown.
    Markdown,
}

impl Format {
    /// The name `--format` takes.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Json => "json",
            Self::Mermaid => "mermaid",
            Self::Markdown => "markdown",
        }
    }
}

/// Whether ANSI colours may be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Colour {
    /// When writing text to a terminal and `NO_COLOR` is not set.
    Auto,
    /// Never.
    Never,
}

/// Everything the command line said.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Options {
    /// What to do.
    pub(crate) mode: Mode,
    /// How to write it.
    pub(crate) format: Format,
    /// The file to write to, or stdout.
    pub(crate) out: Option<PathBuf>,
    /// Whether colours may be used.
    pub(crate) colour: Colour,
    /// The severity that makes the run fail.
    pub(crate) fail_on: Option<Severity>,
    /// Check id prefixes to keep; empty keeps all.
    pub(crate) checks: Vec<String>,
    /// The most findings shown per check in text output.
    pub(crate) limit: Option<usize>,
    /// Whether text output lists each conclusion left unsaid.
    pub(crate) unsaid: UnsaidLines,
    /// The workspace root.
    pub(crate) root: Option<PathBuf>,
    /// The allowlist file.
    pub(crate) allow: Option<PathBuf>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            mode: Mode::Report,
            format: Format::Text,
            out: None,
            colour: Colour::Auto,
            fail_on: None,
            checks: Vec::new(),
            limit: None,
            unsaid: UnsaidLines::Counted,
            root: None,
            allow: None,
        }
    }
}

/// Reads the arguments after the program name.
///
/// # Errors
///
/// Fails on an unknown flag or command, a flag without its value, or a
/// value that is not one of those offered.
pub(crate) fn parse(args: impl IntoIterator<Item = String>) -> Result<Options> {
    let mut options = Options::default();
    let mut args = args.into_iter().peekable();
    while let Some(arg) = args.next() {
        let named = |next: &String| !next.starts_with('-');
        match arg.as_str() {
            "rules" => options.mode = Mode::Rules(args.next_if(named)),
            "check" => options.mode = Mode::Conventions(args.next_if(named)),
            "-h" | "--help" => options.mode = Mode::Help,
            "report" => options.mode = Mode::Report,
            "checks" => options.mode = Mode::Checks,
            "--markdown" => options.format = Format::Markdown,
            "--no-color" | "--no-colour" => options.colour = Colour::Never,
            "--unsaid" => options.unsaid = UnsaidLines::Listed,
            flag => options.take_value(flag, args.next())?,
        }
    }
    Ok(options)
}

impl Options {
    /// Sets what `flag` names to `value`, the argument after it.
    fn take_value(&mut self, flag: &str, value: Option<String>) -> Result<()> {
        let mut value = value;
        let mut value = || match value.take() {
            Some(value) => Ok(value),
            None => bail!("`{flag}` needs a value"),
        };
        match flag {
            "graph" => self.mode = Mode::Graph(value()?),
            "explain" => self.mode = Mode::Explain(value()?),
            "impact" => self.mode = Mode::Impact(value()?),
            "fields" => self.mode = Mode::Fields(value()?),
            "--format" => self.format = format(&value()?)?,
            "--out" => self.out = Some(PathBuf::from(value()?)),
            "--fail-on" => self.fail_on = Some(severity(&value()?)?),
            "--check" => self.checks.push(value()?),
            "--limit" => self.limit = Some(limit(&value()?)?),
            "--root" => self.root = Some(PathBuf::from(value()?)),
            "--allow" => self.allow = Some(PathBuf::from(value()?)),
            other => bail!("unknown argument `{other}`; see --help"),
        }
        Ok(())
    }
}

fn format(text: &str) -> Result<Format> {
    match text {
        "text" => Ok(Format::Text),
        "json" => Ok(Format::Json),
        "mermaid" => Ok(Format::Mermaid),
        "markdown" => Ok(Format::Markdown),
        other => bail!("`--format {other}`: expected text, json, mermaid or markdown"),
    }
}

fn severity(text: &str) -> Result<Severity> {
    match Severity::parse(text) {
        Some(severity) => Ok(severity),
        None => bail!("`--fail-on {text}`: expected high, medium, low or info"),
    }
}

fn limit(text: &str) -> Result<usize> {
    match text.parse() {
        Ok(limit) => Ok(limit),
        Err(_) => bail!("`--limit {text}`: expected a whole number"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(args: &[&str]) -> Result<Options> {
        parse(args.iter().map(|arg| (*arg).to_owned()))
    }

    #[test]
    fn no_arguments_is_a_text_report() {
        let options = parsed(&[]).unwrap();

        assert_eq!(options, Options::default());
    }

    #[test]
    fn graph_takes_its_context_and_flags_follow() {
        let options =
            parsed(&["graph", "messaging", "--format", "mermaid", "--out", "g.md"]).unwrap();

        assert_eq!(options.mode, Mode::Graph("messaging".to_owned()));
        assert_eq!(options.format, Format::Mermaid);
        assert_eq!(options.out, Some(PathBuf::from("g.md")));
    }

    #[test]
    fn explain_and_impact_take_their_name_and_markdown_is_a_format() {
        let explain =
            parsed(&["explain", "webhooks::CreateUseCase", "--format", "markdown"]).unwrap();
        let impact = parsed(&["impact", "WebhookStore::save"]).unwrap();

        assert_eq!(
            explain.mode,
            Mode::Explain("webhooks::CreateUseCase".to_owned())
        );
        assert_eq!(explain.format, Format::Markdown);
        assert_eq!(impact.mode, Mode::Impact("WebhookStore::save".to_owned()));
    }

    #[test]
    fn explain_without_a_name_is_refused() {
        assert!(parsed(&["explain"]).is_err());
    }

    #[test]
    fn fail_on_takes_a_severity() {
        let options = parsed(&["--fail-on", "medium", "--no-color"]).unwrap();

        assert_eq!(options.fail_on, Some(Severity::Medium));
        assert_eq!(options.colour, Colour::Never);
    }

    #[test]
    fn rules_takes_a_context_when_one_follows_and_markdown_is_a_format() {
        let all = parsed(&["rules", "--markdown"]).unwrap();
        let one = parsed(&["rules", "authentication"]).unwrap();

        assert_eq!(all.mode, Mode::Rules(None));
        assert_eq!(all.format, Format::Markdown);
        assert_eq!(one.mode, Mode::Rules(Some("authentication".to_owned())));
    }

    #[test]
    fn unsaid_asks_for_the_unsaid_to_be_listed() {
        let options = parsed(&["--unsaid"]).unwrap();

        assert_eq!(options.unsaid, UnsaidLines::Listed);
    }

    #[test]
    fn a_flag_without_its_value_is_refused() {
        assert!(parsed(&["--format"]).is_err());
    }

    #[test]
    fn an_unknown_severity_or_argument_is_refused() {
        assert!(parsed(&["--fail-on", "critical"]).is_err());
        assert!(parsed(&["--everything"]).is_err());
    }
}
