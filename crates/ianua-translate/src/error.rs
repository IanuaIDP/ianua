//! Every way a command can refuse, each naming the file, message or
//! language at fault and keeping the underlying cause.

use std::io;
use std::path::PathBuf;

/// The result every fallible step of the tool returns.
pub(crate) type Result<T, E = Error> = std::result::Result<T, E>;

/// Why a collection, check, import or Fluent export was refused.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    /// The command line named an unknown command or option, or left one out.
    #[error("{0}; see --help")]
    Usage(String),
    /// A file or folder could not be read or written.
    #[error("{}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// A catalog or draft table is not valid JSON of the expected shape.
    #[error("{}: {source}", path.display())]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    /// A production Rust file does not parse, so its messages cannot be read.
    #[error("{path}: {source}")]
    Rust {
        path: String,
        #[source]
        source: syn::Error,
    },
    /// A template, original or translated, does not parse.
    #[error("{name}: {source}")]
    Template {
        name: String,
        #[source]
        source: minijinja::Error,
    },
    /// `--root` does not name a Cargo workspace.
    #[error("{} is not the Ianua Cargo workspace", .0.display())]
    NotWorkspace(PathBuf),
    /// The workspace holds no built-in mail or page templates.
    #[error("no built-in mail or page templates were found")]
    NoTemplates,
    /// The catalog has another schema version or language list.
    #[error("unsupported catalog schema or language list")]
    UnsupportedSchema,
    /// A message's English source, identity or placeholders were edited.
    #[error("{0}: English source or placeholders were changed")]
    ChangedSource(String),
    /// A message lacks a language column, or its English column differs from the source.
    #[error("{0}: expected the eight language columns and unchanged English")]
    LanguageColumns(String),
    /// A translation is blank or does not keep the source's placeholders.
    #[error("{id}: {language} is empty or changes its placeholders")]
    BrokenTranslation { id: String, language: &'static str },
    /// A message has no source location, or two messages share an identity.
    #[error("{0}: missing source locations or duplicate identity")]
    DuplicateIdentity(String),
    /// A message key is malformed or held by two messages.
    #[error("{0}: message key is malformed or already taken")]
    BadKey(String),
    /// Two places in the source key the same text differently.
    #[error("{0}: the source gives this message two keys; give it one")]
    KeyedTwice(String),
    /// A message's key differs from the one its source gives it.
    #[error("{0}: the catalog's key differs from the source's; run collect again")]
    KeyDiffersFromSource(String),
    /// An active message has no key yet, so it cannot be exported.
    #[error("{0}: no message key; run collect first")]
    MissingKey(String),
    /// The catalog no longer matches what collection finds in the source.
    #[error("catalog source coverage is stale; run collect again")]
    StaleCatalog,
    /// A draft table lists its language columns in another order.
    #[error("{}: unexpected language columns", .0.display())]
    DraftColumns(PathBuf),
    /// A draft table holds a blank cell.
    #[error("{}: an empty translation draft", .0.display())]
    EmptyDraft(PathBuf),
    /// Two draft tables translate the same English differently.
    #[error("{}: conflicting drafts for {english}", path.display())]
    ConflictingDrafts { path: PathBuf, english: String },
    /// A draft would replace a translation already in the catalog.
    #[error("{id}: a different {language} draft already exists")]
    DraftReplaces { id: String, language: &'static str },
    /// A draft translates English the catalog does not hold.
    #[error("draft source is absent from the catalog: {0}")]
    UnknownDraft(String),
    /// A generated Fluent resource does not parse, or reads back differently.
    #[error("{file}: {detail}")]
    Fluent { file: String, detail: String },
    /// The Fluent resources on disk differ from what the catalog produces.
    #[error("{0}: the Fluent resources are stale; run write-fluent again")]
    StaleFluent(String),
}

/// Attaches the path to a failed read or write.
pub(crate) fn io_at(path: impl Into<PathBuf>) -> impl FnOnce(io::Error) -> Error {
    let path = path.into();
    move |source| Error::Io { path, source }
}

/// Attaches the path to JSON that could not be read or written.
pub(crate) fn json_at(path: impl Into<PathBuf>) -> impl FnOnce(serde_json::Error) -> Error {
    let path = path.into();
    move |source| Error::Json { path, source }
}

impl Error {
    /// Whether the error is a file that does not exist yet.
    pub(crate) fn is_not_found(&self) -> bool {
        matches!(self, Self::Io { source, .. } if source.kind() == io::ErrorKind::NotFound)
    }
}
