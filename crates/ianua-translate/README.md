# Ianua translations

`ianua-translate` collects the backend's response-related English text into a
reviewable translation inventory. The catalog has columns for English (`en`),
Ukrainian (`uk`), German (`de`), French (`fr`), Georgian (`ka`), Spanish (`es`),
Simplified Chinese (`zh-Hans`) and Japanese (`ja`).

The tool does not enable localized API responses, emails or other backend
output. The runtime renderer will use Fluent's Rust implementation; this tool
does not implement a translation engine. The inventory's source hashes are
collection identities only. Each message also has a Fluent key, which is given
once and kept in the catalog.

The JSON file is the authoring input for the generated resources in
`crates/ianua-infra/locales/`, not a runtime translation database. The planned
API errors carry stable keys and parameters for clients to translate. The
server renders mail, notifications and served pages in the recipient's
language. Rust selects messages and supplies data; translated sentences belong
in the language resources.

## Collect and verify

Run from the workspace root:

```sh
cargo run --offline -p ianua-translate -- collect --root . --out crates/ianua-translate/catalog.json
cargo run --offline -p ianua-translate -- check --root . --catalog crates/ianua-translate/catalog.json
```

Maintain translations directly in `catalog.json`, then run `check` and
`write-fluent` after editing.
The English source and collection metadata stay unchanged. If source coverage
has changed, run `collect` to refresh locations while preserving translations
for unchanged sources. See [Translating messages](TRANSLATING.md) for terminology
and editing rules.

The optional `import` and `revise` commands accept bulk tables from an explicit
temporary directory. They validate before saving; `import` refuses conflicting
text and `revise` applies intentional corrections. The catalog is the maintained
copy. Temporary import tables are discarded after verification.

Collection parses production Rust and keeps complete built-in mail and page
templates, including HTML, plain text, subjects and MiniJinja expressions. It
also keeps the event descriptions that the domain deliberately publishes from
its declaration comments. Ordinary documentation, test modules, test support,
demo fixtures, logging macros and explicitly masked internal error arguments
are excluded. Startup diagnostics, stored-row labels, corruption details,
OpenAPI metadata and serialized protocol payloads are also excluded.

Every message records its exact English source, interpolation grammar,
placeholders and source locations. Identical text with the same grammar shares
one entry. An absent translation is `null`; English is never copied into another
language to claim completion. Draft translations still need language review.

Response sources include:

- Recognized outward constructors, presentation modules and complete templates.
- Business error displays and indirect helper text whose callers return it in
  responses, including validation fragments and setup instructions. These are
  explicitly scoped by source owner; arbitrary prose is not a catalog entry.
- Dynamic message expressions passed through variables, helpers or external
  libraries, recorded separately so the migration does not silently omit them.

The inventory is a source audit, not a proof that every runtime response is
already localized. Notification titles assembled from event identifiers and
sentences assembled from fragments need complete language-specific messages
when they are wired to Fluent. External library errors need explicit public
message mappings. The dashboard, documentation site, tenant-authored content
and generated protocol bindings are outside this backend collection stage.

The response-only catalog contains 3,007 entries, all with drafts in all eight
languages. All 557 published event descriptions and all 72 complete templates
have drafts. The final nine attribute-error fragments were replaced in Rust
with five complete messages using named values and grammar-independent counts.
The previous fragments are archived under `retired`. Another 91
dynamic expressions need following during runtime integration. These counts
describe authored coverage, not native review or runtime localization.

Recollection preserves translations for unchanged response sources and retains
removed response entries under `retired`. Excluded internal text is discarded
from both active and retired entries. Writes replace the catalog atomically,
and malformed existing catalogs are refused rather than overwritten. `check`
detects source drift and changes to placeholder names in supplied translations.
It does not claim that empty translations are complete, or validate translated
templates as executable runtime content.

## Message keys

Collection gives every new message a Fluent key of the form `<topic>-<words>`,
such as `authorization-a-break-glass-grant-may-last`. The topic is the bounded
context or use-case folder the first public source belongs to, or the crate
(`api`, `infra`, `ldap`, `runner`), with `values` for shared domain values.
The words are the first six English words without placeholders; a key already
taken gets `-2`, `-3` and so on. Event descriptions are named after their event
type (`event-tenant-provisioned`) and mail subjects after their template
(`mail-subject-sign-in-password-reset`).

A key is never changed once given: recollection keeps it when the English is
unchanged, and an edited English source is a new message with a new key. A key
may be renamed by hand in the catalog to something clearer; `check` refuses a
malformed or duplicate key, and an active message without one.

## Fluent resources

```sh
cargo run --offline -p ianua-translate -- write-fluent --catalog crates/ianua-translate/catalog.json --out crates/ianua-infra/locales
cargo run --offline -p ianua-translate -- check-fluent --catalog crates/ianua-translate/catalog.json --locales crates/ianua-infra/locales
```

`write-fluent` writes, for each language:

- `<lang>/messages.ftl`: every plain and formatted message under its key,
  sorted by key, each topic opened by a `## <topic>` group comment. A language
  without a translation for a message leaves it out, so the runtime falls back
  to English.
- `<lang>/templates/<path>`: translated copies of the mail and page templates,
  in the same layout as `crates/ianua-infra/templates`, and
  `<lang>/templates/mail/<template>.subject` for each translated mail subject.
  English templates and subjects stay where the source keeps them.

Rust format fields become Fluent variables: `{name}` becomes `{ $name }`, and a
positional field `{}` or `{0}` becomes `{ $arg0 }`, `{ $arg1 }` in order. Format
specs such as `:?` are dropped, so the caller formats the value it passes.
Literal braces, and spaces Fluent would trim at the start or end of a message,
are written as quoted text such as `{"{"}`.

Every generated Fluent file is read back with Fluent's own parser before it is
written. A message that would read back differently from the catalog refuses
the whole export. Every file below a language folder is generated: writing
replaces changed files and removes files the catalog no longer produces, and
`check-fluent` refuses any missing, edited or leftover file. Edit the catalog,
never the generated files.

The backend builds these resources into its binary. The mail worker renders
the platform's mail from the translated templates in the recipient's language,
and the API words a keyed refusal in the first `Accept-Language` it ships
(`ianua-infra` `language::FluentRefusalWording`). Run `write-fluent` after
every catalog change and rebuild.

## Keying refusals in the source

```sh
cargo run --offline -p ianua-translate -- rewrite-preview --root . --catalog crates/ianua-translate/catalog.json
cargo run --offline -p ianua-translate -- rewrite --root . --catalog crates/ianua-translate/catalog.json
```

`rewrite` wraps every literal, `format!` message or text constant handed to a
refusal (`DomainError`, `AppError`, `ApiError::validation`, `or_not_found`,
`or_conflict`, validation messages) in `message!("<key>", <the same message>)`,
with the key the catalog holds for that text. A constant defined in another
file is matched by name, nearest folder first. An application error built from
other text gets the `.into()` its `Refusal` needs. Messages already keyed are
left alone, so a second run changes nothing; test code is converted where a
type needs it and never keyed. OAuth, SCIM and client-registration descriptions
are protocol text, ASCII by RFC 6749, and are not keyed. `rewrite-preview`
counts and lists what would change, including messages passed through a
variable or helper, without writing.

Production files name the macro short, as `message!`, with one
`use ianua_domain::message;` (`use crate::message;` in the domain) that
`rewrite` adds where it is missing.

Add a new refusal with `message!` directly, or write it plainly, run `collect`,
add its translations, then `rewrite` and `write-fluent`.

The key a `message!` call gives is the message's key in the catalog: the
runtime looks a refusal's wording up by it. `collect` notes it at each place
(`source_fluent_id`) and takes it over a key kept from before, keeping the
translations; `check` refuses a catalog whose key differs. One text keyed two
ways is refused: give the two refusals one key, or words of their own.

## Verification

```sh
cargo nextest run --offline -p ianua-translate
cargo clippy --offline -p ianua-translate --all-targets --all-features -- -D warnings
cargo +nightly fmt -p ianua-translate -- --check
```
