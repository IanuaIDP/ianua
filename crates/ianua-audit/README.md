# ianua-audit

Reads the ianua source and reports where the layers are not connected: what
the domain offers that the app never reaches, events nothing raises, what the
app needs that no adapter provides, and events, rights and data classes that
go nowhere. It parses the code with `syn`; it does not build it, so it also
reads crates that do not compile. A file that does not parse is read as text
and reported (`meta.parse-failed`).

It also finds logic conflicts: places that should agree and do not, such as
two paths that create the same thing and disagree on its plan limit (see
[Logic conflicts](#logic-conflicts-and-the-honesty-rule)).

The shape of the app's own security code (rights checked before a load they do
not need, commands that record, saves followed by their events, store ports
scoped to a tenant) is held by the app's conventions, in
`crates/ianua-audit/src/conventions/app/security.rs`, which `ianua-audit check` runs;
`records.success-without-event` asks the paths of a command, which those
conventions do not, and reads their list of silent commands.

It reads `src/` of `ianua-domain`, `ianua-app` and the adapter crates
(`ianua-api`, `ianua-infra`, `ianua-server`, `ianua-ldap`, `ianua-zero`,
`ianua-grpc`, `ianua-dns`), as they build outside
tests: `#[cfg(test)]` items, `test_support` folders and modules switched off
with `#[cfg(any())]` are left out. Only `impact` and `rules.table-untested`
also read the tests: each file's own unit tests, the files of modules built
only for tests (`#[cfg(test)] mod fixtures;`), `src/**/test_support`, and
every crate's `tests/` (`ianua-scenarios` included).

## Running it

```sh
cargo run -p ianua-audit                          # the report
cargo run -p ianua-audit -- --limit 5             # at most 5 findings per check
cargo run -p ianua-audit -- --check reach.event   # only checks whose id starts with this
cargo run -p ianua-audit -- graph messaging       # one context as an ASCII graph
cargo run -p ianua-audit -- graph messaging --format mermaid --out messaging.md
cargo run -p ianua-audit -- --format json --out audit.json
cargo run -p ianua-audit -- --fail-on high        # exit 1 when a high finding is left
cargo run -p ianua-audit -- checks                # every check with its id and severity
cargo run -p ianua-audit -- explain webhooks::CreateUseCase   # a card of what the code says
cargo run -p ianua-audit -- explain WebhookSubscription --format markdown
cargo run -p ianua-audit -- impact WebhookStore::save        # everything that reaches it
cargo run -p ianua-audit -- rules authentication  # one context's decisions, machines, refusals
cargo run -p ianua-audit -- rules --markdown      # the docs page of every rule
cargo run -p ianua-audit -- --unsaid              # list each conclusion left unsaid
cargo run --release -p ianua-audit -- check       # every layer's house rules, side by side
cargo run --release -p ianua-audit -- check app   # one layer's: domain, app, infra, api or integrations
```

`check` runs the house rules each layer is written to, kept under
`src/conventions/` by layer; the `integrations` group holds the crates under
`integrations/` to the adapters' style and a doc comment on every public
item. Each check reads the source and stops on the first
break it finds; `check` runs them on every core, lists each broken rule with
what it said, and exits `1` when any is broken. Each check is also a test of
this tool, so the workspace test run in CI still runs every one, together with
the planted breaks that show each check finds what it exists to find. The
domain's payload keys are pinned in `src/conventions/domain/payload_keys.snapshot`;
`IANUA_WRITE_SNAPSHOTS=1` rewrites it after a deliberate change.

Colours are on for text written to a terminal, and off with `--no-color`, with
`NO_COLOR` set, or when the output is a file or a pipe. `--root <dir>` points it
at another checkout; by default it looks for the workspace above the current
directory.

Exit codes: `0` done, `1` a finding at or above `--fail-on` is left or a house
rule is broken, `2` a usage
or reading error, an unknown or ambiguous name to `explain` or `impact` among
them.

## What it checks

Each finding has a severity, a check id, `file:line`, a subject and a one-line
message.

| Check | Severity | Finds |
| --- | --- | --- |
| `reach.behaviour` | medium | Public creators and changes of aggregates and operation values (types implementing `Raises` or `RaisesComplete`) no use case calls |
| `reach.ensure` | medium | Public `ensure_*` rules nothing calls |
| `reach.proof` | medium | Caller proofs the app never names |
| `reach.event-unraised` | medium | Events no domain change raises and no called observation builds |
| `reach.event-adapter-only` | low | Events an adapter builds itself, bypassing the domain |
| `adapters.port-unimplemented` | high | Port traits no adapter or app service implements |
| `adapters.method-missing` | high | Adapter impls missing a required port method |
| `adapters.method-stale` | medium | Adapter methods the port no longer declares |
| `adapters.use-case-unwired` | medium | Use cases no adapter constructs or calls |
| `adapters.ports-field-unset` | high | `*Ports` structs written out in an adapter without a field |
| `adapters.ports-field-unknown` | high | Fields set in an adapter that the `*Ports` struct no longer has |
| `flow.event-unheard` | info | Event types no notification category, worker or consumer listens to |
| `flow.permission-unchecked` | medium | Rights a role can grant that no rule names (an area's `Manage` counts when a sibling is checked) |
| `flow.data-class-uncompared` | low | Fields holding a data class that no comparison names |
| `limits.path-missing` | high | A use case creating what another checks a plan limit for first, without that check; or one whose own check some path to the stored create skips |
| `status.final-reopened` | high | A public change that moves a status out of a state its machine says is final, by writing it around `try_transition` |
| `rights.unchecked-change` | high | A creator or change of a stored aggregate a use case calls that takes no caller proof and checks no right |
| `records.success-without-event` | high | A command with a path that saves what a change raised and succeeds without dispatching |
| `gates.dead-end` | high | A path to a capability the deployment may not have that never asks whether it is set up, or a rule owing what only that capability completes without knowing it is there |
| `rules.weaker-when-off` | high | A rule that, all else the same, answers something lower in the code's own order when a capability is not set up than when it is |
| `rules.table-untested` | low | Rows of a worked-out rule no test calls it with |

The caller proofs come from `crates/ianua-audit/src/conventions/domain/lists.rs`
(read as text) and every public `*Control` type in the domain. Each finding
has a one-line message; the logic checks add `detail` lines (in text under
the message, in JSON as `detail`) naming every `file:line` on both sides, why
it matters and the usual fix.

### Logic conflicts, and the honesty rule

The `limits`, `status`, `rights`, `records`, `gates` and `rules` checks find
places that should agree and do not. A finding must be true. So a check never concludes from a
fact the reader marked not read (see **not read** under
[Explaining the code](#explaining-the-code), and the flow below): when a
conclusion would rest on one, it stays silent and counts it. The report ends
with one line saying how many conclusions were left unsaid, per check (JSON:
`silenced_count`, and `silenced` per check).

- **`limits.path-missing`.** A use case that checks a plan limit
  (`ResourceKind::X` handed to a call, or bound to a name first) says the
  limit guards the aggregate it creates whose name ends in the kind's
  singular (`Group` for `Groups`); when no aggregate of the domain is named
  after the kind, the one aggregate it creates, if it creates one and its
  name shares a word with the kind (`ApprovalRequest` for
  `PendingApprovals`, never `ScheduledJob` for `ActiveAgentRuns`). Another
  use case calling a creator of that aggregate (the same
  or another, such as an import or a first sign-in) with no check of that
  kind is reported, naming the checking one. A use case with anything not
  read on its card is counted instead: the check may sit there. A use case
  that does check is also asked of its flow: a path that calls the creator
  and then stores what it made, or succeeds, without passing the check
  (the check in one branch, or after the save) is reported; a value made in
  memory before a check that comes before the save is fine.
- **`status.final-reopened`.** A status machine is an enum with
  `try_transition(self, to: Self)`; its moves are worked out from its body
  for every pair of variants (`matches!`, comparisons, `checked(self, to,
  rule)`, `allowed_transitions`, its own functions), and a state no move
  leaves is final. A state enum maps onto a machine through its own
  `status()`. A public `&mut self` change of an aggregate, with its own
  functions it calls, that writes such a field (`self.status = ..`,
  `mem::replace`) to another state without asking the machine and without
  reading the status is reported. A change that reads the status is asked
  of its guards: a statement before the write (in the change, or in the
  function that writes) that is sure to leave for a value in a final state
  (a `let .. else` whose pattern it does not match, an `if` that returns
  and whose condition holds for it, a `?` on the aggregate's own function
  that does either) refuses that state; when every final state the write
  would leave is refused, nothing is said. The guards are worked out by
  the evaluator described under [Rules](#rules). A machine whose body is
  not read, a new state the reader cannot name, a final state no guard was
  shown to refuse, a change that hands `self` on or calls what it cannot
  find is counted.
- **`rights.unchecked-change`.** A creator or change of a stored aggregate
  that a use case calls, takes no caller proof (by type, `impl` or a generic
  bound, or a listed carrier), checks no right by a call, and is not listed
  in `UNCALLED_CHANGES` of the domain conventions' `lists.rs` (read, not
  copied). One whose rights may be checked beyond what the reader follows (a
  helper more than two calls away, a method of another file on a value of
  unknown type) is counted.
- **`records.success-without-event`.** A command with a path, through no
  not-read point, that calls a change that raises events, writes that
  value to a `*Store` port (`save`, `insert`, `update`, `delete` and the
  like) and hands back `Ok` without dispatching. A write after nothing that
  raises owes no event, and nor does a write of another value: values are
  told apart by the names the code gives them, a helper's parameters being
  its caller's values and a name bound again (a `let`, each run of a loop)
  a new value; a value the reader cannot name may be any. A dispatch that
  fails dispatched nothing. A write that hands back a `bool` (whether it
  wrote anything) and a change that hands back one of the domain's enums
  (what it did, which may decide whether it raised) are not-read points
  after them. The commands the app's conventions list as recording
  nothing on purpose (`SILENT_COMMANDS_ALLOWED`, `UNRECORDED_SAVES_ALLOWED`
  in `crates/ianua-audit/src/conventions/app/security.rs`) are left alone.
- **`gates.dead-end`.** A gate is a capability a deployment may not have,
  read from the code: a port whose method answers an enum with a "not set
  up" variant (`MailSetup::reach` answering `MailReach::NotSetUp`), with
  the ports of the same module it governs (`Mailer`, `MailOutbox`); a port
  held as an `Option`; an adapter setting with a `None`-like variant. Two
  things are asked. A use case that holds the gate's port and has a path to
  a governed port that never asks the gate is reported. And a worked-out
  rule (see [Rules](#rules)) whose answer only the gate completes, because
  every path of some use case to a governed port was narrowed to it (`if
  owes_email_confirmation(owed)`, a `match` arm) and no path with that
  answer succeeds without such a call, is reported when it takes no input
  of the gate's answer, or still gives it while that input says not set
  up.
- **`rules.weaker-when-off`.** A worked-out rule that takes a gate's answer
  is compared row by row, all other inputs the same: where the gate says
  not set up and the answer differs, the two answers are put in the order
  the code gives. The answer enum derives `PartialOrd` (declared earlier
  is lower), or exactly one of its methods taking only `self` maps it to an
  enum that does. A lower answer when off is reported. Where the code gives
  no order, the pair is counted as unsaid with that reason.
- **`rules.table-untested`.** For each worked-out rule, the `#[test]`
  functions of the workspace are read for calls of it whose inputs are
  written out: variants and `true`/`false`, names a `let` binds, `for`
  loops over written lists of values or tuples, and parameters of the test
  file's own helpers. A row no such call takes is reported, low. A call
  with an input not read this way leaves the rows it may take unsaid; so
  does a test calling a domain function that calls the rule. A use case's
  test that reaches the rule is not counted, and the message says only that
  no test calls it with those inputs.

`--unsaid` lists each conclusion left unsaid under the summary, with the
check, what it was about and the `file:line` of the point it rested on and
why that point was not read; JSON always carries them as `unsaid`.

### Flow

Each body the facts read also keeps its shape: its port calls, domain
changes, limit checks and dispatches in the order they run, `if` and `match`
as choices, loops (run any number of times, `loop` at least once), every
early exit (`?`, `return`, the end of a `let .. else`, `break` and `continue`
for their loop), and units of work (`kept_together`, `atomically`,
`scoped_holding`, `UnitOfWork::run`) around what runs inside them. Helpers
are put in at their call as far as the facts follow them; a helper's error
leaves the caller through `?`, and its exits are the caller's when the
caller hands its result back as its own (not when it wraps it, as
`Err(helper())`).

What the reader follows, beyond the plain calls:

- **A step's own failure.** A port call, a domain change or a dispatch
  whose own call fails took no effect: the error of `?` right on it, and of
  a body handing back its result, leaves before it.
- **A result kept and matched.** `match`, `if let Ok(..)`/`if let
  Err(..)`, `let Ok(..) = .. else`, `let _ =`, and `unwrap_or_else`,
  `unwrap_or`, `unwrap_or_default` and `ok` on a helper's, a step's or a
  unit's result split the path: the `Ok` side runs after it succeeded, the
  `Err` side after it failed. A result a `let` binds and the next statement
  matches on splits the same way.
- **Units of work.** What a unit runs hands its result back as the unit's;
  a unit that fails drops everything written and recorded inside it, so its
  failure leaves the path as it was before. A future made by an `async fn`
  and bound to a name just before the unit runs inside it; one handed to a
  helper runs where the helper hands it to a unit (as a sweep's `swept(unit,
  work)` does), or, when the helper does not, where it is handed.
- **Closures.** A closure handed to an iterator adapter or to an `Option`
  or `Result` combinator (`map`, `filter`, `for_each`, `try_for_each`,
  `and_then`, ...) runs any number of times; its `?` and `return` leave the
  closure. One handed to `unwrap_or_else` runs once its receiver failed.
- **Types.** A collection's items (`Vec<T>`, slices, `impl Iterator<Item =
  T>`, through `Result` and `Option`) type a `for` loop's name and a
  closure's parameter; `find`, `next`, `first` and the like pick one. A
  struct of the app taken apart, a field of a field and a tuple struct's
  `.0` are typed by its declaration; an app type alias stands for its type.
  A value of a domain trait (an adapter implements it, such as a password
  hasher) reaches none of the app's ports, so calls on it are read as done.
- **Functions by path.** `Type::function(..)` of an app type and
  `module::function(..)` through an imported module (`use ..::{self}`) are
  followed like any helper; the app's error constructors are not.
- **Events gathered.** `events.extend(..)`, `push` and `append` add to a
  local list of events, and looking at it (`is_empty`, `len`) sends nothing.

A closure, async block or macro with facts inside that runs at no known
point, a call not followed and a helper more than ten calls from `execute`
are not-read points. A question asked of the flow (one step before another
on every path, a path to a step without another, every successful exit
passing a step, two steps inside one unit) answers yes or no only along
paths with no not-read point, and is unknown otherwise, naming the first
not-read point the deciding path passed.

### Parked crates

A crate waiting for a rebuild is listed in `allow.toml` as `[[parked]]`, with
`crate` and `reason`. Its findings are left out of the list and of
`--fail-on`, and counted on one line per crate at the end of the report (JSON:
`parked`). A use case no live adapter names, which only a parked crate wires,
is still reported, at info, its subject naming the crate, and counted on that
crate's line. A parked entry naming no crate in the workspace is reported as
`meta.allow-unused`. Parked crates are still read: `impact` lists their files,
marked `(parked)`.

### When an event counts as raised

Aggregates raise their own events: a mutator builds the event and hands it to
`raise`, `raise_platform`, `raise_organization`, `raise_tenant` or one of the
aggregate's `raise_*` helpers, and the app takes it with `take_events` after
the save. An operation value such as `DirectoryBindAttempt` raises the same
way. Events no aggregate raises are built by the constructors listed in
`OBSERVATIONS` in the domain's `lists.rs`, such as `HoneypotHit::observed`.

So an event counts as raised when a domain function that raises, or a listed
observation, builds it: written out (`Self { .. }` in the event's own `impl`
too), as a tuple struct, through one of the event's own functions
(`StepStarted::new(..)`), or in a helper it calls, at most two calls away. A
function also raises when it hands what it built to one that does
(`Self::raising(event)`) or to a listed observation (`self.login.recorded(event)`).
An observation only counts once something calls it; an event built by an
adapter itself, rather than through its observation, is
`reach.event-adapter-only`. What the app builds no longer counts: the app's
conventions refuse a use case that builds an event.

## Graphs

This is the current graph reporting tool. The legacy domain and wiring docs
snapshots no longer have freshness convention tests; wiring checks still enforce
that ports have implementations and callers.

`graph <context>` draws one context: each aggregate with its creators and
changes and the use cases that call them, the context's events with what raises
them, and each use case with its ports, the types implementing them and the
adapter files that name it. Unreached behaviours, events never raised, ports
with no adapter and unwired use cases are marked. `--format mermaid` writes the
same graph as a flowchart in the docs' style (`ok`, `step`, `ask`, `deny`
classes, stroke widths only); `--format json` writes it as data.

## Explaining the code

`explain <name>` prints a short card per use case or domain change, each line a
fact read from the source, so a developer or an agent can read the card instead
of the files behind it. `<name>` is:

- a use case: `CreateUseCase`, or `webhooks::CreateUseCase` when several
  contexts have one (the error lists them), or a path ending in its file when
  two share a context;
- a context folder, such as `webhooks`: one card per use case;
- a domain type, such as `WebhookSubscription`: one card per creator and change;
- one creator or change, such as `WebhookSubscription::create`.

`--format markdown` gives each fact its `file:line`; `--format json` writes the
facts whole, for tools and later checks. The card for
`webhooks::CreateUseCase`:

```text
CreateUseCase  command in webhooks  crates/ianua-app/src/use_cases/webhooks/subscriptions/create.rs:98
  caller     CallerContext
  input      CreateRequest
  output     Result<CreatedSubscription, AppError>
  ports      webhook_store (WebhookStore): save
             secret_generator (WebhookSecretGenerator): generate via new_secret > fresh_secret
             encryptor (SecretEncryptor): encrypt via new_secret > fresh_secret > sealed_text
             limit_enforcer (LimitEnforcer): check_tenant_limit via ensure_room_in_tenant
             tenant_authorities (TenantAuthorities): authority
  changes    WebhookSubscription::create (create) via new_subscription
               proof: WebhookControl, requires WebhooksAction::Update; raises WebhookSubscriptionCreated (webhooks.subscription_created)
  rights     none outside the changes it calls
  limits     Webhooks, checked by ensure_room_in_tenant
  records    WebhookSubscriptionCreated (webhooks.subscription_created) by dispatch_by
  errors     documented Domain, Forbidden, Internal, Unauthenticated; written none
  not read   nothing
```

How each line is read:

- **caller, input, output**: `type Caller`, `type Input` and `type Output` as
  written in the `Command` or `Query` impl.
- **ports**: the fields of the `*Ports` struct the use case holds, each with its
  port trait, and the methods called on it: `self.ports.<field>.<method>(..)`,
  through a `let` bound to the field, or in a helper handed the port.
- **changes**: the domain creators called by path (`Type::create`) and the
  changes called on a value whose type the reader followed; with what the domain
  says of each, the rights it checks and the events it raises.
- **rights**: rights the use case checks itself, outside the changes.
- **limits**: each `ResourceKind::X` handed to a call, such as
  `ensure_room_in_tenant`.
- **records**: each `dispatch` or `dispatch_by`, with the events of what it is
  handed: `value.take_events(..)` gives the events the changes on that value's
  type raise in this use case, and a listed observation called by path gives
  its own.
- **errors**: the `AppError` variants the `# Errors` section of `execute` names,
  and those written as `AppError::X` in the body and its helpers.
- **order**: what the flow says of the order of the steps, when it says
  something: a limit checked before a create on every path, or before what
  it makes is stored; whether every path that saves what a change raised
  dispatches; a save before a dispatch on every path; a save and a dispatch
  inside one unit. A question that rests on a point the flow does not follow
  says so.
- **not read**: what the reader met and could not place, said plainly rather
  than guessed.

A card only says "none", "nothing dispatched" or "no call read" when every call
in the bodies it followed was read. Any call that can reach a port or the
auditor and was not followed is listed under **not read**, and the empty rows
then say "... read, see not read". Such a call is one on an unread field of
`self`, on a part of a value holding ports, on a `*Ports` field that is not a
port, a method no `impl` of the receiver's type defines, a function the reader
does not follow that is handed a port, a `*Ports` struct, the auditor, events,
`self` or a closure using them, a macro naming any of those, or a helper
deeper than the reader follows.

A domain change's card says the caller proofs its signature takes (`proof:
OperatorAuthority`), which hold a right by their type, the rights it checks by a
call (itself or in a helper at most two calls away), the events it raises, and
the use cases that call it.

A fact found in a helper says `via` the helper, followed up to ten calls from
`execute`: a method of the use case; a method of its `*Ports` struct or of one
nested in it (`via settle_revocation`); a method of an app struct, such as a
`Sender` a ports method hands back (`via Sender::send_test`); a function of
the same file; an app function the file imports, such as a shared service in
`services/`; or one called by its type's or module's path, such as
`TenantBatches::over` or `sign_in_gate::admit`. A port put into a struct
(`Answering { exports: self.ports.exports.as_ref() }`) is followed into the
helper that struct is handed to, and through a `let Struct { .. } = value`
taking it apart. Names are followed through `use` items and `pub use`
re-exports, globs included, to the module that declares them, since many
contexts declare a `CreatePorts` or a `ListUseCase`.

A value's type is known only when the code says it: a parameter or `let` with
its type written, a port method, helper or domain function whose signature
names what it hands back, a struct written out, a creator called by path,
an item of a collection whose items are known (a `for` loop's name, a
closure's parameter, `find`), or a field of an app struct. `?`, `.await`,
`map_err`, `or_*` and `as_ref` keep it. A call named like a domain change on
a value whose type was not followed (a tuple taken apart, a value of
unknown type) is listed under **not read** with the changes it might be,
not joined to one.

A right counts as checked by a call whose name starts with `ensure_may`,
`ensure_holds` or `ensure_controls`, or any `ensure_*` handed a right, such as
`control.ensure_may(WebhooksAction::Update)`. A check handed a variable or
nothing, such as `control.ensure_may_change()`, takes the right its domain
definition writes when every definition of that name agrees, and says through
which; otherwise the right is not read. `holds`, `holds_agent` and
`has_system_permission` handed a right are shown as asking for it.

What the cards do not know, outside the order line: the logic inside a
function, the conditions and branches around a call (a card says a change is
called, not when, or whether only on one path), loops, early returns, and
calls inside a macro. A call
written twice is one fact. The events listed under **records** are those of the
changes the use case calls on that type, not a proof that each path raises
them. Ports set by `#[derive(Fakes)]` and errors converted by `?` are not seen.

## Impact of a change

`impact <name>` lists everything that reaches one thing, grouped by layer with
`file:line`, and ends with a count: the list to brief a change with before
editing. `<name>` is a port method (`WebhookStore::save`), a port
(`WebhookStore`), a domain type (`WebhookSubscription`) or change
(`WebhookSubscription::pause`), or a use case (as for `explain`). A port name
two contexts share is refused with both listed; name one after its context,
`oauth::AssertionReplayGuard` or `oauth::AssertionReplayGuard::first_use`.
Files of a parked crate are listed, marked `(parked)`.

Its output, the fifteen test lines cut to three here:

```text
impact of WebhookStore::save  port method  crates/ianua-app/src/ports/webhooks.rs:147

use cases (5)
  crates/ianua-app/src/use_cases/webhooks/keeping.rs:20  RotateSecretUseCase (webhooks) calls save via kept_subscription
  crates/ianua-app/src/use_cases/webhooks/keeping.rs:20  UpdateUseCase (webhooks) calls save via kept_subscription
  crates/ianua-app/src/use_cases/webhooks/subscriptions/create.rs:136  CreateUseCase (webhooks) calls save
  crates/ianua-app/src/use_cases/webhooks/subscriptions/pause.rs:78  PauseUseCase (webhooks) calls save
  crates/ianua-app/src/use_cases/webhooks/subscriptions/resume.rs:79  ResumeUseCase (webhooks) calls save

adapters (1)
  crates/ianua-infra/src/postgres/webhooks/subscriptions.rs:213  PgWebhookStore implements it (ianua-infra)

fakes (1)
  crates/ianua-app/src/test_support/webhooks.rs:277  FakeWebhookStore implements it

tests (15)
  crates/ianua-api/tests/api/webhooks.rs:11  names FakeWebhookStore
  crates/ianua-app/src/use_cases/webhooks/delivery/job.rs:182  unit tests: names FakeWebhookStore
  crates/ianua-app/src/use_cases/webhooks/subscriptions/create.rs:174  unit tests of CreateUseCase

22 places: domain 0, use cases 5, app services 0, adapters 1, fakes 1, tests 15
```

- **use cases** and **app services**: the calls the facts above found, with
  `via`; app services also list app types implementing a port.
- **adapters**: `impl Port for Type` blocks, at the method's line, and adapter
  files that name the port and call the method, or name the type, change or use
  case.
- **fakes**: `impl Port for Type` in `src/test_support`, and support files that
  name the type or call the change.
- **tests**: files under a crate's `tests/` (and `ianua-scenarios`) and files' own
  unit tests that name the target, one of its fakes, or a use case that reaches
  it. A use case name several contexts share counts only where a `use` imports
  it from its own module, or in its own file's unit tests.

Adapters, fakes and tests are matched by the names they write, as the checks
are: a test that reaches a use case only through HTTP is not listed.

## Rules

`rules [context]` prints the domain's rules as the code says them, each with
its `file:line`; `--markdown` writes the docs page
(`docs/src/content/docs/reference/rules.mdx`, which a test keeps current:
run `the_committed_rules_page_is_current` with `IANUA_WRITE_RULES=1` to
write it) and `--format json` the same as data.

- **Decisions.** A public domain function answering one of the domain's
  enums by a `match`. One whose inputs are all plain enums or `bool` (up to
  512 combinations) is worked out for every combination by an evaluator
  that follows `match`, `if`, `matches!`, comparisons, `let .. else`, `?`
  and the type's own functions up to eight calls deep; rows with the same
  answer are merged on an input that takes every value (**any**). Any other
  is shown arm by arm, as written. A row the evaluator could not work out is
  marked **not read**.
- **Status machines.** Each machine's states, the moves `try_transition`
  allows, its final states, and for each state the changes that move a
  value into it, with the use cases calling them and the proof or right
  each takes.
- **Refusals.** For each creator and change, what leads it to refuse (a
  guard and its error, a rule it calls that refuses), its own functions
  read two calls deep.

## Allowlist

`crates/ianua-audit/allow.toml` lists intentional exceptions. Each entry needs a
check id and a reason; `subject` matches exactly or by prefix with a trailing
`*`, and `path` matches findings in files whose path starts with it:

```toml
[[allow]]
check = "reach.behaviour"
subject = "ScheduledJob::mark_*"
reason = "The queue adapter marks jobs in storage without loading them."
```

An entry that matches nothing is reported as `meta.allow-unused`, so the list
does not keep exceptions that are gone. `--allow <file>` reads another file.

## Known limits

Everything is matched by name, without types:

- A change counts as reached when the app calls any method of that name, so
  two aggregates with a `pause` hide each other.
- A proof the app only receives and passes on without writing its type is
  reported as unreached.
- A port trait is found by where the path to it leads, through the file's
  imports and the app's re-exports, since two contexts may declare ports of
  one name (`AssertionReplayGuard` in oauth and in agents). A name the reader
  cannot follow stands for the only port of that name; among several, it is
  matched to none, and no port of that name is called unimplemented on its
  account (counted as unsaid). An adapter crate's own trait of a port's name
  is not the port. A name imported with `use .. as ..` is read as the
  original.
- Limit kinds and aggregates are paired by the use cases that check one and
  create the other; a use case creating several aggregates pairs a kind only
  with the aggregate named after it, and one creating a single aggregate
  only when the names share a word.
- An app type is known by its name only when exactly one app struct has it
  and no domain type does; a value of a name the two share (`Audience`) is
  not read.
- A `*Ports` struct written out in an adapter is checked against the struct its
  path or imports lead to; one behind a glob import, among several of that
  name, is not checked.
- A method of an app type is looked for in the type's own file first, then
  in any app file when exactly one `impl` of that type defines it. The
  reach checks still look for a raising helper on a value other than `self`
  only in the caller's own file, so an event built in a helper declared
  elsewhere counts as unraised.
- `flow.permission-unchecked` counts a right as checked wherever its action is
  named outside the permission catalogue, including in role defaults.
- Code inside macros is read from tokens: method calls, paths, struct literals
  and strings are seen, nested structure is not.
