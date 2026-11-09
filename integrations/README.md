# Integrations

The outside services a workflow's action steps call, one crate per service,
all built on one SDK. A REST service is described, not written: a profile,
a table of steps, how an account reaches the service, and the request that
proves a credential. GitHub is the reference; copy its shape.

```
integrations/
  core/           ianua-integration: the SDK every integration is built on
  github/         25 steps: issues, pull requests, files, commits, releases, branches, Actions
  gitlab/         21 steps: issues, merge requests, files, commits, pipelines, branches
  slack/          16 steps: messages, members, channels
  teams/          11 steps: teams, channels, channel messages, chats
  discord/        10 steps: messages, reactions, threads, servers, roles
  jira/           10 steps: issues, transitions, search, people
  linear/         13 steps: issues, comments, teams, states, labels, projects
  asana/          13 steps: tasks, projects, sections, comments
  trello/         12 steps: cards, lists, labels, comments
  clickup/        14 steps: tasks, lists, tags, comments
  azure-devops/   10 steps: work items, pipelines, pull requests
  pagerduty/      11 steps: incidents, notes, services, on-call
  mailgun/        10 steps: email, delivery events, suppressions, mailing lists
  twilio/         11 steps: text messages, phone calls, numbers
  google-calendar/ 10 steps: calendars, events, busy times
  google-sheets/   8 steps: sheets, ranges, rows
  gmail/           9 steps: mail, conversations, labels
  notion/         12 steps: pages, databases, content, comments, people
  airtable/        7 steps: bases, tables, records
  hubspot/        10 steps: contacts, companies, deals, owners
  stripe/         11 steps: customers, payments, refunds, invoices, subscriptions
  salesforce/      9 steps: records, SOQL, leads, tasks, cases
  telegram/        8 steps: messages, photos, pins, chats
  postgres/        2 steps: query, execute (Protected data)
  mysql/           2 steps: query, execute (Protected data)
  redis/           2 steps: read, write (Protected data)
  mongodb/         5 steps: find, aggregate, insert, update, delete (Protected data)
```

Each service crate depends on `ianua-domain` and `ianua-integration` only,
never on the database, the API or another service. The server installs the
services its build includes (`crates/ianua-server`, one feature per service
named as its folder, all on by default).

## The SDK

`ianua-integration` (`core/`):

| Module | What it gives you |
| --- | --- |
| `rest::service` | `RestService`: a whole integration made from a `RestServiceParams` description. Most services need nothing else. |
| `rest::operation` | `Operation`, `Field`, `Segment`, `Kind`, `Place`, `Shape`, `Fixed`, `Verb`: each step described once, as data. `Shape::Mail` writes a whole email as Gmail takes it, refusing a header with a line break; `SPREAD` lays an object input over the body itself, as Salesforce takes a record. |
| `rest::access` | `Access`: a bearer token (GitHub, Slack), a key under a fixed user in the region the account names, or limited to one place it proves itself at (Mailgun), an organization's token (Azure DevOps), an account's id and token (Twilio), an account's own site held to `AllowedSites` (Jira), an OAuth grant exchanged for a short-lived token before each call (Google, Teams), such a grant for an account's own allowed site (`SiteGrant`, Salesforce), a token after a scheme of the service's own (`Scheme`: Linear, Discord, PagerDuty), a key and token in one header (`KeyAndToken`, Trello), or a token in the address itself (`PathToken`, Telegram). |
| `rest::checks` | `misdescribed`: the rules every step table keeps, for your tests. |
| `form` | `Ask`, `FormText`, `ChoiceText`, `PickerText`, `PreviewText`: how each input is asked for, which read fills a picker, and how a step is previewed. |
| `rest::openapi` | `Description` (feature `test-support`): your steps checked against the service's published OpenAPI 3 or Swagger 2 description. |
| `rest::request`, `rest::names` | The request built from a step, every part of its address checked and escaped. |
| `answer`, `arguments`, `describe`, `ServiceEndpoint`, `client` | The parts it is built from, for a service that needs its own `Integration`. |
| `data` | `Through`, `DataLogin`, `DataTls`, `Door`: what a Protected data step is handed, an opener of connections through the gateway to a stream route's backend (at most 8 a call), the login the route keeps, and the TLS it asks for. `Through::protected_connection` lays TLS over a connection for a system that starts it from the first byte; `Through::tls` hands the check to a client that starts it inside its own protocol; `Through::door` opens a loopback door for a client that dials an address itself. Such an integration implements `Integration::call_through`, speaks its system's own protocol, and never decides who may connect: `postgres`, `mysql`, `redis` and `mongodb`. |

`RestService` does the rest for you: it refuses a missing input, a value of
the wrong kind or a name that cannot be placed before anything is sent,
signs the call, follows no redirect, holds every call to a time limit,
turns a busy service away and fails anything that may have acted, never
takes a `203` sign-in page as success, and checks a credential with your
probe before an account is kept.

## Rules every step keeps

- **Deny by default.** A missing input, a value of the wrong kind or a name
  that cannot be placed safely fails the step before anything is sent.
- **Honest kind of action.** Reads are `Read`; creating or changing is
  `Write`; messages to people are `Communicate`; removing for good is
  `Delete`; changing how a workspace is set up is `Configure`. A step whose
  effect depends on something else, such as starting a pipeline, is
  `Undeclared`. `Delete`, `Financial`, `Admin`, `Configure` and
  `Undeclared` are high risk: a workflow can only publish them with an
  approval right before the step.
- **The token goes to the service only.** A step names a repository, a
  channel, a project or a path inside them, never an address. An account
  that names its own site is held to the sites the deployment allows.
- **Never log a token.** The SDK marks the credential header sensitive;
  failure reasons are the integration's own words.
- **No message keys in these crates.** Refusals here become a failed step's
  reason, not an API error; the translation tool reads only `crates/`.

## Adding a step

1. Pick the topic file in `<service>/src/operations/`, or add one past
   about a dozen steps and list it in `operations/mod.rs`.
2. Add an `Operation`:

   ```rust
   Operation {
       key: "lock-issue",
       title: "Lock an issue",
       description: "Stops new comments on an issue, saying why when a reason is given.",
       effect: DeclaredAction::Declared(ActionClass::Write),
       verb: Verb::Put,
       path: &[
           Segment::Fixed("repos"),
           Segment::Pair("repository"),
           Segment::Fixed("issues"),
           Segment::Input("issue"),
           Segment::Fixed("lock"),
       ],
       fields: &[
           REPOSITORY,
           ISSUE,
           Field::optional("reason", Kind::Text, Place::Body, "Why: off-topic, too heated, resolved or spam.")
               .sent_as("lock_reason"),
       ],
       fixed: &[],
       query: &[],
       shape: Shape::Object,
       outputs: &[("status", "The status GitHub answered with, 204 when it was locked.")],
   }
   ```

   - **Path:** `Segment::Fixed` is a fixed part; `Segment::Input` places one
     input; `Segment::Pair` places `a/b` as two parts (a repository);
     `Segment::Slashed` places a path of its own, part by part (a file, a
     branch); `Segment::Prefixed` puts fixed text before an input (Azure
     DevOps' `$Bug`) and `Segment::Suffixed` after it (Twilio's
     `{sid}.json`).
   - **Inputs:** `Place::Path`, `Place::Query` or `Place::Body`; `sent_as`
     gives the service's own name. In a JSON body each dot opens an object
     inside (`fields.summary`); in a `Shape::JsonPatch` body the name is the
     path changed (`/fields/System.Title`); a `Shape::Form` body is flat,
     a list sent as its name repeated and other values as JSON text
     (Mailgun's `o:tag`, Twilio's `MediaUrl`).
   - **Kind:** `Text`, `Count` (a whole number above zero), `TextList`,
     `Flag` or `Values` (handed on as they are).
   - **Fixed values:** `fixed` for the body (`("state", Fixed::Text("closed"))`),
     `query` for the query (`("api-version", "7.1")`).
   - **Outputs:** each useful value at its path in the step's output
     (`json.number`, `json.html_url`, `status`). A status output's
     description names the success code the service answers.
   - **Form:** each input asks with the block its kind suggests. Change it
     with `.asked_with(Ask::LongText)`, `Ask::Choices(&[...])` or
     `Ask::Picker(PickerText { filled_by: "list-labels", .. })`; a picker
     is filled by a read of the same service, and names the input it
     depends on. `.example("...")` shows a hint and `.more_options()`
     folds an optional input away. A step that should look like the
     product it acts in gets a line in the service's `PREVIEWS` table.
3. Test the request it builds in `operations/mod.rs`: the exact address and
   body from sample inputs, and one refusal. The `misdescribed` test then
   holds it to the rules.
4. Refresh the API description's extract, where the service publishes one
   (every service but Azure DevOps): download the description and run, for
   GitHub:

   ```
   IANUA_GITHUB_API_DESCRIPTION=/path/to/api.github.com.json \
     cargo nextest run -p ianua-integration-github --lib -E 'test(/api_description/)'
   ```

   The extract is rewritten with only the endpoints the steps use, and every
   step is checked against it: an endpoint the service has, only parameters
   it knows, every one it requires always sent, outputs and statuses its
   answer carries. A nested body name such as `data.name` is checked part by
   part, against the nested names the extract keeps. Commit the extract with
   the step. Run it again from time
   to time: `git diff` on the extract shows what the service changed.

   | Service | Description | Setting |
   | --- | --- | --- |
   | GitHub | `github/rest-api-description/descriptions/api.github.com/api.github.com.json` | `IANUA_GITHUB_API_DESCRIPTION` |
   | Slack | `slackapi/slack-api-specs/web-api/slack_web_openapi_v2.json` | `IANUA_SLACK_API_DESCRIPTION` |
   | Jira | `https://developer.atlassian.com/cloud/jira/platform/swagger.v3.json` | `IANUA_JIRA_API_DESCRIPTION` |
   | Mailgun | `https://documentation.mailgun.com/_spec/docs/mailgun/api-reference/send/mailgun.json` | `IANUA_MAILGUN_API_DESCRIPTION` |
   | Twilio | `twilio/twilio-oai/spec/json/twilio_api_v2010.json` | `IANUA_TWILIO_API_DESCRIPTION` |
   | Google Calendar | `https://api.apis.guru/v2/specs/googleapis.com/calendar/v3/openapi.json`, APIs.guru's conversion of Google's discovery document | `IANUA_GOOGLE_CALENDAR_API_DESCRIPTION` |
   | Google Sheets | `https://api.apis.guru/v2/specs/googleapis.com/sheets/v4/openapi.json`, the same conversion | `IANUA_GOOGLE_SHEETS_API_DESCRIPTION` |
   | Gmail | `https://api.apis.guru/v2/specs/googleapis.com/gmail/v1/openapi.json`, the same conversion | `IANUA_GMAIL_API_DESCRIPTION` |
   | Stripe | `stripe/openapi/openapi/spec3.json`; pin the crate's API version to its `info.version` | `IANUA_STRIPE_API_DESCRIPTION` |
   | GitLab | `gitlab-org/gitlab/doc/api/openapi/openapi_v3.yaml`, converted to JSON; its file endpoints are misdescribed and checked to exist only | `IANUA_GITLAB_API_DESCRIPTION` |
   | Microsoft Teams | `microsoftgraph/msgraph-metadata/openapi/v1.0/openapi.yaml`, converted to JSON | `IANUA_TEAMS_API_DESCRIPTION` |
   | Discord | `discord/discord-api-spec/specs/openapi.json` | `IANUA_DISCORD_API_DESCRIPTION` |
   | PagerDuty | `PagerDuty/api-schema/reference/REST/openapiv3.json` | `IANUA_PAGERDUTY_API_DESCRIPTION` |
   | Asana, Trello, ClickUp | each service's published OpenAPI description, named in its crate's description test | `IANUA_ASANA_API_DESCRIPTION`, `IANUA_TRELLO_API_DESCRIPTION`, `IANUA_CLICKUP_API_DESCRIPTION` |
5. For a step a workflow should prove end to end, add a scenario under
   `crates/ianua-scenarios/tests/accounts/automate_work/integrations/` with a stand-in
   for the service (`upstreams::CannedApp`) that answers its probe.
6. Add the step to the table in
   `docs/src/content/docs/architecture/infrastructure/integrations.mdx`.

## Adding a service

1. Copy `github/` to `integrations/<service>/`, rename the crate
   `ianua-integration-<service>`, and add it to the workspace members and
   dependencies in the root `Cargo.toml`.
2. In `src/lib.rs`, describe it: its settings struct and an
   `integration(settings) -> Result<RestService, DomainError>` filling
   `RestServiceParams`:
   - `profile`: title, description, icon name, brand colour, and
     `picture: include_str!("../assets/icon.svg")`, the service's own mark
     as SVG of shapes only (`svg`, `title`, `g`, `path` and the basic
     shapes, with only the attributes that place and paint them). Take it
     from Simple Icons (CC0) where the service is listed, or draw a plain
     one. The SDK's `picture` refuses anything else, so the integration
     never starts with a script, link, style or embedded page in it.
   - `access`: `Access::Bearer`, `Access::Key`, `Access::Organization`,
     `Access::Account`, `Access::Site` or `Access::Refreshed`.
   - `headers`: what the service asks every call to carry.
   - `probe`: the cheapest request that proves a credential, such as
     GitHub's `GET /user`, Slack's `auth.test` or Jira's `myself`.
   - `answers`: `Answers::ByStatus`, or `Answers::OkFlag` for a service that
     answers a refusal with success and `"ok": false`.
3. Write its steps in `src/operations/`, with the `misdescribed` test, and
   its API description check in the test module of `src/lib.rs` when it
   publishes one (copy GitHub's, setting `lead` to the path parts the
   account's address already holds, such as Jira's `rest/api/2`).
4. In `crates/ianua-server`: a feature and an optional dependency in
   `Cargo.toml`, its settings in `src/config/serving/integrations.rs`
   (an address that is `https` in production and a data ceiling, or allowed
   sites), and one line in `outside_services` in
   `src/platform/providers.rs`.
5. Run `cargo hakari generate` and `cargo hakari manage-deps --yes`, then
   the crate's tests, the server's config tests and the scenarios.
6. Document its settings in `docs/.../reference/configuration.mdx` and its
   steps in the integrations page.

A service that is not REST, or needs more than a description allows,
implements `Integration` itself from the SDK's parts, as the platform's
built-in HTTP request step does.

## Events that are not one webhook per workflow

`register`, `renew`, `unregister` and `read` cover a service with one
signed webhook per workflow. The other methods of `events::Events` have
defaults that offer nothing, so a watcher overrides only what its service
does:

- **It checks the address, or hands over a secret.** `greet` answers
  `Greeting::Prove` with what to send back, or `Greeting::HandsSecret` with
  the secret to keep. It runs before any proof, so a secret is taken only
  while the registration or channel waits for one.
- **It shows a secret once in its answer.** Call
  `credential.keep_given_secret(secret)` in `register`.
- **It has one address per account.** `account_setup` says how the channel
  gets ready: `Registered` (write `open_channel`, `renew_channel` and
  `close_channel`), `PastedKey`, or `TokenFromService` (`greet` hands the
  token over). `read` is still called once per waiting workflow, with the
  channel's secret in `watch.secret`, so it proves the delivery and matches
  the workflow's filters as usual.
- **Its deliveries only announce a change.** Set `pulls_history` and write
  `pull`: prove the delivery first, then hand back at most `MOST_PULLED`
  bodies for `read` and the cursor where it stopped.

Some delivery proofs wait for their first event crate, and are compiled for
their own tests only: `signature`'s `timed_request_signed` (method, address,
body and a recent timestamp, as HubSpot signs) and `every_item_carries`
(Microsoft Graph's `clientState`). The crate that first uses one removes its
`#[cfg(test)]` and makes it `pub`.

## Running the tests

```
cargo nextest run -p ianua-integration -p ianua-integration-github \
  -p ianua-integration-slack -p ianua-integration-jira \
  -p ianua-integration-azure-devops -p ianua-integration-mailgun \
  -p ianua-integration-twilio -p ianua-integration-google-calendar \
  -p ianua-integration-google-sheets -p ianua-integration-gitlab \
  -p ianua-integration-linear -p ianua-integration-asana \
  -p ianua-integration-trello -p ianua-integration-clickup \
  -p ianua-integration-teams -p ianua-integration-discord \
  -p ianua-integration-pagerduty -p ianua-integration-gmail \
  -p ianua-integration-notion -p ianua-integration-airtable \
  -p ianua-integration-hubspot -p ianua-integration-stripe \
  -p ianua-integration-salesforce -p ianua-integration-telegram \
  -p ianua-integration-postgres -p ianua-integration-mysql \
  -p ianua-integration-redis -p ianua-integration-mongodb --lib
```

The end-to-end scenarios run the real platform against stand-ins:

```
cargo nextest run -p ianua-server -p ianua-scenarios --test automate_work
```
