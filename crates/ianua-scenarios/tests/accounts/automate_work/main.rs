//! The automation product: Tess drafts a workflow that calls an outside
//! service through a connected account, Ann publishes the revision she
//! reviewed, and the service itself shows whether a run really called it.
//! Runs and their records survive restarts, a failed step is retried on
//! purpose and never on its own, an approval holds the call until the
//! right person approves what they were shown, and webhooks and schedules
//! start only the version in service.
//!
//! - `executions`: a published workflow delivers once across restarts; a
//!   retry recovers a failed delivery and leaves the first run failed;
//!   Max, Sam, nobody signed in and a record that cannot be written start
//!   nothing.
//! - `run_control`: a cancelled run ends for good, across a restart and a
//!   late approval; a retry runs only what did not finish, a rerun every
//!   step, and only a failed run is rerun.
//! - `flows`: an agent flow hands each stage's answers to the next and
//!   completes; an ended flow cannot be cancelled, only deleted, and Max
//!   lists none.
//! - `live`: a run's live stream shows each step approved, started and
//!   succeeded, then the end, never the data; a draft's stream says its
//!   steps changed; Max opens neither.
//! - `outbound`: Mallory's HTTP step reaches no metadata or private
//!   address however it is written, follows no redirect, and carries no
//!   account's token to her own server.
//! - `races`: ten copies of one approval deliver once, and a cancel
//!   racing an approval leaves the run and the service agreeing.
//! - `risks`: an operation the company raised needs its approval at
//!   publish and stops older runs at that step until Tess removes it;
//!   Uma may raise it but not remove it.
//! - `suggestions`: a step the model suggests that no integration offers
//!   is left out with a note, nothing is saved, and Max may not ask.
//! - `versions`: runs keep using version 1 while version 2 is drafted and
//!   edited; only the reviewed revision is published, which archives
//!   version 1.
//! - `apps`: a Protected apps step reads Acme's orders app as Pat, the
//!   run's person, only on a route opened to workflows and only as far as
//!   the app's own policy lets Pat in.
//! - `data`: a Protected data step reads Acme's Postgres, MySQL, Redis and
//!   MongoDB as Pat through stream routes opened to workflows, over TLS to
//!   the database itself where the login asks for it; a read that writes
//!   is refused, and a closed route, one Pat may not use, a database
//!   without the TLS asked for, or a certificate from another authority
//!   reaches nothing.
//! - `memory`: Acme's support tickets kept in a memory and the one most
//!   alike a new ticket found, through the platform's embedding server, the
//!   real text-embeddings-inference or Acme's own provider, in pgvector or
//!   a vector server; a memory waiting to be deleted takes no texts until
//!   it is brought back.
//! - `company`: a company step signs Lee out as Pat, through the same
//!   action Pat could take by hand, and the audit trail names Pat and the
//!   run; a step Pat could not take by hand fails and changes nothing.
//! - `company_steps`: the rest of the company's own steps, about people,
//!   access, agents and the platform, each as the run's person, each
//!   change to who can do what after two colleagues' yes, and a sealed
//!   audit pack an auditor checks against Acme's published keys.
//! - `company_events`: an agent's run over budget and a person the
//!   gateway turned away each start the version in service once, which
//!   acts on what the event names; an archived version starts nothing.
//! - `places`: a sign-in after a journey too fast to look right, and an
//!   API key first used from another country, each start the version in
//!   service once, on a stack with a city database of its own.
//! - `slack_approvals`: an approval asks in Slack once, with buttons that
//!   open it in the dashboard, and is decided in the platform; each pass
//!   of a loop asks its own question, and one approval of every item asks
//!   once before any pass.
//! - `hiding`: a run hides the fields the company classifies as
//!   sensitive, as the gateway does, and keeps the rest.
//! - `hours`: a wait for working hours goes on at once while the team
//!   works, and waits on a day off.
//! - `keys`: a run pauses an API key, which is refused until someone
//!   resumes it.
//! - `signals`: a run reports a person as high risk, recorded as the run's
//!   person's report for the signal streams.
//! - `approvals`: only Ann's approval of exactly what she was shown
//!   releases the delivery; her denial ends the run for good.
//! - `loops`: a loop's passes each deliver once and give back one answer
//!   per issue; a refused pass fails the loop and stops the other.
//! - `triggers`: a webhook's rotated or revoked secret kills the old one, an
//!   archived version answers no webhook; a schedule fires once a minute
//!   across a worker restart and stops when archived.
//! - `catalog`: the builder is shown each integration with its title,
//!   description and icon, and each step with what it does, what its
//!   inputs mean and what it gives back.
//! - `builder`: GitHub's forms fill their lists from the team's account,
//!   and a test of a draft reads for real, stands in for what would
//!   change GitHub and stays apart from real runs.
//! - `integrations`: each outside service's own steps against a stand-in
//!   for it, its credential checked before it is kept, one step's answer
//!   read by the next, and a refusal from the service failing the run.
//! - `code`: code steps in real containers and the sandboxes they run in:
//!   the container command, the sandbox gate and Kubernetes, the network
//!   filter, and building a version's packages.
//! - `spending`: an agent step stops, over budget, once its model calls
//!   cost more than the cap its author set, and a fair cap lets it finish.
//! - `guardrails`: a guardrail checks a reply before the delivery sends
//!   it: stopping fails the run and nothing is sent, removing sends the
//!   reply masked, recording sends it as it was; the trail never keeps the
//!   text found, and a guardrail reading a step that hands on no text is
//!   refused at publish.
//! - `before_rules`: a rule run before an admin role is given refuses it
//!   with a 403 or allows it; a role holding no built-in permission is not
//!   its to decide, with no rule the change happens as before, and a rule
//!   that would wait is refused at publish. Rules on access given, apps
//!   opened to workflows and audit exports are handed what the change
//!   would do, and one refusing rule stops it however many allow. A rule
//!   whose publisher was deactivated cannot start, which refuses the
//!   change.
//! - `item_approvals`: one approval for every item of a loop counts only
//!   once Ann opened every page, then each pass delivers once; Max may not
//!   approve, and a denial fails the loop before any pass runs.
//! - `evaluations`: sample cases try the draft as tests, passing or
//!   failing with what differed, and with the gate on publishing waits
//!   for a passing evaluation of the draft.
//! - `service`: the outside HTTP service the workflows call, checking the
//!   account's credential and counting what reached it.

#![cfg(test)]

mod approvals;
mod apps;
mod attack;
mod before_rules;
mod builder;
mod catalog;
mod checking;
mod code;
mod company;
mod company_events;
mod company_steps;
mod data;
mod evaluations;
mod executions;
mod flows;
mod guardrails;
mod hiding;
mod hours;
mod integrations;
mod item_approvals;
mod keys;
mod live;
mod loops;
mod memory;
mod outbound;
mod places;
mod races;
mod reviews;
mod risks;
mod run_control;
mod service;
mod signals;
mod slack_approvals;
mod spending;
mod suggestions;
mod support;
mod triggers;
mod versions;
