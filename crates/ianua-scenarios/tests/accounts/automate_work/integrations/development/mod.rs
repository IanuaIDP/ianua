//! Services where software is built and run: code hosts, issue trackers and paging.
//!
//! - `azure_devops`: the organization's token is checked before it is
//!   kept, and a run files a bug as a JSON Patch and comments on it.
//! - `github`: the team's token is checked with GitHub before it is kept,
//!   and a run opens an issue and comments on it through it; a token GitHub
//!   refuses is never connected.
//! - `github_live`: ignored unless asked for; the same against GitHub
//!   itself, in a sandbox repository, an issue opened, commented on,
//!   labelled, closed and read back by one run.
//! - `gitlab`: a pasted token or a signed-in grant, whose exchanged token
//!   is kept and reused, and a run opens an issue in a project named by
//!   its path and comments on it.
//! - `jira`: Jira's action steps through Atlassian's gateway for an
//!   account that signed in, and a pasted site the deployment does not
//!   allow never connected.
//! - `linear`: the key is checked with a `GET` query before it is kept,
//!   and a run posts GraphQL mutations; an `errors` list answered with
//!   success fails the run.
//! - `pagerduty`: an account-wide key names the person in `From` and a
//!   user's own key names nobody, and a run opens an incident and notes it.

mod azure_devops;
mod github;
mod github_live;
mod gitlab;
mod jira;
mod linear;
mod pagerduty;
