//! Services where work is planned and kept: task boards, documents, tables and calendars.
//!
//! - `airtable`: the token is checked before it is kept, and a run adds a
//!   record to a table and changes it; a refused record fails the run.
//! - `asana`: the token is checked before it is kept, and a run creates a
//!   task and comments on it, each body wrapped in `data`.
//! - `clickup`: the token, sent with nothing before it, is checked before
//!   it is kept, and a run creates a task in a list and comments on it.
//! - `google_calendar`: the grant is exchanged for a token before it is
//!   kept and before each call, and a run books an event signed with the
//!   token; the grant itself never reaches the calendar.
//! - `google_sheets`: the grant is exchanged for a token before it is
//!   kept, and a run creates a spreadsheet and adds a tab to it as an
//!   `addSheet` request.
//! - `notion`: the token is checked before it is kept, and a run queries a
//!   database's data source, adds a page under it and comments on the page,
//!   every call pinned to Notion's version.
//! - `trello`: the key and token go in Trello's `OAuth` header, and a run
//!   creates a card from the query and comments on it; the board picked
//!   for the form is never sent.

mod airtable;
mod asana;
mod clickup;
mod google_calendar;
mod google_sheets;
mod notion;
mod trello;
