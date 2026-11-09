//! How an execution starts besides by hand: on a service's event or its
//! webhook, as a real run or a test, and why one may be refused.

pub(super) mod mode;
pub(super) mod refusal;
pub(super) mod service;
pub(super) mod webhook;
