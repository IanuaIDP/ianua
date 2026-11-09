//! Each kind of step an execution runs, what the steps whose work happens
//! outside the domain share, and when a waiting step may start.

pub(super) mod action;
pub(super) mod agent;
pub(super) mod approval;
pub(super) mod code;
pub(super) mod code_work;
pub(super) mod deferral;
pub(super) mod guardrail;
pub(super) mod items;
pub(super) mod loops;
pub(super) mod passes;
pub(super) mod schedule;
pub(super) mod wait;
pub(super) mod work;
