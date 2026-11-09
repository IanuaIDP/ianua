//! What an organization pays for: its plan, its subscription and the
//! catalog of plans.

pub mod catalog;
/// Limits a Custom organization agreed with sales.
pub mod negotiated;
/// How an organization pays and whether it is paid up.
pub mod payment;
/// Subscription plans and the limits each one sets.
pub mod plan;
/// What an organization pays for over time: trial, payment and plan moves.
pub mod subscription;
/// What an organization uses now, counted for a plan check.
pub mod usage;
