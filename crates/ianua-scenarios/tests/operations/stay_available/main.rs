//! Repeated use, bounded bursts and dependency failures preserve service
//! without bypassing authority. API and worker restarts retain durable state
//! and queued delivery; the gateway restarts on its own. A crash, a lost
//! event and the retention sweeps each do their work once.
//!
//! - `crash`: a control plane killed mid-delivery or mid-setup leaves its
//!   jobs held until their holds run out, then they are done once.
//! - `gateway`: a gateway restart keeps Pat signed in and lets nothing
//!   through undecided, ending a request in flight rather than resending it.
//! - `guessing`: bots guessing one person's password from many networks at
//!   once are answered in time while everybody else is served.
//! - `load`: bounded concurrent requests followed by usable protected access.
//! - `lost_events`: an event written while the bus is down and its relay is
//!   killed is delivered from the outbox once and acted on once; an event
//!   the bus hands out again after its job ended starts nothing more.
//! - `outages`: readiness, authoritative checks and recovery without restart.
//! - `reads`: repeated directory reads have bounded retained allocations.
//! - `restart`: sessions, records and queued mail survive a control-plane restart.
//! - `retention`: audit records, memories set to be deleted, notices,
//!   evaluations and workflow runs an hour past their keeping go, and an
//!   hour short of it stay.
//! - `sessions`: repeated sign-in and sign-out have bounded retained allocations.

#![cfg(test)]

mod crash;
mod gateway;
mod guessing;
mod load;
mod lost_events;
mod outages;
mod reads;
mod restart;
mod retention;
mod sessions;
mod support;
