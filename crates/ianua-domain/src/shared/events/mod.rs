//! Domain events: the envelope that carries one and its payload.

pub mod chain;
pub mod data;
/// Domain event traits and the envelope that carries the acting party.
pub mod event;
/// Events an aggregate raised while it changed, held until it is saved.
pub mod raised;
