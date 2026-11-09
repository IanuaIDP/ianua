//! In-app notifications for operators, organization users and tenant users.
//!
//! Each person sees only the notifications their roles allow, and always
//! what changes how safe their own account is.

pub mod alert;
pub mod category;
pub mod channel;
pub mod destination;
pub mod events;
pub mod notice;
pub mod notification;
pub mod personal;
pub mod preference;
pub mod reach;
pub mod reading;
pub mod severity;
