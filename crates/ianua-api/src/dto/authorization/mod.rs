//! Authorization bodies, one file per app folder: roles, groups, the access
//! policy, the permission catalogue, holdings, separation of duties, access
//! requests and reviews, relationships, access checks and clearance.

pub mod access_requests;
pub mod access_reviews;
pub mod checks;
pub mod clearance;
pub mod groups;
pub mod holdings;
pub mod policies;
pub mod relationships;
pub mod resource_types;
pub mod roles;
pub mod separation;
