//! The in-memory tables the request path reads: which tenant a host
//! belongs to, the tenant's routes in the order they are tried, and the
//! hosts its app sign-in answers on.
//!
//! The follower fills them through [`Tables`], one tenant at a time, each
//! change swapped in whole. A request takes one [`Routing`] version with
//! [`Tables::current`] and reads only it. A host no tenant answers on, or
//! more than one does, and a path no route takes, resolve to nothing: never
//! to a default tenant or a default route.

mod hosts;
mod routes;
mod sign_in;
mod tables;

pub(crate) use hosts::HostResolution;
pub(crate) use routes::{MatchedRoute, RouteLookup, RouteQuery, RouteRefusal};
pub(crate) use sign_in::{AppSessionRules, SignInHost};
pub(crate) use tables::{Routing, Tables, TablesParts, TenantTable};
