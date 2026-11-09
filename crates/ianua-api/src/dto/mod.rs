//! Request and response bodies, by context.

pub mod activity;
pub mod agents;
pub mod audit;
pub mod authentication;
pub mod authorization;
pub mod branding;
pub mod consumers;
pub mod crypto;
pub mod data_classification;
pub mod directory;
pub mod domain;
pub mod federation;
pub mod gateway;
pub mod identity;
pub mod messaging;
pub mod metrics;
pub mod notifications;
pub mod oauth;
pub mod onboarding;
pub mod operator;
pub mod organization;
pub mod proxy;
pub mod realtime;
pub mod routing;
/// OpenAPI schemas for the domain enums the API carries.
pub(crate) mod schemas;
pub mod scim;
pub mod signals;
pub mod tenant;
pub mod webhooks;
pub mod workflows;
