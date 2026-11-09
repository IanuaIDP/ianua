//! The HTTP API's tests, over the app's fakes.
//!
//! One binary, not one per file, so the crate is linked once.

#![cfg(test)]

mod activity;
mod agents;
mod audit;
mod authentication;
mod authorization;
mod branding;
mod callers;
mod consumers;
mod credential_use;
mod crypto;
mod data_classification;
mod deadline;
mod directory;
mod domain;
mod federation;
mod files;
mod gateway;
mod identity;
mod messaging;
mod notifications;
mod oauth;
mod onboarding;
mod operator;
mod organization;
mod paging;
mod proxy;
mod realtime;
mod reference;
mod request_bodies;
mod routing;
mod runtime;
mod scim;
mod sign_in_pressure;
mod signals;
mod tenant;
mod webhooks;
mod workflows;
