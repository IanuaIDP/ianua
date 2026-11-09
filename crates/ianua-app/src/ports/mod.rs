//! Ports, dyn-safe async traits that define the boundary
//! between the app layer and infrastructure.
//!
//! Shared ports are used across multiple use cases.
//! BC-specific ports are used by one bounded context.
//!
//! # Tenant scoping
//!
//! Ports that operate on tenant-scoped data extend [`TenantScoped`].
//! Their methods receive `tenant_id: &ScopedTenant` as first parameter
//! (after `&self`) so the caller provides the resolved tenant on
//! every call.
//!
//! Control-plane ports (`OrganizationStore`, `TenantStore`,
//! `OperatorStore`, etc.) do **not** extend `TenantScoped`, they
//! query across tenants or have no tenant dimension at all.

/// Marker trait for ports whose data is scoped to a single tenant.
///
/// Every method on a `TenantScoped` port takes `tenant_id: &ScopedTenant`
/// as its first argument (after `&self`). The marker makes the
/// boundary explicit at the type level so use cases, handlers, and
/// tooling can distinguish tenant-scoped ports from control-plane
/// ports without inspecting method signatures.
pub trait TenantScoped {}

pub mod activity;
pub mod agents;
pub mod audit;
pub mod authentication;
pub mod authorization;
pub mod branding;
pub mod broker;
pub mod cloud;
pub mod consumers;
pub mod crypto;
pub mod data_classification;
pub mod directory;
pub mod domain;
pub mod federation;
pub mod files;
pub mod identity;
pub mod limits;
pub mod messaging;
pub mod metrics;
pub mod notifications;
pub mod oauth;
pub mod operator;
pub mod organization;
pub mod pages;
pub mod provisioning;
pub mod proxy;
pub mod realtime;
pub mod routing;
pub mod runtime;
pub mod scheduling;
pub mod shared;
pub mod signals;
pub mod tenant;
pub mod webhooks;
pub mod workflows;
