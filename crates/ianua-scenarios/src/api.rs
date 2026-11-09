//! Typed calls by area: each function builds one request to the API from
//! this crate's own wire types and names the answer it reads.
//!
//! A function answers a [`Request`], not the answer itself, because a step
//! uses the same request two ways: one actor sends it and reads the
//! answer, and a [`Matrix`](crate::expect::Matrix) sends it as the whole
//! cast. [`Request::send`] gives the [`Answer`]; [`Request::call`] gives
//! the [`Call`] a matrix runs.
//!
//! ```no_run
//! # async fn example(admin: &ianua_scenarios::net::Client, tenant: &ianua_scenarios::api::TenantPath) {
//! use ianua_scenarios::api::people;
//!
//! let listed = people::list(tenant, None).send(admin).await.ok();
//! assert!(listed.items.len() <= listed.limit as usize);
//! # }
//! ```

pub mod account;
pub mod activity;
pub mod agents;
pub mod api_keys;
pub mod app_sign_in;
pub mod attributes;
pub mod audit;
pub mod audit_streams;
pub mod billing;
pub mod branding;
pub mod classification;
pub mod cloud;
pub mod connections;
pub mod consumers;
pub mod control_access;
pub mod crypto;
pub mod destinations;
pub mod directory;
pub mod domains;
pub mod factors;
pub mod member_factors;
pub mod members;
pub mod memories;
pub mod messaging;
pub mod notifications;
pub mod oauth;
pub mod onboarding;
pub mod operators;
pub mod organizations;
pub mod people;
pub mod policies;
pub mod reference;
pub mod registration;
pub mod roles;
pub mod routing;
pub mod saml_apps;
pub mod sandboxes;
pub mod sessions;
pub mod signals;
pub mod tenants;
pub mod webhooks;
pub mod workflows;

use std::fmt;
use std::marker::PhantomData;

use serde::de::DeserializeOwned;
use url::form_urlencoded;

use crate::net::{Call, Client};
use crate::wire::Answer;

/// One request to the API and the type its answer reads as.
pub struct Request<T> {
    call: Call,
    answer: PhantomData<fn() -> T>,
}

impl<T> fmt::Debug for Request<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Request").field(&self.call).finish()
    }
}

impl<T> Clone for Request<T> {
    fn clone(&self) -> Self {
        Self {
            call: self.call.clone(),
            answer: PhantomData,
        }
    }
}

impl<T: DeserializeOwned> Request<T> {
    /// The request `call`, its answer read as `T`.
    #[must_use]
    pub fn of(call: Call) -> Self {
        Self {
            call,
            answer: PhantomData,
        }
    }

    /// Sends it as `client` and reads the answer.
    pub async fn send(self, client: &Client) -> Answer<T> {
        client.send(self.call).await
    }

    /// The call, for a [`Matrix`](crate::expect::Matrix) to make as every
    /// actor.
    #[must_use]
    pub fn call(&self) -> Call {
        self.call.clone()
    }

    /// The same request carrying the header `name: value` too.
    #[must_use]
    pub fn header(self, name: &str, value: &str) -> Self {
        Self::of(self.call.header(name, value))
    }
}

/// What a [`Request`] answers when its answer is a document read as text,
/// such as SAML metadata, rather than JSON.
#[derive(Debug)]
pub struct Text;

impl Request<Text> {
    /// The request `call`, its answer read as text.
    #[must_use]
    pub fn text(call: Call) -> Self {
        Self {
            call,
            answer: PhantomData,
        }
    }

    /// Sends it as `client` and reads the answer as text.
    pub async fn send_text(self, client: &Client) -> Answer<String> {
        client.send_text(self.call).await
    }
}

/// Where an organization's endpoints are: `/api/v1/organizations/{slug}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgPath {
    slug: String,
}

impl OrgPath {
    /// The organization `slug`.
    #[must_use]
    pub fn new(slug: &str) -> Self {
        Self {
            slug: slug.to_owned(),
        }
    }

    /// Organization URL segment used to build scoped API paths.
    #[must_use]
    pub fn slug(&self) -> &str {
        &self.slug
    }

    /// `rest` under the organization's endpoints, such as `/users`.
    #[must_use]
    pub fn at(&self, rest: &str) -> String {
        format!("/api/v1/organizations/{}{rest}", self.slug)
    }

    /// The tenant `tenant_slug` of this organization.
    #[must_use]
    pub fn tenant(&self, tenant_slug: &str) -> TenantPath {
        TenantPath {
            organization: self.clone(),
            slug: tenant_slug.to_owned(),
        }
    }
}

/// Where a tenant's endpoints are:
/// `/api/v1/organizations/{org}/tenants/{slug}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantPath {
    organization: OrgPath,
    slug: String,
}

impl TenantPath {
    /// The organization it belongs to.
    #[must_use]
    pub fn organization(&self) -> &OrgPath {
        &self.organization
    }

    /// Tenant URL segment beneath the owning organization's API path.
    #[must_use]
    pub fn slug(&self) -> &str {
        &self.slug
    }

    /// `rest` under the tenant's endpoints, such as `/users`.
    #[must_use]
    pub fn at(&self, rest: &str) -> String {
        self.organization
            .at(&format!("/tenants/{}{rest}", self.slug))
    }
}

/// `path` with `pairs` as its query, each value encoded; `path` itself
/// when there are none.
pub(crate) fn with_query(path: &str, pairs: &[(&str, &str)]) -> String {
    if pairs.is_empty() {
        return path.to_owned();
    }
    let query = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    format!("{path}?{query}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tenant's path sits under its organization's.
    #[test]
    fn a_tenants_path_sits_under_its_organizations() {
        let tenant = OrgPath::new("acme").tenant("prod");

        assert_eq!(
            tenant.at("/users"),
            "/api/v1/organizations/acme/tenants/prod/users"
        );
        assert_eq!(
            tenant.organization().at("/me"),
            "/api/v1/organizations/acme/me"
        );
    }

    /// Query values are encoded, and no pairs leave the path alone.
    #[test]
    fn query_values_are_encoded() {
        assert_eq!(with_query("/x", &[]), "/x");
        assert_eq!(
            with_query("/x", &[("event_type", "a b"), ("limit", "5")]),
            "/x?event_type=a+b&limit=5"
        );
    }
}
