//! A program calling a tenant's API with one of its keys, made for it by
//! an administrator with the scopes it needs.

use std::fmt;

use super::Member;
use crate::api::{TenantPath, api_keys};
use crate::net::Client;
use crate::stack::Stack;
use crate::wire::api_keys::NewApiKey;

/// A program holding one tenant API key. `Debug` shows no key.
pub struct KeyHolder {
    client: Client,
    tenant: TenantPath,
    key_id: String,
    key: String,
}

/// The program label and permissions requested for its tenant API key.
#[derive(Clone, Copy)]
pub struct KeyRequest<'a> {
    /// The program's label in the API and scenario diagnostics.
    pub name: &'a str,
    /// The scopes carried by the new key.
    pub scopes: &'a [&'a str],
}

impl fmt::Debug for KeyHolder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyHolder")
            .field("tenant", &self.tenant)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl KeyHolder {
    /// A program holding the key `steward` makes in `tenant` with the name
    /// and scopes in `request`.
    ///
    /// # Panics
    ///
    /// When the key is refused, or the client cannot be built.
    /// The scenario requires both key issuance and an independent client.
    #[allow(clippy::expect_used)]
    pub async fn issued_by(
        stack: &Stack,
        steward: &Member,
        tenant: &TenantPath,
        request: KeyRequest<'_>,
    ) -> Self {
        let key = NewApiKey {
            name: request.name.to_owned(),
            scopes: request
                .scopes
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect(),
        };
        let made = api_keys::create(tenant, &key)
            .send(steward.client())
            .await
            .ok();
        let mut client = Client::new(stack, request.name).expect("a client for the program");
        client.authorize(&made.raw_key);
        Self {
            client,
            tenant: tenant.clone(),
            key_id: made.id,
            key: made.raw_key,
        }
    }

    /// The client it calls through.
    #[must_use]
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// The key's id.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The key, to make sure it never appears where it should not.
    #[must_use]
    pub fn secret(&self) -> &str {
        &self.key
    }

    /// The same program after `steward` revoked its key: its client still
    /// sends it.
    ///
    /// # Panics
    ///
    /// When the revocation is refused.
    pub async fn revoked_by(self, steward: &Member) -> Self {
        api_keys::revoke(&self.tenant, &self.key_id)
            .send(steward.client())
            .await
            .ok();
        self
    }
}
