//! A directory calling the tenant's SCIM endpoint: the bearer token it came
//! with, checked against the endpoint the tenant set up.
//!
//! This is the resolver behind [`ScimAuthorities`] in production.
//!
//! A request never says which endpoint it acts through. The tenant comes
//! from the request's address, and the token is compared with the one the
//! tenant holds now, so a token from before a rotation, or from another
//! tenant, finds nothing.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::federation::scim::ScimEndpoint;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::security::secret::Secret;

use crate::acting::ScimAuthorities;
use crate::context::ScimCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::federation::{ScimStore, ScimTokenGenerator};

/// The stores [`ScimActing`] reads a directory's sign-in from.
#[derive(ianua_macros::Fakes)]
pub struct ScimActingPorts {
    /// The tenant's SCIM endpoint.
    pub scim_store: Arc<dyn ScimStore>,
    /// Compares a presented token with the hash the endpoint keeps.
    pub tokens: Arc<dyn ScimTokenGenerator>,
}

/// Signs directories in from the endpoint their tenant keeps.
pub struct ScimActing {
    ports: ScimActingPorts,
}

impl ScimActing {
    /// A resolver reading from `ports`.
    #[must_use]
    pub fn new(ports: ScimActingPorts) -> Self {
        Self { ports }
    }
}

#[async_trait]
impl ScimAuthorities for ScimActing {
    async fn endpoint(
        &self,
        caller: &ScimCaller,
    ) -> Result<ScimEndpoint<ResolvedTenant>, AppError> {
        let Some(bearer) = caller.bearer() else {
            return Err(AppError::Unauthenticated);
        };
        let endpoint = self
            .ports
            .scim_store
            .find(caller.tenant())
            .await
            .or_internal()?
            .ok_or(AppError::Unauthenticated)?;
        ensure_admits(&endpoint, self.ports.tokens.as_ref(), bearer)?;
        Ok(endpoint)
    }
}

/// Refuses `bearer` unless `endpoint` is switched on and it is the token the
/// endpoint keeps the hash of.
fn ensure_admits(
    endpoint: &ScimEndpoint<ResolvedTenant>,
    tokens: &dyn ScimTokenGenerator,
    bearer: &Secret,
) -> Result<(), AppError> {
    let admitted = endpoint.enabled() && tokens.verify(bearer, endpoint.bearer_token_hash());
    if !admitted {
        return Err(AppError::Unauthenticated);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::federation::scim::ScimEndpointRow;
    use ianua_domain::types::{Enablement, TenantId, TokenHash};

    use super::*;
    use crate::tenancy::ScopedTenant;
    use crate::test_support::block_on;
    use crate::test_support::scim::{SCIM_TOKEN, directory_row, scim_caller, scim_sign_in_with};

    fn signed_in_to(
        row: ScimEndpointRow,
        caller: &ScimCaller,
    ) -> Result<ScimEndpoint<ResolvedTenant>, AppError> {
        block_on(scim_sign_in_with(row).endpoint(caller))
    }

    /// Acme's Okta calls with the token Acme holds now. It is let in.
    #[test]
    fn the_current_token_is_accepted() {
        let endpoint = signed_in_to(directory_row(), &scim_caller());

        assert!(endpoint.is_ok());
    }

    /// A SCIM request without a bearer token is unauthenticated.
    #[test]
    fn a_call_without_a_token_is_refused() {
        let caller = ScimCaller::new(*scim_caller().tenant(), None);

        let result = signed_in_to(directory_row(), &caller);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// A token that does not match the endpoint's stored hash is
    /// unauthenticated.
    #[test]
    fn any_other_token_is_refused() {
        let caller = ScimCaller::new(*scim_caller().tenant(), Some(Secret::new("guess")));

        let result = signed_in_to(directory_row(), &caller);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Changing the stored SCIM token hash makes the previous token
    /// unauthenticated.
    #[test]
    fn a_rotated_token_is_refused() {
        let row = ScimEndpointRow {
            bearer_token_hash: TokenHash::from_stored("hash:scim-token-2".to_owned()),
            ..directory_row()
        };

        let result = signed_in_to(row, &scim_caller());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Disabling SCIM rejects even the endpoint's matching token as
    /// unauthenticated.
    #[test]
    fn a_switched_off_endpoint_refuses_its_own_token() {
        let row = ScimEndpointRow {
            enabled: Enablement::Disabled,
            ..directory_row()
        };

        let result = signed_in_to(row, &scim_caller());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Acme's valid SCIM token cannot resolve an endpoint in another
    /// tenant; the result is unauthenticated.
    #[test]
    fn a_token_of_another_tenant_is_refused() {
        let globex = ScopedTenant::for_test(TenantId::new());
        let caller = ScimCaller::new(globex, Some(Secret::new(SCIM_TOKEN)));

        let result = signed_in_to(directory_row(), &caller);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
