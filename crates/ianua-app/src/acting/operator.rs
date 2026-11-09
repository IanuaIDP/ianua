//! What an operator may do on the platform, worked out from their own key,
//! or from the password they gave just now.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::operator::control::{OperatorAuthority, OperatorSignIn};
use ianua_domain::domains::operator::identity::Operator;
use ianua_domain::shared::clock;

use crate::acting::OperatorAuthorities;
use crate::context::OperatorCaller;
use crate::error::AppError;
use crate::ports::operator::{OperatorKeyStore, OperatorStore};

/// The stores [`OperatorActing`] reads from.
pub struct OperatorActingPorts {
    /// Platform operators.
    pub operators: Arc<dyn OperatorStore>,
    /// Their own keys.
    pub operator_keys: Arc<dyn OperatorKeyStore>,
}

/// Works out an operator's authority from the operator and the key they
/// came with, both loaded fresh.
pub struct OperatorActing {
    ports: OperatorActingPorts,
}

impl OperatorActing {
    /// A resolver reading from `ports`.
    #[must_use]
    pub fn new(ports: OperatorActingPorts) -> Self {
        Self { ports }
    }
}

#[async_trait]
impl OperatorAuthorities for OperatorActing {
    async fn authority(&self, caller: &OperatorCaller) -> Result<OperatorAuthority, AppError> {
        let operator = self
            .ports
            .operators
            .find_by_id(caller.operator())
            .await
            .map_err(AppError::from_domain)?
            .ok_or(AppError::Unauthenticated)?;
        let key = self
            .ports
            .operator_keys
            .find_by_prefix(caller.key())
            .await
            .map_err(AppError::from_domain)?
            .ok_or(AppError::Unauthenticated)?;
        OperatorAuthority::of_key(&operator, &key, clock::now()).map_err(AppError::from_domain)
    }

    async fn signed_in(
        &self,
        operator: &Operator,
        sign_in: &OperatorSignIn,
    ) -> Result<OperatorAuthority, AppError> {
        OperatorAuthority::of(operator, sign_in).map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::operator::status::OperatorStatus;
    use ianua_domain::types::{KeyPrefix, OperatorId};

    use super::*;
    use crate::test_support::block_on;
    use crate::test_support::operator::{
        FakeOperatorKeyStore, FakeOperatorStore, stored_operator, stored_operator_key,
    };

    /// Sam, an operator standing as `status`, and Olga, another operator,
    /// each holding a key of their own.
    struct Platform {
        sam: OperatorId,
        olga: OperatorId,
        acting: OperatorActing,
    }

    fn platform(status: OperatorStatus) -> Platform {
        let (sam, olga) = (OperatorId::new(), OperatorId::new());
        Platform {
            sam,
            olga,
            acting: OperatorActing::new(OperatorActingPorts {
                operators: Arc::new(FakeOperatorStore::holding([
                    stored_operator(sam, "sam@ianua.test", status),
                    stored_operator(olga, "olga@ianua.test", OperatorStatus::Active),
                ])),
                operator_keys: Arc::new(FakeOperatorKeyStore::holding([
                    stored_operator_key(sam, "opk_sam"),
                    stored_operator_key(olga, "opk_olga"),
                ])),
            }),
        }
    }

    fn calling(
        platform: &Platform,
        operator: OperatorId,
        key: &str,
    ) -> Result<OperatorAuthority, AppError> {
        let caller = OperatorCaller::new(operator, KeyPrefix::new(key).unwrap());
        block_on(platform.acting.authority(&caller))
    }

    /// Sam comes with his own key. He acts on the platform.
    #[test]
    fn an_operator_acts_with_their_own_key() {
        let platform = platform(OperatorStatus::Active);

        let result = calling(&platform, platform.sam, "opk_sam");

        assert!(result.is_ok());
    }

    /// Sam cannot resolve authority using Olga's key; the owner mismatch
    /// returns forbidden.
    #[test]
    fn an_operator_is_refused_with_another_operators_key() {
        let platform = platform(OperatorStatus::Active);

        let result = calling(&platform, platform.sam, "opk_olga");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Sam's stored key cannot restore authority while his operator
    /// account is disabled; the result is forbidden.
    #[test]
    fn a_disabled_operator_is_refused() {
        let platform = platform(OperatorStatus::Disabled);

        let result = calling(&platform, platform.sam, "opk_sam");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A known operator presenting an unknown key is unauthenticated.
    #[test]
    fn an_unknown_key_is_signed_out() {
        let platform = platform(OperatorStatus::Active);

        let result = calling(&platform, platform.olga, "opk_mallory");

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// A stored key paired with an unknown operator is unauthenticated.
    #[test]
    fn an_unknown_operator_is_signed_out() {
        let platform = platform(OperatorStatus::Active);

        let result = calling(&platform, OperatorId::new(), "opk_sam");

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
