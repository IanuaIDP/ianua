//! The image registries a tenant's administrator allowed: the only places
//! a sandbox version may take the company's own image from, each with the
//! login images are pulled with, kept sealed.
//!
//! Removing a registry stops every version whose image it keeps: their
//! next run fails as not run, so a registry the company no longer trusts
//! runs nothing more. Allowing it again lets them run again.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authorization::permission::WorkflowAction;
use crate::domains::workflows::control::WorkflowControl;
use crate::domains::workflows::events::{
    ImageRegistryAllowed, ImageRegistryRef, ImageRegistryRemoved,
};
use crate::domains::workflows::sandbox::image::RegistryHost;
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::{Human, ImageRegistryId, SealedSecret};

text_value! {
    /// The user an image is pulled as, such as `robot$acme+ci`: one word
    /// of printable characters.
    pub struct RegistryUsername;
}

impl TextValue for RegistryUsername {
    const FIELD: &'static str = "username";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .not_blank()
            .max_bytes(256)
            .no_control_chars()
            .no_whitespace()
            .no_invisible_chars()
    }
}

/// How images are pulled from a registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryLogin {
    /// With no login: the registry serves the images to anyone.
    Anonymous,
    /// As a user, with a password or token kept sealed for the registry's
    /// row.
    Password {
        /// The user images are pulled as.
        username: RegistryUsername,
        /// The password or token, sealed.
        password: SealedSecret,
    },
}

impl RegistryLogin {
    /// The stored and shown name: `anonymous` or `password`.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Anonymous => "anonymous",
            Self::Password { .. } => "password",
        }
    }
}

/// The values a registry is allowed with.
pub struct AllowRegistryParams {
    /// Its id, chosen first so its password can be sealed for it.
    pub id: ImageRegistryId,
    /// The registry's host.
    pub host: RegistryHost,
    /// How images are pulled from it.
    pub login: RegistryLogin,
}

/// A registry as stored.
pub struct ImageRegistryRow {
    /// The row on the tenant's list, which the sealed password is bound to.
    pub id: ImageRegistryId,
    /// The registry's host, once per tenant.
    pub host: RegistryHost,
    /// How images are pulled from it.
    pub login: RegistryLogin,
    /// The administrator who allowed it.
    pub allowed_by: Human,
    /// When it was allowed.
    pub created_at: OffsetDateTime,
    /// When it last changed.
    pub updated_at: OffsetDateTime,
}

/// A registry the tenant takes its own images from.
#[derive(Debug, Clone)]
pub struct ImageRegistry<T: TenantScope> {
    id: ImageRegistryId,
    host: RegistryHost,
    login: RegistryLogin,
    allowed_by: Human,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> ImageRegistry<T> {
    /// `by` allows `params.host`, its images pulled as `params.login` says.
    /// Raises `workflows.image_registry_allowed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not connect accounts.
    pub fn allow(
        params: AllowRegistryParams,
        by: &WorkflowControl<'_>,
    ) -> Result<Self, DomainError> {
        by.ensure_may(WorkflowAction::ConnectAccounts)?;
        let now = crate::shared::clock::now();
        let mut registry = Self {
            id: params.id,
            host: params.host,
            login: params.login,
            allowed_by: by.by().clone(),
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        registry.raised.raise(ImageRegistryAllowed {
            registry: registry.registry_ref(),
            login: registry.login.as_str(),
            occurred_at: now,
        });
        Ok(registry)
    }

    /// Rebuilds a registry from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when it changed before it was
    ///   allowed.
    pub fn reconstitute(row: ImageRegistryRow) -> Result<Self, DomainError> {
        RowCheck::of("image registry")
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was allowed",
            )
            .finish()?;
        Ok(Self {
            id: row.id,
            host: row.host,
            login: row.login,
            allowed_by: row.allowed_by,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// `by` takes the registry off the tenant's list; the store then drops
    /// it. Raises `workflows.image_registry_removed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not connect accounts.
    pub fn remove(&mut self, by: &WorkflowControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(WorkflowAction::ConnectAccounts)?;
        self.updated_at = crate::shared::clock::now();
        self.raised.raise(ImageRegistryRemoved {
            registry: self.registry_ref(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    fn registry_ref(&self) -> ImageRegistryRef {
        ImageRegistryRef {
            registry_id: self.id,
            host: self.host.clone(),
        }
    }

    /// The row the sealed password is bound to.
    #[must_use]
    pub fn id(&self) -> &ImageRegistryId {
        &self.id
    }

    /// The registry's host, which a pinned image names first.
    #[must_use]
    pub fn host(&self) -> &RegistryHost {
        &self.host
    }

    /// How images are pulled from it.
    #[must_use]
    pub fn login(&self) -> &RegistryLogin {
        &self.login
    }

    /// The administrator who allowed it.
    #[must_use]
    pub fn allowed_by(&self) -> &Human {
        &self.allowed_by
    }
}

impl<T: TenantScope> Raises for ImageRegistry<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

impl<T: TenantScope> Aggregate for ImageRegistry<T> {
    type Id = ImageRegistryId;

    fn id(&self) -> &Self::Id {
        &self.id
    }

    fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::workflows::execution::tests::fixtures::{ann, bob, holding_only, managing};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::raised;

    type Kept = ImageRegistry<ResolvedTenant>;

    fn params() -> AllowRegistryParams {
        AllowRegistryParams {
            id: ImageRegistryId::new(),
            host: RegistryHost::new("registry.acme.example").unwrap(),
            login: RegistryLogin::Password {
                username: RegistryUsername::new("robot$acme+ci").unwrap(),
                password: SealedSecret::new("v1.AAECAwQF").unwrap(),
            },
        }
    }

    /// Ann allows Acme's registry with a robot login. The record names the
    /// registry and that a sealed login pulls from it, never the login.
    #[test]
    fn an_administrator_allows_a_registry() {
        let mut registry = Kept::allow(params(), &managing(&ann())).unwrap();

        let allowed = raised(&mut registry);

        assert_eq!(
            allowed[0].event_type().as_str(),
            "workflows.image_registry_allowed"
        );
        assert_eq!(allowed[0].payload().get("login"), Some("password"));
        assert!(allowed[0].payload().get("username").is_none());
    }

    /// Bob may change workflows but not connect accounts, so he can neither
    /// allow a registry nor remove one.
    #[test]
    fn changing_workflows_alone_allows_no_registry() {
        let bob = bob();
        let mut registry = Kept::allow(params(), &managing(&ann())).unwrap();

        let allowed = Kept::allow(params(), &holding_only(&bob, WorkflowAction::Update));
        let removed = registry.remove(&holding_only(&bob, WorkflowAction::Update));

        assert!(matches!(allowed, Err(DomainError::Forbidden(_))));
        assert!(matches!(removed, Err(DomainError::Forbidden(_))));
    }

    /// Removing a registry is recorded.
    #[test]
    fn a_removed_registry_is_recorded() {
        let mut registry = Kept::allow(params(), &managing(&ann())).unwrap();
        let _ = raised(&mut registry);

        registry.remove(&managing(&ann())).unwrap();

        assert_eq!(
            raised(&mut registry)[0].event_type().as_str(),
            "workflows.image_registry_removed"
        );
    }

    /// A stored registry that changed before it was allowed is corrupt.
    #[test]
    fn a_registry_changed_before_it_was_allowed_is_corrupt() {
        let now = crate::shared::clock::now();

        let stored = Kept::reconstitute(ImageRegistryRow {
            id: ImageRegistryId::new(),
            host: RegistryHost::new("ghcr.io").unwrap(),
            login: RegistryLogin::Anonymous,
            allowed_by: ann(),
            created_at: now,
            updated_at: now - time::Duration::seconds(1),
        });

        assert!(refused_as_corrupt(&stored));
    }
}
