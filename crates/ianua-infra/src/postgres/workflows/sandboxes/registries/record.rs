//! An image registry as its row holds it: read back into the aggregate, and
//! written out from it. The password stays sealed both ways.

use ianua_domain::domains::workflows::sandbox::image::RegistryHost;
use ianua_domain::domains::workflows::sandbox::registry::{
    ImageRegistry, ImageRegistryRow, RegistryLogin, RegistryUsername,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{ImageRegistryId, SealedSecret};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::Stored;

const REGISTRY: Stored = Stored("image registry");

const ALLOWED_BY: Kept = Kept {
    entity: REGISTRY.0,
    column: "allowed_by",
    shape: 1,
};

/// A registry as it is read. The store's checked queries fill it.
pub(super) struct RegistryRecord {
    pub(super) id: Uuid,
    pub(super) host: String,
    pub(super) login: String,
    pub(super) username: Option<String>,
    pub(super) password: Option<String>,
    pub(super) allowed_by: Value,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl RegistryRecord {
    /// The registry the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, the login word is unknown or its columns contradict it.
    pub(super) fn into_registry(self) -> Result<ImageRegistry<ResolvedTenant>, DomainError> {
        let login = login_from(&self.login, self.username, self.password)?;
        ImageRegistry::reconstitute(ImageRegistryRow {
            id: ImageRegistryId::from_uuid(self.id),
            host: REGISTRY.value("host", RegistryHost::new(self.host))?,
            login,
            allowed_by: ALLOWED_BY.open(self.allowed_by)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// The login a row's `login`, `username` and `password` columns hold.
fn login_from(
    login: &str,
    username: Option<String>,
    password: Option<String>,
) -> Result<RegistryLogin, DomainError> {
    match (login, username, password) {
        ("anonymous", None, None) => Ok(RegistryLogin::Anonymous),
        ("password", Some(username), Some(password)) => Ok(RegistryLogin::Password {
            username: REGISTRY.value("username", RegistryUsername::new(username))?,
            password: REGISTRY.value("password", SealedSecret::new(password))?,
        }),
        _ => Err(DomainError::corrupt_row(
            REGISTRY.0,
            "a login its columns contradict",
        )),
    }
}

/// A registry's columns, as they are written.
pub(super) struct RegistryColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) host: &'a str,
    pub(super) login: &'static str,
    pub(super) username: Option<&'a str>,
    pub(super) password: Option<&'a str>,
    pub(super) allowed_by: Value,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> RegistryColumns<'a> {
    /// The columns `registry` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when who allowed it cannot be
    /// written out.
    pub(super) fn of(registry: &'a ImageRegistry<ResolvedTenant>) -> Result<Self, DomainError> {
        let (username, password) = match registry.login() {
            RegistryLogin::Anonymous => (None, None),
            RegistryLogin::Password { username, password } => {
                (Some(username.as_str()), Some(password.as_str()))
            }
        };
        Ok(Self {
            id: registry.id().as_uuid(),
            host: registry.host().as_str(),
            login: registry.login().as_str(),
            username,
            password,
            allowed_by: ALLOWED_BY.seal(registry.allowed_by())?,
            created_at: registry.created_at(),
            updated_at: registry.updated_at(),
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::{Human, HumanAccount, PersonKey, UserId};
    use serde_json::json;

    use super::*;

    /// The administrator who allowed a registry is written as their account
    /// and address, and read back.
    #[test]
    fn the_allower_is_stored_in_their_pinned_shape() {
        let ann = Human::new(
            HumanAccount::User(UserId::from_uuid(Uuid::nil())),
            PersonKey::new("ann@acme.example").unwrap(),
        );
        let stored = json!({"v": 1, "value": {
            "account": {"User": "00000000-0000-0000-0000-000000000000"},
            "person": "ann@acme.example"
        }});

        assert_eq!(ALLOWED_BY.seal(&ann).unwrap(), stored);
        assert_eq!(ALLOWED_BY.open::<Human>(stored).unwrap(), ann);
    }

    /// A password login missing its user, or an anonymous one holding a
    /// password, is corrupt.
    #[test]
    fn a_login_its_columns_contradict_is_corrupt() {
        let sealed = || Some("v1.AAECAwQF".to_owned());

        assert!(login_from("password", None, sealed()).is_err());
        assert!(login_from("anonymous", None, sealed()).is_err());
        assert!(login_from("token", None, None).is_err());
        assert!(login_from("password", Some("robot".to_owned()), sealed()).is_ok());
    }
}
