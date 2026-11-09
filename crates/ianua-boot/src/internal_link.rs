//! How a part of the platform reaches a listener of another inside the
//! deployment's network, as both composition roots read it: the worker the
//! gateway's workflow listener, the gateway the API's relay listener.
//!
//! An `https` address goes over mutual TLS, trusting the internal
//! authority alone and presenting the caller's own certificate, and needs
//! all three files. A plain `http` address is taken outside production
//! only, with none of them, so a pass or a sealed question never crosses a
//! production network readable.

use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::CertificatePem;
use ianua_infra::http::client::InternalLink;

use crate::env::{ConfigError, Env, Read};
use crate::environment::Environment;

/// The settings one internal link is read from.
#[derive(Debug, Clone, Copy)]
pub struct LinkSettings {
    /// The listener's address, such as `GATEWAY_WORKFLOW_URL`.
    pub url: &'static str,
    /// The internal authority's certificate.
    pub authority: &'static str,
    /// The caller's certificate.
    pub certificate: &'static str,
    /// The caller's key.
    pub key: &'static str,
}

/// Where a listener is, and how it is reached.
#[derive(Debug, Clone)]
pub struct InternalCaller {
    /// The listener's address.
    pub url: url::Url,
    /// How calls to it are protected.
    pub link: InternalLink,
}

impl Env {
    /// The link `settings` describe in `environment`, or `None` when its
    /// address is unset.
    ///
    /// # Errors
    ///
    /// - [`ConfigError::Missing`] when an `https` address comes without its
    ///   three files.
    /// - [`ConfigError::Contradicts`] when a file is set without the
    ///   address or beside an `http` one, or an `http` address is set in
    ///   production.
    /// - [`ConfigError::Rejected`] when the authority is no certificate.
    pub fn internal_caller(
        &self,
        settings: &LinkSettings,
        environment: Environment,
    ) -> Read<Option<InternalCaller>> {
        let files = [settings.authority, settings.certificate, settings.key];
        let Some(url) = self.url(settings.url)? else {
            self.ensure_unset(&files, &format!("is set without {}", settings.url))?;
            return Ok(None);
        };
        let link = match url.scheme() {
            "https" => self.mutual_link(settings)?,
            _ => self.plain_link(settings, environment, &files)?,
        };
        Ok(Some(InternalCaller { url, link }))
    }

    /// Mutual TLS from the three files, each one required.
    fn mutual_link(&self, settings: &LinkSettings) -> Read<InternalLink> {
        let read = |name: &str| {
            self.file_text(name)?
                .ok_or_else(|| ConfigError::missing(name))
        };
        let authority = CertificatePem::new(read(settings.authority)?)
            .map_err(|cause| ConfigError::rejected(settings.authority, cause))?;
        let identity = format!("{}\n{}", read(settings.certificate)?, read(settings.key)?);
        Ok(InternalLink::Mutual {
            authority,
            identity: Secret::new(identity),
        })
    }

    /// Plain HTTP, refused in production and beside a certificate file.
    fn plain_link(
        &self,
        settings: &LinkSettings,
        environment: Environment,
        files: &[&str],
    ) -> Read<InternalLink> {
        if environment.is_production() {
            return Err(ConfigError::contradicts(
                settings.url,
                "is plain HTTP in production, where internal links are mutual TLS",
            ));
        }
        self.ensure_unset(
            files,
            &format!("is set beside a plain HTTP {}", settings.url),
        )?;
        Ok(InternalLink::PlainInDevelopment)
    }

    /// Refuses the first of `names` that is set, saying `why`.
    fn ensure_unset(&self, names: &[&str], why: &str) -> Read<()> {
        for name in names {
            if self.optional(name)?.is_some() {
                return Err(ConfigError::contradicts(name, why));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    const RELAY: LinkSettings = LinkSettings {
        url: "API_INTERNAL_URL",
        authority: "API_INTERNAL_CA_FILE",
        certificate: "API_INTERNAL_CLIENT_CERT_FILE",
        key: "API_INTERNAL_CLIENT_KEY_FILE",
    };

    const AUTHORITY: &str = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

    fn file(text: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(text.as_bytes()).unwrap();
        file
    }

    /// An `https` address with the authority, certificate and key reads as
    /// mutual TLS, the certificate and key together as the identity.
    #[test]
    fn an_https_address_with_its_files_is_mutual_tls() {
        let (authority, certificate, key) = (file(AUTHORITY), file("CERT"), file("KEY"));
        let path = |file: &tempfile::NamedTempFile| file.path().display().to_string();
        let vars = Env::of([
            (RELAY.url, "https://relay.ianua.svc:3002"),
            (RELAY.authority, path(&authority).as_str()),
            (RELAY.certificate, path(&certificate).as_str()),
            (RELAY.key, path(&key).as_str()),
        ]);

        let caller = vars
            .internal_caller(&RELAY, Environment::Production)
            .unwrap()
            .unwrap();

        let InternalLink::Mutual { identity, .. } = caller.link else {
            panic!("the link is mutual TLS");
        };
        assert_eq!(identity.expose(), "CERT\nKEY");
    }

    /// Production refuses plain HTTP and HTTPS requires its certificate
    /// files, while development permits a plain internal link.
    #[test]
    fn plain_http_is_refused_in_production_and_https_needs_its_files() {
        let plain = Env::of([(RELAY.url, "http://relay.ianua.svc:3002")]);
        let bare_https = Env::of([(RELAY.url, "https://relay.ianua.svc:3002")]);

        let production = plain.internal_caller(&RELAY, Environment::Production);
        let development = plain
            .internal_caller(&RELAY, Environment::Development)
            .unwrap()
            .unwrap();
        let missing = bare_https.internal_caller(&RELAY, Environment::Development);

        assert!(
            matches!(production, Err(ConfigError::Contradicts { name, .. }) if name == RELAY.url)
        );
        assert!(matches!(development.link, InternalLink::PlainInDevelopment));
        assert!(matches!(missing, Err(ConfigError::Missing { .. })));
    }

    /// Certificate files without an address or beside plain HTTP are
    /// refused, naming the file setting that cannot be used.
    #[test]
    fn a_file_without_a_protected_address_is_refused() {
        let alone = Env::of([(RELAY.authority, "/etc/ianua/link/ca.crt")]);
        let beside_plain = Env::of([
            (RELAY.url, "http://relay.ianua.svc:3002"),
            (RELAY.key, "/etc/ianua/link/gateway.key"),
        ]);

        let without = alone.internal_caller(&RELAY, Environment::Development);
        let plain = beside_plain.internal_caller(&RELAY, Environment::Development);

        assert!(
            matches!(without, Err(ConfigError::Contradicts { name, .. }) if name == RELAY.authority)
        );
        assert!(matches!(plain, Err(ConfigError::Contradicts { name, .. }) if name == RELAY.key));
    }
}
