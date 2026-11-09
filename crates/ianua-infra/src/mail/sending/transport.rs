//! The mail transports the app sends through: the platform's own mail,
//! and the provider a tenant named, its credentials opened only for the
//! one delivery.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::authentication::{SealedFor, SecretEncryptor};
use ianua_app::ports::branding::{AddressedMail, MailProviderTransport};
use ianua_domain::domains::branding::mail_provider::MailProvider;
use ianua_domain::shared::errors::DomainError;

use crate::mail::sending::accounts::{Opening, PlatformMail};
use crate::mail::sending::delivery::{Chosen, DeliveryAccount, MailDelivery};
use crate::mail::sending::message::Envelope;

/// Delivers mail through the provider it names: the platform's own
/// account, or a tenant's SMTP server or API account.
pub struct OutboundMailProviderTransport {
    platform: Arc<PlatformMail>,
    delivery: Arc<MailDelivery>,
    secrets: Arc<dyn SecretEncryptor>,
}

impl fmt::Debug for OutboundMailProviderTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboundMailProviderTransport")
            .finish_non_exhaustive()
    }
}

impl OutboundMailProviderTransport {
    /// A transport sending the platform's own mail as `platform` says,
    /// opening a tenant's credentials with `secrets`, delivering through
    /// `delivery`.
    #[must_use]
    pub fn new(
        platform: Arc<PlatformMail>,
        delivery: Arc<MailDelivery>,
        secrets: Arc<dyn SecretEncryptor>,
    ) -> Self {
        Self {
            platform,
            delivery,
            secrets,
        }
    }
}

#[async_trait]
impl MailProviderTransport for OutboundMailProviderTransport {
    async fn deliver(
        &self,
        provider: &MailProvider,
        credential: &SealedFor,
        mail: &AddressedMail<'_>,
    ) -> Result<(), DomainError> {
        let envelope = Envelope::of(mail, &self.platform);
        let opening = Opening {
            secrets: self.secrets.as_ref(),
            place: credential,
        };
        let Some(account) = opening.opened(provider).await? else {
            return self
                .delivery
                .deliver(
                    DeliveryAccount {
                        account: self.platform.sending_account()?,
                        chosen: Chosen::ByPlatform,
                    },
                    &envelope,
                    mail.rendered,
                )
                .await;
        };
        self.delivery
            .deliver(
                DeliveryAccount {
                    account: &account,
                    chosen: Chosen::ByTenant,
                },
                &envelope,
                mail.rendered,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ianua_app::ports::branding::mail_credential_place;
    use ianua_app::ports::shared::MailSetup;
    use ianua_domain::domains::branding::config::MailSender;
    use ianua_domain::domains::identity::account::address::MailReach;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::shared::security::ssrf::UpstreamNetworks;
    use ianua_domain::types::{Email, Label, TenantId};
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::crypto::keys::KEY_BYTES;
    use crate::crypto::{AesGcmSecretEncryptor, SealingKey};
    use crate::mail::sending::accounts::MailAccount;
    use crate::mail::sending::apis::ProviderEndpoints;
    use crate::mail::sending::apis::stand_in::{ann, platform, reset_mail};

    struct Setup {
        server: MockServer,
        secrets: Arc<dyn SecretEncryptor>,
        transport: OutboundMailProviderTransport,
    }

    /// Where Acme's provider keeps its credential.
    fn acme_place() -> SealedFor {
        mail_credential_place(Some(TenantId::from_uuid(uuid::Uuid::nil())))
    }

    impl Setup {
        /// The platform sending through Postmark, every API answered by a
        /// stand-in.
        async fn new() -> Self {
            let server = MockServer::start().await;
            let delivery = MailDelivery::new(
                ProviderEndpoints::all_at(&server.uri()).unwrap(),
                UpstreamNetworks::public_only(),
                Duration::from_secs(5),
            )
            .unwrap();
            let secrets: Arc<dyn SecretEncryptor> = Arc::new(AesGcmSecretEncryptor::new(
                SealingKey::new("k1", [3; KEY_BYTES]).unwrap(),
                Vec::new(),
            ));
            let platform = platform(MailAccount::Postmark {
                server_token: Secret::new("platform-token"),
            });
            let transport = OutboundMailProviderTransport::new(
                Arc::new(platform),
                Arc::new(delivery),
                Arc::clone(&secrets),
            );
            Self {
                server,
                secrets,
                transport,
            }
        }

        async fn answering(&self, route: &str) {
            Mock::given(method("POST"))
                .and(path(route))
                .respond_with(ResponseTemplate::new(200))
                .mount(&self.server)
                .await;
        }
    }

    /// Mail of the platform's own goes out through the platform's account,
    /// from the platform's address.
    #[tokio::test]
    async fn the_platforms_mail_goes_through_the_platforms_account() {
        let setup = Setup::new().await;
        Mock::given(method("POST"))
            .and(path("/email"))
            .and(header("X-Postmark-Server-Token", "platform-token"))
            .and(body_partial_json(
                serde_json::json!({"From": "\"Ianua\" <noreply@ianua.test>"}),
            ))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&setup.server)
            .await;
        let to = ann();
        let rendered = reset_mail();
        let mail = AddressedMail {
            to: &to,
            sender: MailSender::Platform,
            sender_name: None,
            rendered: &rendered,
        };

        let sent = setup
            .transport
            .deliver(&MailProvider::Platform, &mail_credential_place(None), &mail)
            .await;

        assert!(sent.is_ok());
    }

    /// Acme's tested SendGrid account takes Acme's mail, signed in with the
    /// key Acme sealed, from Acme's own address under its name.
    #[tokio::test]
    async fn a_tenants_provider_is_signed_in_with_its_opened_key() {
        let setup = Setup::new().await;
        Mock::given(method("POST"))
            .and(path("/v3/mail/send"))
            .and(header("authorization", "Bearer SG.acme"))
            .and(body_partial_json(serde_json::json!({
                "from": {"email": "hello@acme.test", "name": "Acme"}
            })))
            .respond_with(ResponseTemplate::new(202))
            .expect(1)
            .mount(&setup.server)
            .await;
        let place = acme_place();
        let provider = MailProvider::SendGrid {
            api_key: setup.secrets.encrypt(b"SG.acme", &place).await.unwrap(),
        };
        let (to, acme) = (ann(), Email::new("hello@acme.test").unwrap());
        let name = Label::new("name", "Acme").unwrap();
        let rendered = reset_mail();
        let mail = AddressedMail {
            to: &to,
            sender: MailSender::Tenant(&acme),
            sender_name: Some(&name),
            rendered: &rendered,
        };

        let sent = setup.transport.deliver(&provider, &place, &mail).await;

        assert!(sent.is_ok());
    }

    /// A credential sealed with an unavailable key makes delivery fail without
    /// contacting either the tenant's provider or the platform's provider.
    #[tokio::test]
    async fn a_key_that_does_not_open_sends_nothing() {
        let setup = Setup::new().await;
        setup.answering("/email").await;
        setup.answering("/v3/mail/send").await;
        let elsewhere =
            AesGcmSecretEncryptor::new(SealingKey::new("k9", [9; KEY_BYTES]).unwrap(), Vec::new());
        let place = acme_place();
        let provider = MailProvider::SendGrid {
            api_key: elsewhere.encrypt(b"SG.acme", &place).await.unwrap(),
        };
        let to = ann();
        let rendered = reset_mail();
        let mail = AddressedMail {
            to: &to,
            sender: MailSender::Platform,
            sender_name: None,
            rendered: &rendered,
        };

        let sent = setup.transport.deliver(&provider, &place, &mail).await;

        assert!(matches!(sent, Err(DomainError::Infrastructure(_))));
        assert!(setup.server.received_requests().await.unwrap().is_empty());
    }

    /// A deployment with no mail server says so, and a mail of the
    /// platform's own fails to send rather than vanishing as if sent.
    #[tokio::test]
    async fn without_a_mail_server_the_platforms_mail_fails_and_says_so() {
        let platform = PlatformMail {
            account: None,
            ..platform(MailAccount::Postmark {
                server_token: Secret::new("platform-token"),
            })
        };
        let delivery = unavailable_delivery();
        let reach = platform.mail_setup().reach();
        let setup = Setup::new().await;
        let transport = OutboundMailProviderTransport::new(
            Arc::new(platform),
            Arc::new(delivery),
            setup.secrets,
        );
        let (to, rendered) = (ann(), reset_mail());
        let mail = AddressedMail {
            to: &to,
            sender: MailSender::Platform,
            sender_name: None,
            rendered: &rendered,
        };

        let sent = transport
            .deliver(&MailProvider::Platform, &mail_credential_place(None), &mail)
            .await;

        assert_eq!(reach, MailReach::NotSetUp);
        assert!(matches!(sent, Err(DomainError::Infrastructure(_))));
    }

    /// A delivery adapter pointed at an unavailable local provider endpoint.
    fn unavailable_delivery() -> MailDelivery {
        MailDelivery::new(
            ProviderEndpoints::all_at("http://127.0.0.1:9").unwrap(),
            UpstreamNetworks::public_only(),
            Duration::from_secs(5),
        )
        .unwrap()
    }

    /// A deployment whose platform mail has an account says mail reaches.
    #[test]
    fn with_a_mail_server_mail_reaches() {
        let platform = platform(MailAccount::Postmark {
            server_token: Secret::new("platform-token"),
        });

        assert_eq!(platform.mail_setup().reach(), MailReach::Available);
    }
}
