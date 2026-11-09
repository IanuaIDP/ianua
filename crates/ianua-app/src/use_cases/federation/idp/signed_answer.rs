//! Signing, and sealing, the answer to a SAML app, as the app was set up:
//! the assertion always signed, sealed to the app's key when it asked for
//! that, and the response around it signed too when it asked for that.

use ianua_domain::domains::crypto::signing_key::SigningKey;
use ianua_domain::domains::federation::saml::assertion_builder::{
    AssertionParams, SignedAssertion, build_assertion,
};
use ianua_domain::domains::federation::saml::response_builder::{
    SamlResponseParams, build_response,
};
use ianua_domain::domains::federation::service_provider::{
    AcceptedAuthnRequest, AssertionEncryption, SamlServiceProviderSettings,
};
use ianua_domain::types::SamlEntityId;

use crate::error::{AppError, OrInternal};
use crate::ports::crypto::XmlSigner;
use crate::ports::federation::AssertionEncrypter;
use crate::use_cases::federation::lookup::{fresh_response_id, xml_signing_key};

/// Signs and seals answers.
pub(super) struct AnswerSigner<'a> {
    /// Signs XML with the tenant's key.
    pub(super) xml_signer: &'a dyn XmlSigner,
    /// Seals an assertion to an app's key.
    pub(super) encrypter: &'a dyn AssertionEncrypter,
    /// The key the tenant signs with now.
    pub(super) key: &'a SigningKey,
}

/// What an answer is written for: this identity provider, the sign-in the
/// app was accepted for, and how the app is answered.
pub(super) struct AnswerTerms<'a> {
    /// This identity provider's entity id, written as the issuer.
    pub(super) issuer: &'a SamlEntityId,
    /// The sign-in the answer is for.
    pub(super) accepted: &'a AcceptedAuthnRequest,
    /// How the app is answered.
    pub(super) settings: &'a SamlServiceProviderSettings,
}

impl AnswerSigner<'_> {
    /// The assertion `params` describe, signed, and sealed to the app's key
    /// when the app asked for that.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if a time in it cannot be written.
    /// - `AppError::Internal` on signing or sealing failure.
    pub(super) async fn assertion(
        &self,
        params: &AssertionParams,
        encryption: &AssertionEncryption,
    ) -> Result<SignedAssertion, AppError> {
        let built = build_assertion(params).map_err(AppError::from_domain)?;
        let signed_xml = self.signed(built.xml()).await?;
        let signed = built.signed(signed_xml);
        let AssertionEncryption::EncryptedFor(recipient) = encryption else {
            return Ok(signed);
        };
        let sealed = self
            .encrypter
            .encrypt(signed.xml(), recipient)
            .await
            .or_internal()?;
        Ok(signed.sealed(sealed))
    }

    /// The response carrying `assertion`, as `terms` say, signed when the
    /// app asked for that.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if its time cannot be written.
    /// - `AppError::Internal` on signing failure.
    pub(super) async fn response(
        &self,
        assertion: SignedAssertion,
        terms: &AnswerTerms<'_>,
    ) -> Result<String, AppError> {
        let response = build_response(&SamlResponseParams {
            response_id: fresh_response_id()?,
            issuer: terms.issuer.clone(),
            destination: terms.accepted.acs_url().clone(),
            in_response_to: terms.accepted.in_response_to().cloned(),
            assertion,
        })
        .map_err(AppError::from_domain)?;
        if !terms.settings.signing.signs_response() {
            return Ok(response.xml().to_owned());
        }
        self.signed(response.xml()).await
    }

    /// `xml` signed with the tenant's key.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` on signing failure.
    pub(super) async fn signed(&self, xml: &str) -> Result<String, AppError> {
        self.xml_signer
            .sign_xml(xml, &xml_signing_key(self.key))
            .await
            .or_internal()
    }
}
