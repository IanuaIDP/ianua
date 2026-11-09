uuid_id! {
    /// Id of an app a tenant signs people in to over SAML, with this
    /// platform as the identity provider.
    ///
    /// The app's own name for itself is its entity id. This id is the
    /// tenant's record of it, and what a pairwise `NameID` is worked out
    /// for, so two apps never see the same `NameID` for one person.
    SamlServiceProviderId
}
