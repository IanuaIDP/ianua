uuid_id! {
    /// Id of an OAuth client, for internal use.
    ///
    /// A tenant can have several clients, such as machine-to-machine
    /// integrations and third-party apps. The public `client_id` sent in
    /// OAuth flows is a separate field on the
    /// [`OAuthClient`](crate::domains::oauth::clients::client::OAuthClient).
    OAuthClientId
}
