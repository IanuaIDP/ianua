uuid_id! {
    /// Id of an API key.
    ///
    /// API keys are a sign-in method for machine-to-machine access of their
    /// own, apart from OAuth clients. Each key has this id for internal use,
    /// a `key_prefix` to look it up quickly, and a hashed secret to verify
    /// it.
    ApiKeyId
}
