uuid_id! {
    /// Id of one `WebAuthn` ceremony in progress.
    ///
    /// It is the only part of a ceremony the client holds. The ceremony's
    /// state stays on the server and is looked up by this id. That state is
    /// the challenge the authenticator must sign, and which credentials may
    /// answer it. So a caller cannot choose what their assertion is checked
    /// against.
    CeremonyId
}
