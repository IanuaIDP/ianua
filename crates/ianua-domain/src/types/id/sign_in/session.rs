uuid_id! {
    /// Id of a session.
    ///
    /// Each session belongs to one user in one tenant. The id is unique
    /// everywhere, and as a `UUIDv7` it sorts by time and keeps database
    /// indexes compact. A session means nothing without its tenant. The
    /// [`Session<T>`](crate::domains::authentication::sessions::session::Session)
    /// aggregate ties it to one `TenantScope`.
    SessionId
}
