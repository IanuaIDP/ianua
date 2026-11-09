uuid_id! {
    /// Id of a tenant user.
    ///
    /// Every user in every tenant has their own id, even when one email
    /// address is used in several tenants. A user id means nothing without
    /// its tenant. The [`User<T>`](crate::domains::identity::account::user::User)
    /// aggregate ties it to one `TenantScope`.
    UserId
}
