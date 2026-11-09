uuid_id! {
    /// Id of a resource type in a tenant's permission catalogue.
    ///
    /// Roles and routes name a resource by its [`PermissionSegment`] key, such
    /// as "project" or "invoice", which never changes. The id is how the
    /// catalogue entry itself is fetched, updated and deleted.
    ///
    /// [`PermissionSegment`]: crate::domains::authorization::permission::PermissionSegment
    ResourceTypeId
}
