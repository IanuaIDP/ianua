uuid_id! {
    /// Id of a role.
    ///
    /// It is unique everywhere, but a role only means something in its own
    /// tenant. Acme's "admin" role and Globex's "admin" role are separate,
    /// with different ids and possibly different permissions.
    RoleId
}
