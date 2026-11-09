uuid_id! {
    /// Id of a refresh token family: every refresh token rotated from the
    /// one a single grant first handed out.
    ///
    /// When a rotated token is presented again, someone holds a copy, so
    /// the whole family is revoked by this id.
    RefreshFamilyId
}
