uuid_id! {
    /// Id of an organization member.
    ///
    /// Organization members manage the platform through the dashboard. Their
    /// ids are a different type from a tenant user's [`UserId`](crate::types::id::UserId),
    /// so the two identity planes never share ids.
    OrgUserId
}
