uuid_id! {
    /// Id of a stream route, a port the proxy listens on below HTTP.
    ///
    /// It is a different type from an HTTP route's id, because the two share
    /// no matching rules. An HTTP route is picked by method and path, a
    /// stream route by port and server name.
    StreamRouteId
}
