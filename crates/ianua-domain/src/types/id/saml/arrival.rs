uuid_id! {
    /// Id of a SAML sign-in request held on the server from the moment it
    /// reached this platform.
    ///
    /// It is the only part of the request the dashboard holds. The message
    /// and the time it arrived stay on the server and are looked up by this
    /// id, so a browser cannot change when the request was made and slip
    /// past an app's demand for a fresh sign-in.
    SamlArrivalId
}
