uuid_id! {
    /// Id of a gateway service, a backend a tenant's routes forward to.
    ///
    /// It is not a caller. The machine identities that call in are a
    /// [`ConsumerId`](crate::types::id::ConsumerId). This names something the proxy
    /// calls out to.
    ServiceId
}
