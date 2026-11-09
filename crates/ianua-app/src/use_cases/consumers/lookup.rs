//! Loading the consumer a caller names, which every use case that reads or
//! changes one starts with. Messaging enrolls consumers too, so the lookup
//! itself is shared.

pub(super) use crate::services::lookup::existing_consumer;
