//! The outside HTTP service the workflows deliver to, shared with the
//! other scenarios that need a real delivery to count.

pub(crate) use ianua_scenarios::upstreams::{
    OUTSIDE_CREDENTIAL as CREDENTIAL, OutsideService as Service,
};
