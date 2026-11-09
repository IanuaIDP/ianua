//! The gRPC contract between the control plane and its data planes.
//!
//! Generated from `proto/`, and deliberately nothing else. No domain types,
//! no mapping, no logic — the two ends each own their own translation to and
//! from these, the same way every other adapter owns its DTOs. A crate that
//! knew about both ends would put the control plane's vocabulary in the data
//! plane's dependency graph and undo the separation the split exists for.

/// Zone distribution to the authoritative nameservers.
pub mod dns {
    /// Version 1 of the contract.
    ///
    /// Versioned in the package name because the two ends deploy separately:
    /// a nameserver runs on its own host and is not upgraded in the same
    /// breath as the server. A breaking change becomes `v2`, both are served
    /// while the fleet rolls, and nothing is ever half-understood.
    pub mod v1 {
        // The code below is generated from the `.proto` file: its comments
        // are copied as written and its types are prost's, so these two
        // lints would fault the generator rather than anything kept here.
        #![allow(clippy::doc_markdown, clippy::large_enum_variant)]
        tonic::include_proto!("ianua.dns.v1");

        /// Which revision of `v1` this build understands.
        ///
        /// Bump it when a field is added that a nameserver must read to
        /// answer correctly — not for every change to the file. Both ends
        /// compile it in, and a nameserver reports its own on every catalog
        /// it applies, so a host left behind by a deploy says so instead of
        /// answering wrongly in silence.
        ///
        /// | rev | what it added |
        /// |-----|---------------|
        /// | 1   | zones, records |
        /// | 2   | per-zone `nameservers` — without it a nameserver answers with the deployment's shared names and every delegation fails to verify |
        pub const CONTRACT_VERSION: u32 = 2;
    }
}
