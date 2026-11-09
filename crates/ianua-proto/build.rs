//! Generates the gRPC types from the `.proto` contract.
//!
//! `protoc` comes from `protoc-bin-vendored` rather than the machine, so the
//! workspace builds the same way everywhere — including inside the Docker
//! builder stage, where requiring an apt package would invalidate the cached
//! dependency layer for every image each time it changed.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    // SAFETY: single-threaded, before any other code runs. `prost-build` reads
    // PROTOC from the environment and has no API to pass the path directly.
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/ianua/dns/v1/dns.proto"], &["proto"])?;

    println!("cargo:rerun-if-changed=proto/ianua/dns/v1/dns.proto");

    Ok(())
}
