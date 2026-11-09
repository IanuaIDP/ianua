//! Dumps the OpenAPI spec as pretty JSON.
//! Run: `cargo run -p ianua-api --example openapi_spec`

/// Writes the published document to standard output, reporting serialization failure.
fn main() -> Result<(), serde_json::Error> {
    println!("{}", ianua_api::openapi::document().to_pretty_json()?);
    Ok(())
}
