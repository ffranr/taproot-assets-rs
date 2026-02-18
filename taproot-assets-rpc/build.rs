#[cfg(feature = "build-protos")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // <crate>/proto/
    let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let proto_root = manifest_dir.join("proto");

    tonic_build::configure()
        .out_dir(manifest_dir.join("generated"))
        .compile_protos(&[proto_root.join("taprootassets.proto")], &[&proto_root])?;

    println!("cargo:rerun-if-changed={}", proto_root.display());
    Ok(())
}

#[cfg(not(feature = "build-protos"))]
fn main() {}
