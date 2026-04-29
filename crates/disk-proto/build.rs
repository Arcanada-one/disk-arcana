use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .ok_or("workspace root not found")?
        .join("proto");
    let proto_file = proto_root.join("disk.proto");

    println!("cargo:rerun-if-changed={}", proto_file.display());

    // Build server + client traits.  Reflection descriptor is emitted only when
    // the `dev-reflect` feature is active (information-disclosure mitigation
    // per DISK-0004 § 6 T-Schema-Disclosure).
    let mut config = tonic_build::configure()
        .build_server(true)
        .build_client(true);

    if std::env::var("CARGO_FEATURE_DEV_REFLECT").is_ok() {
        config = config
            .file_descriptor_set_path(
                PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("disk_descriptor.bin"),
            );
    }

    config.compile_protos(&[proto_file], &[proto_root])?;
    Ok(())
}
