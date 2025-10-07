fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure().compile_protos(
        &["pb/slot_stream.proto", "pb/slot_entry.proto"],
        &["proto", "pb/slot_entry.pb"],
    )?;
    Ok(())
}
