use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Ok(output) = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
    {
        if output.status.success() {
            let git_sha = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            println!("cargo:rustc-env=LIGHTBRINGER_BUILD_GIT_SHA={git_sha}");
        }
    }
    println!(
        "cargo:rustc-env=LIGHTBRINGER_BUILD_MARKER=parent-slot-debug-2026-03-22"
    );

    tonic_prost_build::configure().compile_protos(
        &["pb/slot_stream.proto", "pb/slot_entry.proto"],
        &["proto", "pb/slot_entry.pb"],
    )?;
    Ok(())
}
