use std::{io::Read, path::Path};

use anyhow::{Result, anyhow};
use isahc::{
    Request, RequestExt,
    config::{Configurable, RedirectPolicy},
};

/// Blocking. Downloads an incremental snapshot from `rpc_http` and returns the raw bytes
/// of its bank manifest (`snapshots/<slot>/<slot>`), stopping as soon as that entry has
/// been read so the (much larger) status cache and accounts are never downloaded.
pub fn fetch_incremental_snapshot_manifest(rpc_http: &str) -> Result<Vec<u8>> {
    let base = rpc_http.trim_end_matches('/');
    let url = format!("{base}/incremental-snapshot.tar.bz2");

    let response = Request::get(&url)
        .redirect_policy(RedirectPolicy::Follow)
        .body(())
        .map_err(|e| anyhow!("failed to build snapshot request for {url}: {e}"))?
        .send()
        .map_err(|e| anyhow!("failed to fetch snapshot from {url}: {e}"))?;
    if !response.status().is_success() {
        return Err(anyhow!(
            "snapshot request to {url} failed with status {}",
            response.status()
        ));
    }

    let decoder = zstd::stream::read::Decoder::new(response.into_body())
        .map_err(|e| anyhow!("failed to open zstd stream from {url}: {e}"))?;
    let mut archive = tar::Archive::new(decoder);
    let entries = archive
        .entries()
        .map_err(|e| anyhow!("failed to read snapshot tar entries from {url}: {e}"))?;

    for entry in entries {
        let mut entry = entry.map_err(|e| anyhow!("failed to read snapshot tar entry: {e}"))?;
        let path = entry
            .path()
            .map_err(|e| anyhow!("invalid snapshot tar entry path: {e}"))?
            .into_owned();
        if !is_manifest_path(&path) {
            continue;
        }
        let mut manifest = Vec::new();
        entry
            .read_to_end(&mut manifest)
            .map_err(|e| anyhow!("failed to read snapshot manifest entry: {e}"))?;
        return Ok(manifest);
    }

    Err(anyhow!(
        "incremental snapshot archive from {url} had no bank manifest entry"
    ))
}

/// The manifest lives at `snapshots/<slot>/<slot>`: two path components, both equal and
/// numeric. Everything else (`version`, `snapshots/status_cache`, `accounts/...`) is not it.
fn is_manifest_path(path: &Path) -> bool {
    let mut components = path.components();
    let Some(root) = components.next() else {
        return false;
    };
    if root.as_os_str() != "snapshots" {
        return false;
    }
    let (Some(dir), Some(file), None) = (components.next(), components.next(), components.next())
    else {
        return false;
    };
    dir.as_os_str() == file.as_os_str()
        && file
            .as_os_str()
            .to_str()
            .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
}
