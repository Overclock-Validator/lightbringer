use std::{io::Read, path::Path};

use anyhow::{Result, anyhow};
use isahc::{
    Request, RequestExt, ResponseExt,
    config::{Configurable, RedirectPolicy},
};

/// Snapshot artifacts to probe for, in preference order - mirrors the discovery order in
/// `solana-snapshot-finder-go`: incremental (small, fast) before full, and today's real
/// `.tar.zst` format before the legacy `.tar.bz2` alias name. RPC nodes only actually serve
/// snapshots under the `.tar.bz2` alias path (redirecting to the real, usually zstd,
/// artifact) - trying `.tar.zst` directly first only pays off against snapshot mirrors that
/// host the raw files rather than an RPC node's alias endpoint.
const SNAPSHOT_CANDIDATES: &[(&str, &str)] = &[
    ("incremental-snapshot", ".tar.zst"),
    ("incremental-snapshot", ".tar.bz2"),
    ("snapshot", ".tar.zst"),
    ("snapshot", ".tar.bz2"),
];

/// Blocking. Automatically discovers a snapshot at `rpc_http` (incremental preferred,
/// falling back to full) and returns the raw bytes of its bank manifest
/// (`snapshots/<slot>/<slot>`), stopping as soon as that entry has been read so the (much
/// larger) status cache and accounts are never downloaded.
pub fn discover_and_fetch_snapshot_manifest(rpc_http: &str) -> Result<Vec<u8>> {
    let base = rpc_http.trim_end_matches('/');

    let mut last_err = None;
    for (name, ext) in SNAPSHOT_CANDIDATES {
        let url = format!("{base}/{name}{ext}");
        match fetch_manifest_from(&url) {
            Ok(manifest) => return Ok(manifest),
            Err(e) => {
                log::debug!("alpenglow snapshot discovery: {url} unavailable ({e})");
                last_err = Some(e);
            }
        }
    }

    Err(anyhow!(
        "no snapshot found at {rpc_http} (tried {} candidates): {}",
        SNAPSHOT_CANDIDATES.len(),
        last_err.map(|e| e.to_string()).unwrap_or_default()
    ))
}

fn fetch_manifest_from(url: &str) -> Result<Vec<u8>> {
    let response = Request::get(url)
        .redirect_policy(RedirectPolicy::Follow)
        .body(())
        .map_err(|e| anyhow!("failed to build snapshot request: {e}"))?
        .send()
        .map_err(|e| anyhow!("failed to fetch snapshot: {e}"))?;
    if !response.status().is_success() {
        return Err(anyhow!("status {}", response.status()));
    }

    let resolved_url = response
        .effective_uri()
        .map(|uri| uri.to_string())
        .unwrap_or_else(|| url.to_string());
    if !resolved_url.ends_with(".tar.zst") {
        return Err(anyhow!(
            "resolved to {resolved_url}, only .tar.zst snapshots are supported"
        ));
    }
    log::info!("alpenglow: using snapshot source {resolved_url}");

    let decoder = zstd::stream::read::Decoder::new(response.into_body())
        .map_err(|e| anyhow!("failed to open zstd stream from {resolved_url}: {e}"))?;
    let mut archive = tar::Archive::new(decoder);
    let entries = archive
        .entries()
        .map_err(|e| anyhow!("failed to read snapshot tar entries from {resolved_url}: {e}"))?;

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
        "snapshot archive from {resolved_url} had no bank manifest entry"
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
