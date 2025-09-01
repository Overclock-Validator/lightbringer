# Overcast

**Overcast** is a work‑in‑progress, lightweight Solana “edge” node that caches and republishes *ephemeral* Turbine + repair traffic.  
It lets downstream tools pull fresh blocks without the cost of running a full RPC validator or paying for high‑volume block subscriptions from centralized providers.

Because Overcast **drops the Accounts DB, vote engine, and RPC layer**, it’s small enough to run as a *sidecar process*—for example, in the same container/VM/pod as **Mithril**.  

* Overcast performs only **minimal validation**—shred signature checks, leader‑schedule sanity, duplicate suppression—so bad data is filtered early without heavy state.

* Mithril (or any other consumer) owns fork‑choice and full block validation. 

---

### Milestone 1 — Core Turbine / Repair Pipeline *(in progress)*
* Ingest incoming shreds into a rolling cache (default retention ≈ 1 h, configurable).  
* Detect gaps quickly and issue repair requests.  
* **Lightweight validation**: shred sig‑verify, leader‑schedule check, duplicate filtering.  
* Validate repair responses and re‑assemble blocks.  
* Serve valid shreds to any peer that asks.
* Performance optimizations

### Milestone 2 — Mithril Sidecar Integration *(planned)*
* Expose a lightweight local API so Mithril can stream blocks directly from the Overcast sidecar.  
* Co‑location: run Overcast + Mithril on one host with minimal extra CPU/RAM/disk.  
* Optional mesh discovery so multiple Overcast sidecars can backstop block availability for each other.

### Milestone 3 — Mesh & Ops Tooling *(future)*
* Peer discovery to form regional cache meshes.  
* Tunable retention policies and hard resource caps.  
* Prometheus metrics, tracing hooks, and other operational tooling.



