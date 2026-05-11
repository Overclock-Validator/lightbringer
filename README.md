# Lightbringer

**Lightbringer** is a lightweight Rust-based Solana networking sidecar for ingesting, repairing, caching, and serving recent shred data from Turbine and Repair.

It is designed primarily to run alongside **Mithril**, usually on the same server, where it gives Mithril a local stream of fresh block data without requiring a full RPC validator or high-volume block subscriptions from centralized providers.

Lightbringer is now part of Mithril’s normal block ingestion path: Mithril can manage Lightbringer through its own configuration, generate the Lightbringer config, launch it as a sidecar, and consume its gRPC block stream directly.

Lightbringer can also run as a standalone edge service, but the main intended use case is pairing it with Mithril so the two together can operate independently from RPC providers for streaming in recent blocks.

Because Lightbringer does not maintain an AccountsDB, vote engine, or full RPC layer, it can stay relatively small while still participating in Solana’s live data path.

Lightbringer currently:

* Receives shreds via Turbine.
* Filters invalid or duplicate traffic early.
* Detects slot gaps and issues targeted repair requests to Solana gossip peers.
* Validates repair responses before block reassembly.
* Reuses [Agave](https://github.com/anza-xyz/agave)/Solana crates for protocol compatibility, including gossip, shred types, deshredding, decoding, and repair protocol serialization.
* Implements its own lightweight pipeline around those primitives, including Turbine ingestion, packet filtering, slot-gap tracking, repair orchestration, shred caching, block streaming, and Mithril integration.
* Serves deshredded blocks over gRPC.
* Serves raw shreds over a local HTTP/debug API.
* Optionally gates gRPC block streams on confirmed-slot notifications from RPC WebSocket, which is useful for Mithril’s current execution path.

Lightbringer performs lightweight validation, including shred signature verification, leader-schedule sanity checks, duplicate suppression, and repair-response validation. It is not a full validator and does not replace full block execution or application-level fork-choice logic. Consumers such as Mithril remain responsible for deeper validation and execution behavior.

---

## Architecture

Lightbringer is written in Rust and built as a staged pipeline using **Glommio**’s thread-per-core async model, with **kanal** channels connecting internal stages.

At a high level:

1. Shreds are received from Solana Turbine.
2. Incoming traffic is filtered and deduplicated.
3. Slot gaps are detected.
4. Missing shreds are requested through targeted repair.
5. Repair responses are validated.
6. Blocks are reassembled.
7. Downstream consumers can read deshredded blocks, raw shreds, or confirmed-block streams.

---

## Relationship To Agave

Lightbringer is not a fork of [Agave](https://github.com/anza-xyz/agave) and does not run Agave’s validator pipeline.

It reuses selected [Agave](https://github.com/anza-xyz/agave)/Solana crates where doing so helps maintain compatibility with the live network, especially for gossip, shred types, deshredding, decoding, and repair protocol serialization.

Lightbringer implements its own lightweight pipeline around those primitives, including Turbine ingestion, packet filtering, slot-gap tracking, repair orchestration, shred caching, block streaming, and Mithril integration.

---

## Mithril Integration

Lightbringer was built to reduce Mithril’s dependence on RPC providers for recent blocks coming through Turbine and Repair.

When paired with Mithril, Lightbringer provides the live block data path locally, while Mithril handles execution and higher-level logic. In current Mithril deployments, Lightbringer is integrated into Mithril’s configuration and can be treated as a managed sidecar dependency rather than a separate service that users must wire up manually.

Together, Lightbringer and Mithril can run as a single server-side system that is much less dependent on external RPC infrastructure for live or recent block execution.

Typical deployment options include:

* Running Lightbringer as a Mithril-managed sidecar.
* Running Lightbringer alongside Mithril on the same host.
* Running Lightbringer as a sidecar process in the same container, VM, or pod as Mithril.
* Running Lightbringer as a standalone edge service for other downstream consumers.

---

## Current Status

### Milestone 1: Core Turbine / Repair Pipeline

Implemented or in progress:

* Ingest incoming shreds into a rolling cache.
* Detect slot gaps and issue repair requests.
* Perform lightweight validation, including sigverify, leader-schedule checks, and duplicate filtering.
* Validate repair responses.
* Reassemble blocks.
* Serve deshredded blocks over gRPC.
* Serve raw shreds over a local HTTP/debug API.
* Support confirmed-block streaming for Mithril.
* Continue performance optimizations.

### Milestone 2: Active Repair Participation

Near-term work:

* Allow Lightbringer to serve repair requests itself.
* Let Lightbringer/Mithril systems return data to the network instead of only consuming shred traffic.
* Make the shred retention cache window configurable.
* Improve network robustness by increasing the number of systems that can help backstop recent shred availability.

### Milestone 3: Mithril and Alpenglow Support

Planned work:

* Adapt Lightbringer’s networking and block-streaming interfaces for Alpenglow’s consensus and shred distribution models.
* Provide lower-latency streams that Mithril can use for closer-to-tip execution.
* Explore pre-confirmation block-streaming support for downstream systems such as Mithril.

### Milestone 4: Mesh and Ops Tooling

Future work:

* Tunable retention policies and hard resource caps.
* Prometheus metrics.
* Tracing hooks.
* Additional operational tooling.





