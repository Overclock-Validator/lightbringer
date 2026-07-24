# P2P Overlay Network — Design Document Draft

---

## 1. Overview

### 1.1 Goals

- Spread data to all reachable peers as fast as possible
- Tolerate node churn without message loss
- Minimise redundant bandwidth at steady state
- Support heterogeneous nodes (staked validators and anonymous peers)

### 1.2 Non-goals

- Consensus or finality — this layer is transport only
- Ordered delivery — ordering is the application's responsibility
- Encryption at the overlay level — rely on TLS/noise at the transport layer

---

## 2. Network Layers

The overlay is explicitly **two-tiered**.

```
┌────────────────────────────────────────────────────────────┐
│  Layer 0 — Discovery                                        │
│  S/Kademlia DHT · Staked cert advertisement · Bootstrap    │
└────────────────────────────────────────────────────────────┘
         ↓ peer-info + stake certs
┌────────────────────────────────────────────────────────────┐
│  Layer 1 — Relay Mesh (Tier 1)                             │
│  High-stake authenticated nodes · Full / near-full mesh    │
│  Primary shard flooding path                               │
└────────────────────────────────────────────────────────────┘
         ↓ scored fan-out
┌────────────────────────────────────────────────────────────┐
│  Layer 2 — General Gossip (Tier 2)                         │
│  All peers including unstaked · Score-weighted peer views  │
│  Data dissemination: TBD                                   │
└────────────────────────────────────────────────────────────┘
```

### 2.1 Tier 1 — Relay Mesh

Tier-1 nodes are staked validators that have obtained a signed certificate from the authentication server (see §4). They form a **near-full mesh**: each Tier-1 node maintains persistent connections to all other known Tier-1 nodes up to a configurable cap `MAX_RELAY_PEERS` (suggested initial value: 200). Above that cap, connections are prioritised by peer score (§5).

**Promotion to Tier 1** requires:
- A valid, non-expired stake certificate (see §4)
- Peer score above `RELAY_SCORE_THRESHOLD` (suggested: 0.75 on a 0–1 scale)
- Stake above `RELAY_STAKE_THRESHOLD` (network-defined governance parameter)

Tier-1 membership is re-evaluated every **epoch**.

### 2.2 Tier 2 — General Gossip

Any node participates at Tier-2. Nodes maintain a **scored peer view** of `D` peers (suggested initial mesh degree: 8, range 6–12 per GossipSub convention). Peer view slots are competed for by score; the lowest-scored peer is replaced when a higher-scored candidate is discovered.

Tier-2 nodes that exceed the stake and score thresholds are promoted to Tier-1 on the next epoch boundary. Until then they behave as Tier-2 nodes but may receive shards directly from Tier-1 relays if the relay's fan-out list includes them.

**Data dissemination within Tier-2 is TBD.** Candidates under evaluation:

- GossipSub v1.2 with custom peer scoring
- OptimumP2P
- Look at Rotor implementation

---

## 3. Discovery — S/Kademlia DHT

### 3.1 Staked node advertisement

After obtaining a stake certificate (§4), a node stores the following provider record in the DHT:

```
key:   "/stake-cert/" + hex(node_id)
value: StakeCert {
    pubkey:     Ed25519PublicKey,
    stake:      u64,           // lamports or equivalent
    expiry:     UnixTimestamp,
    signature:  Ed25519Signature,  // over (pubkey ‖ stake ‖ expiry), signed by auth server
}
```

Any peer can retrieve and verify a stake cert with a single DHT lookup + `Ed25519.verify`. No trust in the querying node's claim is required.

### 3.4 Bootstrap

Nodes bootstrap via a static list of well-known bootstrap peers (standard Kademlia). Bootstrap peers are not required to be staked. After connecting to ≥ 1 bootstrap peer, the node performs a random-walk `FIND_NODE` query seeded with its own ID to populate its routing table.

### 3.5 Rust crates

| Component | Crate |
|---|---|
| Kademlia DHT | `libp2p-kad` |
| Peer identity & address resolution | `libp2p-identify` |
| S/Kademlia puzzle wrapper | Custom (thin wrapper over `libp2p-kad`) |

---

## 4. Authentication — Staked Node Certificates

Stake authentication is centralised by design: a single **auth server** issues short-lived certificates. This is intentional — it keeps the on-chain footprint minimal and avoids requiring light-client proof verification on every peer connection.
**Note: Subject to change**


### 4.1 Certificate issuance flow

```
1. Node generates an Ed25519 keypair locally.
   private_key  →  kept on disk, never transmitted
   public_key   →  used as network identity

2. Node calls auth server:
   POST /issue-cert
   Body: { pubkey, stake_proof }
   where stake_proof is a signed message from the staking contract / chain

3. Auth server verifies stake_proof on-chain, then issues:
   StakeCert {
       pubkey:    <node pubkey>,
       stake:     <verified amount>,
       expiry:    now() + CERT_TTL,   // suggested: 4 hours
       signature: AuthServer.sign(pubkey ‖ stake ‖ expiry)
   }

4. Node stores cert in memory and advertises it:
   - In DHT provider record (§3.3)
   - In membership gossip (Tier-1 epoch updates)

5. Cert renewal: node repeats steps 2–4 before expiry.
   A node operating with an expired cert is treated as unstaked (score S=0).
```

### 4.2 Certificate revocation

Revocation is handled implicitly by the short TTL (`CERT_TTL = 4h`). Explicit revocation (e.g. on slashing) is handled by the auth server refusing to renew. Peers will naturally down-score an unreachable node within one epoch regardless of cert validity.

---

## 5. Peer Scoring

Every node maintains a score for each peer it knows about. Scores drive:
- Which peers occupy Tier-1 relay connections
- Which peers fill the Tier-2 gossip mesh
- Whether a misbehaving peer is quarantined

### 5.1 Score formula

```
score(peer) = W_L × L(peer) + W_S × S(peer) − W_M × M(peer)

Recommended weights:  W_L = 5,  W_S = 3,  W_M = 2

Each sub-score is normalised to [0.0, 1.0] before weighting.
Final score range: [−2.0, 8.0]  (min when M=1; max when L=1, S=1, M=0)
```

### 5.2 Latency score L(peer)

Measures how fast a peer delivers shards relative to the local network baseline. Uses **exponential decay** so the penalty grows steeply for peers above the baseline RTT and softly rewards peers below it.

```
rtt_sample    = measured round-trip time (EWMA over last 10 samples, ms)
baseline_rtt  = 50th-percentile RTT across all known peers (updated every epoch)

L(peer) = exp(−λ × rtt_sample / baseline_rtt)
          where λ = 0.5  (tunable)
```

| rtt / baseline | L(peer) |
|---|---|
| 0.5× (2× faster) | 0.78 |
| 1.0× (at baseline) | 0.61 |
| 2.0× (2× slower) | 0.37 |
| 4.0× (4× slower) | 0.14 |

RTT samples are collected passively via shard acknowledgement timing and actively via periodic PING messages (one per 10s per peer to avoid probe flood).

### 5.3 Stake score S(peer)

Log-scaled to prevent whale domination: doubling stake gives diminishing score gains.

```
S(peer) = log(1 + stake(peer)) / log(1 + max_stake_in_view)

where max_stake_in_view = maximum known stake across all peers with valid certs
```

An unstaked peer (no valid cert, or cert with stake=0) receives `S = 0.0`. This does **not** exclude unstaked peers from the network — it simply places them in lower-priority gossip slots.

### 5.4 Misbehaviour score M(peer)

`M(peer)` is the application-provided misbehaviour metric, normalised to [0.0, 1.0]. This design document treats the metric itself as pre-existing and out of scope. The scoring layer consumes it as a black box.

Suggested integration contract:

```rust
trait MisbehaviourOracle {
    /// Returns a value in [0.0, 1.0].
    /// 0.0 = no known misbehaviour; 1.0 = confirmed maximal misbehaviour.
    fn score(&self, peer: &PeerId) -> f64;
}
```

### 5.5 Score update cadence

**NOTE: Misbehaviour will not be a factor initially, needs more design**

| Event | Action |
|---|---|
| New shard received from peer | Update L(peer) with new RTT sample |
| PING reply received | Update L(peer) |
| Stake cert refreshed | Re-read S(peer) from cert |
| Misbehaviour mechanism | Update M(peer) |
| Epoch boundary | Recompute baseline_rtt; re-sort peer views; evaluate Tier-1/Tier-2 promotions/demotions |

### 5.6 Quarantine policy

A peer is moved to quarantine (all connections dropped, ID blacklisted for `QUARANTINE_TTL`) when:

```
score(peer) < QUARANTINE_FLOOR   (suggested: −1.0)
```

This threshold corresponds roughly to M(peer) ≥ 0.75 with L and S both at zero — i.e., a peer that is simultaneously slow, unstaked, and flagged for serious misbehaviour. A purely latency-penalised peer never reaches quarantine under normal scoring parameters, preventing network partitioning from transient congestion.

Quarantine records are gossiped among Tier-1 nodes (short signed message: `{peer_id, reason, timestamp, reporter_pubkey}`) so the signal propagates without requiring every node to independently observe the misbehaviour.

---

## 6. Data Encoding — Solana Shred Format (32:32)

The network adopts **Solana's shred encoding** as the canonical data format. 32:32 shreds per batch, Reed-Solomon encoded

---

## 7. Transport

### 7.1 Protocol

**QUIC** (via `libp2p-quic`) is the recommended transport over TCP for the following reasons:

- 0-RTT or 1-RTT connection establishment (vs. TCP+TLS: 3-RTT)
- Stream-level multiplexing without head-of-line blocking
- Connection migration support (relevant for mobile / NAT traversal)
- Native integration with `rust-libp2p`'s multiaddr system

### 7.2 Connection management

| Parameter | Value | Notes |
|---|---|---|
| Idle connection timeout | 30s | Avoids accumulating dead connections |
| Keepalive interval | 10s | PING to prevent NAT mapping expiry |
| Max inbound connections | 1024 | Rate-limited per IP to resist connection flood |

---

## 8. Repair Protocol
Same impl. as solana

## Open Questions

| # | Question | Target |
|---|---|---|
| 1 | Data dissemination algorithm | TBD |
| 2 | Misbehaviour statistics | TBD 

---