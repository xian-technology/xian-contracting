# ZK Privacy Optimization Plan

## Goal

Improve Xian shielded transactions along four axes:

- lower end-user proving latency
- lower validator verification cost at higher shielded transaction volume
- stronger privacy for wallet sync and transaction origination
- preserve or improve security without weakening current correctness guarantees

## Current State

Today Xian shielded transactions already have:

- Groth16/BN254 proof verification in the runtime bridge
- shielded note, command, and relayed hidden-sender transfer flows
- note payloads removed from consensus storage, with wallet recovery driven from transaction history
- selective wallet sync through indexed `sync_hint` / `discovery_tag` retrieval
- native tree-append and relay-digest execution in the `zk` stdlib bridge

The remaining practical bottlenecks are:

- proof generation is still expensive for browsers and phones
- wallet sync still depends on indexed infrastructure to avoid broad history scans
- network-origin privacy is weaker than on-chain sender privacy
- validator-side zk work is still per-transaction rather than batched

## Research-Backed Direction

The most relevant external work points to this order of operations:

1. delegated or split proving for constrained clients
2. better note discovery and light-wallet privacy
3. network-origin privacy for private transactions
4. batch verification and block-level zk optimizations
5. longer-term accumulator redesigns such as Curve Trees / Curve Forests

Important distinction:

- a normal remote prover can improve performance, but it is still trusted with witness material
- a true split-prover design can reduce witness exposure to the proving service, but it requires protocol work and circuit-aware implementation

So phase 1 should not market a remote prover as equivalent to split-prover security.

## Phased Plan

### Implemented: Trusted Prover Service And Runtime Hot Paths

`xian-zk` now has an authenticated local-loopback prover service with matching
client classes.

Purpose:

- let wallets offload proof generation to a desktop companion or local daemon
- keep validator semantics unchanged
- prepare a stable proving API that later split-prover work can target

Security model:

- trusted local service only
- bind to `127.0.0.1` by default
- require an auth token when enabled
- document clearly that witness material is exposed to the service

This implementation round also added native shielded tree append and
relay-digest helpers exposed through the runtime `zk` bridge.

### Implemented: Wallet Sync Privacy

Note-discovery tags and selective indexed retrieval are in place so wallets do
not need to inspect every payload. The design preserves optional disclosures and
avoids putting recipient viewing keys in cleartext in new payloads.

### Remaining: Network-Origin Privacy

Add a privacy-preserving submission layer for private transactions, likely relayer-mesh or Dandelion++ style propagation. Hidden on-chain sender is incomplete if the first peer can still identify the source.

### Remaining: Batch Verification

When shielded transaction volume is high enough, add block-local aggregation or batch verification so validator work scales better than one independent pairing-check path per transaction.

### Remaining: Split Prover

Add a real split-prover protocol for Xian wallets. This is the first phase that can claim witness-exposure reduction against the proving service itself.

### Remaining: Accumulator Redesign

Evaluate whether Xian should eventually move from the current append-only note-root model toward a larger-anonymity-set global membership design such as Curve Trees or related constructions.

## Implemented Scope

The current implementation covers the first practical runtime and wallet
tooling slice needed to make shielded fees usable:

- authenticated prover service in `xian-zk`
- client classes for shielded note, command, and relay proving
- CLI entrypoint to run the service
- tests that prove requests can round-trip through the service
- native shielded tree append / relay-digest helpers exposed through the runtime
  `zk` bridge
- benchmark harness for shielded chi comparison

It does **not** claim:

- untrusted proving
- split-prover security
- network-origin privacy
- batch verification

## Follow-Up Metrics

Keep measuring:

- proof latency on desktop local native path
- proof latency through the local prover service
- wallet-side UX for browser/mobile shielded flows
- CPU and memory profile of the companion prover

## References

- Firo research and Spark roadmap
- Split Prover Zero-Knowledge SNARKs (PKC 2025 / ePrint 2025/373)
- Aztec note discovery and indexed nullifier tree design
- Curve Forests / Curve Trees research
- Dandelion++
