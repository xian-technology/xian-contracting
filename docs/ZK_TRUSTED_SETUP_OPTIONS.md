# ZK Trusted Setup — does Xian need one, and can it be removed?

Status: **decision record / options analysis**
Context: follow-up to the shielded-hash redesign ([SHIELDED_HASH_REDESIGN.md](SHIELDED_HASH_REDESIGN.md)).

## Does the current implementation need a trusted setup?

**Yes.** The shielded circuits are proved with **Groth16** (`ark-groth16`). Groth16
requires a **per-circuit trusted setup** that turns the circuit into a proving key
and a verifying key using secret randomness ("toxic waste"). Anyone who learns the
toxic waste for a circuit can forge proofs for it — i.e. **counterfeit shielded
value**. This is intrinsic to Groth16, independent of the hash fix.

Today the setup is generated single-party (`build_random_*`, OS-rng) or
deterministically for tests (`build_insecure_dev_*`, fixed seed). Neither is safe
for mainnet: in both, one party holds (or can recompute) the toxic waste.

The hash binding fix (Poseidon) and the verifier soundness (subgroup checks,
canonical inputs) are **orthogonal** to this — they're correct regardless of the
proving system.

## Can the trusted setup be removed?

**Not while staying on Groth16.** Removing it means changing the proving system.
Three realistic directions, with the trade-offs that matter for an L1 where
**every validator verifies every shielded transaction under chi metering**:

### Option A — Keep Groth16, run a real MPC ceremony (recommended near-term)
- The setup stays, but its trust drops to **"1-of-N participants honest"** — the
  industry standard (Zcash Sapling, Tornado Cash, most zk-rollups).
- Keeps Groth16's decisive on-chain advantages: **~128–200 byte proofs** and
  **~3-pairing verification** — the cheapest to verify in consensus.
- Cost: a ceremony per circuit. Mitigate by **unifying circuits** (see below) so
  there are fewer setups.
- Effort: low (code already done); operational (run the ceremony, register keys).

### Option B — Universal/updatable setup (Marlin or PLONK) (best "remove the pain")
- One **universal SRS** reusable across *all* circuits and future upgrades; you
  can even reuse an existing public SRS (perpetual Powers of Tau / Aztec
  Ignition), so you may not have to run a ceremony at all.
- Removes **per-circuit toxic waste** and lets you add/modify circuits without new
  ceremonies.
- `ark-marlin` is R1CS-based, so the existing `ConstraintSynthesizer` circuits
  port over with limited rework.
- Cost: larger proofs (~hundreds of bytes–~1 KB) and somewhat more expensive
  verification than Groth16 — still succinct, still on-chain-practical.
- Effort: medium (swap proving/verifying layer, re-bench chi costs, keep Poseidon
  + circuits).

### Option C — Transparent setup, i.e. none at all (Halo2-IPA / STARK / Spartan / Nova)
- **No trusted setup ever.**
- Cost: materially larger proofs and/or more expensive verification (STARKs: tens–
  hundreds of KB; Bulletproofs/IPA: log-size but slow verify). On an L1 that meters
  verification per node, this is a real throughput/chi hit. Largest reimplementation
  effort (different proving stack; arkworks R1CS doesn't drop into Halo2; Spartan is
  R1CS+transparent but less battle-tested here and costs more to verify than Groth16).
- Effort: high. Usually not worth it for a privacy-token use case Groth16/Marlin
  already serve.

## Recommendation

1. **Near-term:** stay on Groth16 and do an **MPC ceremony** before mainnet
   (Option A). Cheapest verification, well-understood trust.
2. **If eliminating ceremonies is a priority:** migrate to **Marlin** (Option B) —
   one reusable universal SRS, R1CS circuits carry over, still succinct on-chain.
   This is the sweet spot between "no per-circuit toxic waste" and "cheap on-chain
   verification."
3. **Transparent (Option C):** only if removing *all* setup trust outweighs a large
   verification-cost and rewrite budget.

Either way the toxic-waste risk should also be reduced structurally:

- **Unify circuits.** There are currently separate deposit / transfer / withdraw /
  command circuits, each needing its own Groth16 setup. A single parameterized
  "shielded transaction" circuit (input/output counts + flags) would cut the number
  of ceremonies (Option A) or proving keys (Option B) to one and shrink the trusted
  surface.
- Keep the registry **governance-owned** (already supports two-step transfer) and
  record real `setup_ceremony` provenance for every registered key.

## What this does *not* change

The Poseidon hash, the binding/value-conservation circuit logic, the verifier's
curve/canonical-input checks, and the consensus-time verification path are all
independent of the setup choice and remain as implemented.
