# Monolythium v2 — Post-Quantum Consensus Signatures: Design Options

**Status:** Design exploration / decision memo
**Scope:** Replacing the classical BLS12-381 anchor-tier aggregate with a *fully* post-quantum
signature so finality is quantum-safe in **real time**, not only at the ~5-minute ML-DSA checkpoints.
**Audience:** Monolythium v2 consensus + cryptography team, and the follow-up agent researching the v2 codebase.

> ⚠️ This document was written against `prototype-ecosystem/protocore` (the Prototype Network / ProtoBFT
> reference node), which is the closest available stand-in. The Monolythium v2 codebase was **not**
> available in the authoring environment. All references to v2 specifics come from the v5.0 whitepaper,
> not from v2 source. Verify against the real code.

---

## 1. Goal & motivation

The v5.0 design secures finality in two tiers:

- **Anchor finality** via **BLS12-381** threshold aggregation ("Starfish-C"), 3-second deterministic finality.
- **Quantum-attested finality** via **ML-DSA-65** checkpoints every ~100 anchors (~5 min).

The whitepaper explicitly acknowledges a **"bounded classical residual"**: between checkpoints, finality
rests on BLS12-381, which a quantum adversary can forge. The goal of this work is to **eliminate that
residual** by making the anchor-tier signature itself post-quantum, so every anchor — not just every
100th — is quantum-safe. The ML-DSA checkpoints then become defense-in-depth rather than the sole
quantum guarantee.

This is a **drop-in replacement for the BLS aggregate inside the finality certificate**, not a redesign
of consensus. The certificate shape to preserve is the accountable-subset multisignature already in use:
an aggregate signature plus a `signers_bitmap` over the active set (cf. `FinalityCert` in
`crates/types/src/block.rs` and `crates/consensus/src/types.rs` in protocore).

---

## 2. Constraints (from the v5.0 design + operator input)

| Constraint | Value |
|---|---|
| Anchor cadence | ~3 s (≈10.5M anchors/year) |
| Active signing operators | ~700 (100 clusters × 7-of-10 threshold; 300 standby) |
| **Storage ceiling** | **≤ 10 TB / year** of consensus-signature data (hard limit) |
| Membership | **Dynamic** — liquid bonding, operators join/exit over time |
| GPU provers | Mandatory ≥1 per cluster, but specified as an **application-layer** service tier (SP1 zkVM + Groth16-BN254), **not** on the consensus path in v5.0 |
| User/tx signatures | ML-DSA-65 (FIPS 204), stateless — unchanged |

### Why the naive path is ruled out

**ML-DSA-65 per operator, no aggregation** (700 × 3,309 B ≈ 2.3 MB/anchor) ⇒ **~24 TB/year**
(~14 TB even with sequential half-aggregation). **Exceeds the 10 TB ceiling.** Rejected.

This leaves two viable options, both under the ceiling, detailed below.

---

## 3. Option A — Chipmunk (native lattice synchronized multisignature)

**Scheme:** Chipmunk (CCS 2023, ePrint 2023/1820), the successor to Squirrel (CCS 2022, ePrint 2022/694).
Synchronized, non-interactive, rogue-key-secure lattice multisignature based on the hardness of
**SIS** in a polynomial ring (ROM). Reference implementations exist
(`github.com/GottfriedHerold/Chipmunk`, `github.com/zhenfeizhang/squirrel`) but it has **never been
deployed in production**.

### 3.1 Sizes & load (≈700 signers, 3 s anchors)

| Metric | Value |
|---|---|
| Aggregate cert | ~50 KB (log-scaling in signer count) |
| **Storage / year** | **~0.5 TB** ✅ (well under 10 TB) |
| Verification | ~5–20 ms/anchor (matrix ops; cheap) |
| Cert bandwidth | ~0.1 Mbps sustained (light for all nodes) |
| **Prover on critical path?** | **No** |
| Per-operator key state | ~100 MB+ working cache + counter (stateful) |

### 3.2 How it works (mental model)

- Each operator generates **one keypair = a tree of 2^τ one-time leaf keys**. The public key is a single
  constant ~1 KB root that never changes.
- A **"slot"** is an index in a synchronized counter shared by all signers. Natural mapping:
  **slot = block/anchor height** (a global clock). Leaf *N* signs height *N*.
- **Each leaf signs exactly one slot, then is burned.** Forward-only.
- On disk the operator stores **`seed + current-counter + ~100 MB precomputed cache`** — not millions of
  literal keys. The cache makes signing fast (Squirrel: ~68 ms sign with a 112 MB cache).
- τ sizing at 3 s/slot: τ=26 ≈ **6.4 years**, τ=28 ≈ **25 years** of leaves (larger τ ⇒ larger cache).

### 3.3 THE critical safety invariant

> **A single leaf must never sign two *different* messages.** Doing so leaks the secret (same algebra as
> ECDSA nonce reuse): an observer can recover the secret short vector and forge that operator's signatures.

Failure modes that violate it (all ⇒ ☠️ key compromise + slashing):

| Path | Mechanism | Mitigation |
|---|---|---|
| **Rollback / stale restore** | Counter moves backward → re-signs a used slot with a new block | State advanced **monotonically + persisted before signature release**; no restoring stale snapshots |
| **Hot standby / failover** | Two machines sign the same slot on different blocks | **Exactly one active signer per key**, ever |
| **Crash mid-update** | Counter and key-tree desync | Atomic, durable state advance (WAL-style) before release |
| **Cross-chain reuse** | Leaf N signs testnet-block-N *and* mainnet-block-N | **Domain-separate keys by chain-id/genesis hash at generation**; never copy the consensus key file across chains |
| **Regenesis** | Height resets to 0 → old leaves re-signed | Treat regenesis as **mandatory re-key**; genesis-hash binding makes the new tree automatically distinct |
| **Tree exhaustion** | Run out of leaves after 2^τ slots | **Scheduled epoch-tied re-key with margin** + exhaustion monitoring |

Note: pure **replay** (rebroadcasting an *existing* signature on the *same* message) is **not** a leak —
it's the same signature, no new information. The danger is strictly *two different messages, one leaf*.

### 3.4 BFT-round subtlety

`slot = height` assumes **one signature per height**. BFT can have multiple rounds at the same height
(re-proposals on timeout). Either:
- map slots to **(height, round)** (bigger tree, faster exhaustion), or
- ensure each leaf signs **only one canonical message per height** (e.g. the precommit on the decided
  block only), so re-proposals never trigger a second signature from the same leaf.

**Decision required.**

### 3.5 Dynamic membership (the hard, novel part for Monolythium)

Chipmunk's textbook setting is a roughly *fixed* signer set with pre-generated trees. Monolythium's
liquid bonding + late-joining operators push it outside that setting:

- **"Bind to chain" ≠ "generate at genesis."** Keys are domain-separated by the **constant** chain-id /
  genesis hash, available to anyone joining at any time. Late joiners are fine.
- **Generate-on-activation:** an operator generates its tree when bonded/activated at epoch E / height H,
  anchored to start at H, and registers its pubkey (extends the existing dynamic-validator-set + epoch
  machinery; cf. `validator_set_hash` / `next_validator_set_hash`).
- **Bonding ≠ keys.** Liquid bonding moves *stake*; the consensus key belongs to the **operator seat**
  (700 active + 300 standby), which changes only on seat join/exit/rotation (epoch-bounded, rare).
  High-frequency delegation flows do **not** churn keys.
- **Per-epoch aggregation + rogue-key re-binding.** Aggregation is over *that epoch's* active set, keyed by
  `validator_set_hash`. The rogue-key defense (linear key-binding / hash-to-matrix) must **re-bind on every
  set change**, not once. This is where rogue-key attacks sneak in if membership changes are mishandled.

### 3.6 Validator wallet transactions

The validator's **wallet** signs transactions with its **stateless ML-DSA-65 account key** — *not* the
Chipmunk tree. The evolving tree is used **only** for consensus block-signing. (Signing arbitrary
transactions with the evolving key would reuse leaves on arbitrary messages → instant leak.)

### 3.7 Risk summary

- ✅ Leanest (~0.5 TB/yr), cheap verify, light bandwidth, **provers stay app-layer**.
- ❌ **Never deployed** — needs serious hardening + independent audit; you would be first.
- ❌ **Stateful keys** — entire ☠️ failure class above; requires real operator key-lifecycle tooling.
- ❌ **Used outside its textbook (fixed-set) regime** — dynamic membership adds audit scope.

---

## 4. Option B — SNARK/STARK-aggregated post-quantum signatures

**Scheme:** Operators sign with stateless **ML-DSA-65**; a prover generates a succinct proof that
*K valid ML-DSA-65 signatures over the anchor exist*, producing a constant-size consensus certificate.

### 4.1 Sizes & load (≈700 signers, 3 s anchors)

| Metric | Value |
|---|---|
| Aggregate cert | ~100 KB (**constant** in signer count) |
| **Storage / year** | **~1 TB** ✅ (under 10 TB) |
| Verification | ~ms (proof verification; cheap) |
| Cert bandwidth | ~0.3 Mbps sustained (light) |
| **Prover on critical path?** | **Yes** — must prove ~700 ML-DSA verifications within the 3 s anchor budget |
| Per-operator key state | None (stateless ML-DSA-65) |

### 4.2 Critical design points

- **Must be a PQ proof system (STARK / FRI).** v5.0's app-layer stack ends in **Groth16-BN254**, which is
  **pairing-based and NOT post-quantum**. Wrapping in Groth16 to shrink the cert would *re-introduce* a
  classical break — defeating the entire purpose. The consensus proof must remain hash-based (FRI) end to
  end. This is a **departure from v5.0's "SNARK ≠ consensus" firewall.**
- **Prover liveness becomes a consensus dependency.** With a PQ-STARK on the critical path, finality
  liveness depends on producing the proof in <3 s. Mandatory per-cluster GPU provers help, but they were
  specified as an app-layer service tier — repurposing them for consensus is a real architectural change.
  Mitigate with **intra-cluster GPU redundancy** and/or **hierarchical proving** (each cluster proves its
  own members → recursive combine), which also keeps per-prover circuits small enough to fit the slot.
- **Stateless keys** — none of Option A's rollback/replay/exhaustion footguns. This is its big advantage.

### 4.3 The catch at this scale

At **~700 signers**, the STARK's "constant size" earns little: its proof-size *floor* (~100 KB) is
actually **larger** per-cert than Chipmunk's ~50 KB aggregate, while adding a prover on the critical path.
The O(1) advantage only pays off at **many thousands** of signers. So Option B is the right call *only if*
Monolythium expects to scale well beyond 700 active signers, or if eliminating stateful keys is judged
worth the prover complexity.

### 4.4 Risk summary

- ✅ **Stateless keys** (standardized ML-DSA-65) — no key-lifecycle footguns.
- ✅ Conservative PQ basis (hash-based FRI + ML-DSA).
- ❌ **Highest engineering cost** — build/operate a PQ-STARK circuit for ML-DSA verification + GPU prover infra.
- ❌ **Prover on the 3 s critical path** ⇒ new liveness dependency; needs redundancy/hierarchy.
- ❌ At 700 signers, **larger cert than Option A** and no size payoff until much larger scale.

---

## 5. Side-by-side

| Dimension | **Option A: Chipmunk** | **Option B: STARK-aggregated** |
|---|---|---|
| Cert size | ~50 KB | ~100 KB (constant) |
| **Storage / year** | **~0.5 TB** | ~1 TB |
| Difficulty | High (stateful key lifecycle) | Very High (PQ-STARK + prover infra) |
| Quantum basis | SIS lattice (ROM, unstandardized) | Hash-FRI + ML-DSA (conservative) |
| Keys | Stateful, key-evolving ☠️-sensitive | **Stateless ML-DSA-65** |
| Prover on critical path | **No** | **Yes** (3 s budget) |
| Load lands on | 700 operators (key state) | GPU provers |
| Scales past 700 signers | Cert grows (log) | Cert stays constant ✅ |
| Maturity | Ref code only, never deployed | Components exist; consensus integration novel |
| Main failure class | Leaf reuse → key leak | Prover liveness / latency |

---

## 6. Recommendation

For Monolythium's **current** scale (~700 operators, ≤10 TB/yr) and the desire to keep GPU provers
app-layer per v5.0:

1. **Lead with Option A (Chipmunk)** — leanest storage, cheapest verification, and it keeps provers off
   the consensus critical path. The dominant risk is *operator key lifecycle*, which is bounded by the
   professional-operator model (bonded seats, slashing, standby).
2. **Choose Option B (STARK)** only if (a) you expect to scale to many thousands of active signers, where
   constant-size finally pays off, or (b) the stateful-key operational risk is judged unacceptable and you
   prefer to pay it down with prover infrastructure instead.

Either way, **the math is the easy 20%**; the hard 80% is the operator/membership lifecycle (Option A) or
the prover/critical-path engineering (Option B).

---

## 7. Open questions for the v2 code research

1. **Certificate shape:** Where is the BLS aggregate produced/verified in v2 ("Starfish-C")? What is the
   exact `FinalityCert`/anchor-cert struct and its serialization? (protocore analogues:
   `crates/types/src/block.rs:492`, `crates/consensus/src/types.rs:351`.)
2. **Slot vs round:** Can a height have multiple BFT rounds requiring multiple signatures from one operator?
   (Decides §3.4 slot↔(height,round) mapping.)
3. **Validator-set rotation:** How are operator seats activated/exited per epoch, and where is
   `validator_set_hash` computed? (Decides §3.5 generate-on-activation + per-epoch aggregation.)
4. **Re-key hooks:** Are there existing epoch/rotation hooks where consensus-key rotation could be attached?
5. **Regenesis runbook:** Does v2 have a regenesis procedure that must force consensus re-keying?
6. **Prover tier:** Are the per-cluster GPU provers PQ-capable (STARK/FRI), or only the SP1+Groth16
   app-layer stack? (Decides feasibility of Option B without re-tooling.)
7. **Scale trajectory:** Is the active signer count expected to stay ~700, or grow into the thousands?
   (Decides whether Option B's constant size ever pays off.)

---

## 8. References

- Chipmunk — ePrint 2023/1820; code: github.com/GottfriedHerold/Chipmunk
- Squirrel — ePrint 2022/694; code: github.com/zhenfeizhang/squirrel
- Compact Aggregate Signature from Module-Lattices — ePrint 2023/471
- Sequential Half-Aggregation of Lattice-Based Signatures — ePrint 2023/159
- HAPPIER (hash-based, SNARK-aggregatable) — CRYPTO 2025
- Hash-Based Multi-Signatures for Post-Quantum Ethereum — ePrint 2025/055
- ML-DSA — FIPS 204
- Monolythium Whitepaper v5.0 (2026/may)
