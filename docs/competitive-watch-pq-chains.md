# Competitive Watch — Post-Quantum L1 Chains

**Last updated:** 2026-06-03
**Purpose:** Track competitors in the post-quantum L1 space so Monolythium can word "first/only/best"
claims defensibly and avoid being blindsided.

> ⚠️ **Sourcing caveat:** Most of this is assembled from press releases, syndicated coverage, and
> third-party review aggregators — **not** primary technical docs (several competitor sites/whitepapers
> blocked automated fetch). Treat every "claim" column as *the project's own assertion*, not verified
> fact. Re-verify against primary sources before relying on any line for marketing or strategy.

---

## Summary table

| Project | Stage (as of 2026-06) | Sig primitive | PQ **consensus**? | PQ **transport**? | PQ mempool? | Legitimacy signal |
|---|---|---|---|---|---|---|
| **Monolythium** | (verify: mainnet?) | ML-DSA-65 | ✅ real-time | ✅ ML-KEM-768 | ✅ claimed | Named/auditable? CI-enforced (verify) |
| **Naoris Protocol** | **Mainnet live** (Apr 2026, invite-only) | **ML-DSA-87** (L5) | ✅ "secures consensus, not just app layer" (claim) | ✅ KEM (claim) | ? | VC-backed, heavy PR; dPoSec model |
| **Cellframe** | **Mainnet since Mar 2022** | Dilithium + Picnic | ✅ (claim) | ✅ PQ encryption (claim) | ? | Long-running, listed token |
| **QANplatform** | Testnet live (Jul 2025); mainnet transition claimed | Dilithium / ML-DSA | ✅ hybrid PoS (claim) | ? | ? | Named entity, EVM-compatible, **cluster+checkpoint model** |
| **Asentum** | **Testnet** (Apr 2026); presale running | ML-DSA-65 | ✅ ~100-validator BFT committee | ❓ none found | ❓ none found | ⚠️ **anonymous team, no audit, presale-first, paid-wire PR** |
| **Autheo** | Mainnet claimed (May 13 2026) | "quantum security" (unspecified) | ? | ? | ? | Press-release grade; low detail |
| **QRL** | **Mainnet since 2018** | XMSS (hash-based) → SPHINCS+ | ✅ full-stack sigs | ❓ | ❌ | Genuine pioneer; ~$83M cap, rank ~#215–330 |
| **Algorand** | Mainnet | Falcon (lattice) | ❌ consensus VRF classical | ❌ | ❌ | Major L1; PQ *transactions* + state proofs only |
| **Solana** | Testnet (Dilithium vault) | Dilithium | ❌ consensus classical | ❌ | ❌ | Major L1; early PQ work |
| **Ethereum** | Roadmap / devnets | hash-based (leanXMSS) + SNARK | 🚧 in progress | ❌ | ❌ | Largest; years out, EF PQ team (Jan 2026) |

---

## Per-project notes

### Naoris Protocol — the most direct threat to "first"
- **Live mainnet since ~April 2026** (invite-only: strategic partners, investors, validator operators).
- Claims **ML-DSA-87 (Security Level 5)** per validator node, explicitly **"securing the consensus
  process, not just the application layer"** — i.e. the *exact* headline Monolythium would use, at a
  *higher* security level, **already live**.
- Uses a "dPoSec" (delegated Proof of Security) consensus that rewards anomaly/device-integrity detection.
- Mentions KEM for transport. Testnet processed 100M+ PQ transactions per their PR.
- **Implication:** Naoris alone kills any unqualified "first ML-DSA consensus" claim.

### Cellframe — the oldest PQ mainnet
- **PQ mainnet since March 2022**, Dilithium + Picnic signatures, "quantum-resistant from the ground up."
- Predates NIST standardization (used Dilithium pre-FIPS-204).
- **Implication:** any "first post-quantum consensus / first Dilithium chain" claim is refuted by a chain
  that's been live for ~4 years.

### QANplatform — architecturally closest to you
- Dilithium-based **hybrid PoS**, EVM-compatible (MetaMask ML-DSA signing via "XLINK").
- **Public validators + permissioned clusters (~3,000 TPS) that anchor to the public ledger via a single
  checkpoint** — a cluster+checkpoint structure conceptually similar to Monolythium's clusters + ML-DSA
  checkpoints. Worth studying.
- Testnet live July 2025; mainnet "transition" claimed but verify.

### Asentum — newest, same trade-off, shakiest profile
- **Testnet only** (Apr 2026), token presale running ahead of mainnet.
- ML-DSA-65 for tx + consensus; **~100-validator rotating BFT committee** — same small-committee trick as
  Monolythium (no novel aggregation; sidesteps the problem identically).
- **No public evidence** of PQ transport, PQ mempool, or PQ VRF — "every layer" appears unsubstantiated.
- ⚠️ Red flags: **anonymous team, no published audit, presale-first, paid-wire PR**. Reviewers rate it
  "watchlist only." Differentiator is JavaScript smart contracts, not full-stack PQ depth.

### QRL / Algorand / Solana / Ethereum
- **QRL:** genuine full-stack PQ (hash-based) since 2018; most conservative assumption; small market cap.
- **Algorand/Solana:** PQ *transactions* only; consensus remains classical (Algorand's VRF leader
  selection is explicitly not future-proof).
- **Ethereum:** hash-based + SNARK aggregation, on roadmap/devnets; years from shipping.

---

## Implications for Monolythium's public claims

### ❌ Do NOT claim (refutable today)
- *"First to ship ML-DSA consensus."* → Naoris (live, ML-DSA-87) and Cellframe (Dilithium mainnet since
  2022) refute it.
- *"First post-quantum L1 / first PQ consensus."* → Cellframe (2022), QRL (2018).
- *"Only chain with PQ consensus."* → multiple live claimants.

### ⚠️ Claim only with verification + precise scope
- *"Quantum-resistant on every layer."* → only if VRF/randomness and the CI-enforcement gate are confirmed
  PQ/absent. Note Naoris and Cellframe make similar full-stack claims.
- Any *"first/only"* superlative → must be narrowed to a specific, unmatched combination and fact-checked
  against this list first.

### ✅ Likely defensible (differentiate on depth + credibility, not the headline)
- *"Real-time ML-DSA-65 finality certificates"* with the **prune-as-liveness-proof** architecture (a
  specific, technical, true claim).
- *"Full-stack PQ: ML-DSA consensus + ML-KEM transport + PQ encrypted mempool, with unsolved surfaces
  disabled rather than shipped vulnerable"* — IF that exact combination is unmatched (transport + encrypted
  mempool appear broader than most competitors' substantiated claims).
- *"Quantum resistance enforced in CI, not promised on a roadmap"* — a credibility/process claim, strong
  **if the CI gate is real** and competitors (esp. anonymous, unaudited ones like Asentum) can't match it.
- The **credibility contrast**: named/audited team + real mainnet vs anonymous, presale-first, unaudited
  competitors.

**Strategic takeaway:** the headline ("ML-DSA consensus") is now commoditized — at least Naoris, Cellframe,
QANplatform, and Asentum occupy it. Monolythium's defensible edge is **depth** (transport + mempool +
disable-don't-fake) and **credibility** (audited, transparent, CI-verified), not chronological firsts.

---

## Re-verify before quoting
- Naoris: confirm ML-DSA-87 is genuinely on the *consensus signing path* (not just validator identity).
- Cellframe / QANplatform: confirm current mainnet status and whether consensus messages (not just txs) are
  PQ-signed.
- Asentum: confirm mainnet launch + whether transport/mempool become PQ.
- All: primary technical docs over press releases.
