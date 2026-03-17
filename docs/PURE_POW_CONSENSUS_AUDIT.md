# Pure PoW Consensus Audit Report

**Project:** BitcoinPoW-unified  
**Scope:** Consensus-critical code paths affecting Proof-of-Work validation, chain selection, and hybrid PoW/PoS transition  
**Date:** 2025-03-17

---

## Executive Summary

This audit reviews the consensus layer of BitcoinPoW-unified, with focus on Pure PoW behavior (blocks 0–10 and the correctness of PoW validation wherever it applies), chain work computation, difficulty adjustment, and the PoW/PoS boundary. The codebase implements a **hybrid** consensus: PoW only up to `nLastPOWBlock` (10), then PoS-only with shared nBits/difficulty and chain work. Several **high-** and **medium-severity** issues were found (debug output in consensus path, missing difficulty-bound checks, and reliance on global chain state in PoS kernel check). Recommendations are provided to harden consensus and prepare for mainnet.

---

## 1. Architecture Overview

### 1.1 Block types and transition

- **Proof-of-Work:** `nNonce` not in `{0xFEEDBEEF, 0xFEEDBEE1, 0xFEEDBEE2}`. Valid only for `height <= nLastPOWBlock` (10).
- **Proof-of-Stake:** `nNonce` in `{0xFEEDBEEF, 0xFEEDBEE1, 0xFEEDBEE2}`. Rejected for `height <= nLastPOWBlock`; before `COINBASE_MATURITY(nHeight)` PoS is also rejected in header acceptance.
- **Consensus params:** `nLastPOWBlock = 10`, `COINBASE_MATURITY(n)` = 2 for `n < BITCOIN_POW256_START_HEIGHT` (23333), else 6. So PoS is allowed from height 11; no gap.

### 1.2 Validation pipeline (relevant to PoW)

1. **AcceptBlockHeader** → nNonce/fork checks, PoW rejection above `nLastPOWBlock`, **CheckBlockHeader** (PoW hash vs nBits).
2. **ContextualCheckBlockHeader** → **GetNextWorkRequired** (nBits), timestamps, version.
3. **AcceptBlock** → **CheckBlock** (header PoW again, merkle, tx basic checks, optional PoS sig).
4. **ConnectBlock** → PoW/PoS type vs height, **CheckHeaderPoW** / **CheckHeaderPoS**, **UpdateHashProof** (nBits + PoW/PoS proof), script checks, BIP30, subsidy, etc.

PoW is enforced in:

- `CheckBlockHeader()` → `CheckHeaderPoW()` → `CheckProofOfWork(block.GetHash(), block.nBits, consensusParams)`.
- `ContextualCheckBlockHeader()` → `block.nBits == GetNextWorkRequired(pindexPrev, &block, consensusParams)`.
- `ConnectBlock()` → `CheckHeaderPoW(block)` again; `UpdateHashProof()` enforces nBits and, for PoW, sets `hashProof = block.GetHash()`.

---

## 2. Findings

### 2.1 CRITICAL / HIGH: Debug output in consensus path

**Location:**  
- `validation.cpp` lines 4181, 4186, 4191: `std::cout` in AcceptBlockHeader when nNonce does not match fork height.  
- `pos.cpp` line 155: `std::cout << "actual: " << actual.ToString() << std::endl;` in CheckStakeKernelHash.  
- `kernel/chainparams.cpp` line 532 (and similar): `std::cout << "time: " << nTime` in genesis search loop.

**Impact:**  
- Consensus path must be deterministic and free of observable side effects. Console output can change behavior in constrained/embedded environments and is not acceptable in consensus code.  
- In validation, this is triggered on invalid blocks; in pos.cpp it is on the success path of a valid kernel check.

**Recommendation:**  
Remove all `std::cout` (and any other debug I/O) from:  
- `validation.cpp` AcceptBlockHeader,  
- `pos.cpp` CheckStakeKernelHash,  
- `kernel/chainparams.cpp` genesis loops.  
Use `LogPrint`/`LogPrintf` only for non-consensus logging if needed.

---

### 2.2 HIGH: PermittedDifficultyTransition is a no-op

**Location:** `pow.cpp` lines 147–151:

```cpp
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    return true;
}
```

**Impact:**  
No limit on how much difficulty can change in one step. LWMA3 in this codebase clamps the next target to ±50% and 94–106% in certain conditions, but a future change or a different code path could produce an extreme transition. Bitcoin Core and many forks enforce a maximum per-retarget step (e.g. 4x) to avoid time-warp or bugs from yielding a sudden jump.

**Recommendation:**  
Implement a real bound (e.g. `new_nbits` may not differ from `old_nbits` by more than a factor of 4 in work) and call it from any path that assigns a new nBits for the next block. Optionally add unit tests that assert permitted/rejected transitions.

---

### 2.3 MEDIUM: Chain work from PoS blocks uses same formula as PoW

**Location:** `chain.cpp` GetBlockProof(), `node/blockstorage.cpp` nChainWork update.

**Observation:**  
`GetBlockProof(block)` uses only `block.nBits`: `(~bnTarget / (bnTarget + 1)) + 1`. There is no distinction between PoW and PoS blocks. So PoS blocks add to chain work exactly like PoW blocks with the same nBits.

**Impact:**  
- Design choice: if PoS and PoW share the same nBits schedule (as in this code), then using the same work formula keeps chain selection consistent (most “work” wins).  
- If in the future PoS used a different nBits meaning (e.g. posLimit), then PoS blocks could contribute disproportionately to nChainWork and could be used to outcompete honest PoW chains.  
- Current design (shared nBits, same limit in practice for the PoS phase) is consistent; the risk is future change without updating GetBlockProof.

**Recommendation:**  
Document that chain work is intentionally unified for PoW and PoS. If PoS ever gets a separate difficulty limit or encoding, introduce a separate proof metric for PoS or bound its contribution so that chain selection cannot be gamed.

---

### 2.4 MEDIUM: LWMA3 uses mixed PoW/PoS window

**Location:** `pow.cpp` Lwma3CalculateNextWorkRequired().

**Observation:**  
For `height > 10`, the next nBits is computed from the last N=45 blocks by height (`pindexLast->GetAncestor(i)`). No filtering by proof type: both PoW and PoS blocks are included. After block 10, all blocks in the window are PoS, so effectively LWMA3 is retargeting based on PoS block timestamps and nBits.

**Impact:**  
- For the PoS-only phase this is consistent.  
- For the first few PoS blocks (e.g. 11–55), the window includes PoW blocks; solvetime and nBits mix PoW (10 min target) with PoS (faster target). The comment “For 600 nPoSTargetSpacing” suggests the algorithm is tuned for 600s spacing; mixing with 10 min PoW may cause a brief retarget quirk.  
- GetLastBlockIndex(pindex, fProofOfStake) exists but is **not** used in GetNextWorkRequired or Lwma3. So there is no “PoW-only” difficulty for the hybrid segment if you ever wanted it.

**Recommendation:**  
- If the intended design is “single difficulty schedule for the whole chain,” document it and consider whether the first N blocks after the transition should use a different rule (e.g. PoW-only window for the first block after nLastPOWBlock).  
- If the chain were to support both PoW and PoS blocks concurrently in the same window, define how each type contributes to the next nBits and add tests.

---

### 2.5 MEDIUM: PoS kernel validation depends on active chain

**Location:** `pos.cpp` CheckStakeKernelHash(), lines 117, 126, 141–146.

**Observation:**  
For height >= BITCOIN_POW256_START_HEIGHT (23333), the kernel hash uses:

- `int h = ChainActive().Height();`  
- `auto& chain_active = gp_chainman->m_active_chainstate->m_chain;`  
- `chain_active[h-a]->...`, `chain_active[h-b]->...`, etc., with a,b,c,d,e,f,g derived from the hash.

**Impact:**  
- Validation depends on **which chain is currently active**, not solely on the block’s ancestor chain. During a reorg or when validating a side chain, the “active” tip may differ from the block’s chain. That can make the same block valid or invalid depending on context, i.e. **consensus non-determinism**.  
- If a node receives two competing chains, the outcome of PoS kernel check could depend on which chain was applied last, opening the door to reorg or split-view bugs.

**Recommendation:**  
- Replace `ChainActive()` and `gp_chainman->m_active_chainstate->m_chain` with the chain implied by `pindexPrev` (e.g. walk from `pindexPrev` back by indices derived from the hash).  
- Ensure all inputs to the kernel hash are from the block’s own chain (e.g. `pindexPrev->GetAncestor(h - a)`, etc.) and that bounds checks prevent out-of-range access.  
- Add tests that validate the same block in the context of different “active” tips and ensure the result is unchanged.

---

### 2.6 LOW: Redundant CheckBlockHeader in AcceptBlock

**Location:** `validation.cpp` AcceptBlock(): CheckBlockHeader is called inside CheckBlock(), and CheckBlock is called from AcceptBlock. AcceptBlockHeader (called earlier) already ran ContextualCheckBlockHeader (which includes the nBits check) and the block is in the index. So CheckBlock (and thus CheckBlockHeader) is redundant for header checks when AcceptBlockHeader has already been used.

**Impact:**  
No correctness issue; minor redundancy and a small performance cost.

**Recommendation:**  
Optional: document or refactor so that when a block is accepted via the normal path (header first, then body), header checks are not repeated in CheckBlock for that path. Care must be taken not to skip checks for other code paths that call CheckBlock directly.

---

### 2.7 LOW: CheckIndexProof skips PoS kernel for loaded blocks

**Location:** `validation.cpp` CheckIndexProof(), lines 6452–6464.

**Observation:**  
For PoS, the function returns true without calling CheckKernel, with the comment “blocks are loaded out of order, so checking PoS kernels here is not practical.”

**Impact:**  
Block index consistency checks do not re-validate PoS kernel. If ConnectBlock/UpdateHashProof had a bug that wrote a bad hashProof, or if the index were corrupted, CheckBlockIndex would not detect it. Risk is limited because full validation in ConnectBlock/UpdateHashProof is the authority.

**Recommendation:**  
Either document that PoS kernel is intentionally not re-checked in CheckBlockIndex, or add an optional strict mode that re-runs kernel check when block order allows it (e.g. when the block’s previous block is already in the index and UTXO set is available).

---

## 3. Positive Observations

- **PoW rejection above nLastPOWBlock** is enforced in multiple places: AcceptBlockHeader, AcceptBlock, ConnectBlock, UpdateHashProof. Consistent and defense-in-depth.
- **PoS rejection at or before nLastPOWBlock** is similarly enforced in ConnectBlock and AcceptBlock.
- **CheckProofOfWork** correctly checks compact nBits range (no negative/overflow), compares hash to target, and enforces powLimit.
- **GetBlockProof** is used consistently for nChainWork; monotonicity (parent work + block proof) is asserted in CheckBlockIndex.
- **ContextualCheckBlockHeader** enforces nBits via GetNextWorkRequired before the block is added to the index, so invalid nBits cannot grow the chain.
- **Subsidy** (GetBlockSubsidy) is standard (50 COIN, halvings every nSubsidyHalvingInterval); no extra inflation found in consensus.
- **Merkle and witness** checks (CVE-2012-2459 style, witness commitment) are present; BIP30 and coinstake structure (prevoutStake vs coinstake, first coinstake output) are enforced.

---

## 4. Summary Table

| Severity | Finding | Recommendation |
|----------|---------|-----------------|
| High | Debug std::cout in consensus (validation, pos, chainparams) | Remove; use LogPrint if needed |
| High | PermittedDifficultyTransition always true | Implement real difficulty step bound |
| Medium | GetBlockProof same for PoW/PoS | Document; revisit if PoS encoding diverges |
| Medium | LWMA3 mixes PoW/PoS in window | Document or restrict window by proof type |
| Medium | PoS kernel uses ChainActive() / global chain | Use pindexPrev-based chain only |
| Low | Redundant CheckBlockHeader in AcceptBlock | Optional refactor |
| Low | CheckIndexProof skips PoS kernel | Document or add optional strict check |

---

## 5. Conclusion

The Pure PoW phase (blocks 0–10) is clearly bounded and enforced in several layers. PoW validation (hash vs nBits, nBits vs GetNextWorkRequired, powLimit) is implemented correctly. The main risks are: (1) **consensus path pollution** (debug output), (2) **no difficulty step bound** (PermittedDifficultyTransition), and (3) **PoS kernel depending on the active chain** (ChainActive/gp_chainman), which can cause non-deterministic validation across reorgs. Addressing these three items is strongly recommended before treating the consensus layer as production-hardened. The remaining items are documentation or optional hardening.

---

*End of report.*
