# ADAM Spending-Guard — Threat Model (Per-Asset Guard)

This document is the security narrative for an independent audit of the ADAM
spending-guard validator, **per-asset caps** revision. It states what the
contract guarantees, the actor/trust model, every on-chain invariant with its
enforcing clause, the attack classes considered (and the red-team evidence that
closed them), and — explicitly — what is **out of scope / knowingly accepted**.
Every invariant below maps to a line in the committed source; line references
are to `lib/guard/logic.ak` and `lib/guard/types.ak` in this repository.

- **Repo:** `adam-spending-guard`, branch `v2-per-asset-caps`. License Apache-2.0.
  This is the public audit repo for **fable** (external integrator building the
  Gero iOS wallet client).
- **Validator:** ADAM spending-guard, **Plutus V3, UNPARAMETERIZED** — one
  universal, pinnable script address for *all* guards. No `apply_params`: the
  per-user configuration lives entirely in the datum, so a client can attest a
  guard from hashes alone.
- **Toolchain:** Aiken v1.1.23+8949565, stdlib v3.1.0. Reproducible via
  `aiken build`.
- **Final hashes (reproducible):**
  - guard `scriptHash` = `ecb3ce037188879d7fea47aa5e7eb4cbb1e24479816bf439e57acbc6`
  - STT (`state_token`) `policyId` = `5c48f601de2cf0a92d20f351e89704ec85871fafff310cebc7d80704`

---

## 1. What the guard is

An opt-in, per-user **bounded-autonomy vault**. A user ("owner", holding a phone
key) deposits ADA + tokens into a UTxO at the universal guard script address,
authenticated by a one-shot **STT** NFT singleton. A delegated server-side
**agent session key** may then trade on the user's behalf — including
**autonomously SELLING** the owner-declared tokens — **without further owner
approval**, but the *ledger*, not any off-chain policy, bounds what the agent
can do:

- the agent may move at most `per_tx_cap` net **ADA** out in a single tx, and at
  most `daily_cap` net ADA over **any** trailing `window_len` interval;
- for **each** owner-declared token (`token_caps`), the agent may move at most
  that token's `per_tx` **quantity** out per tx and `daily` **quantity** over the
  same sliding window;
- **undeclared** tokens are **acquire-only** — every non-ADA, non-STT,
  non-declared input asset must remain on the continuation at ≥ its input
  quantity;
- the guarded ADA position never drops below `min_principal`;
- the STT is never re-minted or stranded on the agent branch;
- the **owner can unconditionally sweep, retune, kill, or rotate at any time with
  only their key**.

The design bounds loss by **economic conservation and owner-declared quantities,
not a destination allow-list** and **not price** (`logic.ak:1-5`). There is **no
oracle**: a fully-compromised agent controls the entire transaction, so no
counterparty/DEX-ratio can be enforced on-chain. What *is* enforced is that the
agent can never move more of any asset out of the guard than the owner declared,
can never touch an undeclared token or the STT, and can never breach the ADA
floor.

---

## 2. Actors & assets

| Actor | Key | Trust | Capability |
|-------|-----|-------|------------|
| **Owner** | phone key (`datum.owner` VKH) | trusted root | Unrestricted `OwnerSpend`: sweep, retune caps/token_caps, extend/close, kill, rotate agent |
| **Agent (session key)** | server session key (`datum.agent` VKH) | **untrusted / assume fully compromised** | Bounded `AgentSpend` only, within the on-chain caps below |
| **Gateway / runtime** | holds the encrypted session key | **untrusted** for this model | Builds + submits agent txs; cannot exceed what the validator permits |
| **Attacker** | any key ≠ owner, possibly == agent | hostile | Full control of tx construction; may hold the agent key; goal = extract value or trap funds |
| **Auditor** | — | — | Verifies the invariants below against the source |

**Assets at stake:**
1. **ADA** in the guard UTxO — bounded by `per_tx_cap` / `daily_cap` / `min_principal`.
2. **Declared tokens** (`token_caps`) — bounded, per token, by `per_tx` / `daily`
   **quantity** caps.
3. **Undeclared tokens** — fully protected: acquire-only, conserved on the
   continuation.
4. **The STT singleton** — protects the *identity* of the guard UTxO; never
   mintable/burnable/movable off the guard on the agent branch.

The core security claim is about **outbound quantity** of every class of asset.
Token *appreciation/price* is knowingly at risk (§7) — the oracle-free design
bounds quantities, not exchange rates.

---

## 3. Trust boundary

**The on-chain validator is the entire trust root.** Everything off-chain — the
gateway, the runtime, the session key, the tx builders — is assumed potentially
compromised. The audit question is precisely: *given a fully hostile holder of
the agent session key and full control of transaction construction, what is the
maximum the owner can lose, and can the owner always recover?*

Sources in scope:
- `lib/guard/logic.ak` — all decision logic (`spend_ok` and the `AgentSpend`
  path `agent_spend_ok`). The validator entry point calls into this so the
  adversarial suite exercises the exact deployed code.
- `lib/guard/types.ak` — `GuardDatum`, `AssetCap`, `SpendRecord`, `GuardRedeemer`.
- The **separate** `state_token` minting policy — the STT one-shot singleton
  invariant (see §6 and Findings F-3). **The client must also pin/trust this
  policy**; it is a distinct, audited script, out of scope for the *spending*
  validator's own guarantees.

---

## 4. Data model (`types.ak`)

`GuardDatum`, **12 fields, in CBOR constructor order** (this order is pinned by
`datum_cbor_conformance_test.ak`):

```
GuardDatum {
  owner: VKH,               // 0  owner phone key — root authority
  stt_policy: PolicyId,     // 1  STT minting-policy id (in datum for hash-only attestation)
  agent: VKH,               // 2  bounded session key
  per_tx_cap: Int,          // 3  ADA (lovelace) per-tx cap
  daily_cap: Int,           // 4  ADA (lovelace) sliding-window cap
  window_len: Int,          // 5  window length (ms), shared by ADA + all tokens
  token_caps: List<AssetCap>, // 6  declared sellable tokens + quantity caps
  spends: List<SpendRecord>,  // 7  sliding-window ledger (THE ONLY agent-mutable field)
  min_principal: Int,       // 8  ADA floor that must remain on the continuation
  max_spends: Int,          // 9  record-count bound (anti-bloat)
  expiry: Int,              // 10 hard expiry (agent locked out at/after)
  kill: Bool,               // 11 owner kill switch
}
```

```
AssetCap   { policy: ByteArray, name: ByteArray, per_tx: Int, daily: Int }
SpendRecord{ policy: ByteArray, name: ByteArray, at: Int,     amount: Int }
```

`SpendRecord` / `AssetCap` convention: `policy == "" && name == ""` (empty bytes)
denotes **ADA** (lovelace); otherwise the `(policy, name)` identifies a declared
token. The STT token **name** is `blake2b_256(cbor.serialise(genesis
OutputReference))` — see `CONFORMANCE.md` vectors and
`stt_name_conformance_test.ak`.

`owner` and `stt_policy` live *in the datum* precisely so a client can attest a
guard from hashes alone (§8).

---

## 5. The two branches (`logic.ak:20-30`)

```aiken
when redeemer is {
  OwnerSpend -> list.has(tx.extra_signatories, datum.owner)   // unrestricted root
  AgentSpend -> agent_spend_ok(datum, own_ref, tx)            // bounded
}
```

### 5.1 OwnerSpend — unconditional (`logic.ak:27`)

The owner branch requires **only** the owner's signature. No gateway co-sig, no
timelock, no second signer, no cap. The owner can at any time sweep all funds,
burn the STT (close the guard), retune every cap and `token_caps`, extend/shorten
`expiry`, flip `kill`, or rotate the agent key. This is the "you can always
withdraw" guarantee, and it holds **even if the gateway is offline or
compromised** — the sweep tx is built and signed on the owner's device; the
session key is never involved.

**Audit ask:** confirm no path lets the owner branch be blocked, griefed, or made
to require a non-owner signature.

### 5.2 AgentSpend — bounded by conjunctive checks (`logic.ak:32-132`)

All checks in the final `and { … }` block (`logic.ak:116-131`) must hold; failure
of any one fails the spend.

| # | Invariant | Enforcing clause | Line |
|---|-----------|------------------|------|
| 1 | Agent signed | `agent_signed = list.has(tx.extra_signatories, datum.agent)` | 33 |
| 2 | Kill switch off | `not_killed = !datum.kill` | 34 |
| 3 | Own input's STT is a singleton `[Pair(stt_nm, 1)]` | `expect [Pair(stt_nm, 1)] = ... assets.tokens(datum.stt_policy)` | 40-41 |
| 4 | **Exactly one** guard-address input, STT-bearing | `expect [guard_in] = guard_inputs` + `quantity_of(...) == 1` | 43-46 |
| 5 | **Exactly one** STT output | `expect [cont] = stt_outputs` | 48-53 |
| 6 | Continuation goes back to guard | `cont_to_guard = cont.address == guard_address` | 54 |
| 7 | Asset-count bound (anti-bloat) | `assets_ok` — flattened non-ADA count `<= max_assets` (20) | 56-57 |
| 8 | Validity range finite + skew-bounded | `range_ok = hi >= lo && hi - lo <= max_skew` | 59-61 |
| 9 | Not past hard expiry | `not_expired = now < datum.expiry` (`now = hi`) | 62-63 |
| 10 | ADA per-tx cap | `ada_per_tx_ok = ada_outflow <= datum.per_tx_cap` | 74-75 |
| 11 | ADA min-principal floor | `floor_ok = ada_out >= datum.min_principal` | 73,76 |
| 12 | ADA sliding-window daily cap | `ada_daily_ok = sum_active_for("","") + ada_outflow <= daily_cap` | 77-78 |
| 13 | **Per-declared-token quantity metering** | `tokens_ok` from `meter_tokens(...)` | 87-94, 151-180 |
| 14 | **Undeclared-token conservation (acquire-only)** | `undeclared_conserved = conserve_undeclared(...)` | 97-103, 184-202 |
| 15 | Record-count bound | `count_ok = list.length(new_spends) <= datum.max_spends` | 106-107 |
| 16 | **Datum invariance** — agent may change ONLY `spends` | `datum_ok = cont_datum == GuardDatum { ..datum, spends: new_spends }` | 109-112 |
| 17 | No STT re-mint on this branch | `no_stt_mint = quantity_of(tx.mint, stt_policy, stt_nm) == 0` | 114 |

Each invariant is detailed below.

---

## 6. Invariants in detail

### 6.1 STT singleton authentication (inv. 3-6, `logic.ak:36-54`)

The agent path first locates its own input by `own_ref`, reads that input's
address as the canonical `guard_address`, and `expect`s the STT policy to hold
**exactly one** token there (`[Pair(stt_nm, 1)]`, line 40). It then re-derives the
STT name `stt_nm` from that pair and requires:

- **exactly one** input at the guard address (`expect [guard_in] = guard_inputs`,
  line 45), and that input carries `quantity_of(... stt_nm) == 1` (line 46);
- **exactly one** output anywhere in the tx bearing that STT (`expect [cont] =
  stt_outputs`, line 53), and it is addressed back to the guard (`cont_to_guard`,
  line 54).

This is what authenticates the *single canonical* guard UTxO: there is no older
datum copy to roll back to, and no parallel guard fork to drain a cap N times.

**Anti-double-satisfaction (inv. 4).** The `expect [guard_in] = guard_inputs`
pattern-match **fails closed** if a tx presents two inputs at the universal guard
address. This is the defense against the classic shared-address
double-satisfaction attack (one continuation "satisfying" two guard inputs). It
was fable's "Not a finding" — the defense holds and is regressioned in
`guard_redteam_test.ak`. **Liveness caveat:** because a *second* guard-address
input causes a fail-closed, the client tx-builder must **NEVER** add a second
input at the universal guard address (see §7.2).

### 6.2 ADA sliding-window cap + min-principal floor (inv. 8-12, `logic.ak:59-84`)

- **Clock.** `now = hi`, the validity-range **upper** bound (`logic.ak:62`).
  Deliberately the upper (not lower) bound: `hi ≥ real inclusion slot`, so a spend
  can never be charged into an already-elapsed window.
- **Skew bound.** The validity range width is capped: `range_ok = hi >= lo && hi -
  lo <= max_skew`, `max_skew = 180_000` ms (`logic.ak:16, 59-61`).
- **Prune.** Records are kept when `r.at + datum.window_len >= now - max_skew`
  (`logic.ak:66-70`) — boundary-inclusive, skew-shifted. The **same** pruned
  `active` set feeds ADA and every token leg (shared `window_len`).
- **ADA outflow.** `ada_outflow = lovelace_of(guard_in) - lovelace_of(cont)`
  (`logic.ak:73-74`).
- **Per-tx:** `ada_outflow <= per_tx_cap`. **Daily:** `sum_active_for("","") +
  ada_outflow <= daily_cap`. **Floor:** `lovelace_of(cont) >= min_principal`.
- A new ADA record `{ "", "", now, ada_outflow }` is prepended **only when
  `ada_outflow > 0`** (`logic.ak:79-84`) — token-only or ADA-inbound moves don't
  bloat the ledger.

**Ledger-consistency property.** Net ADA outflow ≤ `daily_cap` over **any**
real-time `window_len` interval, with no off-chain reset/heartbeat/privileged
actor. Because a tx is only included when the real slot is in `[lo, hi]` with
`hi - lo <= max_skew`, the `now = hi` clock is **ledger-consistent**:
"fast-forward `hi`" drains are unit-test artifacts, not on-chain drains (the real
slot cannot exceed `hi`).

### 6.3 Per-declared-token quantity metering (inv. 13, `meter_tokens`, `logic.ak:87-94, 151-180`)

For **each** `AssetCap` in `datum.token_caps`, folded in `token_caps` order:

- `outflow = quantity_of(in_val, cap.policy, cap.name) - quantity_of(out_val,
  cap.policy, cap.name)` (`logic.ak:163-164`);
- `per_tx_ok = outflow <= cap.per_tx` (`logic.ak:165`);
- `daily_ok = sum_active_for(active, cap.policy, cap.name) + outflow <= cap.daily`
  (`logic.ak:166-167`) — same sliding window as ADA;
- if `outflow > 0`, append `SpendRecord { cap.policy, cap.name, now, outflow }`
  **in cap order** (`logic.ak:168-176`).

`tokens_ok` is the conjunction of every leg's `per_tx_ok && daily_ok`. These are
**quantity** caps — no oracle, no price. The agent may **sell** a declared token
(a genuine outflow), but never more than the owner declared per tx or per window.

### 6.4 Undeclared-token conservation — acquire-only (inv. 14, `conserve_undeclared`, `logic.ak:97-103, 184-202`)

Fold over every non-ADA asset triple `(p, n, q)` on the guard input
(`assets.flatten(assets.without_lovelace(in_val))`). For each asset that is
**neither the STT (`p == stt_policy`) nor a declared token (`is_declared`)**,
require `quantity_of(out_val, p, n) >= q` (`logic.ak:195-198`). STT and declared
tokens are skipped (handled by their own legs).

**Property.** Any token the owner did *not* declare can be **acquired** (bought
into the guard) but can **never leave** the guard on the agent branch — its
continuation quantity must be ≥ its input quantity. This is the invariant that
closed fable's F-1/F-2 native-token exfiltration (§9).

### 6.5 Datum invariance — agent may change ONLY `spends` (inv. 16, `logic.ak:105-112`)

The canonical continuation datum is `expected_datum = GuardDatum { ..datum,
spends: new_spends }` (`logic.ak:109`), where

```
new_spends = ada_records ++ token_records ++ active
           = [ADA record if ada_outflow>0]
          ++ [one record per token_caps entry with outflow>0, IN token_caps ORDER]
          ++ pruned-active
```

(`logic.ak:105-106`). The check is a **full structural equality**: `cont_datum ==
expected_datum` (`logic.ak:112`). The agent therefore **cannot** raise its own
ADA caps, add/relax/remove any `AssetCap`, extend `expiry`, clear `kill`, lower
`min_principal`, raise `max_spends`, or rotate `owner`/`agent`/`stt_policy` — any
such mutation fails `datum_ok`. **Every field except `spends` is an
owner-controlled invariant.**

**Client obligation.** Because `datum_ok` is a byte-exact structural equality, the
tx-builder MUST reconstruct `new_spends` **exactly** as above: the ADA record
first (only if `ada_outflow > 0`), then token records **in `token_caps` order**
(only those with `outflow > 0`), then the pruned `active` tail, pruned with the
identical predicate `r.at + window_len >= now - max_skew`, `now = hi`, `max_skew =
180000`. Any deviation in order, inclusion, or stamp fails the spend (fail-closed;
not a fund-loss risk).

### 6.6 Anti-bloat & lifecycle (inv. 7, 9, 15, 17)

- **`assets_ok` / `max_assets = 20`** (`logic.ak:18, 56-57`): the continuation may
  carry at most 20 distinct non-ADA assets, preventing datum/UTxO bloat that could
  brick future spends.
- **`count_ok` / `max_spends`** (`logic.ak:106-107`): the `spends` ledger is
  length-bounded.
- **`not_expired`** (`logic.ak:63`): once `now >= datum.expiry` the agent is
  locked out; only the owner can act.
- **`kill`** (`logic.ak:34`): owner's on-chain kill switch; when set, the agent
  branch fails immediately.
- **`no_stt_mint`** (`logic.ak:114`): the agent branch forbids re-mint/burn of the
  STT (`quantity_of(tx.mint, stt_policy, stt_nm) == 0`), so the agent cannot forge
  a second authenticated guard or destroy the singleton.

---

## 7. Residual risks / out of scope

An auditor should treat these as **design decisions, not findings**.

### 7.1 Agent-acquired position PRICE risk is bounded by QUANTITY, not price

The per-asset caps are **quantity** caps and the design is **oracle-free by
design** (`logic.ak:1-5`, `types.ak:14-16`). A fully-compromised agent controls
the *entire* transaction, so no on-chain check can enforce a fair
counterparty/DEX ratio — that enforcement is **void** against a hostile agent.
Consequence: the agent can **cut losses** and can sell declared tokens at a *bad*
price, and the guard cannot stop it. What the guard *does* guarantee is that the
agent can never move **more of any asset out** than the owner declared
(`per_tx`/`daily` quantities, `min_principal` for ADA), and can never touch
undeclared tokens or the STT. **Loss is bounded by owner-set quantities, not
price.** Owners must fund guards, and set `token_caps`, accordingly.

### 7.2 Liveness griefing via a second guard-address input (tx-builder responsibility)

Inv. 4 fails closed if two inputs at the universal guard address appear in one tx.
A hostile party who can splice a second guard-address input into a tx-build could
**grief liveness** (make an agent spend un-satisfiable). This is a **tx-builder
responsibility**: the client must never construct a tx with a second input at the
universal guard address. It is a **liveness** (availability) caveat only — it can
never cause fund loss (the owner branch is unaffected and always recovers funds),
and the fail-closed behavior is the safe direction.

### 7.3 External `state_token` policy trust

The spending validator pins only its **own** STT *name* usage via `no_stt_mint`
(inv. 17). The **one-shot singleton** guarantee (that the STT policy mints exactly
one token, ever, gated on a genesis `OutputReference`) is enforced by the
**separate `state_token` minting policy**, not by this validator. That policy is a
distinct, audited one-shot script. **The client must also pin/trust it** as part
of attestation (§8, step 2). See Findings F-3 (§9).

### 7.4 Other accepted items

- **Within-cap activity is the delegation's loss boundary.** An attacker holding
  the agent key/gateway *can* trade up to the caps until the owner disarms or
  sweeps. This is the accepted price of no-approval autonomy; the mitigation is
  conservative owner caps + the owner's unilateral, gateway-independent exit.
- **Off-chain session-key handling is a separate review.** Its compromise is fully
  bounded by the on-chain caps above and is revocable on-chain by the owner
  regardless of gateway cooperation.

---

## 8. Hash-only client attestation (4 parts)

What fable / AdamKit computes to trust a guard **without** trusting any server —
enabled by the unparameterized design (config is in the datum, not in script
params):

1. **guard `scriptHash`** from the committed compiled `plutus.json` — pin by
   hashing the compiled code (no `apply_params`). Must equal
   `ecb3ce03…e57acbc6`.
2. **STT `policyId`** from the separate `state_token` blueprint — same hash-only
   pin. Must equal `5c48f601…c7d80704`. (This is where §7.3's external-policy
   trust is discharged: the client pins the audited one-shot policy id.)
3. **STT token name** via the CBOR rule `blake2b_256(cbor.serialise(genesis
   OutputReference))` — see `CONFORMANCE.md` vectors and
   `stt_name_conformance_test.ak`.
4. **Decode the on-chain `GuardDatum`** (12-field CBOR order of §4) and verify
   `datum.owner == my key` **and** `datum.token_caps == the user-consented set`
   (and `stt_policy` matches step 2). Datum CBOR layout is pinned by
   `datum_cbor_conformance_test.ak`.

---

## 9. Findings closure (fable's PR #1 red-team)

fable red-teamed the earlier **lovelace-only** `v2-pinnable` guard. Disposition
against this per-asset revision:

| Finding | Severity | Description | Status |
|---------|----------|-------------|--------|
| **F-1** | HIGH | **Native-token exfiltration.** The agent branch metered lovelace only, so tokens shipped out "for free" (`outflow = 0` for tokens). | **CLOSED** — per-declared-token metering (`meter_tokens`, inv. 13) + acquire-only conservation of undeclared tokens (`conserve_undeclared`, inv. 14). Proven **REJECTED** in `security_findings_test.ak`. |
| **F-2** | HIGH | **Drain hidden by negative ADA outflow** — the same token drain produced no ADA spend record (net ADA in ≥ out), so nothing was charged. | **CLOSED** — same per-asset mechanism: tokens are now metered/conserved independently of the ADA leg, so a token exfil can no longer be masked by ADA accounting. Proven **REJECTED** in `security_findings_test.ak`. |
| **F-3** | LOW | `no_stt_mint` pins only the guard's **own** STT name, so the universal STT policy's singleton invariant relies on the **separate** `state_token` minting policy. | **Carried forward as an explicit note (by design).** The one-shot singleton invariant is enforced by the SEPARATE, audited `state_token` policy; the **client must also pin/trust that policy** (§7.3, §8 step 2). Not a defect in the spending validator. |
| (double-sat) | — | Shared-address singleton double-satisfaction. | fable's **"Not a finding."** Defense holds: `expect [guard_in]` (inv. 4). Regressioned in `guard_redteam_test.ak`. |

---

## 10. Red-team evidence (this handoff)

The `aiken-validator-redteam` skill was run against the per-asset validator: **17
agents, 14 eUTxO exploit classes** (double_sat, value_underpay, mint_integrity,
auth, index, continuation, terms, receipt, refscript, composed, directional,
datum_decode, time, oracle_premium) **+ 3 novel rounds**.

**Result: GREEN** — zero confirmed and zero even-claimed vulnerabilities; every
attacker confirmed it was testing the per-asset validator.

**Integrity note (recorded for the auditor).** The **first** full run returned a
**spurious RED** because the skill's shared scratch dir let agents read **stale
copies of OLDER validators** (the buy-only and v1 ADA-only builds), not the
per-asset one. This was caught by post-run source verification. The **re-run** used
a fresh scratch root + a mandatory source-check gate (`grep
conserve_undeclared/token_caps`) + a **fungible-backfill refutation criterion**.

The one finding that could touch the real code — **"fungible backfill" on
`conserve_undeclared`** — is a **PROVEN WASH**: conservation forces `cont_qty >=
guard_in_qty`, hence
```
attacker_out = guard_in + attacker_in - cont <= attacker_in
```
i.e. an attacker can never extract more of an asset than they themselves deposit.
The `double_sat` case was independently re-checked by hand: **all aiken tests
pass**, every high-value theft attempt rejected. The `now = hi` sliding-window
clock was separately confirmed **ledger-consistent** (§6.2): a tx is only included
when the real slot is in `[lo, hi]` with `hi - lo <= max_skew`, so "fast-forward
`hi`" drains are unit-test artifacts, not on-chain drains.

---

## 11. Test suite (all green under `aiken check` — 54 tests)

| File | Tests | Coverage |
|------|-------|----------|
| `guard_test.ak` | 10 | per-asset baseline |
| `guard_ported_test.ak` | 25 | ported v1 adversarial suite |
| `stt_name_conformance_test.ak` | 5 | STT-name CBOR vectors (byte + `blake2b_256` name) |
| `security_findings_test.ak` | 3 | F-1 + F-2 exfil now REJECTED; declared-token over-cap REJECTED |
| `guard_redteam_test.ak` | 10 | singleton / STT / window / datum-invariance regressions |
| `datum_cbor_conformance_test.ak` | 1 | pins `cbor.serialise(GuardDatum)` for a concrete 12-field datum |

---

## 12. Build & reproduce

```
aiken check      # type-check + run the full test suite (54 tests)
aiken build      # produces plutus.json blueprints (compare to committed)
```

- Compiler pinned: **Aiken v1.1.23+8949565**, Plutus **V3**.
- stdlib pinned: **v3.1.0**.
- Reproducible hashes: guard `scriptHash = ecb3ce03…e57acbc6`,
  STT `policyId = 5c48f601…c7d80704`.

---

## 13. What we ask the audit to confirm

1. **STT singleton authentication + anti-double-satisfaction** — `expect [Pair(stt_nm,1)]`,
   `expect [guard_in]`, `expect [cont]`, `cont_to_guard` (`logic.ak:36-54`).
2. **ADA sliding-window** ≤ `daily_cap` per real-time `window_len`, including the
   `now = hi` / `max_skew` boundary reasoning (`logic.ak:59-84`).
3. **Per-declared-token quantity metering** — each `AssetCap` bounded per-tx and
   per-window (`meter_tokens`, `logic.ak:151-180`).
4. **Undeclared-token conservation** — acquire-only, `cont_qty >= in_qty`
   (`conserve_undeclared`, `logic.ak:184-202`).
5. **Datum invariance** — agent may change ONLY `spends`; the canonical
   `new_spends` reconstruction (`logic.ak:105-112`).
6. **`min_principal` floor, `expiry`, `kill`, `no_stt_mint`, `max_assets`,
   `max_spends`** — no state that traps funds or that the agent can exploit.
7. **OwnerSpend is unconditional** and cannot be blocked or made to require a
   co-signer (`logic.ak:27`).
8. Datum/redeemer **CBOR decoding** cannot be abused (malformed datum, wrong
   constructor, extra fields) — cf. the conformance tests.
9. **Findings closure** (§9): F-1/F-2 closed by per-asset caps; F-3's external
   `state_token` trust is correctly scoped.
