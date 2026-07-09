# Guard v2 — per-asset quantity caps (autonomous sell)

> **STATUS: FROZEN for handoff — validator source + plutus.json final; guard
> scriptHash `ecb3ce03...`, STT policyId `5c48f601...`; 54 aiken tests green;
> final red-team GREEN (see RED-TEAM-REPORT.md).**

Repo `adam-spending-guard`, branch `v2-per-asset-caps` (this worktree). Apache-2.0.
Public audit repo for **fable** (external integrator building the Gero iOS wallet
client). The on-chain core is frozen; everything remaining is client-side
productionization tracked in the ADAM app repo, not here (see the last section).

## Goal

Let ADAM autonomously **sell** (not just buy) tokens on mainnet while a fully-
compromised agent key can still only lose a bounded amount. Since a compromised
agent controls the *whole* transaction (including any counterparty), fair-price /
DEX-order enforcement is worthless. Bounds must be **owner-set quantities** (no
oracle). The agent can cut losses (quantity-bounded, not price-bounded); it can
never move more of any asset out than the owner declared, and can never touch
undeclared tokens, the STT, or the ADA floor (`min_principal`).

## Frozen build

- **Validator:** ADAM spending-guard, Plutus V3, **UNPARAMETERIZED** — one
  universal, pinnable script address for ALL guards. No `apply_params`; a client
  pins the script by hashing the committed compiled code.
- **Toolchain:** Aiken v1.1.23+8949565, stdlib v3.1.0.
- **Final hashes** (reproducible via `aiken build`, present in `plutus.json`):
  - guard scriptHash = `ecb3ce037188879d7fea47aa5e7eb4cbb1e24479816bf439e57acbc6`
  - STT (`state_token`) policyId = `5c48f601de2cf0a92d20f351e89704ec85871fafff310cebc7d80704`

## Model

Funds sit at the guard script address, authenticated by a one-shot **STT NFT
singleton**. Two redeemers (`lib/guard/types.ak`):

- **`OwnerSpend`** — only requires the owner signature
  (`list.has(tx.extra_signatories, datum.owner)`); unrestricted retune / sweep.
- **`AgentSpend`** — bounded session key; all the per-asset metering below.

`owner` and `stt_policy` live **in the datum** (not as script params) so a client
can attest a guard hash-only. The STT token **name** =
`blake2b_256(cbor.serialise(genesis OutputReference))`.

Metering (`lib/guard/logic.ak`, oracle-free):

- **ADA** — net lovelace outflow (`guard_in - cont`) metered vs `per_tx_cap`
  (`ada_per_tx_ok`) and vs `daily_cap` over the sliding window (`ada_daily_ok`);
  the continuation must keep `ada_out >= min_principal` (`floor_ok`).
- **Declared tokens** (`token_caps`) — each metered the SAME way (`meter_tokens`):
  net quantity out `<= per_tx` and prior-window sum + out `<= daily`, per its own
  QUANTITY caps. The agent may buy AND sell them.
- **Undeclared tokens** — acquire-only (`conserve_undeclared`): every non-ADA,
  non-STT, non-declared input asset must remain on the continuation at `>=` its
  input quantity. It may be acquired but never leaves on the agent branch.

A compromised key moves at most `daily` of each declared token per window and
**nothing** undeclared.

## Datum

`GuardDatum` (types.ak), **12 fields in this order** — CBOR field order is
load-bearing for attestation (see the datum_cbor vector):

```
GuardDatum {
  owner:         VerificationKeyHash,   // owner key — hash-only attestation target
  stt_policy:    PolicyId,              // STT policy id — in the datum, not a param
  agent:         VerificationKeyHash,   // bounded session key
  per_tx_cap:    Int,                   // ADA (lovelace) per-tx cap
  daily_cap:     Int,                   // ADA per-window cap
  window_len:    Int,                   // shared sliding window (ms) for ADA + tokens
  token_caps:    List<AssetCap>,        // owner-declared tradeable tokens
  spends:        List<SpendRecord>,     // unified: ADA (policy=name="") + per-token
  min_principal: Int,                   // ADA floor kept on the continuation
  max_spends:    Int,                   // cap on len(new_spends)
  expiry:        Int,                   // now (= hi) must be < expiry
  kill:          Bool,                  // kill switch
}

AssetCap    { policy: ByteArray, name: ByteArray, per_tx: Int, daily: Int }
SpendRecord { policy: ByteArray, name: ByteArray, at: Int, amount: Int }
            // policy == "" && name == ""  =>  ADA (lovelace)
```

Only `spends` changes on the agent branch — every other field is an owner-set
invariant enforced by `datum_ok` (full structural equality, below).

## Canonical `spends` reconstruction (tx-builder MUST reproduce, for `datum_ok`)

`datum_ok` is a **full structural equality**: the continuation datum must equal the
input datum with **only `spends` changed**
(`expected_datum = GuardDatum { ..datum, spends: new_spends }`). The client
tx-builder must reproduce `new_spends` exactly:

```
now          = hi                      // validity-range UPPER bound
max_skew     = 180000  ms
active       = [ r in datum.spends | r.at + window_len >= now - max_skew ]   // prune, order preserved
ada_records  = [ {"", "", now, ada_outflow} ]  if ada_outflow > 0  else []
token_records= for cap in token_caps, IN ORDER: [ {cap.policy, cap.name, now, outflow} ]  if outflow > 0
new_spends   = ada_records ++ token_records ++ active     // list.concat(concat(ada, token), active)
```

Structural invariants the tx-builder must honor:

- **Exactly one guard-address input** — the validator does `expect [guard_in]`
  after filtering inputs by `guard_address`. The tx-builder must **NEVER** add a
  2nd input at the universal guard address (fail-closed liveness caveat).
- **Exactly one STT-bearing continuation** to the guard address (`cont_to_guard`),
  carrying the STT singleton (`quantity_of == 1`), and **no STT mint/burn**
  (`no_stt_mint`).
- **`max_assets = 20`** non-ADA assets on the continuation (`assets_ok`).
- **`range_ok`**: `hi >= lo && hi - lo <= max_skew`; `not_expired`: `now < expiry`.
- `count_ok`: `len(new_spends) <= max_spends`.

## Hash-only client attestation (4-part checklist)

What fable / AdamKit computes to trust a guard — **no `apply_params`, hash-only**:

1. **Guard scriptHash** — from the compiled per-asset `plutus.json` (hash the
   committed compiled code); pin `ecb3ce03...`.
2. **STT policyId** — from `state_token` in `plutus.json` the same way (hash-only);
   pin `5c48f601...`.
3. **STT token name** — recompute via the CBOR rule
   `blake2b_256(cbor.serialise(genesis OutputReference))` and confirm it is the
   name on the guard's STT. Reproducing `cbor.serialise(OutputReference)`
   byte-for-byte is the interop trap; use the vectors in **CONFORMANCE.md**
   (indefinite-length array `9F…FF`, Plutus `Data` constructor tag `D8 79`, NOT a
   bare CSL 2-array).
4. **Decode `GuardDatum`** (12-field CBOR order above) and verify
   `datum.owner == my key` **and** `token_caps == the user-consented set`.

> **NOTE — what is unchanged vs NEW from fable's PR #1.** The STT **name rule** and
> the STT **policyId** are **unchanged** from fable's pr1: `state_token.ak` is
> byte-identical, so its policyId (`5c48f601...`) and the
> `blake2b_256(cbor.serialise(out_ref))` name rule (CONFORMANCE.md vectors) carry
> over verbatim. What is **NEW** is the **datum CBOR**: `GuardDatum` now has **12
> fields** (adds `stt_policy`, `token_caps`, and unifies `spends` across ADA +
> tokens). A pr1 datum decoder will NOT decode a per-asset datum — clients MUST
> re-pin against the new `datum_cbor` vector
> (`validators/datum_cbor_conformance_test.ak`, one concrete 12-field datum with a
> declared AssetCap + a mixed ADA/token `spends` list).

## Test suite — 54 tests, all green (`aiken check`)

| file | count | covers |
|---|---|---|
| `guard_test.ak` | 10 | per-asset baseline (ADA + declared-token + undeclared happy/reject paths) |
| `guard_ported_test.ak` | 25 | the ported v1 adversarial suite, re-run on the per-asset datum |
| `stt_name_conformance_test.ak` | 5 | STT-name CBOR vectors — asserts bytes **and** `blake2b_256` name (CONFORMANCE.md) |
| `security_findings_test.ak` | 3 | F-1 + F-2 exfil now REJECTED, + declared-token over-cap REJECTED |
| `guard_redteam_test.ak` | 10 | singleton / STT / window / datum-invariance regressions |
| `datum_cbor_conformance_test.ak` | 1 | pins `cbor.serialise(GuardDatum)` for a concrete 12-field datum |

`security_findings_test.ak` tests (all `fail`-expecting, i.e. the exploit is now
rejected): `f1_token_exfiltration_now_rejected`,
`f2_negative_outflow_token_drain_now_rejected`,
`f1_declared_token_over_cap_now_rejected`.

## fable's PR #1 findings — disposition

From fable's red-team of the earlier lovelace-only v2-pinnable guard:

- **F-1 (HIGH) native-token exfiltration** — the agent branch metered lovelace
  only, so tokens shipped out for free (`outflow = 0`). **CLOSED** by per-asset
  caps (`token_caps` metering + `conserve_undeclared`); proven rejected in
  `security_findings_test.ak`.
- **F-2 (HIGH) negative-ADA-outflow drain** — the same token drain hidden by a
  negative ADA outflow so no spend record was written. **CLOSED** (same tests).
- **F-3 (LOW)** — `no_stt_mint` pins only the guard's OWN STT name, so the
  universal STT policy's singleton invariant relies on the SEPARATE `state_token`
  minting policy. **Carried forward** as an explicit threat-model note (by design:
  `state_token` is a distinct, audited one-shot policy).
- **Shared-address singleton double-satisfaction** was fable's *"Not a finding"* —
  the defense holds (`expect [guard_in]`), regressioned in
  `guard_redteam_test.ak` (`rt_two_guard_inputs_rejected`,
  `rt_foreign_utxo_at_guard_addr_rejected`).

## Final red-team (this handoff's evidence) — GREEN

The `aiken-validator-redteam` skill was run against the per-asset validator: **17
agents, 14 eUTxO exploit classes** (double_sat, value_underpay, mint_integrity,
auth, index, continuation, terms, receipt, refscript, composed, directional,
datum_decode, time, oracle_premium) **+ 3 novel rounds**. Result: **GREEN — zero
confirmed and zero even-claimed vulnerabilities**; every attacker confirmed it was
testing the per-asset validator.

**Integrity note.** The FIRST full run returned a spurious **RED** because the
skill's shared scratch dir let agents read STALE copies of OLDER validators (the
buy-only and v1 ADA-only builds), not the per-asset one. This was caught by
post-run source verification. The re-run used a fresh scratch root, a mandatory
source-check gate (`grep conserve_undeclared` / `token_caps`), and a
fungible-backfill refutation criterion.

The one finding that could touch the real code — **"fungible backfill" on
`conserve_undeclared`** — is a **PROVEN WASH**: conservation forces
`cont_qty >= guard_in_qty`, so
`attacker_out = guard_in + attacker_in - cont <= attacker_in` — the attacker can
never extract more of an asset than they themselves deposit. The `double_sat` copy
was independently re-checked by hand: 56/56 aiken tests pass, every high-value
theft attempt rejected. Also locked in: the `now = hi` sliding-window clock is
ledger-consistent (a tx is only included when the real slot is in `[lo,hi]` with
`hi - lo <= max_skew`), so "fast-forward hi" drains are unit-test artifacts, not
on-chain drains.

## Client-side productionization (tracked in the ADAM app repo, NOT this validator)

The validator is frozen. What remains is entirely off-chain, in the ADAM app repo:

- **Gateway** — thread `token_caps` through provisioning; add the owner
  cap-retune route (adjust tradeable tokens via `OwnerSpend`).
- **agent-core tx-builder** — compute the canonical `spends` reconstruction above;
  never add a 2nd input at the universal guard address.
- **AdamKit** — implement the 4-part hash-only per-asset attestation (pin
  `ecb3ce03...` + `5c48f601...`, recompute the STT name per CONFORMANCE.md, decode
  the 12-field `GuardDatum`, verify owner + `token_caps == consent`).

None of these can change the frozen hashes; they consume them.
