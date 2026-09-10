# Security findings — ADAM spending-guard, per-asset caps (`v2-per-asset-caps`)

Handoff status of the independent red-team of `agent_spend_ok` (`lib/guard/logic.ak`).
This supersedes fable's original PR #1 red-team of the earlier lovelace-only
`v2-pinnable` guard. F-1 and F-2 (both HIGH) are now **CLOSED** by per-asset caps and
proven rejected by execution; F-3 (LOW) is carried forward as an explicit,
by-design threat-model note; the shared-address singleton "Not a finding" defense
still holds and is regressioned.

Every claim below is grounded in the real source (`lib/guard/logic.ak`) and runnable
reproducers under `validators/`. The full suite is **green under `aiken check` (54
tests)**: Aiken v1.1.23+8949565, stdlib v3.1.0.

- Repo: `adam-spending-guard`, branch `v2-per-asset-caps`, Apache-2.0.
- Validator: ADAM spending-guard, Plutus V3, **UNPARAMETERIZED** — one universal,
  pinnable script address for all guards.
- Final reproducible hashes (`aiken build`):
  - guard `scriptHash` = `ecb3ce037188879d7fea47aa5e7eb4cbb1e24479816bf439e57acbc6`
  - STT (`state_token`) `policyId` = `5c48f601de2cf0a92d20f351e89704ec85871fafff310cebc7d80704`

## Model recap (for the auditor)

Funds sit at the universal guard script address, authenticated by a one-shot STT NFT
singleton (`state_token` policy). Redeemers: `OwnerSpend` (only the owner signature —
unrestricted retune/sweep) and `AgentSpend` (bounded session key). `owner` and
`stt_policy` live in the datum for hash-only client attestation. The STT token *name*
is `blake2b_256(cbor.serialise(genesis OutputReference))`.

The `AgentSpend` bound is **oracle-free and quantity-based**. A fully compromised agent
controls the entire transaction, so there is no counterparty/DEX-ratio enforcement to
rely on — only the owner-set *quantities* bound the loss:

- ADA outflow is metered against `per_tx_cap` / `daily_cap` over a sliding window, and
  `min_principal` is a hard ADA floor on the continuation.
- **Each owner-declared token** (`token_caps`) is metered the *same way* against its
  own `per_tx` / `daily` quantity caps.
- **Undeclared tokens are acquire-only**: every non-ADA, non-STT, non-declared input
  asset must remain on the continuation at `>=` its input quantity.

The agent can cut losses (quantity-bounded, not price-bounded); it can never move more
of any asset out than the owner declared, can never touch an undeclared token or the
STT, and can never breach the ADA floor.

---

## F-1 (High) — native-token exfiltration via lovelace-only metering — **CLOSED**

**Original finding (v2-pinnable).** `agent_spend_ok` metered lovelace only. A tx that
kept ADA within caps but shipped the guard's native tokens to an attacker returned
`True`: `outflow = lovelace_of(guard_in) − lovelace_of(cont) = 0`, so the caps and
floor were trivially satisfied, and the old `assets_ok` clause only bounded the *count*
of assets on the continuation (dropping a token lowers it). For an ADAM trading bot —
which holds non-ADA value whenever it buys a token — the guard provided no protection
on that value; a compromised session key drained it in one transaction.

**How it's closed.** The agent branch now enforces `conserve_undeclared` for any token
that is not the STT and not in `token_caps` (`lib/guard/logic.ak:96-103`, definition at
`lib/guard/logic.ak:184-202`). It folds over
`assets.flatten(assets.without_lovelace(guard_in))` and, for each asset that is neither
the STT policy nor a declared `(policy, name)`, requires
`quantity_of(cont.value, p, n) >= q` — the full input quantity must remain on the
continuation. An exfiltration output drops that token from the continuation, making
`quantity_of(cont, T) = 0 < input`, so the fold returns `False` and the whole `and { … }`
(`lib/guard/logic.ak:116-131`) fails closed. For a token the owner *does* declare, the
same movement is instead metered by `meter_tokens` (`lib/guard/logic.ak:151-180`)
against that token's own `per_tx` / `daily` quantity caps — so a declared token is
bounded exactly like ADA, never free.

**Proof (now-passing rejection tests).** `validators/security_findings_test.ak`:

- `f1_token_exfiltration_now_rejected` — fable's exact repro, inverted: guard input
  `100 ADA + 1000·T + STT`, continuation `100 ADA + STT` (T dropped, ADA unchanged so
  `ada_outflow = 0`), `1000·T` shipped to the attacker. T is undeclared, so
  `conserve_undeclared` requires the continuation to retain `>= 1000·T`; it retains 0.
  The test is declared `fail` and passes — the drain is **rejected**.
- `f1_declared_token_over_cap_now_rejected` — shows the metered path also bounds a
  *declared* token: `token_caps` declares T with `per_tx = 100`; the agent tries to move
  500 out (input 500 → continuation 0). `meter_tokens` computes `outflow = 500 > per_tx`,
  so `per_tx_ok` is `False`. Declared `fail`, passes — **rejected**.

---

## F-2 (High) — token drain hidden by negative ADA outflow (no spend record) — **CLOSED**

**Original finding (v2-pinnable).** The same drain could be masked by having the agent
*add* ADA so `ada_out > ada_in`. Then `outflow = −10 ADA`, caps passed, and because the
record branch was `if outflow > 0 { [record, ..] } else { active }`, **no `SpendRecord`
was written** — the rolling daily window never observed the movement. Same root cause as
F-1, additionally showing the daily accounting was blind to any non-positive-lovelace
transaction.

**How it's closed.** Token conservation/metering is now independent of the ADA sign.
`conserve_undeclared` (`lib/guard/logic.ak:184-202`) inspects each token's quantity
directly and does not consult `ada_outflow` at all, so raising the continuation's ADA to
force a negative ADA outflow does nothing to relax the token check. (For declared tokens,
`meter_tokens` likewise keys its per-token records off each token's own `outflow`, not the
ADA leg — `lib/guard/logic.ak:163-176`.) The negative-ADA masking trick therefore has no
effect on the token defense.

**Proof (now-passing rejection test).** `validators/security_findings_test.ak
:: f2_negative_outflow_token_drain_now_rejected` — guard input `50 ADA + 500·T + STT`,
continuation `60 ADA + STT` (ADA up, `ada_outflow = −10 ADA`, so no ADA spend record),
`500·T` shipped to the attacker. T is undeclared → `conserve_undeclared` requires the
continuation to retain `>= 500·T`; it retains 0. Declared `fail`, passes — **rejected**.

---

## F-3 (Low / by-design) — guard does not constrain the rest of the universal STT policy

**Status: accepted, carried forward as a threat-model note.**

`no_stt_mint = quantity_of(tx.mint, datum.stt_policy, stt_nm) == 0`
(`lib/guard/logic.ak:114`) pins only *this* guard's STT name. A mint of a *different*
name under the same universal `stt_policy`, in the same transaction, is not blocked by
`agent_spend_ok`. This is **not** a theft of the guard being spent — uniqueness of the
universal STT policy (one-shot per genesis `OutputReference`) is enforced by the
**separate** `state_token` minting policy (`validators/state_token.ak`), which is a
distinct, audited one-shot policy. The guard therefore relies on that external validator
for the policy-wide singleton invariant, by design. No failing reproducer — this is an
accepted low, recorded here for the threat model.

---

## Not a finding — shared-address singleton double-satisfaction

The universal script address is shared across all owners' guards, distinguished only by
STT name. Attempts to break per-guard accounting by co-locating a second guard (or a
foreign UTxO) at the address do **not** succeed. The defense holds:
`expect [guard_in] = <inputs at guard address>` (`lib/guard/logic.ak:43-45`) admits
exactly one guard input, and the STT name is read from *that* input
(`lib/guard/logic.ak:40-41,46`), so guard A's caps can never be satisfied using guard
B's value. Regression tests live in `validators/guard_redteam_test.ak`.

**Liveness caveat (fail-closed, not a safety issue).** Because `expect [guard_in]` is
fail-closed, a third party can grief a pending agent tx by inserting any UTxO at the
universal address. The off-chain tx-builder must **never** itself include a second
guard-address input.

---

## Canonical `spends` reconstruction (client tx-builder obligation)

`datum_ok` is a **full structural equality**: the continuation datum must equal the input
datum with *only* `spends` changed (`lib/guard/logic.ak:109-112`). The tx-builder must
reproduce exactly:

```
new_spends =
  [ ADA record {"", "", now, ada_outflow}  if ada_outflow > 0 ]
  ++ [ one {cap.policy, cap.name, now, outflow} per token_caps entry with outflow > 0,
       IN token_caps ORDER ]
  ++ pruned-active
```

(assembled at `lib/guard/logic.ak:79-84, 87-94, 105-106`). Prune predicate:
`r.at + window_len >= now − max_skew` (`lib/guard/logic.ak:66-70`), with
`now = validity UPPER bound (hi)` (`lib/guard/logic.ak:60,62`) and `max_skew = 180000` ms
(`lib/guard/logic.ak:16`). Also: exactly one guard-address input (`expect [guard_in]`),
and `max_assets = 20` on the continuation (`lib/guard/logic.ak:18,56-57`).

Clock note: `now = hi` is ledger-consistent — a tx is only included when the real slot is
in `[lo, hi]` with `hi − lo <= max_skew` (`range_ok`, `lib/guard/logic.ak:61`) — so
"fast-forward hi" drains are unit-test artifacts, not on-chain drains.

---

## Test suite (all green under `aiken check` — 54 tests)

- `guard_test.ak` — per-asset baseline (10)
- `guard_ported_test.ak` — ported v1 adversarial (25)
- `stt_name_conformance_test.ak` — STT-name CBOR vectors, byte + `blake2b_256` name (5)
- `security_findings_test.ak` — **F-1 + F-2 exfil now REJECTED, + declared-token
  over-cap REJECTED (3)**
- `guard_redteam_test.ak` — singleton / STT / window / datum-invariance regressions (10)
- `datum_cbor_conformance_test.ak` — pins `cbor.serialise(GuardDatum)` for a concrete
  12-field datum (1)

---

## Final red-team (this handoff's evidence)

The `aiken-validator-redteam` skill was run against the per-asset validator: 17 agents,
14 eUTxO exploit classes (`double_sat`, `value_underpay`, `mint_integrity`, `auth`,
`index`, `continuation`, `terms`, `receipt`, `refscript`, `composed`, `directional`,
`datum_decode`, `time`, `oracle_premium`) plus 3 novel rounds. **Result: GREEN — zero
confirmed and zero even-claimed vulnerabilities**; every attacker confirmed testing the
per-asset validator.

Integrity note. The *first* full run returned a spurious RED because the skill's shared
scratch dir let agents read stale copies of older validators (the buy-only and v1
ADA-only builds), not the per-asset one. This was caught by post-run source
verification. The re-run used a fresh scratch root, a mandatory source-check gate
(`grep conserve_undeclared` / `token_caps`), and a fungible-backfill refutation
criterion. The one finding that could touch real code — "fungible backfill" on
`conserve_undeclared` — is a **proven wash**: conservation forces
`cont_qty >= guard_in_qty`, so `attacker_out = guard_in + attacker_in − cont <=
attacker_in`; the attacker can never extract more of an asset than they themselves
deposit. The `double_sat` copy was independently re-checked by hand: 56/56 aiken tests
pass, every high-value theft attempt rejected.

---

## 4-part hash-only client attestation (what fable / AdamKit computes to trust a guard)

1. **guard `scriptHash`** from the compiled per-asset `plutus.json` — pin by hashing the
   committed compiled code (no `apply_params`).
2. **STT `policyId`** from `state_token` — same, hash-only.
3. **STT token name** via `blake2b_256(cbor.serialise(genesis OutputReference))` — see
   `CONFORMANCE.md` vectors.
4. **Decode the on-chain `GuardDatum`** (12 fields, order:
   `owner, stt_policy, agent, per_tx_cap, daily_cap, window_len, token_caps, spends,
   min_principal, max_spends, expiry, kill`) and verify `datum.owner == my key` and
   `token_caps == the user-consented set`.
