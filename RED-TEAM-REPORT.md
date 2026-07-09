# ADAM Spending-Guard — Adversarial Red-Team Report (Per-Asset Caps)

**Repo:** `adam-spending-guard` · **Branch:** `v2-per-asset-caps` · **License:** Apache-2.0
**Audience:** fable (external integrator, Gero iOS wallet client) + the external P6 auditor
**Validator:** ADAM spending-guard, Plutus V3, **UNPARAMETERIZED** (one universal, pinnable script address shared by all guards)
**Toolchain:** Aiken `v1.1.23+8949565`, stdlib `v3.1.0`
**Result:** **GREEN** — zero confirmed and zero even-claimed vulnerabilities.

This is a public audit repo. Every claim below is grounded in the committed source
(`lib/guard/logic.ak`, `lib/guard/types.ak`, `validators/`) and reproducible with
`aiken check`. Numbers are not inflated; the one integrity caveat from the run is
documented in full in §4.

---

## 1. Scope, Final Hashes, and What Was Tested

### 1.1 Final compiled hashes (reproducible via `aiken build`)

| Artifact | Hash |
|---|---|
| Guard `scriptHash` (`guard.guard.spend`) | `ecb3ce037188879d7fea47aa5e7eb4cbb1e24479816bf439e57acbc6` |
| STT (`state_token`) `policyId` (`state_token.state_token.mint`) | `5c48f601de2cf0a92d20f351e89704ec85871fafff310cebc7d80704` |

Both are UNPARAMETERIZED (no `apply_params`), so a client pins each by hashing the
committed compiled code in `plutus.json`. These hashes were read directly from the
committed `plutus.json` in this worktree.

### 1.2 The scope under test — the per-asset validator

The subject of this red-team is the **per-asset-caps** guard: the new autonomous-SELL
capability, oracle-free. Its distinguishing logic (not present in the older buy-only
or v1 ADA-only builds) is metering *each* owner-declared token like ADA and conserving
*undeclared* tokens. Confirmed present in `lib/guard/logic.ak`:

- `meter_tokens/5` — meters every declared token's net outflow vs its own `per_tx` /
  `daily` **quantity** caps over the shared sliding window.
- `conserve_undeclared/4` — every non-ADA, non-STT, non-declared input asset must
  remain on the continuation at `>=` its input quantity (acquire-only).
- `token_caps: List<AssetCap>` field in the 12-field `GuardDatum`.

**Model.** Funds sit at the guard script address, authenticated by a one-shot STT NFT
singleton. Two redeemers: `OwnerSpend` (owner signature only → unrestricted retune /
sweep) and `AgentSpend` (bounded session key). `owner` and `stt_policy` live in the
datum so a client can attest hash-only. STT token **name** = `blake2b_256(cbor.serialise(genesis OutputReference))`.

**Datum** (`lib/guard/types.ak`), 12 fields in order:
`GuardDatum { owner, stt_policy, agent, per_tx_cap, daily_cap, window_len, token_caps, spends, min_principal, max_spends, expiry, kill }`.
`AssetCap { policy, name, per_tx, daily }`. `SpendRecord { policy, name, at, amount }`
where `policy == name == ""` denotes ADA (lovelace).

**Per-asset bound (oracle-free).** ADA outflow is metered vs `per_tx_cap` / `daily_cap`
over a sliding window; each declared token is metered the same way vs its own quantity
caps; undeclared tokens are acquire-only. There is **no oracle** — a fully-compromised
agent controls the whole tx, so counterparty / DEX-ratio enforcement is void. Only the
owner-set **quantities** bound the loss: the agent may cut losses (quantity-bounded,
never price-bounded), can never move more of any asset out than the owner declared,
and can never touch undeclared tokens, the STT, or the ADA floor (`min_principal`).

### 1.3 Test suite — 54 Aiken tests, all green

`aiken check` on this worktree reports **54 pass / 0 fail**. Breakdown by file
(verified by counting `test` declarations):

| File | Tests | Purpose |
|---|---:|---|
| `validators/guard_test.ak` | 10 | per-asset baseline (honest + reject) |
| `validators/guard_ported_test.ak` | 25 | ported v1 adversarial suite |
| `validators/stt_name_conformance_test.ak` | 5 | STT-name CBOR vectors (byte + `blake2b_256` name) |
| `validators/security_findings_test.ak` | 3 | fable's F-1/F-2 exfil now REJECTED + declared-token over-cap REJECTED |
| `validators/guard_redteam_test.ak` | 10 | singleton / STT / window / datum-invariance regressions |
| `validators/datum_cbor_conformance_test.ak` | 1 | pins `cbor.serialise(GuardDatum)` for a concrete 12-field datum |
| **Total** | **54** | |

---

## 2. Methodology — the `aiken-validator-redteam` skill

The final adversarial pass used the **`aiken-validator-redteam`** skill: an
**executable, multi-agent** red-team, not a checklist review. Its defining properties:

- **A PASSING attack test = a confirmed vuln.** Each attacker writes a PoC exploit as
  an Aiken test asserting `logic.spend_ok(...) == True` for a malicious tx. If that
  test *passes* under `aiken check`, the theft is real and confirmed. This inverts the
  usual convention (the committed regression tests use `test … fail {}`, which passes
  iff the validator *rejects*); the attacker's job is to produce a test that the
  validator lets through.
- **Skeptic-verified.** Every claimed finding is independently re-checked by a skeptic
  before it counts; unverified claims are discarded.
- **Each attacker compiles PoC Aiken exploits** against the real `lib/guard/logic.ak`
  — no hand-waving, the exploit must build and run.

**Coverage.** 17 agents total: **14 eUTxO exploit classes** + **3 novel rounds**. The
14 classes: `double_sat`, `value_underpay`, `mint_integrity`, `auth`, `index`,
`continuation`, `terms`, `receipt`, `refscript`, `composed`, `directional`,
`datum_decode`, `time`, `oracle_premium`.

---

## 3. Result — GREEN

**Zero confirmed and zero even-claimed vulnerabilities.** No attacker produced a
passing exploit test against the per-asset validator. Every attacker confirmed (via
the source-pin gate in §4) that it was testing the per-asset validator.

### Coverage table

| # | Exploit class | Outcome | Guard mechanism (in `lib/guard/logic.ak`) |
|---:|---|---|---|
| 1 | `double_sat` | defended | `expect [guard_in]` (single guard input) + `expect [cont]` (single STT continuation); re-checked by hand, see §4 |
| 2 | `value_underpay` | defended | ADA: `ada_per_tx_ok` / `ada_daily_ok` / `floor_ok`; tokens: `meter_tokens`; undeclared: `conserve_undeclared` |
| 3 | `mint_integrity` | defended | `no_stt_mint` (`quantity_of(tx.mint, stt_policy, stt_nm) == 0`) blocks burn/mint of the live STT |
| 4 | `auth` | defended | `OwnerSpend` requires `datum.owner` sig; `AgentSpend` requires `datum.agent` sig (`agent_signed`) |
| 5 | `index` | defended | continuation found by STT presence, not positional index (`stt_outputs` filter) |
| 6 | `continuation` | defended | `cont_to_guard` (STT output returns to guard address) + `datum_ok` full structural equality |
| 7 | `terms` | defended | `datum_ok`: `cont_datum == GuardDatum { ..datum, spends: new_spends }` — only `spends` may change |
| 8 | `receipt` | defended | canonical `new_spends` reconstruction is enforced by `datum_ok`; caps/records cannot be forged |
| 9 | `refscript` | defended | no reference-script trust path; STT authentication is value-based |
| 10 | `composed` | defended | `expect [guard_in]` rejects a second guard input; `assets_ok` (`<= max_assets`) bounds continuation |
| 11 | `directional` | defended | `ada_outflow = in − out`; `meter_tokens` net-out per asset; negative outflow writes no record and is bounded by conservation |
| 12 | `datum_decode` | defended | `expect cont_datum: GuardDatum = cont_datum_data` (typed decode of continuation datum) |
| 13 | `time` | defended | `range_ok` (`hi − lo <= max_skew`), `not_expired` (`now < expiry`), window prune keyed on `now = hi` |
| 14 | `oracle_premium` | defended | **oracle-free by design**: only owner-set quantities bound loss; no price path to attack |
| — | 3 novel rounds | defended | no novel class produced a passing exploit |

---

## 4. Integrity of the Run (honest + specific)

This section is deliberately explicit. **The first full run returned a spurious RED.**
It must not be read as a real vulnerability, and the reason is documented so the P6
auditor can independently confirm the correction.

### 4.1 What went wrong

The skill's **shared scratch directory** let agents read **STALE copies of OLDER
validators** — specifically the earlier **buy-only** build and the **v1 ADA-only**
build — rather than the per-asset validator under test. Attacks that "succeeded"
succeeded against code that is not the subject of this audit (e.g. a lovelace-only
metering path that the per-asset validator replaced). The RED was an artifact of
reading the wrong source, not a defect in the per-asset guard.

### 4.2 How it was caught

Post-run **source verification**: comparing what each agent had actually loaded
against the committed per-asset `lib/guard/logic.ak`. The stale reads were identified
because the "vulnerable" code paths did not contain `conserve_undeclared` or
`token_caps` — constructs that exist only in the per-asset build.

### 4.3 The corrected re-run

The re-run was hardened with three controls:

1. **Fresh scratch root** — no shared/stale directory; each agent works against a
   clean checkout of this worktree.
2. **Mandatory source-pin gate** — every agent must `grep` for `conserve_undeclared`
   and `token_caps` in the loaded validator before its findings count. (Both confirmed
   present here: `conserve_undeclared` and `token_caps` appear in `lib/guard/logic.ak`.)
3. **Fungible-backfill refutation criterion** — an explicit rule for evaluating the
   one class of finding that could touch the real per-asset code (`conserve_undeclared`),
   see §5(a).

After hardening, **every agent verified it was testing the per-asset validator**, and
the result was GREEN with zero claimed findings.

### 4.4 Independent hand re-check of `double_sat`

Because double-satisfaction across the *shared universal address* is the highest-value
class for a pinnable, address-shared guard, the `double_sat` case was independently
re-checked by hand: **56/56 aiken tests pass** in that hand-checked copy, and every
high-value theft attempt was rejected. (This report's own worktree tallies 54/54 under
`aiken check`; the 56/56 figure is the hand-checked double_sat copy, which carried two
additional cases.) The relevant committed regressions are
`rt_two_guard_inputs_rejected`, `rt_foreign_utxo_at_guard_addr_rejected`, and
`rt_duplicate_stt_continuation_rejected` in `validators/guard_redteam_test.ak`, plus
`attack_double_satisfaction` in `validators/guard_ported_test.ak` — all `fail` tests
that pass iff the validator rejects. The defense is `expect [guard_in]` (exactly one
guard-address input) and `expect [cont]` (exactly one STT-bearing continuation).

---

## 5. Two Soundness Proofs (stated explicitly)

### (a) Fungible backfill on `conserve_undeclared` = a wash

The one finding that could touch the real per-asset code was **"fungible backfill"**:
could an attacker satisfy `conserve_undeclared` by supplying, from their *own* input,
the same fungible asset they are draining — thereby returning `>= input` on the
continuation while still walking away with value?

This is a **proven wash**. For any asset `A`, value conservation over the tx forces the
continuation to retain at least what the guard put in:

```
cont_qty(A) >= guard_in_qty(A)        (conserve_undeclared requires this on the continuation)
```

The most the attacker can carry out of the tx is what enters minus what the
continuation keeps:

```
attacker_out(A) = guard_in_qty(A) + attacker_in_qty(A) − cont_qty(A)
               <= guard_in_qty(A) + attacker_in_qty(A) − guard_in_qty(A)
               =  attacker_in_qty(A)
```

So `attacker_out(A) <= attacker_in(A)`: **the attacker can never extract more of an
undeclared asset than they themselves deposited.** Backfilling to satisfy conservation
just returns their own tokens; it moves none of the guard's. No value leaves the guard.
`conserve_undeclared` operates over `assets.flatten(assets.without_lovelace(guard_in))`
and asserts `quantity_of(out_val, p, n) >= q` for every undeclared `(p, n, q)`, which
is exactly the inequality above.

### (b) The `now = hi` sliding-window clock is ledger-consistent

The validator sets `now = hi` (the validity-range **upper** bound) and prunes records
with `r.at + window_len >= now − max_skew` (`max_skew = 180_000` ms). A unit test can
construct a tx whose `hi` is arbitrarily far in the future to "fast-forward" the window
and appear to reset caps — but **that is a unit-test artifact, not an on-chain drain**:

- The ledger only *includes* a tx when the real slot is within `[lo, hi]`.
- `range_ok` enforces `hi − lo <= max_skew`.
- Therefore, at inclusion, `hi` is within `max_skew` of the real slot.

So on-chain `now = hi` can never be more than `max_skew` ahead of real time; a
"fast-forward-hi" drain cannot be included by any node. The pruning window is
ledger-consistent. (Committed regression: `attack_expiry_skew_bypass` and
`rt_excessive_skew_rejected` reject the over-wide-range attempt.)

---

## 6. fable's Findings — Status

From fable's PR #1 red-team of the earlier **lovelace-only v2-pinnable** guard:

| ID | Sev | Finding | Status |
|---|---|---|---|
| **F-1** | HIGH | Native-token exfiltration — the agent branch metered lovelace only, so tokens shipped out for free (`outflow = 0`). | **CLOSED** |
| **F-2** | HIGH | The same drain hidden by negative ADA outflow, so no spend record was written. | **CLOSED** |
| **F-3** | LOW | `no_stt_mint` pins only the guard's own STT name; the universal STT policy's singleton invariant relies on the separate `state_token` minting policy. | **Carried forward** (by design) |

**F-1 / F-2 closure** is proven in `validators/security_findings_test.ak` — fable's
exact reproducers, inverted to `fail` tests that pass iff the drain is now rejected:

- `f1_token_exfiltration_now_rejected` — drains 1000·T (undeclared) with ADA unchanged
  (`outflow = 0`); `conserve_undeclared` requires the continuation to keep `>= 1000·T`,
  it keeps 0 → REJECTED.
- `f2_negative_outflow_token_drain_now_rejected` — same drain hidden by ADA going *up*
  (no ADA record); T is still undeclared → `conserve_undeclared` REJECTS regardless of
  ADA accounting.
- `f1_declared_token_over_cap_now_rejected` — even a **declared** token is bounded:
  `per_tx = 100`, agent tries to move 500 out → `meter_tokens` per-tx check REJECTS.

The mechanism: under per-asset caps the drained token is either **undeclared**
(`conserve_undeclared` forbids any net outflow) or **declared** (`meter_tokens` bounds
net outflow to the owner-set quantity). Either way the free drain is closed.

**F-3 is carried forward as an explicit threat-model note** — it is by design. The
`state_token` policy is a distinct, audited one-shot minting policy: name =
`blake2b_256(cbor.serialise(genesis OutputReference))`, minted only when an input's
`OutputReference` hashes to that name (single-use UTxO), so each name mints exactly
once. The guard's `no_stt_mint` guarantees the live STT is neither minted nor burned
in an `AgentSpend` tx; the *singleton* invariant across the guard's lifetime rests on
the separate `state_token` policy, which the P6 audit should also cover.

**"Not a finding" (fable):** the shared-address singleton double-satisfaction. The
defense holds — `expect [guard_in]` + `expect [cont]` — and is regressioned in
`validators/guard_redteam_test.ak` (see §4.4).

---

## 7. Reproduction

### 7.1 Verify tests + hashes

```sh
# From the worktree root (branch v2-per-asset-caps):
aiken check          # → 54 tests, all pass
aiken build          # regenerates plutus.json

# Confirm the pinned hashes:
#   guard.guard.spend        hash == ecb3ce037188879d7fea47aa5e7eb4cbb1e24479816bf439e57acbc6
#   state_token…mint  policyId == 5c48f601de2cf0a92d20f351e89704ec85871fafff310cebc7d80704
```

Toolchain: Aiken `v1.1.23+8949565`, stdlib `v3.1.0` (per `aiken.toml` / `aiken.lock`).

### 7.2 How the red-team was configured

- Skill: `aiken-validator-redteam`, executable multi-agent (a *passing* attack test =
  a confirmed vuln; findings skeptic-verified).
- 17 agents = 14 eUTxO exploit classes (§3) + 3 novel rounds; each attacker compiles
  PoC Aiken exploits against `lib/guard/logic.ak`.
- Hardening (post spurious-RED, §4): **fresh scratch root**; **mandatory source-pin
  gate** — every agent must `grep conserve_undeclared` and `token_caps` in the loaded
  validator before findings count; **fungible-backfill refutation criterion** (§5a).
- `double_sat` additionally re-checked by hand (§4.4).

---

## 8. Residual Risk

An **external P6 Plutus audit is still recommended before mainnet.** This report is
adversarial evidence produced by an automated multi-agent red-team plus the committed
test suite; it is not a substitute for an independent human audit. In particular, the
P6 audit should cover the separate `state_token` one-shot minting policy (F-3's
singleton dependency) alongside the guard `spend` logic.

---

### Appendix — 4-part hash-only client attestation

What fable / AdamKit computes to trust a specific guard UTxO:

1. **Guard `scriptHash`** from the compiled per-asset `plutus.json` (hash the committed
   compiled code — no `apply_params`) == `ecb3ce…7acbc6`.
2. **STT `policyId`** from `state_token` (same, hash-only) == `5c48f6…d80704`.
3. **STT token name** via `blake2b_256(cbor.serialise(genesis OutputReference))` — see
   `CONFORMANCE.md` vectors (note the two encoding traps: Aiken emits an
   **indefinite-length** array `9F … FF`, and it is Plutus `Data` with a constructor
   tag, *not* a bare CSL `TransactionInput` 2-array).
4. **Decode the on-chain `GuardDatum`** (12-field CBOR order in §1.2) and verify
   `datum.owner == myKey` and `token_caps == the user-consented set`.
