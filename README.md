# ADAM Spending-Guard — per-asset caps (v2)

> Repo: `adam-spending-guard`, branch `v2-per-asset-caps`. Apache-2.0. Public audit
> repo prepared for an external integrator building the Gero iOS wallet client.

## What this is

An **opt-in Plutus V3 spending-guard** that bounds a delegated ADAM **agent session
key** so it can trade 24/7 autonomously without ever being able to drain the user.
Funds sit at the guard script address; the **owner** (phone key) keeps unrestricted
control — retune, sweep, revoke — with only their own signature. The **agent** may
spend only within on-chain, **oracle-free per-asset quantity caps**: a net ADA
outflow cap per tx and per rolling window, an ADA principal floor, and — new in this
version — a per-token **quantity** cap on each owner-declared tradeable token, so the
agent can autonomously SELL (cut losses) but can never move more of any asset out
than the owner declared, and can never touch undeclared tokens or the guard's
authenticating token. Because a fully-compromised agent controls the whole
transaction, price/DEX-ratio fairness is unenforceable by design; only owner-set
**quantities** bound the loss.

## Design at a glance

- **Unparameterized, universal, pinnable address.** One script (`validators/guard.ak`)
  serves ALL guards — no `apply_params`. Its script hash (and therefore its address)
  is fixed, so a client pins the guard by hashing the committed compiled code. The
  `owner` key and `stt_policy` live **in the datum**, so a client attests a specific
  guard purely by reading the datum (hash-only, no per-user script).
- **STT singleton authentication.** A one-shot state-thread token
  (`validators/state_token.ak`, also unparameterized/pinnable) marks the live guard
  UTxO. Uniqueness comes from the token **name**, not a script parameter:
  `name = blake2b_256(cbor.serialise(genesis OutputReference))`. The genesis UTxO can
  be spent once, so each name mints once. Mint is exactly `+1` (one input's outref
  must hash to the name); burn is `-1`. The mint also opens the guard: the token must
  land at the guard script on an inline `GuardDatum` with empty `spends`, `kill =
  False`, bounded terms and its own policy id, in a transaction signed by
  `datum.owner` (see "Opening rules" below). The burn checks nothing else, so the
  owner can always close.
- **Two redeemers.** `OwnerSpend` — passes on the owner signature alone; unrestricted
  retune/sweep/close. `AgentSpend` — the bounded session-key path; all caps enforced.
- **Datum** (`lib/guard/types.ak`, `GuardDatum`, 12 fields, in CBOR/declared order):

  | # | Field | Type | Meaning |
  |---|-------|------|---------|
  | 1 | `owner` | `VerificationKeyHash` | Unrestricted key (in datum for hash-only attestation) |
  | 2 | `stt_policy` | `PolicyId` | Universal STT policy id (in datum for attestation) |
  | 3 | `agent` | `VerificationKeyHash` | Bounded session key |
  | 4 | `per_tx_cap` | `Int` | Max net ADA (lovelace) outflow per tx |
  | 5 | `daily_cap` | `Int` | Max net ADA outflow over the sliding window |
  | 6 | `window_len` | `Int` | Sliding-window length (ms), shared by ADA + tokens |
  | 7 | `token_caps` | `List<AssetCap>` | Owner-declared sellable tokens, each quantity-capped |
  | 8 | `spends` | `List<SpendRecord>` | Metered outflow records, newest first |
  | 9 | `min_principal` | `Int` | ADA floor the continuation must retain |
  | 10 | `max_spends` | `Int` | Cap on `spends` list length |
  | 11 | `expiry` | `Int` | Hard expiry; agent branch fails once reached |
  | 12 | `kill` | `Bool` | Owner kill switch; agent branch fails when true |

  `AssetCap { policy, name, per_tx, daily }` — a per-token QUANTITY cap.
  `SpendRecord { policy, name, at, amount }` — an outflow record; `policy == name ==`
  empty-bytes denotes **ADA** (lovelace), otherwise a declared token.

**How the bound works (`lib/guard/logic.ak`, `AgentSpend`):** ADA outflow is metered
against `per_tx_cap` / `daily_cap` over a sliding window. EACH declared token
(`token_caps`) is metered the SAME way against its own `per_tx` / `daily` quantity
caps. UNDECLARED tokens are **acquire-only**: `conserve_undeclared` requires every
non-ADA, non-STT, non-declared input asset to remain on the continuation at `>=` its
input quantity — so the agent can buy anything but can only ever sell what the owner
declared. The continuation datum must equal the input datum with **only** `spends`
changed (`datum_ok` is a full structural equality), so all other fields are agent-
immutable. There must be exactly **one** guard-address input (`expect [guard_in]`);
the STT singleton is enforced on both the input and the single continuation, and the
guard never mints its own STT (`no_stt_mint`). `max_assets = 20` on the continuation.

The sliding-window clock is `now = hi`, the validity-range upper bound, with
`max_skew = 180000` ms and `hi - lo <= max_skew`; a tx is only included when the real
slot is inside `[lo, hi]`, so `now = hi` is ledger-consistent (no on-chain
fast-forward drain).

## FINAL HASHES

Reproducible from the committed compiled `plutus.json` via `aiken build`.

| Artifact | Hash |
|----------|------|
| Guard `scriptHash` (`validators/guard.ak`) | `8daa9ed8f913173d6e9360a5783bc9f9bdc7399526ff174b340ef3ff` |
| STT `policyId` (`validators/state_token.ak`) | `73b53d7c459a7c95b348b469888ea37acc5d12f5bc7ba92340f56082` |

Compiler: `aiken.toml` pins **Aiken v1.1.23** (CI); the committed `plutus.json` was
built with **v1.1.22+39d6b04**. stdlib **v3.1.0**, Plutus **V3**.

`validators/state_token.ak` embeds the guard script hash (`guard_script_hash`). The
guard does not reference the policy, so the build has no hash cycle, but any change to
the guard changes its hash: update the constant to the new `guard.guard.spend` hash and
run `aiken build` again, or the policy keeps minting only into the old guard.

## Build & verify

```sh
export PATH="$HOME/.aiken/bin:$PATH"
aiken build      # regenerates plutus.json and the two hashes above
aiken check      # type-checks and runs all 112 tests
```

A reviewer should see: `aiken build` reproduce **exactly** the two FINAL HASHES above
in `plutus.json` (byte-identical to the committed blueprint), and `aiken check` report
**112 tests, all passing**, with no warnings from the guard/state_token sources.

## Repo layout

```
lib/guard/types.ak        GuardDatum (12 fields), AssetCap, SpendRecord, GuardRedeemer
lib/guard/logic.ak        All spend-decision logic (OwnerSpend + the AgentSpend caps)
validators/guard.ak       Spending validator entry point (unparameterized)
validators/state_token.ak One-shot universal STT minting policy (name = blake2b_256 rule);
                          the mint checks the opening guard output and datum
```

Test suite (`validators/*_test.ak`, all green under `aiken check` — 112 tests):

| File | Tests | What it covers |
|------|-------|----------------|
| `guard_test.ak` | 10 | Per-asset baseline: honest ADA buys + within-cap declared-token sells PASS; over-cap sells, undeclared exfil, config tamper REJECT |
| `guard_ported_test.ak` | 25 | The v1 adversarial suite ported onto the per-asset datum (fully-compromised agent; true sliding window) |
| `stt_name_conformance_test.ak` | 5 | STT-name CBOR vectors — pins exact `cbor.serialise(OutputReference)` bytes AND the `blake2b_256` name |
| `security_findings_test.ak` | 3 | fable's F-1 + F-2 exfil reproducers, now REJECTED, plus a declared-token over-cap REJECT |
| `guard_redteam_test.ak` | 10 | Singleton / STT / window / datum-invariance regressions that must fail-closed |
| `datum_cbor_conformance_test.ak` | 1 | Pins `cbor.serialise(GuardDatum)` for a concrete 12-field datum |
| `audit_2026_11_16_test.ak` | 9 | Non-positive window or spend record, second state token or reference script on the continuation REJECT; owner sweeps a poisoned guard |
| `audit_2026_11_17_test.ak` | 49 | Every opening rule of the state-token mint REJECTS its violation, honest openings and the burn PASS; the agent branch refuses out-of-bounds terms; owner exit and the heaviest agent spend at the bounds |

## Opening rules and budgets

A mint is refused unless exactly one output carries the new token, at the guard script
(any stake credential), with no reference script, at least `min_principal` lovelace, no
other token of the policy and at most 20 non-ADA assets, under an inline `GuardDatum`
with `stt_policy` = the policy, empty `spends`, `kill = False`,
`3_600_000 <= window_len <= 2_592_000_000`, `0 < per_tx_cap <= daily_cap`,
`min_principal >= 0`, `1 <= max_spends <= 50`, at most 10 `token_caps` each with
`0 < per_tx <= daily`, and `datum.owner` among the required signers. The full table is in
[`CONFORMANCE.md`](./CONFORMANCE.md). The agent branch holds every guard to the same
window, cap and count bounds, so an out-of-bounds owner retune stops the agent, never
the owner.

Measured with `aiken tx simulate` on the compiled `plutus.json` (per-tx limit 14,000,000
mem / 10,000,000,000 cpu):

| Transaction | mem | cpu |
|---|---|---|
| Owner exit, any datum (empty, 50 records + 10 caps, 1,700 records, undecodable) | 31,551 | 9,139,636 |
| Owner close: exit + burn | 56,250 | 16,356,066 |
| Mint, honest opening | 246,017 | 87,417,232 |
| Mint at the bounds (`max_spends` 50, 10 `token_caps`) | 440,561 | 151,346,302 |
| Agent spend, 1 declared token, no prior records | 600,490 | 199,871,589 |
| Agent spend at the bounds (48 live records, 10 caps, 19 tokens + STT held) | 7,997,797 | 2,528,665,728 |

Docs:

```
THREAT_MODEL.md    Guarantees, trust boundaries, every invariant + enforcing clause, out-of-scope
PER_ASSET_CAPS.md  The per-asset-cap model, datum, and canonical `spends` reconstruction
CONFORMANCE.md     STT-name CBOR interop contract + the pinned name vectors
V2_PINNABLE.md     The unparameterized/pinnable design rationale (owner + stt_policy in datum)
```

**Security findings (fable's PR #1 red-team of the earlier lovelace-only v2-pinnable
guard):** **F-1** (HIGH) native-token exfiltration — the agent branch metered lovelace
only, so tokens shipped out for free (`outflow = 0`); **F-2** (HIGH) the same drain
hidden behind a negative ADA outflow so no spend record was written; **F-3** (LOW) the
guard's `no_stt_mint` pins only its own STT name, so the universal STT policy's
singleton invariant relies on the separate `state_token` minting policy. F-1 and F-2
are now **CLOSED** by per-asset caps (`token_caps` metering + `conserve_undeclared`)
and proven rejected in `security_findings_test.ak`. F-3 is carried as an explicit
threat-model note (by design: `state_token` is a distinct, audited one-shot policy).
The shared-address singleton double-satisfaction was fable's "Not a finding" — the
defense holds (`expect [guard_in]`) and is regressioned in `guard_redteam_test.ak`.

**Final red-team (this handoff):** the `aiken-validator-redteam` skill was run against
the per-asset validator — 17 agents across 14 eUTxO exploit classes (double_sat,
value_underpay, mint_integrity, auth, index, continuation, terms, receipt, refscript,
composed, directional, datum_decode, time, oracle_premium) plus 3 novel rounds.
**Result: GREEN** — zero confirmed and zero even-claimed vulnerabilities; every
attacker confirmed testing the per-asset validator. Integrity note: a first full run
returned a spurious RED because the skill's shared scratch dir let agents read STALE
copies of older validators (the buy-only and v1 ADA-only builds); this was caught by
post-run source verification, and the re-run used a fresh scratch root, a mandatory
source-check gate (grep `conserve_undeclared` / `token_caps`), and a fungible-backfill
refutation criterion. The one finding that could touch real code — "fungible backfill"
on `conserve_undeclared` — is a proven wash: conservation forces
`cont_qty >= guard_in_qty`, so `attacker_out = guard_in + attacker_in - cont <=
attacker_in` (an attacker can never extract more of an asset than they themselves
deposit). The double_sat copy was independently re-checked by hand: all aiken tests
pass and every high-value theft attempt is rejected.

## Client integration (hash-only attestation)

To trust a guard, the client (fable / AdamKit) computes a **4-part, hash-only**
attestation — no `apply_params` anywhere:

1. **Guard `scriptHash`** from the compiled per-asset `plutus.json` (pin by hashing
   the committed compiled code).
2. **STT `policyId`** from `state_token` (same, hash-only).
3. **STT token name** via `blake2b_256(cbor.serialise(genesis OutputReference))` — the
   exact CBOR rule and pinned vectors are in [`CONFORMANCE.md`](./CONFORMANCE.md).
4. **Decode the on-chain `GuardDatum`** (CBOR field order above) and verify
   `datum.owner == my key` and `token_caps == the user-consented set`.

The tx-builder must reproduce the canonical `spends` for `datum_ok`:
`new_spends = [ADA record {"","",now,ada_outflow}] if ada_outflow>0` `++` one
`{cap.policy,cap.name,now,outflow}` per `token_caps` entry with `outflow>0`, **in
`token_caps` order**, `++` the pruned-active records (prune predicate
`r.at + window_len >= now - max_skew`, `now = hi`, `max_skew = 180000`). It must emit
**exactly one** guard-address input and never add a second input at the universal
guard address (a deliberate fail-closed liveness caveat). See
[`PER_ASSET_CAPS.md`](./PER_ASSET_CAPS.md) and [`CONFORMANCE.md`](./CONFORMANCE.md).

## License

Apache-2.0.
