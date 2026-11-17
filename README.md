# ADAM Spending-Guard — per-asset caps (v2)

> Repo: `adam-spending-guard`, branch `v2-per-asset-caps`. Apache-2.0. Public audit
> repo prepared for an external integrator building the Gero iOS wallet client.

## What this is

An **opt-in Plutus V3 spending-guard** that bounds a delegated ADAM **agent session
key** so it can trade 24/7 autonomously without ever being able to drain the user.
Funds sit at the guard script address; the **owner** (phone key) can withdraw
everything, retune or revoke with only their own signature. The **agent** may
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
- **STT singleton authentication.** A one-shot state-thread token marks the live
  guard UTxO. The guard validator mints it itself (`mint` handler in
  `validators/guard.ak`), so the STT policy id **is** the guard script hash: one hash
  to pin. Uniqueness comes from the token **name**:
  `name = blake2b_256(cbor.serialise(genesis OutputReference))`. The genesis UTxO can
  be spent once, so each name mints once. Mint is exactly `+1`; burn is `-1` and checks
  nothing else.
- **STT lifetime.** The token only ever sits in an output that `guard_output` admits:
  at the guard script, under an inline `GuardDatum` naming the policy, on bounded terms,
  signed by that datum's owner. The mint opens one (empty `spends`, `kill = False`); an
  owner spend burns the token or continues the guard under the same rules with its
  `spends` carried forward; the agent keeps the datum. See "STT lifetime rules" below.
- **Two redeemers.** `OwnerSpend` — the owner signature alone; withdraw (burn the
  STT), retune, kill, top up, hand over (new owner co-signs). `AgentSpend` — the
  bounded session-key path; all caps enforced.
- **Datum** (`lib/guard/types.ak`, `GuardDatum`, 12 fields, in CBOR/declared order):

  | # | Field | Type | Meaning |
  |---|-------|------|---------|
  | 1 | `owner` | `VerificationKeyHash` | Owner key: withdraws alone (in datum for hash-only attestation) |
  | 2 | `stt_policy` | `PolicyId` | STT policy id = the guard script hash (in datum for attestation) |
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
immutable. There must be exactly **one** input at the guard's full address, payment and stake
credential (`expect [guard_in]`);
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
| Guard `scriptHash` = STT `policyId` (`validators/guard.ak`, `spend` + `mint`) | `785306d6add9549d2cfce3d6290ea4cf56f03903310232166754716a` |

Compiler: `aiken.toml` pins **Aiken v1.1.23** (CI); the committed `plutus.json` was
built with **v1.1.22+39d6b04**. stdlib **v3.1.0**, Plutus **V3**.

`plutus.json` lists `guard.guard.spend` and `guard.guard.mint` under the same hash: the
deploy transaction mints with the guard script itself.

## Build & verify

```sh
export PATH="$HOME/.aiken/bin:$PATH"
aiken build      # regenerates plutus.json and the hash above
aiken check      # type-checks and runs all 151 tests
```

A reviewer should see: `aiken build` reproduce **exactly** the FINAL HASH above
in `plutus.json` (byte-identical to the committed blueprint), and `aiken check` report
**151 tests, all passing**, with no warnings from the guard sources.

## Repo layout

```
lib/guard/types.ak        GuardDatum (12 fields), AssetCap, SpendRecord, GuardRedeemer
lib/guard/logic.ak        All spend-decision logic (OwnerSpend + the AgentSpend caps)
validators/guard.ak       Validator entry points (unparameterized): spend, and mint for
                          the one-shot STT (name = blake2b_256 rule)
```

Test suite (`validators/*_test.ak`, all green under `aiken check` — 151 tests):

| File | Tests | What it covers |
|------|-------|----------------|
| `guard_test.ak` | 10 | Per-asset baseline: honest ADA buys + within-cap declared-token sells PASS; over-cap sells, undeclared exfil, config tamper REJECT |
| `guard_ported_test.ak` | 25 | The v1 adversarial suite ported onto the per-asset datum (fully-compromised agent; true sliding window) |
| `stt_name_conformance_test.ak` | 5 | STT-name CBOR vectors — pins exact `cbor.serialise(OutputReference)` bytes AND the `blake2b_256` name |
| `security_findings_test.ak` | 3 | fable's F-1 + F-2 exfil reproducers, now REJECTED, plus a declared-token over-cap REJECT |
| `guard_redteam_test.ak` | 10 | Singleton / STT / window / datum-invariance regressions that must fail-closed |
| `datum_cbor_conformance_test.ak` | 1 | Pins `cbor.serialise(GuardDatum)` for a concrete 12-field datum |
| `audit_2026_11_16_test.ak` | 9 | Non-positive window or spend record, second state token or reference script on the continuation REJECT; owner sweeps a poisoned guard |
| `audit_2026_11_17_test.ak` | 88 | Every STT lifetime rule REJECTS its violation at mint and on owner continuation, the look-alike plant and its drains REJECT; agent spends that move nothing REJECT; stray funds go to the stake key or stay locked; honest openings, retunes, top-ups, handovers, withdrawals and burns PASS; the agent branch refuses out-of-bounds terms; budgets at the bounds |

## STT lifetime rules and budgets

Every output that receives the STT, at mint or on a continuing owner spend, must hold
exactly this token of the policy, at the guard script (any stake credential), with no
reference script, at least `min_principal` lovelace and at most 20 non-ADA assets,
under an inline `GuardDatum` with `stt_policy` = the guard hash,
`3_600_000 <= window_len <= 2_592_000_000`, `0 < per_tx_cap <= daily_cap`,
`min_principal >= 0`, `1 <= max_spends <= 50`, at most 10 `token_caps` each with
`0 < per_tx <= daily`, and that datum's `owner` among the required signers. A mint also
needs empty `spends` and `kill = False`; an owner continuation needs the input's
`spends` unchanged and the input owner's signature. An owner spend that does not
continue the guard must burn the STT. The full tables are in
[`CONFORMANCE.md`](./CONFORMANCE.md). The agent branch holds every guard to the same
bounds, and every agent spend must move ADA or a declared token out (write a record),
so `max_spends` also bounds how often the agent can spend in a window. An output at
the guard address with no state token and no inline `GuardDatum` (a plain send) goes
to the key in the address's stake credential, or stays locked if there is none, as on
ADAM's unstaked guard addresses.

Measured with `aiken tx simulate` on the compiled `plutus.json` (per-tx limit 14,000,000
mem / 10,000,000,000 cpu):

| Transaction | mem | cpu |
|---|---|---|
| Owner withdrawal (spend + STT burn), any datum incl. 1,700 records or out-of-bounds terms | 155,561 | 48,537,885 |
| Stray sweep by the stake key (no datum / foreign datum) | 71,168 / 81,282 | 23,142,549 / 26,206,942 |
| Owner retune (agent, caps, window, expiry) | 326,382 | 110,590,246 |
| Owner retune or top-up at the bounds (50 records, 10 caps) | 1,022,784 | 370,077,350 |
| Mint, honest opening | 257,315 | 89,443,310 |
| Mint at the bounds (`max_spends` 50, 10 `token_caps`) | 451,859 | 153,372,380 |
| Agent spend, 1 declared token, no prior records | 639,982 | 213,530,249 |
| Agent spend at the bounds (48 live records, 10 caps, 19 tokens + STT held) | 8,119,405 | 2,565,169,772 |

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
singleton invariant relies on the policy's own mint rules. F-1 and F-2
are now **CLOSED** by per-asset caps (`token_caps` metering + `conserve_undeclared`)
and proven rejected in `security_findings_test.ak`. F-3 is carried as an explicit
threat-model note: the policy is the guard validator's own one-shot `mint` handler,
and the STT lifetime rules keep every token inside an admitted guard output.
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
2. **STT unit** — the guard hash as policy plus the name of the user's own genesis
   input; locate the guard by this exact unit, never by "any token of the policy".
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
