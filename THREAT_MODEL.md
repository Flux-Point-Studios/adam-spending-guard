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
- **Toolchain:** `aiken.toml` pins Aiken v1.1.23; the committed `plutus.json`
  was built with v1.1.22+39d6b04. stdlib v3.1.0. Reproducible via `aiken build`.
- **Final hashes (reproducible):**
  - guard `scriptHash` = STT `policyId` = `d7f32b57ac6365683fe35f43f60e2e21dd4626a5518614f96ba513ac`
    (one validator with a `spend` and a `mint` handler: the guard is its own
    state-token policy)

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
- the **owner can withdraw everything at any time with only their key** (burning the
  STT, whatever the datum holds), and retune, kill, top up or rotate the agent within
  the bounds;
- the STT never leaves an admitted guard output (§6.7), so a genuine token always
  means a guard whose current owner signed for it.

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
| **Owner** | phone key (`datum.owner` VKH) | trusted root | `OwnerSpend` on their key alone: withdraw everything (burn the STT), retune caps/token_caps/expiry within the bounds, kill, rotate agent, hand over with the new owner's signature |
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
- `validators/guard.ak` — the validator entry points: `spend` and `mint`. The `mint`
  handler is the one-shot STT policy (`mint_ok`), so the policy id is the guard's own
  script hash and the guard reads it from its own input's payment credential; there
  is no constant to keep in sync and no hash cycle.

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

## 5. The two branches (`logic.ak:42-61`)

```aiken
expect Script(policy) = own_input.output.address.payment_credential
when redeemer is {
  OwnerSpend -> owner_spend_ok(datum, own_input.output, policy, tx)   // owner root
  AgentSpend -> agent_spend_ok(datum, own_input.output, policy, tx)   // bounded
}
```

### 5.1 OwnerSpend — owner key only (`owner_spend_ok`, `logic.ak:63-77`)

The owner branch needs **only** the owner's signature: no gateway co-sig, no
timelock, no cap. What it constrains is where the **state token** goes. For every
token of the policy on the spent output, the same transaction either **burns** it or
**continues** the guard into an output that `guard_output` admits (§6.7), with the
input's `spends` carried forward unchanged. So the owner can at any time:

- **withdraw everything**: burn the STT and take all funds, whatever the datum holds
  (only `datum.owner` is read);
- **retune** caps, `token_caps`, `window_len`, `max_spends`, `min_principal`,
  `expiry` or `agent`, flip `kill`, top up, or move the guard to another stake
  credential, as long as the new datum stays within the bounds;
- **hand over** the guard to a new owner who co-signs.

An output at the guard address that carries no token of the policy is not a guard;
its datum's `owner` sweeps it with a signature and nothing else in the datum is read.

What the owner can no longer do is move the STT anywhere else (a wallet, another
script, or a guard naming an owner who did not sign). That was the 2026-11-17
red-team finding (§9): an attacker opened a guard they owned, owner-spent it into a
copy of a victim's guard (owner = victim, agent = attacker) at the victim's stake
address, and the copy carried a genuine STT, so it passed client attestation; any
top-up was then the attacker agent's to drain.

**Audit ask:** confirm no path lets the owner be blocked from withdrawing, or made
to need a non-owner signature to withdraw; and that no transaction can leave a token
of the policy in an output `guard_output` would refuse.

### 5.2 AgentSpend — bounded by conjunctive checks (`logic.ak:32-132`)

All checks in the final `and { … }` block (`logic.ak:116-131`) must hold; failure
of any one fails the spend.

| # | Invariant | Enforcing clause | Line |
|---|-----------|------------------|------|
| 1 | Agent signed | `agent_signed = list.has(tx.extra_signatories, datum.agent)` | 33 |
| 2 | Kill switch off | `not_killed = !datum.kill` | 34 |
| 3 | Own input's STT is a singleton `[Pair(stt_nm, 1)]` | `expect [Pair(stt_nm, 1)] = ... assets.tokens(datum.stt_policy)` | 40-41 |
| 4 | **Exactly one** input at the guard's full address (payment and stake credential), STT-bearing | `expect [guard_in] = guard_inputs` + `quantity_of(...) == 1` | 43-46 |
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
| 18 | Terms within the bounds (§6.7) and positive spend records | `state_ok = terms_ok(datum) && all spends amount > 0` | 163-166, 247-259 |
| 19 | Continuation holds only its own state token under the STT policy | `stt_singleton` | 63-65 |
| 20 | Continuation carries no reference script | `no_ref_script = cont.reference_script == None` | 66 |

Invariants 18-20 were added after the 2026-11-16 pre-mainnet audit; invariant 18 took its
current form, the shared `terms_ok`, after the 2026-11-17 re-audit. Every output that
receives the STT is checked against the same terms (§6.7), and the agent branch re-checks
them on every spend as defence in depth: a window shorter than one hour, a non-positive
cap, `max_spends` above 50 or more than 10 `token_caps` stops the agent, and a
non-positive spend record would void the rolling caps (18). An agent-key
holder could park a second token of the STT policy on the continuation, which
killed the agent branch for that guard (19), or attach a reference script to it (20).
Accepted as a design limit: the agent may still acquire up to `max_assets` undeclared
assets, whose min-ADA stays with them when the owner sweeps.

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

### 6.7 STT lifetime: `guard_output`, `mint_ok`, `owner_spend_ok` (`logic.ak:63-127`)

**Invariant.** Every token of the policy sits in an output at the guard script under
an inline `GuardDatum` that names the policy, holds terms within the bounds, and whose
`owner` signed the transaction that put the token there. The mint establishes it; the
owner branch keeps it (burn or admitted continuation); the agent branch keeps it (datum
invariance at the same full address, inv. 6 and 16).

`guard_output(policy, name, tx)` is the single check, shared by the mint and the owner
continuation. Each clause has a refusal test in `audit_2026_11_17_test.ak`:

| Rule | Clause | Refusal test(s) |
|---|---|---|
| Exactly one output carries the token | `expect [out] = list.filter(outputs, qty > 0)` | `token_carried_by_no_output_is_refused`, `token_carried_by_two_outputs_is_refused`, `owner_cannot_take_the_state_token_to_a_wallet` |
| It sits at the guard script (any stake credential) | `payment_credential == Script(policy)` | `token_sent_to_a_key_address_is_refused`, `token_sent_to_another_script_is_refused`, `owner_continuation_must_stay_at_the_guard_script` |
| No reference script | `reference_script == None` | `opening_with_a_reference_script_is_refused`, `owner_continuation_cannot_carry_a_reference_script` |
| Only its own token of the policy | `tokens(value, policy) == [Pair(name, 1)]` | `opening_with_a_second_state_token_is_refused` |
| At most `max_assets` (20) non-ADA assets | `length(flatten(without_lovelace)) <= 20` | `opening_with_more_than_twenty_assets_is_refused` |
| At least `min_principal` lovelace | `lovelace_of(value) >= min_principal` | `opening_below_min_principal_is_refused` |
| Inline datum decoding as `GuardDatum` | `expect InlineDatum(raw)`, `expect datum: GuardDatum = raw` | `opening_datum_by_hash_is_refused`, `opening_without_a_datum_is_refused`, `opening_datum_that_is_not_a_guard_datum_is_refused` |
| `stt_policy` is the policy | `datum.stt_policy == policy` | `opening_datum_naming_another_policy_is_refused`, `owner_continuation_must_name_this_policy` |
| Terms within the bounds | `terms_ok(datum)` | the 14 `opening_with_…` window, cap, `min_principal`, `max_spends`, `token_caps` tests; `owner_continuation_must_keep_its_terms_in_bounds` |
| The datum's owner signed | `list.has(extra_signatories, datum.owner)` | `opening_not_signed_by_the_owner_is_refused`, `a_handover_needs_the_new_owner_signature`, `attacker_cannot_plant_a_victim_owned_look_alike` |

**Mint (`mint_ok`).** Exactly one token of the policy, quantity `+1`, named after an
input it consumes (`minting_without_the_genesis_input_is_refused`,
`minting_a_name_no_input_hashes_to_is_refused`, `minting_two_is_refused`), landing in a
`guard_output` with empty `spends` and `kill = False`
(`opening_with_a_spend_record_is_refused`, `opening_with_1700_spend_records_is_refused`,
`opening_killed_is_refused`). Burn (`-1`) checks nothing else
(`burning_needs_nothing_but_the_burn`).

**Owner spend (`owner_spend_ok`).** The input datum's owner signs
(`an_exit_without_the_owner_signature_is_refused`,
`a_sweep_without_the_owner_signature_is_refused`), and each token on the spent output is
burned or continued into a `guard_output` whose `spends` equal the input's
(`owner_continuation_must_carry_its_spend_records_forward`; carrying records forward
means a retune or top-up never resets the daily window). `kill` and the stake credential
are free; the owner may change only with the new owner's signature, which
`guard_output` requires. Honest paths that pass: `owner_retunes_caps_agent_and_expiry_within_bounds`,
`owner_kills_the_guard`, `owner_tops_up_the_guard`,
`owner_moves_the_guard_to_another_stake_credential`,
`a_handover_signed_by_both_owners_passes`, `owner_exits_a_guard_retuned_out_of_bounds`,
`owner_exits_at_the_record_and_token_cap_bounds`, `owner_sweeps_a_utxo_without_a_state_token`.

**Stake credential.** A continuing owner spend may move the guard to any stake
credential. The stake credential grants no authority over the guard and is not part of
what a client attests; the owner's key is. Requiring the same stake credential would
add a rule without closing an attack: a plant at the victim's stake address needs the
victim's signature to name the victim as owner.

**Bounds.** The one-hour floor stops a short window from pruning records minutes after
they are stamped (with `window_len = 1` every record pruned about 180 s later, so the
agent could move `daily_cap` every 181 s and `max_spends` meant nothing). The thirty-day
ceiling keeps records prunable, so a full `spends` list empties within a window.
`max_spends <= 50` and at most 10 `token_caps` bound the agent's work, which grows with
records times declared tokens.

### 6.8 Execution budgets (measured)

Measured with `aiken tx simulate` on transactions built against the compiled
`plutus.json` (mainnet per-tx limit 14,000,000 mem / 10,000,000,000 cpu):

| Transaction | mem | cpu |
|---|---|---|
| Owner withdrawal: spend + STT burn, any datum (empty, 50 records + 10 caps, 1,700 records, out of bounds) | 86,931 + 32,101 | 27,272,267 + 8,528,812 |
| Owner sweep of a UTxO without an STT, undecodable datum | 60,728 | 19,497,217 |
| Owner retune (agent, caps, window, expiry) | 290,753 | 97,997,440 |
| Owner retune or top-up at the bounds (50 records, 10 caps) | 987,155 | 357,484,544 |
| Mint, honest opening | 256,815 | 89,363,310 |
| Mint at the bounds (`max_spends` 50, 10 `token_caps`) | 451,359 | 153,292,380 |
| Agent spend, 1 declared token, no prior records | 598,356 | 198,251,041 |
| Agent spend, 1 declared token, 48 live records, 19 tokens held | 4,315,286 | 1,379,510,399 |
| Agent spend at the bounds: 10 caps, 48 live records, 19 tokens + STT held | 8,006,463 (57%) | 2,528,773,180 (25%) |

The withdrawal reads only `datum.owner`, so its cost does not grow with the datum. The
unit tests that decode the whole datum first give the upper bound with a full decode:
`owner_exits_at_the_record_and_token_cap_bounds` 1,128,122 mem / 349,401,516 cpu under
`aiken check --trace-level silent`. The agent spend at the bounds leaves about 6M mem for
the swap scripts that run in the same transaction. On the compiled script the plant, the
unburned move of the STT to a wallet, and every out-of-bounds mint are refused.

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

### 7.3 The STT policy is the guard itself

The agent branch pins only its **own** STT *name* via `no_stt_mint` (inv. 17). The
**one-shot singleton** guarantee and the lifetime rules (§6.7) are enforced by the
same validator's `mint` handler and owner branch, so pinning the guard hash pins the
policy (§8, step 1). See Findings F-3 (§9).

### 7.4 Other accepted items

- **Within-cap activity is the delegation's loss boundary.** An attacker holding
  the agent key/gateway *can* trade up to the caps until the owner disarms or
  sweeps. This is the accepted price of no-approval autonomy; the mitigation is
  conservative owner caps + the owner's unilateral, gateway-independent exit.
- **Consented terms are the client's to pin.** The ledger bounds every guard's terms
  (§6.7) but cannot know which agent key, caps or expiry a user agreed to; the
  attestation (§8) pins them. A wallet must not sign a transaction that makes its key
  the owner of a guard it did not open and consent to, since that signature is what
  `guard_output` accepts as consent.
- **Duplicate `token_caps` entries, or an entry for the ADA sentinel (`""`, `""`),**
  only make the caps stricter (the same outflow is metered twice); the consent check
  rejects them off chain.
- **Off-chain session-key handling is a separate review.** Its compromise is fully
  bounded by the on-chain caps above and is revocable on-chain by the owner
  regardless of gateway cooperation.

---

## 8. Hash-only client attestation

What fable / AdamKit computes to trust a guard **without** trusting any server —
enabled by the unparameterized design (config is in the datum, not in script
params). The full checklist is in `CONFORMANCE.md`:

1. **guard `scriptHash`** from the committed compiled `plutus.json` — pin by hashing
   the compiled code (no `apply_params`). Must equal `d7f32b57…6ba513ac`. It is also the
   STT policy id.
2. **Locate the guard by the exact STT unit the user minted**: the guard hash plus
   `blake2b_256(cbor.serialise(genesis OutputReference))` of the input the user's own
   deposit consumed (`CONFORMANCE.md` vectors, `stt_name_conformance_test.ak`). Never
   accept any token of the policy: another user's guard carries a genuine one too.
3. **Decode the on-chain `GuardDatum`** (12-field CBOR order of §4) and pin every
   consented term: `owner == my key`, `stt_policy ==` the guard hash, `agent`, ADA
   caps, `window_len`, `token_caps`, `min_principal`, `max_spends`, `expiry`. Datum
   CBOR layout is pinned by `datum_cbor_conformance_test.ak`.

---

## 9. Findings closure (fable's PR #1 red-team)

fable red-teamed the earlier **lovelace-only** `v2-pinnable` guard. Disposition
against this per-asset revision:

| Finding | Severity | Description | Status |
|---------|----------|-------------|--------|
| **F-1** | HIGH | **Native-token exfiltration.** The agent branch metered lovelace only, so tokens shipped out "for free" (`outflow = 0` for tokens). | **CLOSED** — per-declared-token metering (`meter_tokens`, inv. 13) + acquire-only conservation of undeclared tokens (`conserve_undeclared`, inv. 14). Proven **REJECTED** in `security_findings_test.ak`. |
| **F-2** | HIGH | **Drain hidden by negative ADA outflow** — the same token drain produced no ADA spend record (net ADA in ≥ out), so nothing was charged. | **CLOSED** — same per-asset mechanism: tokens are now metered/conserved independently of the ADA leg, so a token exfil can no longer be masked by ADA accounting. Proven **REJECTED** in `security_findings_test.ak`. |
| **F-3** | LOW | `no_stt_mint` pins only the guard's **own** STT name, so the policy's singleton invariant rests on the mint and the STT lifetime rules. | **Carried forward as an explicit note.** The policy is the guard validator's own `mint` handler (one-shot name, quantity 1) and the owner branch keeps every token inside an admitted guard output (§6.7); pinning the guard hash pins the policy (§8). |
| (double-sat) | — | Shared-address singleton double-satisfaction. | fable's **"Not a finding."** Defense holds: `expect [guard_in]` (inv. 4). Regressioned in `guard_redteam_test.ak`. |
| ADAM-AUD-054 | HIGH | A non-positive spend record in the opening datum offset the rolling window. | **CLOSED** — refused at mint (`spends` empty) and on the agent branch (inv. 18). `audit_2026_11_16_test.ak`; `opening_with_a_spend_record_is_refused`. |
| ADAM-AUD-055 | HIGH | A non-positive `window_len` pruned every record at once. | **CLOSED** — refused at mint and on the agent branch below one hour (inv. 18). `audit_2026_11_16_test.ak`; `opening_with_a_1ms_window_is_refused`. |
| Re-audit 2026-11-17 #1 | — | An opening `spends` list of ~1,700 records was reported to push the owner exit to ~17.19M mem. | **CLOSED** at mint (`spends` empty, `max_spends <= 50`): `opening_with_1700_spend_records_is_refused`, `opening_with_max_spends_1700_is_refused`. The 17.19M figure came from a test that decodes the whole datum; the compiled owner branch costs 31,551 mem on that datum (§6.8), so owner exit was not blocked on chain. |
| Red-team 2026-11-17 (look-alike guard) | HIGH | With no victim key, an attacker opened a guard they owned, owner-spent it into a copy of the victim's guard (owner = victim, agent = attacker) at the victim's stake address. The copy carried a genuine STT and passed client attestation; a top-up was then drainable by the attacker's agent, within the copied caps or entirely with greedy caps. | **CLOSED** — the guard is its own STT policy, and an owner spend must burn the STT or continue it into an output `guard_output` admits, signed by the new datum's owner (§5.1, §6.7): `attacker_cannot_plant_a_victim_owned_look_alike`, `a_look_alike_never_reaches_client_attestation`, `a_look_alike_cannot_drain_a_deposit_within_copied_caps`, `a_greedy_look_alike_cannot_drain_a_whole_deposit`, `owner_cannot_take_the_state_token_to_a_wallet`. Clients now locate a guard by the exact STT unit they minted and pin agent, caps, `min_principal` and `expiry` (§8). |
| Re-audit 2026-11-17 #2 | HIGH | `window_len = 1` ms let the agent move `daily_cap` every ~181 s and voided `max_spends`. | **CLOSED** — one-hour floor at mint and on the agent branch: `opening_with_a_1ms_window_is_refused`, `agent_refuses_a_1ms_window_that_resets_the_daily_cap`. |

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

## 11. Test suite (all green under `aiken check` — 136 tests)

| File | Tests | Coverage |
|------|-------|----------|
| `guard_test.ak` | 10 | per-asset baseline |
| `guard_ported_test.ak` | 25 | ported v1 adversarial suite |
| `stt_name_conformance_test.ak` | 5 | STT-name CBOR vectors (byte + `blake2b_256` name) |
| `security_findings_test.ak` | 3 | F-1 + F-2 exfil now REJECTED; declared-token over-cap REJECTED |
| `guard_redteam_test.ak` | 10 | singleton / STT / window / datum-invariance regressions |
| `datum_cbor_conformance_test.ak` | 1 | pins `cbor.serialise(GuardDatum)` for a concrete 12-field datum |
| `audit_2026_11_16_test.ak` | 9 | 2026-11-16 audit: history, second-STT and reference-script refusals; owner sweeps a poisoned guard |
| `audit_2026_11_17_test.ak` | 73 | STT lifetime rules (§6.7): mint, owner continuation, look-alike plant; agent-branch terms; withdrawal, retune and agent spend at the bounds |

---

## 12. Build & reproduce

```
aiken check      # type-check + run the full test suite (136 tests)
aiken build      # produces plutus.json blueprints (compare to committed)
```

- Compiler pinned in `aiken.toml`: **Aiken v1.1.23**; `plutus.json` built with
  v1.1.22+39d6b04. Plutus **V3**.
- stdlib pinned: **v3.1.0**.
- Reproducible hash: guard `scriptHash` = STT `policyId` = `d7f32b57…6ba513ac`.

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
7. **OwnerSpend** withdraws with the owner key alone whatever the datum holds, and no
   transaction leaves a token of the policy outside an output `guard_output` admits
   (`owner_spend_ok`, `mint_ok`, `guard_output`, `logic.ak:63-127`).
8. Datum/redeemer **CBOR decoding** cannot be abused (malformed datum, wrong
   constructor, extra fields) — cf. the conformance tests.
9. **Findings closure** (§9): F-1/F-2 closed by per-asset caps; the look-alike guard
   closed by the STT lifetime rules; F-3 correctly scoped now that the policy is the
   guard itself.
