# ADAM Spending-Guard — Threat Model

This document is the security narrative for an independent audit of the ADAM
spending-guard validator. It states what the contract is supposed to guarantee,
the trust boundaries, every on-chain invariant with its enforcing clause, the
attack classes considered, and — explicitly — what is **out of scope / knowingly
accepted**. Line references are to the sources in this repository.

## 1. What the guard is

An opt-in, per-user **bounded-autonomy vault**. A user ("owner", holding a phone
key) deposits ADA + tokens into a script UTxO. A delegated server-side **agent
session key** may then trade on the user's behalf **without further owner
approval**, but the *ledger* — not any off-chain policy — bounds what the agent
can do:

- the agent may lose at most `per_tx_cap` net ADA in a single tx,
- and at most `daily_cap` net ADA over **any** trailing `window_len` interval,
- while the guarded position never drops below `min_principal` ADA,
- and the **owner can unconditionally sweep/revoke at any time with only their key**.

The design bounds loss by **economic conservation, not a destination allow-list**
(`validators/guard.ak:7-13`): every lovelace that leaves the guard is captured by
`outflow = ada_in − ada_out` and charged against the caps, and the continuing
value is forced back to the guard address. A compromised agent therefore cannot
launder funds to its own address — doing so would drop the continuing output
below the caps and fail the spend.

## 2. Actors & assets

| Actor | Key | Trust | Capability |
|-------|-----|-------|------------|
| **Owner** | phone key (`owner` VKH, validator param) | trusted root | Unrestricted: sweep, retune caps, kill, rotate agent |
| **Agent** | server session key (`datum.agent` VKH) | **untrusted / assume-compromised** | Bounded spends only, within on-chain caps |
| **Gateway/runtime** | holds the encrypted session key | **untrusted** for this model | Builds + submits agent txs; cannot exceed what the validator permits |
| **Auditor** | — | — | Verifies the below |

**Asset at stake:** the ADA in the guard UTxO. **The security claim is about ADA
outflow only.** Non-ADA tokens may freely leave on the agent branch (that *is*
selling on a DEX); their appreciation is knowingly at risk (§7).

## 3. Trust boundary

**The on-chain validator is the entire trust root.** Everything off-chain — the
gateway, the runtime, the session key, the tx builders — is assumed potentially
compromised. The audit question is precisely: *given a fully hostile holder of
the agent session key and full control of transaction construction, what is the
maximum the owner can lose, and can the owner always recover?*

The validators in scope:
- `validators/guard.ak` — the spending validator (entry point).
- `lib/guard/logic.ak` — all decision logic (factored so the adversarial test
  suite runs the exact deployed code).
- `lib/guard/types.ak` — `GuardDatum`, `SpendRecord`, `GuardRedeemer`.
- `validators/state_token.ak` — the one-shot STT minting policy.

## 4. The two branches (`lib/guard/logic.ak:32-35`)

```aiken
when redeemer is {
  OwnerSpend -> list.has(tx.extra_signatories, owner)      // unrestricted root
  AgentSpend -> agent_spend_ok(datum, own_ref, tx, ...)    // bounded
}
```

### 4.1 OwnerSpend — unconditional

The owner branch requires **only** the owner's signature (`logic.ak:33`). No
gateway co-signature, no timelock, no second signer, no cap. The owner can at any
time sweep all funds, burn the STT (close the guard), retune every cap, flip the
kill switch, or rotate the agent key. This is the "you can always withdraw"
guarantee, and it holds **even if the gateway is offline or compromised** — the
sweep tx is built and signed on the owner's device; the session key is never
involved.

**Audit ask:** confirm there is no path by which the owner branch can be blocked,
griefed, or made to require a non-owner signature.

### 4.2 AgentSpend — bounded by 12 conjunctive checks (`logic.ak:38-147`)

All twelve must hold (`and { … }`, `logic.ak:134-146`); failure of any one fails
the spend:

| # | Invariant | Clause |
|---|-----------|--------|
| 1 | Agent signed | `agent_signed` — `list.has(tx.extra_signatories, datum.agent)` (45) |
| 2 | Kill switch off | `not_killed` — `!datum.kill` (46) |
| 3 | Exactly one guard input, STT-bearing | `expect [guard_in] = guard_inputs` + `quantity_of(...) == 1` (56-59) |
| 4 | Exactly one STT output, back to guard | `expect [cont] = stt_outputs` + `cont_to_guard` (62-68) |
| 5 | Asset-count bound (anti-dust-brick) | `assets_ok` ≤ `max_assets`(20) (81-82) |
| 6 | Validity range sane (≤ `max_skew`=180s) | `range_ok` (86) |
| 7 | Not past hard expiry | `not_expired` — `now < datum.expiry` (92) |
| 8 | Per-tx ADA outflow cap | `per_tx_ok` — `outflow <= per_tx_cap` (99) |
| 9 | Min-principal floor | `floor_ok` — `ada_out >= min_principal` (100) |
| 10 | Sliding-window daily cap | `daily_ok` — `sum_active + outflow <= daily_cap` (109-115) |
| 11 | Record-count bound | `count_ok` — `len(new_spends) <= max_spends` (125) |
| 12 | Datum invariance (config immutable to agent) | `datum_ok` — `cont_datum == GuardDatum { ..datum, spends: new_spends }` (127-130) |
| — | No STT re-mint on this branch | `no_stt_mint` (132) |

**Invariant 12 is load-bearing:** the agent forwards the *entire* datum unchanged
except `spends`. It **cannot raise its own caps, extend expiry, clear the kill
bit, or rotate itself** — any such change fails `datum_ok`.

## 5. The daily cap: a trustless sliding window

This is the subtlest property and the one most worth an auditor's attention
(`logic.ak:84-115`).

- The clock is the tx validity-range **upper** bound, `now = hi` (`logic.ak:91`).
  Deliberately the upper (not lower) bound: `hi ≥ real inclusion slot`, so a spend
  can never be charged into an already-elapsed window. Using `lo` would leak up to
  ~3× across a boundary; the upper-bound choice restores the clean bound.
- The validity range width is capped at `max_skew = 180_000` ms (`logic.ak:15,86`).
- **Prune** keeps records within the trailing window, boundary-inclusive and
  skew-shifted: `r.at + window_len >= now − max_skew` (`logic.ak:109-113`). Because
  both a record's stamp and `now` may lead real time by ≤ `max_skew`, a record is
  never dropped until `window_len` of **real** time has definitely elapsed.
- **Cap check:** `sum(active) + outflow <= daily_cap` (`logic.ak:115`).
- A new record `{at: now, amount: outflow}` is prepended only when `outflow > 0`
  (token-only / ADA-in moves don't bloat the list); the list is bounded by
  `max_spends` (`logic.ak:119-125`).

**Property to confirm:** net ADA outflow ≤ `daily_cap` over **any** real-time
`window_len` interval — i.e. no ≥2× burst across a window boundary. This is
trustless: there is no off-chain reset, heartbeat, or privileged actor; records
age out purely as a function of on-chain time. `validators/guard_test.ak`'s
`attack_boundary_burst_blocked` and `attack_window_len_apart_burst_blocked`
target exactly this.

## 6. The STT (state-thread token) — non-forgeable singleton

`validators/state_token.ak`: a one-shot policy that mints **exactly one** token
and only if a specific genesis UTxO is consumed (`state_token.ak:24`), and allows
only a single burn (`-1`) — every other quantity fails (`state_token.ak:21-28`).

Why it matters: the STT authenticates the **single canonical** guard UTxO. It
makes the daily accumulator non-forgeable — there is no older copy of the datum to
roll back to, and no parallel guard fork to drain the cap N times. The agent
branch requires exactly one STT input and one STT output back to the guard
(invariants 3-4), which is what kills the classic **double-satisfaction** attack.

## 7. Out of scope / knowingly accepted

An auditor should treat these as **design decisions, not findings**:

1. **Token appreciation is at risk.** The bound is on ADA only. A hostile agent
   can trade the guard's tokens on any DEX at bad prices; it just cannot extract
   more than `daily_cap` **ADA** per window, and proceeds return to the guard.
   Users are expected to fund guards with ADA they're willing to put under a bot.
2. **`daily_cap` per window is the delegation's loss boundary.** Within the caps,
   an attacker who controls the agent key/gateway *can* trade up to the cap until
   the owner disarms or sweeps. This is the accepted price of no-approval autonomy;
   the mitigation is conservative caps + the owner's unilateral exit, **not**
   preventing within-cap activity.
3. **Off-chain session-key handling is a separate review.** The key is generated
   server-side, encrypted at rest (AES-256-GCM under a dedicated secret), and held
   in-process only while armed. A full compromise is bounded by (1)+(2) above:
   never the principal below `min_principal`, never faster than the cap, and fully
   revocable on-chain by the owner regardless of gateway cooperation.
4. **No real-time on-chain anomaly detection yet.** Detection today is the owner
   noticing + disarming/sweeping. Adding alerting is a planned pre-mainnet item; it
   does not change the on-chain bound.

## 8. Attack classes considered (with tests)

`validators/guard_test.ak` is an adversarial suite (assumes a fully compromised
agent). Classes covered — an auditor should confirm coverage is complete and the
assertions are correct:

per-tx overflow · daily overflow · **boundary burst / ≤cap-per-window** ·
spend-record forgery/reset · max-spends overflow · dust-bloat DoS · window-boundary
abuse w/ max_skew · missing agent signature · kill-switch active · expired session ·
expiry-skew bypass · **cap elevation (datum tamper)** · **laundering to attacker
address** · STT strand-out · **double-satisfaction** · unbounded validity range ·
below-min-principal · no continuing output · sell-token flows.

## 9. Build & reproduce

```
aiken check      # type-check + run the full test suite (validators/guard_test.ak, state_token.ak tests)
aiken build      # produces plutus.json (compare to the committed one)
```

- Compiler pinned: **Aiken v1.1.23**, Plutus **V3** (`aiken.toml`).
- Dependencies pinned: `aiken.lock` (aiken-lang/stdlib v3.1.0).
- `plutus.json` is committed — the blueprint the deploy funds. Spend-validator
  hash **`f20044d0…`**. A reproducible `aiken build` should match it.

## 10. What we ask the audit to confirm

1. The sliding-window ≤ `daily_cap`-per-window property, **including** the
   `max_skew` boundary reasoning (`logic.ak:84-115`).
2. The owner branch is **unconditional** and cannot be blocked or made to require
   a co-signer (`logic.ak:33`).
3. **Datum invariance** on the agent branch — the agent cannot mutate any config
   field (`logic.ak:127-130`).
4. **STT singleton / no double-satisfaction** (`logic.ak:56-68`, `state_token.ak`).
5. `min_principal`, `expiry`, and `kill` interactions — no state that traps funds
   or that the agent can exploit.
6. Datum/redeemer CBOR decoding cannot be abused (malformed datum, wrong
   constructor, extra fields).
7. Completeness of the adversarial test suite vs. the invariants in §4.
